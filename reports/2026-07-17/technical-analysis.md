# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-17

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 644 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 644 |
| Unique family labels | 3 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 73 |
| unknown | 26 |
| Gafgyt | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 76 |
| sh | 11 |
| exe | 7 |
| xapk | 3 |
| vbs | 2 |
| dll | 1 |

## Per-Sample Analysis

### Sample 1: `f01dc226fd5602bc`

| Field | Value |
|---|---|
| SHA-256 | `f01dc226fd5602bc34e89dc712b84d8dc3783ff049d3a1344d698f1cfcb3dacb` |
| Family label | `unknown` |
| File name | `DHL Shipping Document-2774038374-PDF.vbs` |
| File type | `vbs` |
| First seen | `2026-07-17 03:33:47` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a59e1081c64b62686bc941ef7ec38c36` |
| SHA-1 | `58a8fe2fa581596b63b5bea4f7722e5a8ae2a63c` |
| SHA-256 | `f01dc226fd5602bc34e89dc712b84d8dc3783ff049d3a1344d698f1cfcb3dacb` |
| SHA3-384 | `971a0b89dc028d4583301743d9a9816f342f353600a503ab390b285e494ad69827ec57fe05be9fb5fd083d4e9bd08a67` |
| TLSH | `T153C20AD3BF5106938DCF139ADDBC0FAA8C94CA6580317C70ADBD761AD441B5822BD62A` |
| SSDEEP | `768:o6r2zEWuuytebDf9TfGfbfKff9K+NqDCKR2jXvIzKc6hqiiEIORLPcY9t:+zbGeblbqDCKRmXAec6hqVEfRrcYH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_f01dc226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f01dc226fd5602bc34e89dc712b84d8dc3783ff049d3a1344d698f1cfcb3dacb"
    family = "unknown"
    file_name = "DHL Shipping Document-2774038374-PDF.vbs"
    file_type = "vbs"
    first_seen = "2026-07-17 03:33:47"
  condition:
    hash.sha256(0, filesize) == "f01dc226fd5602bc34e89dc712b84d8dc3783ff049d3a1344d698f1cfcb3dacb"
}
```

### Sample 2: `276986727cd341d9`

| Field | Value |
|---|---|
| SHA-256 | `276986727cd341d97eecd625486862c423563b36038e6226ae0ea5a40c47f78d` |
| Family label | `unknown` |
| File name | `EGPL-476-2026.vbs` |
| File type | `vbs` |
| First seen | `2026-07-17 03:32:48` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3046299828205d546b0710ca26ba3229` |
| SHA-1 | `80de241f8905c157e2a31171c80860e7f5b62a53` |
| SHA-256 | `276986727cd341d97eecd625486862c423563b36038e6226ae0ea5a40c47f78d` |
| SHA3-384 | `8c384ec81072338756b0dd4a2c6d9286aa958b58cb4df6ab9b686bad362ae9276d4461abfe42323ba4c166d242c5699f` |
| TLSH | `T135C24C93BF8504D749CF11B789BC0F56885CC6C581737CA4EFEC7B59C845A1C21A891E` |
| SSDEEP | `768:m4zYfWOYJvxv7R9rd5rhier1m2f3i1kFNwnynWeYstRH:kOhxD9i+1Zfy1kFNWyzvH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_27698672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "276986727cd341d97eecd625486862c423563b36038e6226ae0ea5a40c47f78d"
    family = "unknown"
    file_name = "EGPL-476-2026.vbs"
    file_type = "vbs"
    first_seen = "2026-07-17 03:32:48"
  condition:
    hash.sha256(0, filesize) == "276986727cd341d97eecd625486862c423563b36038e6226ae0ea5a40c47f78d"
}
```

### Sample 3: `d820561970105911`

| Field | Value |
|---|---|
| SHA-256 | `d8205619701059115b6f9ca0bb30157effcdea1819188b97519fe29c59724227` |
| Family label | `unknown` |
| File name | `Phone+Simple+Cleaner_1.2.4.xapk` |
| File type | `xapk` |
| First seen | `2026-07-17 03:28:13` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95646f52772decfb480b809f94013e90` |
| SHA-1 | `7ea78766eec367ff1e772d09118f2702b02b2551` |
| SHA-256 | `d8205619701059115b6f9ca0bb30157effcdea1819188b97519fe29c59724227` |
| SHA3-384 | `ed2843cc784789afdd5eb945ab84e8bbed223babd6b4252afe86c659f53b6e56920b6f367974179bad9f54f0b750c1c7` |
| TLSH | `T1D7C61256F7A8EA1FD4377032496A5231514B4D169E839B43A81C3F0C78BBAD84F4EBC9` |
| SSDEEP | `196608:0K2apfzy/yqbXpxOC4Bc/bHKZL2KEjpp/1+QoBySfzO648tcqrUBdNbcnEc4:HbfzE9bXp/4Bc/j8EjjELBytPbqrUBdZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_d8205619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8205619701059115b6f9ca0bb30157effcdea1819188b97519fe29c59724227"
    family = "unknown"
    file_name = "Phone+Simple+Cleaner_1.2.4.xapk"
    file_type = "xapk"
    first_seen = "2026-07-17 03:28:13"
  condition:
    hash.sha256(0, filesize) == "d8205619701059115b6f9ca0bb30157effcdea1819188b97519fe29c59724227"
}
```

### Sample 4: `cec2a39e52791bf8`

| Field | Value |
|---|---|
| SHA-256 | `cec2a39e52791bf8b7505f1fda1ed41cb2d23e78951e6df5c327f0cc937ea4e2` |
| Family label | `unknown` |
| File name | `Super+Clean_1.8.xapk` |
| File type | `xapk` |
| First seen | `2026-07-17 03:27:23` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4e944b08e8c4ebda27e0fd9460a3fa9` |
| SHA-1 | `c1bc28303ca60fb31792c7cf29ca74605fd9680c` |
| SHA-256 | `cec2a39e52791bf8b7505f1fda1ed41cb2d23e78951e6df5c327f0cc937ea4e2` |
| SHA3-384 | `f9400c02c6145f0a02363ffc9c994cecab4b9baebdf9de072fe4cd965923d604efe13b8b51ce4537cd2b8ef84235c03a` |
| TLSH | `T19E37220AEF0DE42FDDE7B0388A9A0322A1577845574197A73A21C51DBE937E6DF09BC0` |
| SSDEEP | `393216:zHqoeT3K6QuHAYnqCNzRTPJ6k9cKFIMqF1Heuq9YAWcA+QxKI:bqoe7pQ+pqCoMcKeF1HtpEW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_cec2a39e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cec2a39e52791bf8b7505f1fda1ed41cb2d23e78951e6df5c327f0cc937ea4e2"
    family = "unknown"
    file_name = "Super+Clean_1.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-17 03:27:23"
  condition:
    hash.sha256(0, filesize) == "cec2a39e52791bf8b7505f1fda1ed41cb2d23e78951e6df5c327f0cc937ea4e2"
}
```

### Sample 5: `6b9650bb8feaa29b`

| Field | Value |
|---|---|
| SHA-256 | `6b9650bb8feaa29b1fdf076cf0b4f6aecdbe2bbcb40782a71b015ce6512c61f8` |
| Family label | `unknown` |
| File name | `com.empir.cist.camera_1.8.xapk` |
| File type | `xapk` |
| First seen | `2026-07-17 03:26:40` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17177abe07442152b6876b17096401bf` |
| SHA-1 | `44fd0f681ef520d3bf157db32c9c6d5e9a213f6d` |
| SHA-256 | `6b9650bb8feaa29b1fdf076cf0b4f6aecdbe2bbcb40782a71b015ce6512c61f8` |
| SHA3-384 | `9509d841d42a04dab8981725f10eeb816b25ca8e85d17f2498b6d75e4fc8106a7567e7becf1ebaaaf518ca5c642476e0` |
| TLSH | `T15677E14EE60CD93ADDCAF0BD4E8D05A3A0577D0416B1C1DA2C16960CFB936E44A76FA3` |
| SSDEEP | `786432:x9f7cuLzDkfCT+57YI9QIN53Rv0xRG49Juw1c0sg421goOTq4cUX:jDJDkK+Bjf5hSiX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_6b9650bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b9650bb8feaa29b1fdf076cf0b4f6aecdbe2bbcb40782a71b015ce6512c61f8"
    family = "unknown"
    file_name = "com.empir.cist.camera_1.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-17 03:26:40"
  condition:
    hash.sha256(0, filesize) == "6b9650bb8feaa29b1fdf076cf0b4f6aecdbe2bbcb40782a71b015ce6512c61f8"
}
```

### Sample 6: `199370e9ef009d12`

| Field | Value |
|---|---|
| SHA-256 | `199370e9ef009d12fee9b3c4ad682dd95d2809d3081396a839d4316b9107b1ac` |
| Family label | `Mirai` |
| File name | `tmpsl` |
| File type | `elf` |
| First seen | `2026-07-17 02:54:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a8ee48edc7c5be6c4865f9d93f5299e` |
| SHA-1 | `e379bf782b511e45e0c3db01cc8c9e9b3554dcad` |
| SHA-256 | `199370e9ef009d12fee9b3c4ad682dd95d2809d3081396a839d4316b9107b1ac` |
| SHA3-384 | `8f827d88aaa3d471a2b70a3890ada148ffda22cdb4088ccb9c13f19f5a533a242344a786fcd13a344d8e04c003e351c4` |
| TLSH | `T149D30906BF610FFBD86BDD3706B90705249C542A2AFA7B7579B4C818F64B24B4DD3860` |
| SSDEEP | `1536:UzEs5II1IsNc3hOJptF/pw+cXDVu0odRIDyfQukHKmHNBhHwA2Vwx:UzEs5IXxI1/BCFDyfelwA7x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_199370e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "199370e9ef009d12fee9b3c4ad682dd95d2809d3081396a839d4316b9107b1ac"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-17 02:54:51"
  condition:
    hash.sha256(0, filesize) == "199370e9ef009d12fee9b3c4ad682dd95d2809d3081396a839d4316b9107b1ac"
}
```

### Sample 7: `6affd6590f618b2a`

| Field | Value |
|---|---|
| SHA-256 | `6affd6590f618b2ae670f46f6351036f419eea08e139d06354354d74be857ca6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-17 02:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e7b7f30d00410ba40932d012d0c40b5` |
| SHA-1 | `b5b756209921adf2fe44385cdf2cfd43f0567589` |
| SHA-256 | `6affd6590f618b2ae670f46f6351036f419eea08e139d06354354d74be857ca6` |
| SHA3-384 | `b7cf1ab7df32828b39e54fe2fe861a089b110d695448cfec60f0b7a86c258d7df679cd422ef0fb5670c3b12c8eb5d7a8` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C8E63308AEE511EDEAB7413CAED15745F299B0B99B70C98F0B6CC722AD131F54D3DA02` |
| SSDEEP | `393216:4yhgNqS+zMJut7GOzpXMCHWUjXccuI3/PGTAI:9XSWMUFXpXMb8XJH/O7` |
| ICON-DHASH | `d4f8fcbc8cc47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_6affd659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6affd6590f618b2ae670f46f6351036f419eea08e139d06354354d74be857ca6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 02:52:09"
  condition:
    hash.sha256(0, filesize) == "6affd6590f618b2ae670f46f6351036f419eea08e139d06354354d74be857ca6"
}
```

### Sample 8: `5da44e36790d8bb2`

| Field | Value |
|---|---|
| SHA-256 | `5da44e36790d8bb2ab51d7b70bbc25063d8236b959a3452cbb4bc41b5bcd4966` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-17 01:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8c3c8d8b522b6c0879c364ccfbf38b0` |
| SHA-1 | `265109b8a26b6602bc5bcbb300fc7d38e7d07936` |
| SHA-256 | `5da44e36790d8bb2ab51d7b70bbc25063d8236b959a3452cbb4bc41b5bcd4966` |
| SHA3-384 | `31e904f1bd3c596e3d9055a3980426e68151cb49bffa93417f385fb186ecc4f9f31e372d27a1eaf39d395331590bf699` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BCE63358BBD002EED8A3403CDBE191DEA69974771B31C59F57AC43A65E832E08E3C617` |
| SSDEEP | `393216:dTqwYdIi8pp4cBKeB7+Sa5JnoXMCHWUjX1cuI3/PGTAI:dOkTpejeB7+S+mXMb8XCH/O7` |
| ICON-DHASH | `70f0f0e8e8e0f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_5da44e36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da44e36790d8bb2ab51d7b70bbc25063d8236b959a3452cbb4bc41b5bcd4966"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 01:52:09"
  condition:
    hash.sha256(0, filesize) == "5da44e36790d8bb2ab51d7b70bbc25063d8236b959a3452cbb4bc41b5bcd4966"
}
```

### Sample 9: `3bf8bc35c9909047`

| Field | Value |
|---|---|
| SHA-256 | `3bf8bc35c9909047deea7338c690480e8e2e36e5eb36b207c449080bda0e9a40` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-17 01:51:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaa40766d73644b1aea823ee8274d4d6` |
| SHA-1 | `e0ff53931adf18ec1bf38bb69a739bf3a3a3a38f` |
| SHA-256 | `3bf8bc35c9909047deea7338c690480e8e2e36e5eb36b207c449080bda0e9a40` |
| SHA3-384 | `fd2772441b1c704ac22cf1e26f3f193d2840177e5ecdd9be42bb6a5e339492ab91b3ed24f535536e19bdb437714a24d2` |
| TLSH | `T19DC32945B8829622C6D723BAFA6E21CD336163E9D3DF31038E219F1137C659B0D67B91` |
| TELFHASH | `t13c311077ef912bacabd94189919ae0190acc30dd3b5c1592df3ca74f8802dd1b42dc5b` |
| SSDEEP | `1536:lKSmAASQ6ei2cdv/Lpl+9RKp1anmmA4zQyCR8PajUSi0CmOlc45PLv7Htt:8PAA/6eedYZAlmPajU3xX7Htt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_3bf8bc35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bf8bc35c9909047deea7338c690480e8e2e36e5eb36b207c449080bda0e9a40"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-17 01:51:40"
  condition:
    hash.sha256(0, filesize) == "3bf8bc35c9909047deea7338c690480e8e2e36e5eb36b207c449080bda0e9a40"
}
```

### Sample 10: `94a7cc706c15d397`

| Field | Value |
|---|---|
| SHA-256 | `94a7cc706c15d397c1269f95c40b34d0ad7b9d4a90289bc1a133fc77323a3e98` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-17 01:50:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56da8a8b5981071db11ba15f633cdc3c` |
| SHA-1 | `3be7631d7e8dcae60dbaf3e43ca73e4c9d07646d` |
| SHA-256 | `94a7cc706c15d397c1269f95c40b34d0ad7b9d4a90289bc1a133fc77323a3e98` |
| SHA3-384 | `fa29ef425121675927a3b3302ebed8817745e5abd8b17a689adca03bdd0cbecb0f3cf11b5d812cadd56c05c4367aa60b` |
| TLSH | `T12123F142659E24B1DEF8133C7EADE98F621A0BE082C5731B17292BB8779871D1B77601` |
| SSDEEP | `768:2a4qwsMicR0iSKWLgPZEmWI/rMSUqJQb6PldfHny0HKAUGqXL7/ldQ6Gs3Uoz8:2qGR0/ELJUG0KXX5ML7/zXrz8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_94a7cc70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94a7cc706c15d397c1269f95c40b34d0ad7b9d4a90289bc1a133fc77323a3e98"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-17 01:50:54"
  condition:
    hash.sha256(0, filesize) == "94a7cc706c15d397c1269f95c40b34d0ad7b9d4a90289bc1a133fc77323a3e98"
}
```

### Sample 11: `7873a2d6270b9eb4`

| Field | Value |
|---|---|
| SHA-256 | `7873a2d6270b9eb4b775d3a95a2b358d36ce2021fb09dc50ee538ff0782b8b2b` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-17 01:46:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15accbb84473e4d8acce18393a4a3ec9` |
| SHA-1 | `75923c8ecf134bcd108a1389269af549d52ad7a4` |
| SHA-256 | `7873a2d6270b9eb4b775d3a95a2b358d36ce2021fb09dc50ee538ff0782b8b2b` |
| SHA3-384 | `8374cd8e14b8a9bf59a146f303f408eab1ec525bd70491aed2a467110bee7bc5794392e9576db581f585da0dc4bdf0fd` |
| TLSH | `T1CD433A95FD42AA12C6C545BBFF0E428C7727439CE2EA33039E256F21378B56A0E3B455` |
| TELFHASH | `t152b0121344005e7ce050c82380fb764010e913f801862c0e30cd6c12536788058162a8` |
| SSDEEP | `768:a94iNIIgQyGs4+BQj368TFAWM/Q4wulPj+ORQhZsK69Y2Vujjblcu25j8vx0RnI:ZiKQWEj1y/QYPaORtK69j4N4wvx0Rn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_7873a2d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7873a2d6270b9eb4b775d3a95a2b358d36ce2021fb09dc50ee538ff0782b8b2b"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-17 01:46:51"
  condition:
    hash.sha256(0, filesize) == "7873a2d6270b9eb4b775d3a95a2b358d36ce2021fb09dc50ee538ff0782b8b2b"
}
```

### Sample 12: `58c8bfd399a97340`

| Field | Value |
|---|---|
| SHA-256 | `58c8bfd399a9734077089dd88ef9efc22751ea002461b52ff744180fb3e366f2` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-17 01:43:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b01db963647017060bb234d611f97e1a` |
| SHA-1 | `1f3b0bdca85b3476db2d009572cc43e6d969b156` |
| SHA-256 | `58c8bfd399a9734077089dd88ef9efc22751ea002461b52ff744180fb3e366f2` |
| SHA3-384 | `57b2a5077cec270b6b27d5613d4b9bd0ca5a52f6b0384007981567372251499427291ef6afae4a1c09dd27f5eee539e1` |
| TLSH | `T15093F781B8824A6AC6E02379E66E718E33A0B3F5D2CF3127DD615B11779518B0D67F81` |
| TELFHASH | `t187e06140fe764b1844e75634ecdd07b49511211761664710cf54daf0883f118a31cd5e` |
| SSDEEP | `1536:9m0L9q1B6mDftrSq1hu9TnTb4UUhL2o2jDthSDH8ku8oeIH:9rBq1BtD6wq5UIORIH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_58c8bfd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58c8bfd399a9734077089dd88ef9efc22751ea002461b52ff744180fb3e366f2"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:43:39"
  condition:
    hash.sha256(0, filesize) == "58c8bfd399a9734077089dd88ef9efc22751ea002461b52ff744180fb3e366f2"
}
```

### Sample 13: `3f267bfc1659d5ad`

| Field | Value |
|---|---|
| SHA-256 | `3f267bfc1659d5ad927a7ba7cc278af09163e102449517040f8269cc4c485b66` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-07-17 01:42:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00a3180dcb1d284914add2c59bd54cb0` |
| SHA-1 | `7e5ea280b4901673dab405ebc9f468ca1df43162` |
| SHA-256 | `3f267bfc1659d5ad927a7ba7cc278af09163e102449517040f8269cc4c485b66` |
| SHA3-384 | `a2760225fd05258234e31b99db19818deb4500d923b3bad5317c33df16e38ff09300933fb1419b06fb284799d072e139` |
| TLSH | `T142E2D0A224D01EB0CB70C831EFA591C7B6832A3D8197A55A66498FF452EE8D809F8557` |
| SSDEEP | `768:SZ+6GyLuOzsD5AwQhe4ljYaDTTqu79rXu7Xs3UozL9:SKawDq3he4ljYaHTqu79rUKzp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_3f267bfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f267bfc1659d5ad927a7ba7cc278af09163e102449517040f8269cc4c485b66"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:42:54"
  condition:
    hash.sha256(0, filesize) == "3f267bfc1659d5ad927a7ba7cc278af09163e102449517040f8269cc4c485b66"
}
```

### Sample 14: `eb3f3fdc3f19e5ee`

| Field | Value |
|---|---|
| SHA-256 | `eb3f3fdc3f19e5ee7dd861389b3fb1fbd6b27b869b0977a11c5e8ead42582f0f` |
| Family label | `Mirai` |
| File name | `nz.spc` |
| File type | `elf` |
| First seen | `2026-07-17 01:42:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c78ad0b879be5aa317767d14263a234` |
| SHA-1 | `211b7dd3b7c5d7d5c797a3aafc5a576bf940e272` |
| SHA-256 | `eb3f3fdc3f19e5ee7dd861389b3fb1fbd6b27b869b0977a11c5e8ead42582f0f` |
| SHA3-384 | `4a7be0cc26590e9543cb45c77b89289d32f6be19c74b56d676383035236519f947cc92203525c515d6b8e77266c52d70` |
| TLSH | `T13DC36D22B4791E27C4E0A47B12F75722B1F657D915A8CA4E7E720E8EFF112D02907BB4` |
| SSDEEP | `1536:qZiuQ4LdR2JrmiofE/Srjq5mQ14WrGExdZCvhnfAlQAQKC1D+tAlPYm5XLxgFxHD:n3IbE/HnQBKC1ySNYOX1FXvI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_eb3f3fdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3f3fdc3f19e5ee7dd861389b3fb1fbd6b27b869b0977a11c5e8ead42582f0f"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-17 01:42:53"
  condition:
    hash.sha256(0, filesize) == "eb3f3fdc3f19e5ee7dd861389b3fb1fbd6b27b869b0977a11c5e8ead42582f0f"
}
```

### Sample 15: `a784ce0b3b32c06e`

| Field | Value |
|---|---|
| SHA-256 | `a784ce0b3b32c06ecfdf9f096bcb1876ed37ba124e393aeb03f1ca5ccf6dbf46` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-17 01:41:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be720fa7be18a370deec9fd9405f9379` |
| SHA-1 | `56747aa3d67e5c375ed582521856d0380b039d11` |
| SHA-256 | `a784ce0b3b32c06ecfdf9f096bcb1876ed37ba124e393aeb03f1ca5ccf6dbf46` |
| SHA3-384 | `c5127e910d2b257f3dade24435ae5130fec5bc3383cb2af6e2dfd0b2d194c9a6062c3b2c90922cf6ca9f51b628a22327` |
| TLSH | `T18EF3F805BB610EF7E85FCC3706E9270128CDA51622B97B36B534D958F64B28B26E3D70` |
| SSDEEP | `3072:ldrx+vzsw8TONAdQLty5l6Gm7UxbiuyZ6RlPP4FQQm8DrfIHB:lJx+vzXUONAdQLtKlTm7UxbiuyZ6RlPP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_a784ce0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a784ce0b3b32c06ecfdf9f096bcb1876ed37ba124e393aeb03f1ca5ccf6dbf46"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 01:41:41"
  condition:
    hash.sha256(0, filesize) == "a784ce0b3b32c06ecfdf9f096bcb1876ed37ba124e393aeb03f1ca5ccf6dbf46"
}
```

### Sample 16: `2a1776c73595bcee`

| Field | Value |
|---|---|
| SHA-256 | `2a1776c73595bcee6974802751eff6d9c579b1ce189909a74bce7ab6128d7a91` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-07-17 01:40:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cfabb89d39470e519460c28e0d1c338` |
| SHA-1 | `b8a5e59bafd11839c1e5691d5a65b8dc2da66ae1` |
| SHA-256 | `2a1776c73595bcee6974802751eff6d9c579b1ce189909a74bce7ab6128d7a91` |
| SHA3-384 | `35585366a5a00c5c190c05fa1fbd6af741eb14ab946f3a410dd517b552f3d675027f062884148de363f557c98d4bfb6c` |
| TLSH | `T16533F1EBD62B78C1CA7C99BD95EDAB746B5120F17223578CC7A51C4D530A7F82A4A00C` |
| SSDEEP | `768:c4MsSKFz9Q3V71gRjZ6G7wxPiix0RGuoFhrzwexQa0fvIY0JjKE67PMHN154RWW+:/FFOh157E81u+Wex5MX0J+E6Ax48` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_2a1776c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a1776c73595bcee6974802751eff6d9c579b1ce189909a74bce7ab6128d7a91"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 01:40:50"
  condition:
    hash.sha256(0, filesize) == "2a1776c73595bcee6974802751eff6d9c579b1ce189909a74bce7ab6128d7a91"
}
```

### Sample 17: `504e8e159761fa56`

| Field | Value |
|---|---|
| SHA-256 | `504e8e159761fa56a843801922b86e2c8c5c346c85062e56ed90901aaf3553de` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-17 01:26:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b58e4591b9c1dcceeeff4be3f03a010` |
| SHA-1 | `dc4396afd2a6816f56542deb7bf0f9c8688d6f62` |
| SHA-256 | `504e8e159761fa56a843801922b86e2c8c5c346c85062e56ed90901aaf3553de` |
| SHA3-384 | `a33aa09f598d6de3f036be461f2228bf06cc5921acc64929900edceb1100ea3eec8c88921971834868582ccb911b4e5a` |
| TLSH | `T1F4333995FD41AA02C6C155B7FF0E428C7727539CE2EE7303AA256F61378B86A0E3B541` |
| TELFHASH | `t152b0121344005e7ce050c82380fb764010e913f801862c0e30cd6c12536788058162a8` |
| SSDEEP | `768:yw4ONIBgQmGs687QV367NFYgMDGowelPj+ORIS/L6ghYKH1SsnvhPaXRjZ0RrI:sOxQyeVgEDGIPaORv6ghHHHaht0Rr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_504e8e15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "504e8e159761fa56a843801922b86e2c8c5c346c85062e56ed90901aaf3553de"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:26:58"
  condition:
    hash.sha256(0, filesize) == "504e8e159761fa56a843801922b86e2c8c5c346c85062e56ed90901aaf3553de"
}
```

### Sample 18: `1cb6602444e604e0`

| Field | Value |
|---|---|
| SHA-256 | `1cb6602444e604e0dfe8cb7b5240fb0e90536c503823293a9e9c1f3954aae038` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-17 01:23:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `294cf4cf1d626539bb1d3fd198c65ba2` |
| SHA-1 | `d8d9a9c29b6f1249135489f5d6359e0a0a9bf561` |
| SHA-256 | `1cb6602444e604e0dfe8cb7b5240fb0e90536c503823293a9e9c1f3954aae038` |
| SHA3-384 | `1be317689d46e16d97831a47dbf2b7006406ea0e95fd5f571e6e476335b05c996c7b0c03a0ead97b2375cc360c3eab47` |
| TLSH | `T174236D651A857C24AA98C4371D7E2F0CBDAD43E6324492DE7FCB3CF28C5AA9D910871D` |
| SSDEEP | `768:wXRWNGxVlal9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:klx7cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_1cb66024
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cb6602444e604e0dfe8cb7b5240fb0e90536c503823293a9e9c1f3954aae038"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-17 01:23:07"
  condition:
    hash.sha256(0, filesize) == "1cb6602444e604e0dfe8cb7b5240fb0e90536c503823293a9e9c1f3954aae038"
}
```

### Sample 19: `24c693f26a9b6a79`

| Field | Value |
|---|---|
| SHA-256 | `24c693f26a9b6a79dfbb2622ccf7f3a15748a31b60ebafa3930252efa591dc52` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-17 01:21:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35d5d50f26ee5b4efe6d1896cd843134` |
| SHA-1 | `905a5aaa8491af69e080e7e30b7fd533eb953dd2` |
| SHA-256 | `24c693f26a9b6a79dfbb2622ccf7f3a15748a31b60ebafa3930252efa591dc52` |
| SHA3-384 | `3d65cfffe6559a1efb06ba5d740b179f6930cff26ea0cf8e04667a474f43af9875296e70a3a73d321d0deaaa732956e9` |
| TLSH | `T1EDD097B3307B023A28BE0C81F0C6EC60F006C73F6D96C288BA0328706E64219F9C0B54` |
| SSDEEP | `6:hTmI+6/2rtosBkXzF/FvqAulNXYq9DG+NjVsNXYrkJ:Vu6/xD5BqPiq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_24c693f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24c693f26a9b6a79dfbb2622ccf7f3a15748a31b60ebafa3930252efa591dc52"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-17 01:21:14"
  condition:
    hash.sha256(0, filesize) == "24c693f26a9b6a79dfbb2622ccf7f3a15748a31b60ebafa3930252efa591dc52"
}
```

### Sample 20: `76feca35c0f4edbc`

| Field | Value |
|---|---|
| SHA-256 | `76feca35c0f4edbce47b970cf3dea5cfe4ec3af628bb3baa4efa32c22cb195fc` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-07-17 01:14:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `588ac7b4b964ceae35ca3ee57cf0a1f3` |
| SHA-1 | `d418decc049557544024a0b7088d7ca49acfde4b` |
| SHA-256 | `76feca35c0f4edbce47b970cf3dea5cfe4ec3af628bb3baa4efa32c22cb195fc` |
| SHA3-384 | `ae79bf99b44a64f4f05e086c0ab1f8a252f264572e39a52bac7558b17a3d9ea00d68fdfec62240f8d4fd95b7bd6ba71c` |
| TLSH | `T10DC37CC2B10D7EADE4933E7DC20527176E1C9A519C83511150B5FE072ABB6E72E32ACB` |
| TELFHASH | `t1cee024f2834fa725064dcbdd87ca73ac5a2de0880147ef57fe41043c90aaa4e761498f` |
| SSDEEP | `3072:ZIPI2h11W3WMnPpDBGadr5BrFN1lUvkov5NQLLjyoI:ePI2hUplh9BrDUvkoxNQXvI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_76feca35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76feca35c0f4edbce47b970cf3dea5cfe4ec3af628bb3baa4efa32c22cb195fc"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-17 01:14:54"
  condition:
    hash.sha256(0, filesize) == "76feca35c0f4edbce47b970cf3dea5cfe4ec3af628bb3baa4efa32c22cb195fc"
}
```

### Sample 21: `dfad56d46b0379ea`

| Field | Value |
|---|---|
| SHA-256 | `dfad56d46b0379eaf32c1969204b70dc30d5f44a74bc49d952a330eb170c0d93` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-17 01:09:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a7fa5f9c81b1e54da17eb5e7473c85d` |
| SHA-1 | `888b3da0ab027bddd645673676b95cc043b20957` |
| SHA-256 | `dfad56d46b0379eaf32c1969204b70dc30d5f44a74bc49d952a330eb170c0d93` |
| SHA3-384 | `5f141dcc2eca377b5f622964ba501c33df4ff43c8d2d8c061aae070a7afe634f80fbb5d30a7483267e98f96f292528c5` |
| TLSH | `T10DB35BC5E247D0F9D8160A302276FB375E76E17B1329DA83D7F49A32AC12AC1D4167AC` |
| TELFHASH | `t1e031f5faf2770cecabe08803964f27719c0d697b746026fd0af26826367715191b5d39` |
| SSDEEP | `3072:vpe9zJgGmi+dkEF5nSMnuAhDb4ySUBNIHcCeBX:vpe9zRx+dkE5nfuzwIHcCeBX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_dfad56d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfad56d46b0379eaf32c1969204b70dc30d5f44a74bc49d952a330eb170c0d93"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-17 01:09:46"
  condition:
    hash.sha256(0, filesize) == "dfad56d46b0379eaf32c1969204b70dc30d5f44a74bc49d952a330eb170c0d93"
}
```

### Sample 22: `e899c163318892d3`

| Field | Value |
|---|---|
| SHA-256 | `e899c163318892d3d121b80e85b53c4b2d6361a27820b921a11d825413d457a4` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-17 01:09:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adf1b34c494b3eca02ae3316c31db77f` |
| SHA-1 | `7a9039f0537278fea97f244afc5bb25d45af1da5` |
| SHA-256 | `e899c163318892d3d121b80e85b53c4b2d6361a27820b921a11d825413d457a4` |
| SHA3-384 | `c184ac50117a36c4872d39573abf721a850fa0eb3ce90946709504e5e926208e0d9e298ec5cce9dc3a9fb814d655bafd` |
| TLSH | `T1D923E16250D68909F8750273C9DF2F5FBC40F29768459AFF23C86066A152A297F19B81` |
| SSDEEP | `768:A5SFVzSlajq4M5tMbf8Ksm3CzFB9ix3DZkpae6wCawrbei3Glr2sbat3s9nbcuyK:A4i2BIFmypB9Av2grbeCuHnouy8Hy8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_e899c163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e899c163318892d3d121b80e85b53c4b2d6361a27820b921a11d825413d457a4"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-17 01:09:03"
  condition:
    hash.sha256(0, filesize) == "e899c163318892d3d121b80e85b53c4b2d6361a27820b921a11d825413d457a4"
}
```

### Sample 23: `a12922f8f8906ee5`

| Field | Value |
|---|---|
| SHA-256 | `a12922f8f8906ee5ebc6f0612236307e24a2a53a5f26f34b23e2ddab998fc304` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-17 01:07:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ff2e67d41a53a94a50b7163d9c5875d` |
| SHA-1 | `a37b62c043ca70f9c9b1d10c460917878c039dfa` |
| SHA-256 | `a12922f8f8906ee5ebc6f0612236307e24a2a53a5f26f34b23e2ddab998fc304` |
| SHA3-384 | `17d7090c454dfb9de544a4309b1b7128241cf5ce5276689bf32faa47db80bf1a56a917745c072a7505325b6af6e5cc99` |
| TLSH | `T1CFC32A06746158FDC15BC434C77FE937EA31B46D13243AAF2784AA712E22E751F0AB92` |
| SSDEEP | `1536:bLvXvtUQsrSA4YaQ1piFKpGPZixR3PsBawxelU8Hht5RQC/6xp5U+zh5G44porzF:bL92rSA4V7mGxecERex7zh5G4FZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_a12922f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a12922f8f8906ee5ebc6f0612236307e24a2a53a5f26f34b23e2ddab998fc304"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 01:07:47"
  condition:
    hash.sha256(0, filesize) == "a12922f8f8906ee5ebc6f0612236307e24a2a53a5f26f34b23e2ddab998fc304"
}
```

### Sample 24: `f8956e30821ef8a7`

| Field | Value |
|---|---|
| SHA-256 | `f8956e30821ef8a73215795e607abbe14b6d3efa17f9ba47fcdafc44b1f20e91` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-17 01:07:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da92e64fcd280f8c65a38ab9e611db29` |
| SHA-1 | `d825e5512e4e60df767abb7ec848a9691f19fb2c` |
| SHA-256 | `f8956e30821ef8a73215795e607abbe14b6d3efa17f9ba47fcdafc44b1f20e91` |
| SHA3-384 | `853d12c42108ffc1e2e80ac2ac5a58258d042162df7efeabf1c8a6bb3f3c34f951012a83d95dcf6cea5f65f9b26763ce` |
| TLSH | `T1444301FEA9ABD1B8DA1388F6958022C1BE341C0B77787967145843DE4DF7DA12B20F21` |
| SSDEEP | `1536:hc0/7x0Cn9SsMwkDeQaWVcsnMywKu+oavnkzvgZUd/v:xtZnsUkeq+l4vnkE6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_f8956e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8956e30821ef8a73215795e607abbe14b6d3efa17f9ba47fcdafc44b1f20e91"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 01:07:07"
  condition:
    hash.sha256(0, filesize) == "f8956e30821ef8a73215795e607abbe14b6d3efa17f9ba47fcdafc44b1f20e91"
}
```

### Sample 25: `2c97e2d57359fb34`

| Field | Value |
|---|---|
| SHA-256 | `2c97e2d57359fb344b5de8164fa93f8ec2e4cb758a908ec25a1ab742dca9a99c` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-17 01:07:05` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43b96948e81a27c875aa637c5ffb04ee` |
| SHA-1 | `e4cf3ac30b94c0aa93d27912b16c8f63398d72ff` |
| SHA-256 | `2c97e2d57359fb344b5de8164fa93f8ec2e4cb758a908ec25a1ab742dca9a99c` |
| SHA3-384 | `d50547e8cb5225d9f2adde6039d852c23c77800d59c9f2a91c0b3d8c0c0815b21e0ca13b0b81ed347f187d5ce86101f2` |
| TLSH | `T1EC01CED69500AC2100DE8A1C32971459F820D3CF164A4F38BFAC6E3DEBD8C14B06AFC8` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohah3yzz+/dBMTAnX:e9Qp+Msh3yz6/MTAnX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_2c97e2d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c97e2d57359fb344b5de8164fa93f8ec2e4cb758a908ec25a1ab742dca9a99c"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-17 01:07:05"
  condition:
    hash.sha256(0, filesize) == "2c97e2d57359fb344b5de8164fa93f8ec2e4cb758a908ec25a1ab742dca9a99c"
}
```

### Sample 26: `1f04bb3edad6c3ba`

| Field | Value |
|---|---|
| SHA-256 | `1f04bb3edad6c3ba22205bed96a5085aefb0611ec48c6eb73b57cc365ab3a16d` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-17 01:06:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `923803733bbf5b720d67ce2b9c935cd1` |
| SHA-1 | `ab90d703128ff42f7949ed66e15bc5944aef677f` |
| SHA-256 | `1f04bb3edad6c3ba22205bed96a5085aefb0611ec48c6eb73b57cc365ab3a16d` |
| SHA3-384 | `5b8e1f578b1f174ec383c8a7fe3b26aafd012b299654597dc748f48a265584d2507ee3028b7e847268e330ea4099489b` |
| TLSH | `T1D1C339A9F890DE52C6D1267AF75E518C33231378C3DE7106CE249E3477EB95A0A3E942` |
| SSDEEP | `3072:N2348J4ZU5Ng4EpPOoX9tUWcYEEUv57pMx2+jSOBFt7QUkZu+df1Dl:N2oc6PuWcYEEUv57pK2GvBFzA5d95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_1f04bb3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f04bb3edad6c3ba22205bed96a5085aefb0611ec48c6eb73b57cc365ab3a16d"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:06:26"
  condition:
    hash.sha256(0, filesize) == "1f04bb3edad6c3ba22205bed96a5085aefb0611ec48c6eb73b57cc365ab3a16d"
}
```

### Sample 27: `b78a23549c477c5e`

| Field | Value |
|---|---|
| SHA-256 | `b78a23549c477c5ebc564b25dd6871c6e1f1964302f5cbc4b5de190a8447319c` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-17 01:05:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e96d02c4e1795c83ad808f1e2ffac87c` |
| SHA-1 | `b0219308d2e4f4249eb2dd4eb4faabf914744abe` |
| SHA-256 | `b78a23549c477c5ebc564b25dd6871c6e1f1964302f5cbc4b5de190a8447319c` |
| SHA3-384 | `335c857b29ef598d53ac3a4707959601b39a2f79b90365b973e339deed333404052ee634771367ef4675c47896c3c82f` |
| TLSH | `T18143F11119016BEBC6E82C77B42F824997F71A7E9E3635702D207B79BAC560BB0B140F` |
| SSDEEP | `1536:MBRZXd83A0lYIQh/2hH1u7RIrNXJvacLfT:otOwGBPH16axXT7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_b78a2354
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78a23549c477c5ebc564b25dd6871c6e1f1964302f5cbc4b5de190a8447319c"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:05:06"
  condition:
    hash.sha256(0, filesize) == "b78a23549c477c5ebc564b25dd6871c6e1f1964302f5cbc4b5de190a8447319c"
}
```

### Sample 28: `b0f13b57395ac71b`

| Field | Value |
|---|---|
| SHA-256 | `b0f13b57395ac71b39d1d041c1c7fe8c145d9e3b0783cb336f66ab1f3f1ec596` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-17 01:02:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c38113f40d8be0d79a05f3b00520289` |
| SHA-1 | `f6c6687e75c748d2e7d9f27d01baf31348a7fa95` |
| SHA-256 | `b0f13b57395ac71b39d1d041c1c7fe8c145d9e3b0783cb336f66ab1f3f1ec596` |
| SHA3-384 | `cac83d9fefade99adae61da7ff88a7ace632adcb8331d1f6c6421cdfcb0293317dc05d276b6e6e85b2f07f2b05535bed` |
| TLSH | `T117B34BC4E243D0F9EC560534213AFB379A73E5BF212DDA43D3A49AB26C96AC1D40679C` |
| TELFHASH | `t12131d1fcb2770ce45bc09902f58e8b22cd0d7b2b296076a345b26924326755243bfc38` |
| SSDEEP | `3072:hd5qGekwumbRajd24Wg4I28xxfebx/S3HgGL:75qGek6bRaj4JI3GJS3HgGL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_b0f13b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f13b57395ac71b39d1d041c1c7fe8c145d9e3b0783cb336f66ab1f3f1ec596"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-17 01:02:17"
  condition:
    hash.sha256(0, filesize) == "b0f13b57395ac71b39d1d041c1c7fe8c145d9e3b0783cb336f66ab1f3f1ec596"
}
```

### Sample 29: `3b03e32d06c84721`

| Field | Value |
|---|---|
| SHA-256 | `3b03e32d06c84721bce47173fdb28283c185edf5a7b3a3b0c1282e424af0a40a` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-17 01:02:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1f524f7e00b3027630e8954dcbdb8e3` |
| SHA-1 | `8dbe7fde1c61b43497a14c3713ad4ef428ae7479` |
| SHA-256 | `3b03e32d06c84721bce47173fdb28283c185edf5a7b3a3b0c1282e424af0a40a` |
| SHA3-384 | `d2e22e60dabb80fd3f9bf8e1c5c65a09e8db0a6cd0c1caa99ad04e275c9fa582aaeda6bbfbaea29e98f84176b470f03f` |
| TLSH | `T1AE041A4F7721CF21C369D53049B38B9756A922622AE28485F35CDE083E6434DB91FFE9` |
| TELFHASH | `t16431cdf08b3b55219a89cbec89edb75a4a1e9115470adf33fe2180bc50160ede229d4f` |
| SSDEEP | `3072:XjYtZmy5PRLailkkaGEw/AQ+YLouEX0GoZSo1Dqjs9t:TYfmypR+Kknfy3vnonySe0m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_3b03e32d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b03e32d06c84721bce47173fdb28283c185edf5a7b3a3b0c1282e424af0a40a"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-17 01:02:09"
  condition:
    hash.sha256(0, filesize) == "3b03e32d06c84721bce47173fdb28283c185edf5a7b3a3b0c1282e424af0a40a"
}
```

### Sample 30: `e8c0c3b714243b97`

| Field | Value |
|---|---|
| SHA-256 | `e8c0c3b714243b977d7279d191686a355c2ef73bcda1dbbca1c4f751f33c2286` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-17 01:00:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2bf1805d108ea443fb850ae8baf173f` |
| SHA-1 | `7193de687e717e5104fa3d9892e192bc0210b66f` |
| SHA-256 | `e8c0c3b714243b977d7279d191686a355c2ef73bcda1dbbca1c4f751f33c2286` |
| SHA3-384 | `7b029ea44cfda5245312b4c47c126cf287d8c45a4e9c3442ecb79a10b40ba270681ee242f9a03092051f19f57f77b836` |
| TLSH | `T14F23F156A43E2A08C66B7231757D31C310A4D08D7EB2803B8E80E4AA9A71F5DEC7D3D3` |
| SSDEEP | `768:IQKTOSNoekrlarmeqOskbRUXwE5L4owd3jdJZQc3WrqamIHDLn4aCOkOwJnbcuyv:IQKTOGoeO1eqlXwOEowd50MTIjLnjaJU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_e8c0c3b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c0c3b714243b977d7279d191686a355c2ef73bcda1dbbca1c4f751f33c2286"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-17 01:00:53"
  condition:
    hash.sha256(0, filesize) == "e8c0c3b714243b977d7279d191686a355c2ef73bcda1dbbca1c4f751f33c2286"
}
```

### Sample 31: `560409bf7fd5c356`

| Field | Value |
|---|---|
| SHA-256 | `560409bf7fd5c35647e55577c5746fb4e8242fc2885f21828ded731ce7d442ed` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-17 01:00:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c171a9661e3c702345a1a5188989b101` |
| SHA-1 | `215639cc70d124e84f424bdcfe3e3e20afef9774` |
| SHA-256 | `560409bf7fd5c35647e55577c5746fb4e8242fc2885f21828ded731ce7d442ed` |
| SHA3-384 | `5a4c28e9952ca0385d372877203136a9aa35e1c59112950ccedf4e1ef328ef1a9760536a29f9d885bc09a792df84cbe7` |
| TLSH | `T1088312478C3C2967D2E313FE2F4D4D43F52AE29A3C18F249C3599C2D1D51988EAA9D36` |
| SSDEEP | `1536:o0/9WZOrYu1PX1JcmWyufakE8tjrgdixynWtQkEiw4K+w9ix/a/TeQMv:/muP1lWywJtj6itQkEiw4K+4ix/F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_560409bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "560409bf7fd5c35647e55577c5746fb4e8242fc2885f21828ded731ce7d442ed"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-17 01:00:52"
  condition:
    hash.sha256(0, filesize) == "560409bf7fd5c35647e55577c5746fb4e8242fc2885f21828ded731ce7d442ed"
}
```

### Sample 32: `e34fd49b7b29fe32`

| Field | Value |
|---|---|
| SHA-256 | `e34fd49b7b29fe32d7730995313d3c95c41a638a9679fe3fc8f63a1e66d46753` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-17 00:57:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed0e22368d57ad624797af95e92c768c` |
| SHA-1 | `bae43f1eb9803ae126fb8349448f311dfbd50a54` |
| SHA-256 | `e34fd49b7b29fe32d7730995313d3c95c41a638a9679fe3fc8f63a1e66d46753` |
| SHA3-384 | `24ed37a5b34372378eb261e1e5f21d419eb9fe72bd9c795c870107337f09cb803012386484165499ebf870e2c994b320` |
| TLSH | `T19CE34A59FA53C0F0E1C341F1067BABAA563A99226237F5E2FF563762F871302588532D` |
| SSDEEP | `3072:07o4IvnRjCebCEf1G4AT5KRcyBag6Gg2WIbH7K9G:5n5mxDKRLzO2ZbY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_e34fd49b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e34fd49b7b29fe32d7730995313d3c95c41a638a9679fe3fc8f63a1e66d46753"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-17 00:57:56"
  condition:
    hash.sha256(0, filesize) == "e34fd49b7b29fe32d7730995313d3c95c41a638a9679fe3fc8f63a1e66d46753"
}
```

### Sample 33: `1c17118204be5150`

| Field | Value |
|---|---|
| SHA-256 | `1c17118204be51503b5f6095c8ee14da3e4df8831b3fc973378e61d081a7120c` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-17 00:56:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cf8ce688029427988cfae77a437814e` |
| SHA-1 | `8841b7ba5fcef03b8440ade4f2a45224126e4ae1` |
| SHA-256 | `1c17118204be51503b5f6095c8ee14da3e4df8831b3fc973378e61d081a7120c` |
| SHA3-384 | `ee930620ac643545f1b0dba6694edd5e482b10c4d096c74e0697bd0c19a4d10c261f2524b1a91ab9fe90ebba2c9ef366` |
| TLSH | `T1114302A3437770E4C444BC7E880F7E8D8578F92A9454CBDA8C10AA334E6F966A55C73B` |
| SSDEEP | `1536:yPmAjqQM4sZGF5leZ3T+JONFa/Xzwnouy8DMW:mmSM3G9i7NQb4outDMW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_1c171182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c17118204be51503b5f6095c8ee14da3e4df8831b3fc973378e61d081a7120c"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-17 00:56:51"
  condition:
    hash.sha256(0, filesize) == "1c17118204be51503b5f6095c8ee14da3e4df8831b3fc973378e61d081a7120c"
}
```

### Sample 34: `5c8b631173fb1e60`

| Field | Value |
|---|---|
| SHA-256 | `5c8b631173fb1e60c3435613ac2620aa4e62fd10fb2f95ac07bb753d3355867b` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-17 00:56:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e2868a711f8efd7beef0e7ec1c1ad09` |
| SHA-1 | `49b9b125b0e47012bc1afec372a9bdb9dcb43653` |
| SHA-256 | `5c8b631173fb1e60c3435613ac2620aa4e62fd10fb2f95ac07bb753d3355867b` |
| SHA3-384 | `f16ffaec5339c0a06939375608627792bf1268558625a9c58dd31d78cf3c1afa04e4d3a6a2f0dbde8466dbf42ecd8d0d` |
| TLSH | `T16E237C46E643D4F9FA6B06B1103B97164772E8394039D756CBB96932ED33A00D72B3AC` |
| TELFHASH | `t1d43123a17e6608fcb740bd4ecb1a8693af09cfa74561b1bd40f82b4237f32758221930` |
| SSDEEP | `768:/FbMExhkby4yX6KWHPJJ/KE88vY1vwv7q6Xw8SJ19LhBb+IRdSjII4:/hvJ4A7WxQvwvW6XCdf3dSjI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_5c8b6311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8b631173fb1e60c3435613ac2620aa4e62fd10fb2f95ac07bb753d3355867b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-17 00:56:49"
  condition:
    hash.sha256(0, filesize) == "5c8b631173fb1e60c3435613ac2620aa4e62fd10fb2f95ac07bb753d3355867b"
}
```

### Sample 35: `cc17b6dc8a38d09e`

| Field | Value |
|---|---|
| SHA-256 | `cc17b6dc8a38d09ecb5c13c5eb24dff13b5015fa4e084931a82fcf84502e756c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-17 00:55:08` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f33f8c748e9958350c472514366a3aa` |
| SHA-1 | `c7efea5d14f5bd79ee789c62c0efa2f8ee759331` |
| SHA-256 | `cc17b6dc8a38d09ecb5c13c5eb24dff13b5015fa4e084931a82fcf84502e756c` |
| SHA3-384 | `bff78f3387d1f520c1d786e04463d522beef3478479a8ab3c6632763408a5d4ac149729ed1b5a5c4b95bf1819a936bac` |
| IMPHASH | `722ee3c091a704dcbdee8bc509a6531f` |
| TLSH | `T175E3491EA600458EFC8D21F18BC977EAC35910DDD397BA9D1E31FA6884B045CA2E375E` |
| SSDEEP | `3072:2Mh8Uh2QGmEfZJS4jwA9buGgUV3XFKWuEGTGiYiJcVl81BiG:2sh2qEfDS4jwA9buGgUVHqi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_cc17b6dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc17b6dc8a38d09ecb5c13c5eb24dff13b5015fa4e084931a82fcf84502e756c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-17 00:55:08"
  condition:
    hash.sha256(0, filesize) == "cc17b6dc8a38d09ecb5c13c5eb24dff13b5015fa4e084931a82fcf84502e756c"
}
```

### Sample 36: `e1568cae97252fa9`

| Field | Value |
|---|---|
| SHA-256 | `e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-17 00:52:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afc7b029f3a05b97b920d0407791ee68` |
| SHA-1 | `1d5b8d5858ed9521bc305b362d2a99e24272bfa2` |
| SHA-256 | `e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9` |
| SHA3-384 | `d0b14d69e6067eed8ff0b81cdfba8768fd0e83df6f10135be6976c30fd5b4c6993754ea00f6ce617be6c351d8bdff607` |
| TLSH | `T1E0F0AFD941016AE39F88D91F3953542D2242BBC931272FDCADCE25B9A284FD6F020E59` |
| SSDEEP | `12:KhI5W3CtI1/TKxfvbQYpLOhPvqbiAE+8lHA:KOQyS1bkfvbZpLOSiAylg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_e1568cae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-17 00:52:50"
  condition:
    hash.sha256(0, filesize) == "e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9"
}
```

### Sample 37: `9de680fe7c5e49f7`

| Field | Value |
|---|---|
| SHA-256 | `9de680fe7c5e49f7e9192caf0f3432f8086e6de549c5737a9912a97cd69abac1` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-17 00:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef71150d3850b8420428784c44ba6a66` |
| SHA-1 | `48d9f2084c960a15755d560df105a3a312b6e9a6` |
| SHA-256 | `9de680fe7c5e49f7e9192caf0f3432f8086e6de549c5737a9912a97cd69abac1` |
| SHA3-384 | `5328b399d47eb0daf4a95f7fc78f2ce9f6799532b3bc4efd0e716e8ade0a2642fb9fd2819cc69088e38a0d2e7e2d4990` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1FEE63308A9E026FDE9B3017CACE25592D6A1F8769B77C9CF175847E0AD571A04C3E323` |
| SSDEEP | `393216:+ADa5ux8pmpzuQOBJlkSdkKXOMDXMCHWUjX0cuI3/PGTAI:+zMx8pozuRD7XRXMb8XhH/O7` |
| ICON-DHASH | `e4b960c0dcf97218` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_9de680fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9de680fe7c5e49f7e9192caf0f3432f8086e6de549c5737a9912a97cd69abac1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 00:52:08"
  condition:
    hash.sha256(0, filesize) == "9de680fe7c5e49f7e9192caf0f3432f8086e6de549c5737a9912a97cd69abac1"
}
```

### Sample 38: `23ce81ebe09d6028`

| Field | Value |
|---|---|
| SHA-256 | `23ce81ebe09d6028b0e8259073855ef820e38f0107f4d6381bed182535095822` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-17 00:50:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da700c693bc248d9fd5bd934ac1f8bf9` |
| SHA-1 | `a90e30a99998a0f6585982cf77c85df2f9494aba` |
| SHA-256 | `23ce81ebe09d6028b0e8259073855ef820e38f0107f4d6381bed182535095822` |
| SHA3-384 | `cee6f984d543564ba1c3086bdb855bee7485b726069a480cd370b75b0e2989a9214657b1a351ec3d229c663474fdc191` |
| TLSH | `T15E235C512A857C14AA98C8371D7F2F0CB9A943E6324452DE7FCF3CF68C4AA9DA10971D` |
| SSDEEP | `768:hQFWzZx5/W9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:akzZcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_23ce81eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23ce81ebe09d6028b0e8259073855ef820e38f0107f4d6381bed182535095822"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-17 00:50:50"
  condition:
    hash.sha256(0, filesize) == "23ce81ebe09d6028b0e8259073855ef820e38f0107f4d6381bed182535095822"
}
```

### Sample 39: `b81bda693566e7b4`

| Field | Value |
|---|---|
| SHA-256 | `b81bda693566e7b4964f843c8d59e28cb75bc4d43faacbec6f0ef960040ee16d` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-17 00:50:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1ae2b07de3f11dc13cef996d3f93e19` |
| SHA-1 | `b13c60e824fb8901a8ccbd64cd0afcd2d961c5c7` |
| SHA-256 | `b81bda693566e7b4964f843c8d59e28cb75bc4d43faacbec6f0ef960040ee16d` |
| SHA3-384 | `0cac41e7acba73f21a1e4ee0c42af13f740232ebc83962d45fe5af6c71c74f163b9e14f89927c9a9939a8c5afac965d9` |
| TLSH | `T125D097B27A2302BC60321A99F2CBA860B0124B3F8D92812E7013A0305F8070EF0C03E0` |
| SSDEEP | `6:hTuigNsQCyTiKRFUycbAulNXYq4HvXDG+NjVsNXYrkJ:VuMvurcbPiq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_b81bda69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81bda693566e7b4964f843c8d59e28cb75bc4d43faacbec6f0ef960040ee16d"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-17 00:50:49"
  condition:
    hash.sha256(0, filesize) == "b81bda693566e7b4964f843c8d59e28cb75bc4d43faacbec6f0ef960040ee16d"
}
```

### Sample 40: `5947a93487ce5601`

| Field | Value |
|---|---|
| SHA-256 | `5947a93487ce560122175027f194386b6362768e266376a26ce90148f806fee0` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-17 00:46:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3af7d9a198a31e3c667a1789488811c` |
| SHA-1 | `df8706e55784e02176403d089215d06cc3b44d91` |
| SHA-256 | `5947a93487ce560122175027f194386b6362768e266376a26ce90148f806fee0` |
| SHA3-384 | `8e47fecff5a98b7f32419c0deca73dddf953320b0a9e17bd138d6f351dfd33d31806d3050e840e2813d06c0051e9dc01` |
| TLSH | `T152C28D966A867C44BEC94A3E4CBD2B1D6DF4C3D1324952AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:w8vCB+25j6es8Rj9FYpMSUpi+20qUpi+20YQX:w8l25Jld2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_5947a934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5947a93487ce560122175027f194386b6362768e266376a26ce90148f806fee0"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-17 00:46:52"
  condition:
    hash.sha256(0, filesize) == "5947a93487ce560122175027f194386b6362768e266376a26ce90148f806fee0"
}
```

### Sample 41: `815d37f2c17fbed0`

| Field | Value |
|---|---|
| SHA-256 | `815d37f2c17fbed0d44554177fc338f577901fecf43e101b8809b5540777095d` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-07-17 00:36:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7096945864afc2e99f5b447f8c7b5705` |
| SHA-1 | `0b155c87dd0de14487f7e1d4f08105f6d7547628` |
| SHA-256 | `815d37f2c17fbed0d44554177fc338f577901fecf43e101b8809b5540777095d` |
| SHA3-384 | `d68e50fda16bb72620e0e812026fb432bd8d0e868abe6ffa2cfa118ca4f4bca91941efa33369e5fb79bc530528cf41c1` |
| TLSH | `T1A2B3AE36E81968F4C06E8574E5A4BE790BA3F48052931EF716E6C6B65047EE4F806BF0` |
| SSDEEP | `1536:t/juy48gLDajwrmRZ2QprowQi1YKiC7p74Pe/9C/6otd1pH+:t7uy7eaMYZProwQi1fiQye/93efpH+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_815d37f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815d37f2c17fbed0d44554177fc338f577901fecf43e101b8809b5540777095d"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-17 00:36:53"
  condition:
    hash.sha256(0, filesize) == "815d37f2c17fbed0d44554177fc338f577901fecf43e101b8809b5540777095d"
}
```

### Sample 42: `5e1dea6db2c27f33`

| Field | Value |
|---|---|
| SHA-256 | `5e1dea6db2c27f33766997b67f3a2dc95ba58fa7e5851a30de8b074fe678dc31` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-17 00:35:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a937ce1d6eee9ee44d89c80e4b7569ff` |
| SHA-1 | `c2819ca06df3a83ea7e25a6661652868d391f7d5` |
| SHA-256 | `5e1dea6db2c27f33766997b67f3a2dc95ba58fa7e5851a30de8b074fe678dc31` |
| SHA3-384 | `91fd6991d83586bb7d1854650135a61e1463e9f833c32e4d50d9d6900479df4601757149bb33f357d55dccd65dbb6195` |
| TLSH | `T1B6147D01FF180953D5522EB45A3F07B6E379D88318F9E009190ABB561733EB7A6C7B89` |
| SSDEEP | `6144:kTgJqVdY0NPcpBjwAAkpOpLqo0nftfQ89:B4PcWeeNc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_5e1dea6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e1dea6db2c27f33766997b67f3a2dc95ba58fa7e5851a30de8b074fe678dc31"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:35:44"
  condition:
    hash.sha256(0, filesize) == "5e1dea6db2c27f33766997b67f3a2dc95ba58fa7e5851a30de8b074fe678dc31"
}
```

### Sample 43: `c73cbed870744e02`

| Field | Value |
|---|---|
| SHA-256 | `c73cbed870744e026b4f09dd0e2e8f3ae22a74ea46199b1a0a076a39b5f3be40` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-17 00:34:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e2e885b964b6223702ec7447790fa8f` |
| SHA-1 | `5ccb10e667978f8e2294a2d6e033ebd252231c8b` |
| SHA-256 | `c73cbed870744e026b4f09dd0e2e8f3ae22a74ea46199b1a0a076a39b5f3be40` |
| SHA3-384 | `f6e1d6abb37e330bfdba5651f2596df6cafad8401160436da4b6f19828f5700dbe949a356447d7fe3bb4f0f3083a26b3` |
| TLSH | `T1785302A3C25BD902FD63C652DD25D1E92BE207053070DAC34DECA320AF9257BAC68DE5` |
| SSDEEP | `1536:/arYAH4YwpsQUXzHPz4TcqxbrMdiUNnayz/rNVNJJ4u+qgw0r/:4+FXsk5Br8ifyzRf4u+qgwQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_c73cbed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c73cbed870744e026b4f09dd0e2e8f3ae22a74ea46199b1a0a076a39b5f3be40"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:34:53"
  condition:
    hash.sha256(0, filesize) == "c73cbed870744e026b4f09dd0e2e8f3ae22a74ea46199b1a0a076a39b5f3be40"
}
```

### Sample 44: `2e05529f2e98504b`

| Field | Value |
|---|---|
| SHA-256 | `2e05529f2e98504b0f04733be686c8628daa6032d56b8726573799aa48e5e0da` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-07-17 00:34:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `deca76e69218e65c5c1b8b92a4ab9483` |
| SHA-1 | `ecf78e954061b54ce4d78cda4c3f4fc5d1f9d85b` |
| SHA-256 | `2e05529f2e98504b0f04733be686c8628daa6032d56b8726573799aa48e5e0da` |
| SHA3-384 | `797a0f8595a6a455615923fb2b970e026c1807595815afedde68630d50e143a6c5ba694ed027f419eeca627ce47f6146` |
| TLSH | `T106C34B9AB4019D3DF94FD57B58632D1ABD20A3925183272A639BFD93AC321F47C02F85` |
| SSDEEP | `3072:XjXiHb1ZoCGRs0rBlpUjeZ5JqieX8KJFLOQs:TSHbPoCGRHqCZrquKJFLOQs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_2e05529f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e05529f2e98504b0f04733be686c8628daa6032d56b8726573799aa48e5e0da"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-17 00:34:52"
  condition:
    hash.sha256(0, filesize) == "2e05529f2e98504b0f04733be686c8628daa6032d56b8726573799aa48e5e0da"
}
```

### Sample 45: `64e65bae703a6b84`

| Field | Value |
|---|---|
| SHA-256 | `64e65bae703a6b848b5cbd19bfd6f56cf085fea6341a1dc03fbf3fa520ed8da4` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-17 00:32:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72ae0bc75d6a38213b9317ab00ec07cf` |
| SHA-1 | `f6a723c97014ec53196f8d3d1ff776d6013cd664` |
| SHA-256 | `64e65bae703a6b848b5cbd19bfd6f56cf085fea6341a1dc03fbf3fa520ed8da4` |
| SHA3-384 | `d128bd4718ec065ab239dc9d04a9e0f493d8c4ce85406c599a749894d27b1cb05bf9e41420df36d62f59c09ae2e53f5f` |
| TLSH | `T1D763C74A6E228FEDF66C833047B74B20E76963D623E1D685E29CD5041F6034D685FBA8` |
| TELFHASH | `t14e115a58443842f097a10ded6becff76e5a160db06256e378d10fda99b29a429d00c2c` |
| SSDEEP | `1536:E25iZVSKiVIsHv3AynvuOeFLWSgGiRyuv:E1sHv3AavuDg5yS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_64e65bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e65bae703a6b848b5cbd19bfd6f56cf085fea6341a1dc03fbf3fa520ed8da4"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-17 00:32:52"
  condition:
    hash.sha256(0, filesize) == "64e65bae703a6b848b5cbd19bfd6f56cf085fea6341a1dc03fbf3fa520ed8da4"
}
```

### Sample 46: `a1b7623d37a8540e`

| Field | Value |
|---|---|
| SHA-256 | `a1b7623d37a8540e38f18b56dffd692e84c1bcca672ed58bfec64921f7aa8e63` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-17 00:31:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c33789241b8dfc6edfdacd1a650367b` |
| SHA-1 | `c56185789153d1ffc11fc1d1f7ac82fa982ecc78` |
| SHA-256 | `a1b7623d37a8540e38f18b56dffd692e84c1bcca672ed58bfec64921f7aa8e63` |
| SHA3-384 | `a9406a6f158550dedd933e9d06b196a626b8b40bd102c6efce3d518495027a72607f40a5b29725bf1a7577c6c8b2a8a8` |
| TLSH | `T18FC339A9F890DE52C6D1267AF75E518C33231378C3DE7106CE249E3477EB95A0A3E942` |
| SSDEEP | `3072:N2348J4ZU5Ng4EpPOoX9tUWcYEEUv57pMx2+jSOBFt7QUkZu+Af1Dl:N2oc6PuWcYEEUv57pK2GvBFzA5A95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_a1b7623d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1b7623d37a8540e38f18b56dffd692e84c1bcca672ed58bfec64921f7aa8e63"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-17 00:31:00"
  condition:
    hash.sha256(0, filesize) == "a1b7623d37a8540e38f18b56dffd692e84c1bcca672ed58bfec64921f7aa8e63"
}
```

### Sample 47: `3e24ad303b4fe1d1`

| Field | Value |
|---|---|
| SHA-256 | `3e24ad303b4fe1d1715656a959aa40aa036128f694fa059377bac2b247ba788c` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-17 00:30:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `444b80f6b6d09a131a7b8d322a44fd8f` |
| SHA-1 | `d1bd6941e225f4b1cad12729b03a736573dcf186` |
| SHA-256 | `3e24ad303b4fe1d1715656a959aa40aa036128f694fa059377bac2b247ba788c` |
| SHA3-384 | `2c1c9fd8dc906af59fb890cd43d115f7fac4e4c7882ebaed0d6e2a1fc54f5783c7e33e7c09ba331bad302e54737f1f88` |
| TLSH | `T12443F11029012BDBC5F41C3BB52E930896AB5BBE5A76767028306B7DBB9271B74B044F` |
| SSDEEP | `768:hmKBnBAqA+iXd1iqgAfSplB1cB0IEYIQh/2hH1uk2R2bRLdhgQffK2yGxQi3U03y:MBRZXd83A0lYIQh/2hH1u7RIrtK2jefd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_3e24ad30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e24ad303b4fe1d1715656a959aa40aa036128f694fa059377bac2b247ba788c"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-17 00:30:47"
  condition:
    hash.sha256(0, filesize) == "3e24ad303b4fe1d1715656a959aa40aa036128f694fa059377bac2b247ba788c"
}
```

### Sample 48: `5baaccc34a67d221`

| Field | Value |
|---|---|
| SHA-256 | `5baaccc34a67d2217d67b45da0776bf139f63f45f5f40adcbe39cedbc7a31c5f` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-17 00:25:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f725ed6036e7c6947c361fbcbe5d464c` |
| SHA-1 | `68bb6ad005be6c0ded2158a3d7aa1893b7bfe30c` |
| SHA-256 | `5baaccc34a67d2217d67b45da0776bf139f63f45f5f40adcbe39cedbc7a31c5f` |
| SHA3-384 | `b8a713daa56dfc0307648a272adeb3784514bbdc6d98cacd178238df131a8c1435a09e14a84f2f30a7b0984a24ff74fb` |
| TLSH | `T172C32C99FC90DE52C6D1267AFA5E418C332357B8C3DA7205CD209F3477EBD5A0A3A942` |
| SSDEEP | `3072:KGTno9FSNuuBvo1iyk6UQ4g8OECqFmiPF9hS7amQ3f1Dlr:KGTonSNuub6UQ4g8OZqFmQS7aJ395r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_5baaccc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5baaccc34a67d2217d67b45da0776bf139f63f45f5f40adcbe39cedbc7a31c5f"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-17 00:25:55"
  condition:
    hash.sha256(0, filesize) == "5baaccc34a67d2217d67b45da0776bf139f63f45f5f40adcbe39cedbc7a31c5f"
}
```

### Sample 49: `07a3507588c075ff`

| Field | Value |
|---|---|
| SHA-256 | `07a3507588c075ffe32b516d435cfd27a9080d9fda8ba20b441a04cc13a8c103` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-07-17 00:24:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8133fd8007a0f2054b2e209dd3141552` |
| SHA-1 | `b606904eec49c87df820532c767ee2847dabba75` |
| SHA-256 | `07a3507588c075ffe32b516d435cfd27a9080d9fda8ba20b441a04cc13a8c103` |
| SHA3-384 | `651eb4ac16a2ef9bbd4f3fcfd82957f9422d28aec325ba7222327facbbfc807e16375df24132fc895a0f5576367bdda0` |
| TLSH | `T14133F23883DD7166D8194C33D3BA87819A81D0F823D96B1F2414C39C25D6ECFAE6C99B` |
| SSDEEP | `768:jFn0wBQ8q8DkOWEXJ8kZL1QQ0uHrsH3LNVkFaFBxMq2U2Wd4+gcMWO8h13U03wfD:jF0DIbVJl1QQtLsH35VUaFUqVic30fD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_07a35075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a3507588c075ffe32b516d435cfd27a9080d9fda8ba20b441a04cc13a8c103"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-17 00:24:51"
  condition:
    hash.sha256(0, filesize) == "07a3507588c075ffe32b516d435cfd27a9080d9fda8ba20b441a04cc13a8c103"
}
```

### Sample 50: `685da3603fe49eb1`

| Field | Value |
|---|---|
| SHA-256 | `685da3603fe49eb177b07a7c10b1da1dccdb99ff4d421c1cf299eea55107837a` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-17 00:13:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2322a4a63b4480f278b264988d32c0a9` |
| SHA-1 | `76eef747a4d53d837aeaa163a2e794c5b8725ea7` |
| SHA-256 | `685da3603fe49eb177b07a7c10b1da1dccdb99ff4d421c1cf299eea55107837a` |
| SHA3-384 | `97dfb9070521dc31519677179481d460c0fa800e999ff2f4a5a03dc39b186de7b2912ef755a591e1b57202abf86bea12` |
| TLSH | `T13B043B496E756BEBD05FCE30162D830712DDA44FA2F6A73EA678CC4C3D9A20859F3854` |
| TELFHASH | `t16431cdf08b3b55219a89cbec89edb75a4a1e9115470adf33fe2180bc50160ede229d4f` |
| SSDEEP | `3072:yej0n2FfuPdvkPXCVgaSGqcNIrcVcfF8XOn7HYQi1DR8:Za2FfuPpkPXUgaSGqcjVcfF8XOn7DYt8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_685da360
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "685da3603fe49eb177b07a7c10b1da1dccdb99ff4d421c1cf299eea55107837a"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 00:13:44"
  condition:
    hash.sha256(0, filesize) == "685da3603fe49eb177b07a7c10b1da1dccdb99ff4d421c1cf299eea55107837a"
}
```

### Sample 51: `56724d0851431582`

| Field | Value |
|---|---|
| SHA-256 | `56724d085143158238d02f1472e87786ff41e50f7a8d29fe254c427018065746` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-17 00:12:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7e3f8ace7b461f4ef6d513badcf93a3` |
| SHA-1 | `f8ac156ee5b4051db1f80b2bdb29f0ec66710fbe` |
| SHA-256 | `56724d085143158238d02f1472e87786ff41e50f7a8d29fe254c427018065746` |
| SHA3-384 | `74cb37d78aeecc241343b1b0a3236685732e0e256a067e26a225355432a1881a4239cee08862ba922999fa47e4bb6f4e` |
| TLSH | `T1E18312D608F35EBCD2C23FF76AB3D852C957E259BB8D93324B9045EC1D16492C94182B` |
| SSDEEP | `1536:GeHyd8OLduiLgLTti0D6PpEn4k5U9/HZlx0Rv7nnpJDIQ0Jml78jbF+G8E+ZtKHq:G3TLduiLgLTRuPpEn1UxHZle7nD5Kmlz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_56724d08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56724d085143158238d02f1472e87786ff41e50f7a8d29fe254c427018065746"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 00:12:52"
  condition:
    hash.sha256(0, filesize) == "56724d085143158238d02f1472e87786ff41e50f7a8d29fe254c427018065746"
}
```

### Sample 52: `c68ac31b40203f39`

| Field | Value |
|---|---|
| SHA-256 | `c68ac31b40203f39c9a784ea8209736364ce9a05a9b06670938e66ade6e25d78` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-17 00:12:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72793a36b6ad03df42e8fc4c3c39b671` |
| SHA-1 | `96442e6b491eda901d0e5e29e79377f362b493a6` |
| SHA-256 | `c68ac31b40203f39c9a784ea8209736364ce9a05a9b06670938e66ade6e25d78` |
| SHA3-384 | `34324c131271d5dc92ed8a8e966b269e96938d658ac93f692a090aac0cd6905fe10cd9210aef2d74a41935c5a2424bf3` |
| TLSH | `T176C34B0273180B47C5A319B02E3E3BE687FFE5E021E4BB89251E8B564575EB75849FC8` |
| SSDEEP | `1536:KqL5Jj5lED60/rhmvQ+f2evxDNScNGPuFZ+1mWdHKyELsHzI:KqL5JjQ2w5qbDPfFUmLGHzI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_c68ac31b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c68ac31b40203f39c9a784ea8209736364ce9a05a9b06670938e66ade6e25d78"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:12:50"
  condition:
    hash.sha256(0, filesize) == "c68ac31b40203f39c9a784ea8209736364ce9a05a9b06670938e66ade6e25d78"
}
```

### Sample 53: `c9889d7751721e05`

| Field | Value |
|---|---|
| SHA-256 | `c9889d7751721e0531e9221143ea1d9c20e3eda5dc18e88ddab6d52e3d729d74` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-07-17 00:11:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad4130be23b5bf51906d14f005f5c204` |
| SHA-1 | `772f60999af558e7b7bc197a5ce42ab7562b0411` |
| SHA-256 | `c9889d7751721e0531e9221143ea1d9c20e3eda5dc18e88ddab6d52e3d729d74` |
| SHA3-384 | `df2482933ddde874f5f2ee84040530e028f5bda3dd885e09dadf1a40cc3297091ebc0a7ba1096a1118cd94b8184f5fc1` |
| TLSH | `T13223F118D2F45FBADF9B52B61888D19627A0CBF7C367CE9230CDF6603155E02B499A90` |
| SSDEEP | `768:OmBrN1oPOSI35TzozdYvuP+3zx8QnjL5JnK+08vKOfdx/IA/k6xt6/NC/HxQR7k0:OCrN1oPO5KzdYvuCNPnjLvnKxoKmXIA+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_c9889d77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9889d7751721e0531e9221143ea1d9c20e3eda5dc18e88ddab6d52e3d729d74"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:11:05"
  condition:
    hash.sha256(0, filesize) == "c9889d7751721e0531e9221143ea1d9c20e3eda5dc18e88ddab6d52e3d729d74"
}
```

### Sample 54: `424f302b4f6f7edb`

| Field | Value |
|---|---|
| SHA-256 | `424f302b4f6f7edb6d7b6539e961216e078a12b2ce6c6df33bdb347ae50f73e7` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-17 00:09:12` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81c7439398578c2100a31d7a3ccab83b` |
| SHA-1 | `66538e46df9256efcdc999056c11b30e29b2013a` |
| SHA-256 | `424f302b4f6f7edb6d7b6539e961216e078a12b2ce6c6df33bdb347ae50f73e7` |
| SHA3-384 | `89c645911ef70b9a9b99f0878af208815c836c9c8d30fb490a524e2078030ee0e10c42bd7bf12f3226e80efd6ede8ca0` |
| TLSH | `T197016BC6D26099004059896E66AB9290B431C3C7555A4F6C7FDC983EEB89E14B03AF98` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkauCkS7KA7lCQJB8C9nU8CuDFCz1YkauD:kXCKysE2hi0ziQvZohaurmJNkZ8TFe7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_424f302b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "424f302b4f6f7edb6d7b6539e961216e078a12b2ce6c6df33bdb347ae50f73e7"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-17 00:09:12"
  condition:
    hash.sha256(0, filesize) == "424f302b4f6f7edb6d7b6539e961216e078a12b2ce6c6df33bdb347ae50f73e7"
}
```

### Sample 55: `d7fd0e83e6509cc2`

| Field | Value |
|---|---|
| SHA-256 | `d7fd0e83e6509cc290a309bab475d70008b04be72a307435d86e426464ce969b` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-17 00:07:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `538c27804f9d9382867b5b19f2c5fbae` |
| SHA-1 | `54884e23d1154349361e6e5c11857847db18003c` |
| SHA-256 | `d7fd0e83e6509cc290a309bab475d70008b04be72a307435d86e426464ce969b` |
| SHA3-384 | `b3f3324f1963e45c555176fb0fbea49619c1b9fd8e42866afab17ddb6b3613a98d6fc1267f8fc4947b534e5eecf44d46` |
| TLSH | `T191B31907BDC18DFDC089C038477F753ED822F0ED0239B2AB67D4AE262D5DEA11A19A55` |
| TELFHASH | `t1cb2177b03ed27a5c20c3d39ab35ede7ae0b209241a92b1e58f0b6dd98e06fc80c41456` |
| SSDEEP | `3072:gHoE9uzAHZeQ9eAT9kkzyQtJGCvR0MeITI8IunXYUxme:gIE4zAHZeQ9XT9kKjGMeKIIXYUxme` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_d7fd0e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7fd0e83e6509cc290a309bab475d70008b04be72a307435d86e426464ce969b"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 00:07:56"
  condition:
    hash.sha256(0, filesize) == "d7fd0e83e6509cc290a309bab475d70008b04be72a307435d86e426464ce969b"
}
```

### Sample 56: `e8e7b13785d70a30`

| Field | Value |
|---|---|
| SHA-256 | `e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c` |
| Family label | `Mirai` |
| File name | `e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c` |
| File type | `elf` |
| First seen | `2026-07-17 00:06:18` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `369c3ba06e1a86ed979e1ac18be5d235` |
| SHA-1 | `1ed6709d7d370242bb69330437fab23d612fcd75` |
| SHA-256 | `e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c` |
| SHA3-384 | `b82db6c85ca071531842d53e95aa01fb586ab740cc4ec9627b169365e9a168209b90e5db7dda11e5aaa4021fd8296acb` |
| TLSH | `T188F2E144BE7082CBCD84DC3E1E8C1735E6BE9A11BE05903183E45275DBB3DA5DAB3295` |
| SSDEEP | `768:GfI4zlmuIruFUZ+47HU49oc2UIFCPI1St0M:ABEZ57049bI8PGQz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_e8e7b137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c"
    family = "Mirai"
    file_name = "e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c"
    file_type = "elf"
    first_seen = "2026-07-17 00:06:18"
  condition:
    hash.sha256(0, filesize) == "e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c"
}
```

### Sample 57: `667d249e882f6e18`

| Field | Value |
|---|---|
| SHA-256 | `667d249e882f6e189bb1ef23aa29b147d89bf7de8820c2ea7b98ad12a1c78f21` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-17 00:04:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ff805e2db0c798a0a93c88e3f0eb07f` |
| SHA-1 | `4a9f3303a431ff8c31265c1b15a3c74c1d728a21` |
| SHA-256 | `667d249e882f6e189bb1ef23aa29b147d89bf7de8820c2ea7b98ad12a1c78f21` |
| SHA3-384 | `c5600c8f537ec22276e8e6fd4e739263425758d3a5197a1610015ba683ad8ab98c86c3240e258a63cba919364871755b` |
| TLSH | `T17823F2E7827FEA3EC511E676948F9650AA3E88092550C39B3FF422AD4FF7D4A1C10E04` |
| SSDEEP | `768:k+an3RY7qKS4o2SeAgPBOAcLorb6T8/s/hOMBtE47fJmfHq2BwyNIbiFj7QFix0S:03+7k4oZCAonl/aTE47BmAh6j0kx1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_667d249e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "667d249e882f6e189bb1ef23aa29b147d89bf7de8820c2ea7b98ad12a1c78f21"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 00:04:33"
  condition:
    hash.sha256(0, filesize) == "667d249e882f6e189bb1ef23aa29b147d89bf7de8820c2ea7b98ad12a1c78f21"
}
```

### Sample 58: `79e70f6eeddc2cb6`

| Field | Value |
|---|---|
| SHA-256 | `79e70f6eeddc2cb6a68a125ce45e985100cb51e35f66a327d97d5fa0e308327c` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-17 00:02:12` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a3d2bb882f413f4dfeda169d545eb7e` |
| SHA-1 | `840473bf6a313352b00d467bcda70c66c0467c5c` |
| SHA-256 | `79e70f6eeddc2cb6a68a125ce45e985100cb51e35f66a327d97d5fa0e308327c` |
| SHA3-384 | `2b171b7701a0f22ed4aded711819033a045ac0367a5600346a2fc639ddc13168c9d982430cac6b38cef0edd92d033cb0` |
| TLSH | `T108838D68AA0F6D81C2C7E3BEBD5A0FA370273CB48364C1B15A00E69DD4E9ED48D95167` |
| SSDEEP | `1536:bM9QcaqFqe2zYOa7gC+2zR+xWX7/FSKOC54L6AzIr:QeRq71wcRmWLFSKhRh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_79e70f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79e70f6eeddc2cb6a68a125ce45e985100cb51e35f66a327d97d5fa0e308327c"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-17 00:02:12"
  condition:
    hash.sha256(0, filesize) == "79e70f6eeddc2cb6a68a125ce45e985100cb51e35f66a327d97d5fa0e308327c"
}
```

### Sample 59: `199f3b730634be3c`

| Field | Value |
|---|---|
| SHA-256 | `199f3b730634be3c5259ec80111f7ac2b20e61e122dc56bf7516b75b965aab57` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-16 23:57:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f39c47286b0296690c11fa9d7ad637f0` |
| SHA-1 | `2bac65444a1acc97a40195c7b3f738eca56683ec` |
| SHA-256 | `199f3b730634be3c5259ec80111f7ac2b20e61e122dc56bf7516b75b965aab57` |
| SHA3-384 | `0642aee23d539c4247595033a39e8e7913954f52419aaa5034d8366aec4239024077dde87a5a6e353f9fb39523994da1` |
| TLSH | `T1FA73185AFD40AF11E5D625BAFF4E414933534B6CE3EE7212AE209B2527CA91B0F3B405` |
| TELFHASH | `t1b8b012e249440c9c5980ea27016f315120655e14549b3c2b3188de04d15301081354d8` |
| SSDEEP | `1536:TNBnk613bXwz8uy7Yaj65Gd6oMwtsTql3nibRkRBCUeZWYHQw0Rit:TXbAzI7Yaj65Gd6o1aRkRBCUeIfFit` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_199f3b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "199f3b730634be3c5259ec80111f7ac2b20e61e122dc56bf7516b75b965aab57"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-16 23:57:54"
  condition:
    hash.sha256(0, filesize) == "199f3b730634be3c5259ec80111f7ac2b20e61e122dc56bf7516b75b965aab57"
}
```

### Sample 60: `d5f9274b2974147a`

| Field | Value |
|---|---|
| SHA-256 | `d5f9274b2974147a1bcb86fe6568e05302880dd9c6c71d2c77cda32599ec68aa` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-16 23:57:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c17df48a5acebd237b924e51f8435d07` |
| SHA-1 | `dcffcced3518153c20bcd06cef4bc27f801abe4f` |
| SHA-256 | `d5f9274b2974147a1bcb86fe6568e05302880dd9c6c71d2c77cda32599ec68aa` |
| SHA3-384 | `7f382d9c937a1186e08b573769e7fe5572f8fa04e47f9c21a021cfae7443636d5d7b79ffc0f9978f5d7923cdb6d76846` |
| TLSH | `T110C32BC0F98B81F6C40B88305166F73FDB7198A95123DA9DEF999F72DA73582912234C` |
| TELFHASH | `t1843124b1f9b21eec5bd08803c6cf4b02ec0de6bb356021bd09fa1a5032b2151517ac3a` |
| SSDEEP | `3072:6FjlzYNVoZXRgn4c30tItERjnDBBMesWrhK8HY:mYNVoZhkD3OItYzDjw8HY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_d5f9274b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5f9274b2974147a1bcb86fe6568e05302880dd9c6c71d2c77cda32599ec68aa"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-16 23:57:40"
  condition:
    hash.sha256(0, filesize) == "d5f9274b2974147a1bcb86fe6568e05302880dd9c6c71d2c77cda32599ec68aa"
}
```

### Sample 61: `5ea3509f840f6cc8`

| Field | Value |
|---|---|
| SHA-256 | `5ea3509f840f6cc8b36e4930c7f6514253c3be358c7f83683c021d51fe6a2b97` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-16 23:56:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd654e0d1383fd54736077605ffd04ea` |
| SHA-1 | `199170845aaf06e9b608c5c3c20142f6d088abbe` |
| SHA-256 | `5ea3509f840f6cc8b36e4930c7f6514253c3be358c7f83683c021d51fe6a2b97` |
| SHA3-384 | `334d27ab79181b19c35d522f856f0bf6bebcefec67ea4f63184e8352fd37fc82bf5fb4be2661406084bf5a021df262e2` |
| TLSH | `T19623F12801B26E59B11F87F7686DF71B2B5430056621C5C632E0E071D7F3B3A1E2879A` |
| SSDEEP | `768:mYcUTiSFnR+ZW54r03UK12jc8/xCrNhRQeccxdk05pHFFGxhUWVuA53488Inbcum:mYcUTiMnR+1rKm9gTRRcyplFGxn35yIq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_5ea3509f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ea3509f840f6cc8b36e4930c7f6514253c3be358c7f83683c021d51fe6a2b97"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:06"
  condition:
    hash.sha256(0, filesize) == "5ea3509f840f6cc8b36e4930c7f6514253c3be358c7f83683c021d51fe6a2b97"
}
```

### Sample 62: `b228a7e7b1deba42`

| Field | Value |
|---|---|
| SHA-256 | `b228a7e7b1deba424f0a2764fc19c9d7181da226dec3bc3f9c16b0e66758ad6e` |
| Family label | `Mirai` |
| File name | `nerv.mpsl` |
| File type | `elf` |
| First seen | `2026-07-16 23:56:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e3147c080091800fedbf2153fb59736` |
| SHA-1 | `600fab2fd0b13cb4d9b9b195eba898d424aba6f7` |
| SHA-256 | `b228a7e7b1deba424f0a2764fc19c9d7181da226dec3bc3f9c16b0e66758ad6e` |
| SHA3-384 | `4273f7f512efd80b985661da9eb4ad1ba91ca1fd127fa1ecc89ca0f51f0d4030135ad4726cdf2c08839ab6838d931bf0` |
| TLSH | `T1D2D30816FB210EFBDCABCD374AE91705258C651A22AE7F367934C928F44B15B16E3C60` |
| SSDEEP | `3072:NXj17Jo82I/GFSiPep0639c51hER2jPrRz:NXFLOPX8mxERWVz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_b228a7e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b228a7e7b1deba424f0a2764fc19c9d7181da226dec3bc3f9c16b0e66758ad6e"
    family = "Mirai"
    file_name = "nerv.mpsl"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:05"
  condition:
    hash.sha256(0, filesize) == "b228a7e7b1deba424f0a2764fc19c9d7181da226dec3bc3f9c16b0e66758ad6e"
}
```

### Sample 63: `c995c35c2566d952`

| Field | Value |
|---|---|
| SHA-256 | `c995c35c2566d952e457350412fedbdce454a96c4690f06c68c730df7f7bc5c6` |
| Family label | `Mirai` |
| File name | `nerv.ppc` |
| File type | `elf` |
| First seen | `2026-07-16 23:56:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43cc44494a6a1510b1f89aebd3494e61` |
| SHA-1 | `a1075441487d2c80b31f500e62a4493d242cdd7a` |
| SHA-256 | `c995c35c2566d952e457350412fedbdce454a96c4690f06c68c730df7f7bc5c6` |
| SHA3-384 | `d4811790e2f13920ac45b97115e627d7a71a571bf8dcbb8a8e312c60683b9ec67ce4d57dd3f8c1400a3bb5f25a0a8c17` |
| TLSH | `T198B34D02731C0F47C5A75AB02E3F57E1A3FF999021F4BA89251E9B5692B1E361182FCD` |
| SSDEEP | `1536:bL8aGHx7rZazxJWsvNW/GHogtC4sr73+LzK9HqfYLObJqe4KwgmkyRwPIew5:bKKNvjoUsWCOb9djK5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_c995c35c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c995c35c2566d952e457350412fedbdce454a96c4690f06c68c730df7f7bc5c6"
    family = "Mirai"
    file_name = "nerv.ppc"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:04"
  condition:
    hash.sha256(0, filesize) == "c995c35c2566d952e457350412fedbdce454a96c4690f06c68c730df7f7bc5c6"
}
```

### Sample 64: `c714ddde7d41e337`

| Field | Value |
|---|---|
| SHA-256 | `c714ddde7d41e33700ce64966ad0673edcd92d5643f133919c9cff8532ebfea4` |
| Family label | `Mirai` |
| File name | `nerv.arm4` |
| File type | `elf` |
| First seen | `2026-07-16 23:56:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70eb1ab75d3139df06057b994c1f72e1` |
| SHA-1 | `ec1d23f089dbd7b497d69b28b9f1b0ab743198cd` |
| SHA-256 | `c714ddde7d41e33700ce64966ad0673edcd92d5643f133919c9cff8532ebfea4` |
| SHA3-384 | `df0247144fe1cd8749b81f5ba912084194db2d99b69a9d03e7582bcc68f1f99740d037de214c8b020efa8fcd01928fb7` |
| TLSH | `T172B31851BC825612C6D612BBFA6E418E375623A8D3EF3213CD255F203BC791B0E77652` |
| SSDEEP | `1536:7jcuL8lzTm/NWSGmQAf3ilNUsdnS3qF4h7Fo1YW/avLKX4zZ5thK1rKcLl6DUtaG:7jcKamISANUsdnS3qWJnWALw4zZlfjI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_c714ddde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c714ddde7d41e33700ce64966ad0673edcd92d5643f133919c9cff8532ebfea4"
    family = "Mirai"
    file_name = "nerv.arm4"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:02"
  condition:
    hash.sha256(0, filesize) == "c714ddde7d41e33700ce64966ad0673edcd92d5643f133919c9cff8532ebfea4"
}
```

### Sample 65: `186268920bb9c037`

| Field | Value |
|---|---|
| SHA-256 | `186268920bb9c037bc928b21d405d552f7b0127c551ff795661ee342ac1f9029` |
| Family label | `Mirai` |
| File name | `nerv.ppc440` |
| File type | `elf` |
| First seen | `2026-07-16 23:56:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c4a669cac6a76e4576d9bc49d3385aa` |
| SHA-1 | `69c73288944835b09f3bf0a27a003edf95351dff` |
| SHA-256 | `186268920bb9c037bc928b21d405d552f7b0127c551ff795661ee342ac1f9029` |
| SHA3-384 | `bbdc431b11e28de414d562f45c4c704c593b2d950ed7b7332c211bbae5cd12b9fb53f55e4482325a0203e9486d2ec855` |
| TLSH | `T1F0B3290377080F07D05319F42ABB4BF143AABDA128F4B689651ABF859771EF66042FC9` |
| SSDEEP | `1536:mLZU+Xofn/yNTWmukkQYxnMNEd/FWQ+g+N7O0uNqZ8bX3SO5KCorJQKq6+wIehJ:mrTtYYEJF4X7ODX3SgKrJrlJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_18626892
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "186268920bb9c037bc928b21d405d552f7b0127c551ff795661ee342ac1f9029"
    family = "Mirai"
    file_name = "nerv.ppc440"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:01"
  condition:
    hash.sha256(0, filesize) == "186268920bb9c037bc928b21d405d552f7b0127c551ff795661ee342ac1f9029"
}
```

### Sample 66: `f2b7fc5bec0da916`

| Field | Value |
|---|---|
| SHA-256 | `f2b7fc5bec0da916cad60ab71fedc56cfcf9e1f6a119aaa5fc3e856fa1d9ed1e` |
| Family label | `Mirai` |
| File name | `nerv.arm6` |
| File type | `elf` |
| First seen | `2026-07-16 23:56:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `009b2e3ee6e1d1ded153e62fe42d281a` |
| SHA-1 | `4715d405564ec405ed77425a75f961501bf9e398` |
| SHA-256 | `f2b7fc5bec0da916cad60ab71fedc56cfcf9e1f6a119aaa5fc3e856fa1d9ed1e` |
| SHA3-384 | `17400e75bbb60ca2d257ea91ca2049bcaf94b94303e2b623dc9e9916b8c8bd38a2c83d6271b15bcd5648f51c165cee74` |
| TLSH | `T1F4B32A86AC814A11C5D613BFFA2E118D3313277CE3DE72129D205F2477CA96B0E7BA56` |
| TELFHASH | `t1bdf08bd4a085318cabd51a95d5adb69114e638f83f4a1cc2ab8e5a4e13484f1b834c3f` |
| SSDEEP | `3072:BfxGIfE1qVXbO4bnOfGZKKajrfjIbVva4qWXCfuaM1kfxG/:iIfvlDDOeZKKa/jIbtancCgk5K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_f2b7fc5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b7fc5bec0da916cad60ab71fedc56cfcf9e1f6a119aaa5fc3e856fa1d9ed1e"
    family = "Mirai"
    file_name = "nerv.arm6"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:00"
  condition:
    hash.sha256(0, filesize) == "f2b7fc5bec0da916cad60ab71fedc56cfcf9e1f6a119aaa5fc3e856fa1d9ed1e"
}
```

### Sample 67: `2a2c89f18adebe53`

| Field | Value |
|---|---|
| SHA-256 | `2a2c89f18adebe537c277f96c0a4170de7e756ea3813b8bf1f141b6db9e10980` |
| Family label | `Mirai` |
| File name | `nerv.arm5` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0c3644421352a0e544e590bbcd1e5f5` |
| SHA-1 | `8699ec66c32d9ccb52b9a0af72367cd4753ad235` |
| SHA-256 | `2a2c89f18adebe537c277f96c0a4170de7e756ea3813b8bf1f141b6db9e10980` |
| SHA3-384 | `557eaac641b6cbd44838b375fbe79966888690b942575f9989bdd527c07a695fd437b986d497ddec5aa3db727bb8c4da` |
| TLSH | `T14CB32986BD826622C5D423BBFA6E418E771623A8D3EF72138D215F2037C792B0D77651` |
| TELFHASH | `t1afb012a1222077f6f7ce248200fb33110a84900f25ad15e162e86c4e01c7413b27bd12` |
| SSDEEP | `1536:fOlvWIlGPodwHHK7CDvDNUsdnYkqlGBPRLUa7agWzT70Vhg41clTWzutuIe0:fOlezoONUsdnYkq4CuvWzHbnWyh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_2a2c89f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a2c89f18adebe537c277f96c0a4170de7e756ea3813b8bf1f141b6db9e10980"
    family = "Mirai"
    file_name = "nerv.arm5"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:58"
  condition:
    hash.sha256(0, filesize) == "2a2c89f18adebe537c277f96c0a4170de7e756ea3813b8bf1f141b6db9e10980"
}
```

### Sample 68: `75226ce6759ba3b8`

| Field | Value |
|---|---|
| SHA-256 | `75226ce6759ba3b83b867d9529fd9361b8886ae1c27b3ffa479a9a8e48d79926` |
| Family label | `Mirai` |
| File name | `nerv.x86` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1aaaf52af5ae21176bacec187d5ec5db` |
| SHA-1 | `649e7cb0010b8b386295def9b196aa7907690bfe` |
| SHA-256 | `75226ce6759ba3b83b867d9529fd9361b8886ae1c27b3ffa479a9a8e48d79926` |
| SHA3-384 | `b851fbfdb6f51501b6ae6b7241ead30ccf7f5d4c1fcabf5a2e40eb5095b41eac781ed144e6dc2e71cfbfbabfe034fb1f` |
| TLSH | `T1DB936BC1E653E8F5ED1705751137E33B4B37F139102DD697DBA8AA32BCA2600D5262AC` |
| TELFHASH | `t196410cfa197f0cd897d4a802d20e2f31798eab3b656073e206f3b5753067501517ac39` |
| SSDEEP | `1536:Lh+jn2+ifI/EIzRBIepUGzX+VCW+XpElUx02V79KTiI3nPKxCdg71G+dkChCO:9+jn2tA/EIzPIepUG6VCPulo79AiI3Pa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_75226ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75226ce6759ba3b83b867d9529fd9361b8886ae1c27b3ffa479a9a8e48d79926"
    family = "Mirai"
    file_name = "nerv.x86"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:57"
  condition:
    hash.sha256(0, filesize) == "75226ce6759ba3b83b867d9529fd9361b8886ae1c27b3ffa479a9a8e48d79926"
}
```

### Sample 69: `fda211282012512d`

| Field | Value |
|---|---|
| SHA-256 | `fda211282012512d84a383602f1b7bebd9bdc8f737da26388c5884c1e36e2920` |
| Family label | `Mirai` |
| File name | `nerv.mips` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4264ad00e1204af090326e7e44c3fc7a` |
| SHA-1 | `87494ada5c7a8b12323986b46887b92d3145a022` |
| SHA-256 | `fda211282012512d84a383602f1b7bebd9bdc8f737da26388c5884c1e36e2920` |
| SHA3-384 | `0ca5cecbff70632d411f3ca9266b16f1748a03181706d0dfc0eebf59dca1f842e537d920ff4be1c0b64e1237a1565711` |
| TLSH | `T17FD3E71E6E218FBDF769C33447B78E25A39873C622E1C641E17CD6115E6028E641FFA8` |
| TELFHASH | `t1022151584e7827e477365c89559dfb7bd2a130ef3b125c378e11a8aab76cc819e20c0c` |
| SSDEEP | `3072:z0SBJcnFwP9oYCz0iL+6dw9BaFZnugZQeAgS1:vJoFwP7Cz0iqicp1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_fda21128
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fda211282012512d84a383602f1b7bebd9bdc8f737da26388c5884c1e36e2920"
    family = "Mirai"
    file_name = "nerv.mips"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:56"
  condition:
    hash.sha256(0, filesize) == "fda211282012512d84a383602f1b7bebd9bdc8f737da26388c5884c1e36e2920"
}
```

### Sample 70: `a771462d3aacd20a`

| Field | Value |
|---|---|
| SHA-256 | `a771462d3aacd20a9c599533fcd83bb86f24f081a0e7b95055013f9e1944a80a` |
| Family label | `Mirai` |
| File name | `nerv.sh4` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0a84742e4e22132577dd824c0712dca` |
| SHA-1 | `c8b254095bf8746380bdf2e34254eed0685758ad` |
| SHA-256 | `a771462d3aacd20a9c599533fcd83bb86f24f081a0e7b95055013f9e1944a80a` |
| SHA3-384 | `e39d495e178297d9b5d122436631187d858fd7b895038533ef9f8d7010fbc18259b2a2d5b8971dde95e4c8714f907d15` |
| TLSH | `T17393AD33C52A6DD4D6559674E0F48AF81B63E50082671FBB19D8C5E95087EBCF20A3F8` |
| SSDEEP | `1536:CGKS0rFc8wtAGzd8qjeCckbJcNcnwCQQjCTFilb3qK+UAA7ULEKwvCpuJUEFW8I7:CG70rFc89GBxjeCcEeWnDWY3t+mmEKwc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_a771462d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a771462d3aacd20a9c599533fcd83bb86f24f081a0e7b95055013f9e1944a80a"
    family = "Mirai"
    file_name = "nerv.sh4"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:54"
  condition:
    hash.sha256(0, filesize) == "a771462d3aacd20a9c599533fcd83bb86f24f081a0e7b95055013f9e1944a80a"
}
```

### Sample 71: `32bdd896bee92a82`

| Field | Value |
|---|---|
| SHA-256 | `32bdd896bee92a8235ecc41a890208096d20fa5c834b30a4aa88fc9f31568c7c` |
| Family label | `Mirai` |
| File name | `nerv.x86_64` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d7f16867ab6bd1a425f5ff30b055bf6` |
| SHA-1 | `e4b8827adcd1ce105349a16eb78c70171631623e` |
| SHA-256 | `32bdd896bee92a8235ecc41a890208096d20fa5c834b30a4aa88fc9f31568c7c` |
| SHA3-384 | `12c38bc358758a41ac26de024cf42c2f12778710eac0dcc210e88edd6812448ca6f63b3b7c395e7384bb5881ded9dfe0` |
| TLSH | `T14FA33903B4C088FDC189C17817AF763AD972F56E0139F1FB2BD0EA166D4DE215A1EA64` |
| TELFHASH | `t1cb317d701d9d28a850eb5729734ee0f9e9b1092504f235e65d37ecd2cf57b804ea50d3` |
| SSDEEP | `3072:EpSf3dIub3tZGahSksTYjSOYYQ2V1E1oRi6LbDMfsNMp/Uu:MSmub3tZrhSYjSOCiax6HD5Mp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_32bdd896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32bdd896bee92a8235ecc41a890208096d20fa5c834b30a4aa88fc9f31568c7c"
    family = "Mirai"
    file_name = "nerv.x86_64"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:53"
  condition:
    hash.sha256(0, filesize) == "32bdd896bee92a8235ecc41a890208096d20fa5c834b30a4aa88fc9f31568c7c"
}
```

### Sample 72: `835e224f2cc0d30c`

| Field | Value |
|---|---|
| SHA-256 | `835e224f2cc0d30c2bf23e403aa557bc94daa2000860b38a32762f75c65cabd0` |
| Family label | `Mirai` |
| File name | `nerv.x86_32` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6667239f85bd6acaa46f9e9645610cf` |
| SHA-1 | `f590ac9b12fbef6f147f84a6985b44f9530a45a8` |
| SHA-256 | `835e224f2cc0d30c2bf23e403aa557bc94daa2000860b38a32762f75c65cabd0` |
| SHA3-384 | `704aa1195d62ccd9761c8c63dbb1e5032c80f2356d9f37f65543a54cb4b8506bdb17bc11e10faf6a5f40596f8dd56fe1` |
| TLSH | `T19DA329C1F68B84F9D54B48704066F33FCF32E5268071C9AEDF99AF26DA37641921629C` |
| TELFHASH | `t1db411afa56760cd8a7d0ac03a64e5730ad0d27bb546076a309f72924331fd8645bbc3d` |
| SSDEEP | `3072:ZTdeqPbQ0yhOEckEUI6An128egcTz3s6GNCoUKcnsEW+QuYCeRh:ZTFPbQ0yhOEckEUI6A12ZHTz1emn0jIk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_835e224f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "835e224f2cc0d30c2bf23e403aa557bc94daa2000860b38a32762f75c65cabd0"
    family = "Mirai"
    file_name = "nerv.x86_32"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:52"
  condition:
    hash.sha256(0, filesize) == "835e224f2cc0d30c2bf23e403aa557bc94daa2000860b38a32762f75c65cabd0"
}
```

### Sample 73: `1d918cd3a53d12a7`

| Field | Value |
|---|---|
| SHA-256 | `1d918cd3a53d12a7342b8a5c952faf6f3dd31b43984376dc50376eef9250e8f1` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:50` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e364d4bb5c9de478f146f117389f49be` |
| SHA-1 | `fff923faaeed1e9a897128acee23d5ce03e4332b` |
| SHA-256 | `1d918cd3a53d12a7342b8a5c952faf6f3dd31b43984376dc50376eef9250e8f1` |
| SHA3-384 | `928d9475b606ee23f66cc49ae210e47b6d97dcba2bea9b8654a123dda6f4b30949ee581d860222c09403e95da68faed7` |
| TLSH | `T1D163E80AEF510EEBD86FDE3705A9070235CC994722B43B3A3574D92CF65A54B4AE3C68` |
| SSDEEP | `1536:6Az3UKmIIhbkmXIyKdTnpYr/AeIVHMSmOkR4B:6Az3gTXIhooO74B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_1d918cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d918cd3a53d12a7342b8a5c952faf6f3dd31b43984376dc50376eef9250e8f1"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:50"
  condition:
    hash.sha256(0, filesize) == "1d918cd3a53d12a7342b8a5c952faf6f3dd31b43984376dc50376eef9250e8f1"
}
```

### Sample 74: `30b74bdbf27c10ad`

| Field | Value |
|---|---|
| SHA-256 | `30b74bdbf27c10add54294d75e73d34ddca5bd389bd61a5c9c51e1bab2705ff8` |
| Family label | `Mirai` |
| File name | `nerv.m68k` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73b7403a31c4644828a38dbdabbf93db` |
| SHA-1 | `6d9402c64de7ae37bac768936f6bc5472399d937` |
| SHA-256 | `30b74bdbf27c10add54294d75e73d34ddca5bd389bd61a5c9c51e1bab2705ff8` |
| SHA3-384 | `4f00a17a32489229e58b6403dffadb44b56bcbe40d535c1a76ebd0fc8a5ae1104d1e049dbc8cedc7080a7d271f938a46` |
| TLSH | `T130B34AD6F801DE7DFC0EDB7F4457050AB621A36216835F3A6757BE63BC310A46922E82` |
| SSDEEP | `1536:M/Fd8MNhs3SVr7fVnYMFNlzV2I1K8FFBGPtj6vpPc/rLU1BCuQJ0dpj0:GFd/GC/VnrNl52I1bBe61KPuQJGpQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_30b74bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30b74bdbf27c10add54294d75e73d34ddca5bd389bd61a5c9c51e1bab2705ff8"
    family = "Mirai"
    file_name = "nerv.m68k"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:49"
  condition:
    hash.sha256(0, filesize) == "30b74bdbf27c10add54294d75e73d34ddca5bd389bd61a5c9c51e1bab2705ff8"
}
```

### Sample 75: `a266eed844e439b9`

| Field | Value |
|---|---|
| SHA-256 | `a266eed844e439b943d2d734b2697905914a8a5478c3767fe7435da339db8173` |
| Family label | `Mirai` |
| File name | `all.sh` |
| File type | `sh` |
| First seen | `2026-07-16 23:55:48` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b95a8166d6570ad88a76e4693d4905a8` |
| SHA-1 | `f0a8ec9bc84ea6a20aa43a425a0d8db528c1179e` |
| SHA-256 | `a266eed844e439b943d2d734b2697905914a8a5478c3767fe7435da339db8173` |
| SHA3-384 | `71c3525ca11bd36f42ac285f19aec457729df6f08a25eb2be06c3711e33d19df5c5f5a05065c513d1e25794127615c0b` |
| TLSH | `T12A11C2166803C0F2D36A557F8B6FE24A30F730531022A818B74E3B214F7B5217962A45` |
| SSDEEP | `24:EucrM1apkMQHMQZrxMQQLHMQXBMQuH2MqMuM3hMsD+MFw3MT3sKkMxslMrlu/+MB:5craapkFHrrxyHNBMWUuAhfD+gK4st0I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_a266eed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a266eed844e439b943d2d734b2697905914a8a5478c3767fe7435da339db8173"
    family = "Mirai"
    file_name = "all.sh"
    file_type = "sh"
    first_seen = "2026-07-16 23:55:48"
  condition:
    hash.sha256(0, filesize) == "a266eed844e439b943d2d734b2697905914a8a5478c3767fe7435da339db8173"
}
```

### Sample 76: `b019e12026ac88f8`

| Field | Value |
|---|---|
| SHA-256 | `b019e12026ac88f8e95e5b579aaea7129659e1c97433d16bea769b29c2acf7f6` |
| Family label | `Mirai` |
| File name | `nerv.arm7` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce8c364f2cddd7ad361174d846dc3069` |
| SHA-1 | `39db49fa376caea91da1f3ed1d23545369243d3c` |
| SHA-256 | `b019e12026ac88f8e95e5b579aaea7129659e1c97433d16bea769b29c2acf7f6` |
| SHA3-384 | `d43c0a47e94311343b746f4398b7009f853a7bbd52e89870234bc9c4a8b20340854ce06ef6a131b1a759b0842008a45c` |
| TLSH | `T101D32A46A9415E12D5D732FAFAAE408933137F79E3FA7102DD205F5023C9A9B0EB7612` |
| TELFHASH | `t1d0b0120fa520205d076180bac0c7d869807034df15002940c5541609a0a0a12380b267` |
| SSDEEP | `3072:7+P2y1xiqVpO4nnHfGxKWER3AsBcaJYC8E8ABgc4f3610uGjIHC:fy1hznHexKWEdAGcaJYC8Ebgc460TsHC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_b019e120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b019e12026ac88f8e95e5b579aaea7129659e1c97433d16bea769b29c2acf7f6"
    family = "Mirai"
    file_name = "nerv.arm7"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:47"
  condition:
    hash.sha256(0, filesize) == "b019e12026ac88f8e95e5b579aaea7129659e1c97433d16bea769b29c2acf7f6"
}
```

### Sample 77: `569aa5e2595d7e43`

| Field | Value |
|---|---|
| SHA-256 | `569aa5e2595d7e43f98234445da9f7284c8d307b09f0c2d599cb2568763eb410` |
| Family label | `Mirai` |
| File name | `nerv.sparc` |
| File type | `elf` |
| First seen | `2026-07-16 23:55:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8e24a6c90ffdb4560953150b718e405` |
| SHA-1 | `7d2bc151426e90db1148fd9dfa53f2d92559358b` |
| SHA-256 | `569aa5e2595d7e43f98234445da9f7284c8d307b09f0c2d599cb2568763eb410` |
| SHA3-384 | `60506089745d262ad4856f0437826e4d796a18e78adf56f7a856b6d6c121192e530019ed40e53bbb0b340bf64ab10226` |
| TLSH | `T187B35C22B9751E2BC4D4A8B661F34361F1F3579E21ACC61E3D710E8EEF246503257AB8` |
| SSDEEP | `1536:3t/ikUw0qX/ySCcYIUkKrN8v4AOaOHqkDfBAXoCJdhIyAiWY2IdtorNWq5F9AcUv:3pDwN8AA8h3CrdmrNlDcb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_569aa5e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "569aa5e2595d7e43f98234445da9f7284c8d307b09f0c2d599cb2568763eb410"
    family = "Mirai"
    file_name = "nerv.sparc"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:45"
  condition:
    hash.sha256(0, filesize) == "569aa5e2595d7e43f98234445da9f7284c8d307b09f0c2d599cb2568763eb410"
}
```

### Sample 78: `48c87b2b9f07b95a`

| Field | Value |
|---|---|
| SHA-256 | `48c87b2b9f07b95acc572da0221641011d454c3f587001e820dbec71990a72cf` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-16 23:54:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `448aa15a1791fffd5daa7f6804a00f2b` |
| SHA-1 | `0e8521f5886ab0ebc34d88d25b0faa6e3dc987b3` |
| SHA-256 | `48c87b2b9f07b95acc572da0221641011d454c3f587001e820dbec71990a72cf` |
| SHA3-384 | `9d41aa64aed6c20f0e15ef4e2d1b23f9512ad6793f0ae3c84f2c9aac382fe96f22842c9743d7ec3e21c5fd7e3f3d6173` |
| TLSH | `T10EC339A9F890DE52C6D1267AF75E518C33231378C3DE7106CE249E3477EB95A0A3E942` |
| SSDEEP | `3072:N2348J4ZU5Ng4EpPOoX9tUWcYEEUv57pMx2+jSOBFt7QUkZu+2f1Dl:N2oc6PuWcYEEUv57pK2GvBFzA5295` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_48c87b2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48c87b2b9f07b95acc572da0221641011d454c3f587001e820dbec71990a72cf"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 23:54:42"
  condition:
    hash.sha256(0, filesize) == "48c87b2b9f07b95acc572da0221641011d454c3f587001e820dbec71990a72cf"
}
```

### Sample 79: `9082d1bbe9998076`

| Field | Value |
|---|---|
| SHA-256 | `9082d1bbe9998076cbc823607eb229b2990fc9c0ef41225966761086583d2388` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-16 23:53:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6317f11b50b4ee274c61c9cc72e67ba3` |
| SHA-1 | `9cbe1ed7a1cd96949c9e9ffff81a750cb56d6d02` |
| SHA-256 | `9082d1bbe9998076cbc823607eb229b2990fc9c0ef41225966761086583d2388` |
| SHA3-384 | `32fc407ed3783139e483750a9d20716606aadd60850ca164fd7b9e942bf778bc9db4bed958bed2fe717dbefce45d04df` |
| TLSH | `T19C43F11029012BEFD5E50C37B42B430597E64ABADA3675B06C306F79BBC665BB4B048F` |
| SSDEEP | `768:hmKBnBAqA+iXd1iqgAfSplB1cB0IEYIQh/2hH1uk2R2bRLdhgQy723U03wf1f:MBRZXd83A0lYIQh/2hH1u7RIrM/fV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_9082d1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9082d1bbe9998076cbc823607eb229b2990fc9c0ef41225966761086583d2388"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 23:53:39"
  condition:
    hash.sha256(0, filesize) == "9082d1bbe9998076cbc823607eb229b2990fc9c0ef41225966761086583d2388"
}
```

### Sample 80: `5d7cf1694cbd34d6`

| Field | Value |
|---|---|
| SHA-256 | `5d7cf1694cbd34d61441e99e8efca3d64561a4a84b49de920a77119045725303` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-16 23:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27e63e3faf9b8b93e26eb194b3133189` |
| SHA-1 | `f3928d455615c75f63624be059ec855adcad920e` |
| SHA-256 | `5d7cf1694cbd34d61441e99e8efca3d64561a4a84b49de920a77119045725303` |
| SHA3-384 | `2b8bbe9ef699e33595c6e3e875e803f0789e9ced9b715de5c1ee762794e8196b58e4a906fc5bd696206965d983acec58` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T10CE63318A6E165EDE9F34138FFF08999E4A771168B32C9DB47A4A7A53E032D00D38717` |
| SSDEEP | `393216:Ho1ZJxjqsMuB/utQrkXf2/nIXBoiXMCHWUjX+cuI3/PGTAI:HAJp1ZB2WrkXWnI+iXMb8XzH/O7` |
| ICON-DHASH | `f1f0e8e8e8e8f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5d7cf169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7cf1694cbd34d61441e99e8efca3d64561a4a84b49de920a77119045725303"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 23:52:09"
  condition:
    hash.sha256(0, filesize) == "5d7cf1694cbd34d61441e99e8efca3d64561a4a84b49de920a77119045725303"
}
```

### Sample 81: `8f8343033b9e1dc3`

| Field | Value |
|---|---|
| SHA-256 | `8f8343033b9e1dc3f62527ab0f24ce3d774dc7ea3d54f2d5bc4805bb9360319c` |
| Family label | `Mirai` |
| File name | `bot` |
| File type | `elf` |
| First seen | `2026-07-16 23:51:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4535e89776b3803c6570acb0afdc83ff` |
| SHA-1 | `d4f370776180d3161a031dda2cb27a4e77d8c0e6` |
| SHA-256 | `8f8343033b9e1dc3f62527ab0f24ce3d774dc7ea3d54f2d5bc4805bb9360319c` |
| SHA3-384 | `56753ac006d9c642239747fcab298c2a3b727e93e2c298d485b728c26684a42ea2479042af198369e6cc623ea386098b` |
| TLSH | `T13F466C06B5A315AEC09AC430876FC6136D35F85496327D7B3A849E342EF6E245F2EF21` |
| TELFHASH | `t162e3f8650829d75bc8616aa82dfd7e16428607c7b320fee57fe4c51c8f00c9f62e65b8` |
| SSDEEP | `98304:PCQboyVgQegbdTD1W0+48y9+5wN96duTZt4iptZJ2Y3Wy0879syuFM4WxMHww6:ZXpH96fiT2Y3Wz87CyiM4WxMHww6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_8f834303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f8343033b9e1dc3f62527ab0f24ce3d774dc7ea3d54f2d5bc4805bb9360319c"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-07-16 23:51:45"
  condition:
    hash.sha256(0, filesize) == "8f8343033b9e1dc3f62527ab0f24ce3d774dc7ea3d54f2d5bc4805bb9360319c"
}
```

### Sample 82: `317343a58620066f`

| Field | Value |
|---|---|
| SHA-256 | `317343a58620066fe067f7729b65d0afee20b114c3d4565e89257a409ee9fd27` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-16 23:48:26` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e22822d6ea69264d894c7ec1712f20a9` |
| SHA-1 | `3a79fb25c10e47fd50de748f1525a6123a817c85` |
| SHA-256 | `317343a58620066fe067f7729b65d0afee20b114c3d4565e89257a409ee9fd27` |
| SHA3-384 | `ee5cecccf7eddf9f6786d642b866ef6866d4cf1c4a0ad01a65535f46cd8bf5c368c6970a3dadd1be29ba1044089ae5a5` |
| IMPHASH | `646167cce332c1c252cdcb1839e0cf48` |
| TLSH | `T14BB5331367DA8134DA296BB544A24607003ABCE39F99679771B1B4CB22B3DF4E17072F` |
| SSDEEP | `49152:qIMf275Mquh/aRIjJbTUUMjrHMAnYjGJEQhvF96Ip6Nqh4W:BMf4OMC5UBTMAnued9Zp6Nq` |
| ICON-DHASH | `71e4c4f0f0e1e071` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_317343a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "317343a58620066fe067f7729b65d0afee20b114c3d4565e89257a409ee9fd27"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 23:48:26"
  condition:
    hash.sha256(0, filesize) == "317343a58620066fe067f7729b65d0afee20b114c3d4565e89257a409ee9fd27"
}
```

### Sample 83: `27a3b0bd80b8038e`

| Field | Value |
|---|---|
| SHA-256 | `27a3b0bd80b8038e73834b8824c88d5084f187a35037218192ca70d0dec8310e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-16 23:45:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0593d318ca306414ddd1f71b942fcc9` |
| SHA-1 | `ef306e320b1426d60602a7ba306402366aca3377` |
| SHA-256 | `27a3b0bd80b8038e73834b8824c88d5084f187a35037218192ca70d0dec8310e` |
| SHA3-384 | `8ec889f5fc7588f40461bd969ec9dd1b94e58813ad85608aba51bfb6b6f55b486f0986ccfcea357f9a2ee24e280f4857` |
| TLSH | `T1B7C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:o8vCB+25j6es8RQ9FYpMSUpi+20qUpi+20YQX:o8l25JWd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_27a3b0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27a3b0bd80b8038e73834b8824c88d5084f187a35037218192ca70d0dec8310e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-16 23:45:48"
  condition:
    hash.sha256(0, filesize) == "27a3b0bd80b8038e73834b8824c88d5084f187a35037218192ca70d0dec8310e"
}
```

### Sample 84: `c0605974f0c0efec`

| Field | Value |
|---|---|
| SHA-256 | `c0605974f0c0efecb1cb7426588b72762746574b331781c5e29d9c599bc8ac2f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-16 23:42:03` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6171e00d15bf7abeb413ec1586c3c7ed` |
| SHA-1 | `c7510a8146cb277530f6d9af301199f9e17ca9aa` |
| SHA-256 | `c0605974f0c0efecb1cb7426588b72762746574b331781c5e29d9c599bc8ac2f` |
| SHA3-384 | `167ec65a3a11dace4a8419d0868418f1672edc3367e4a451ceffbd8edbe0a89ad8b08c05cfc3c1d3d4146a8a24e0ccfc` |
| TLSH | `T1FD236D6616857C24AA98C4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:3XRWNGxVB9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Rlxocr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_c0605974
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0605974f0c0efecb1cb7426588b72762746574b331781c5e29d9c599bc8ac2f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-16 23:42:03"
  condition:
    hash.sha256(0, filesize) == "c0605974f0c0efecb1cb7426588b72762746574b331781c5e29d9c599bc8ac2f"
}
```

### Sample 85: `b1ee45a84d93ac69`

| Field | Value |
|---|---|
| SHA-256 | `b1ee45a84d93ac693f95caa82101559e9d5dabb7e5b15067ad58bf193c20707f` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-07-16 23:17:59` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe9885d0230eb6797b695e203ba229d5` |
| SHA-1 | `7fb858b5938c15bb53c72518524854e5cd2f92b6` |
| SHA-256 | `b1ee45a84d93ac693f95caa82101559e9d5dabb7e5b15067ad58bf193c20707f` |
| SHA3-384 | `59ced76dc816ea1b3087ab5f4475b49c5deae3cd9a6aa4e843226b0824d136f362dab6c633a05dd3a9ff139ac8ee4621` |
| TLSH | `T1E6157D2AF2F2E67DD00BC03047DBC6B15131F0755A322D7B26C09A353EAADA5171AB66` |
| TELFHASH | `t10d1159304b61b9015b92ce5898ee6757362c8d1b9b1cae77d831845d61000feea37c4f` |
| SSDEEP | `12288:qglfBNgdY4IrdcHZ7jJ9pn0tArMvGwGayCWBHXlLOOpNTCpNB:qgdBNgdVfHF0tA4vGH/OSNTm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_b1ee45a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1ee45a84d93ac693f95caa82101559e9d5dabb7e5b15067ad58bf193c20707f"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-07-16 23:17:59"
  condition:
    hash.sha256(0, filesize) == "b1ee45a84d93ac693f95caa82101559e9d5dabb7e5b15067ad58bf193c20707f"
}
```

### Sample 86: `e08f40dadc814924`

| Field | Value |
|---|---|
| SHA-256 | `e08f40dadc8149249e559bf08d2506a67ca843783bb674a0d86858adf5d37ac9` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-16 22:52:14` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d654ff7d5fe7ae5039144d634471777` |
| SHA-1 | `9b855b07fb91d17e6406b5dcf39d525ed851b402` |
| SHA-256 | `e08f40dadc8149249e559bf08d2506a67ca843783bb674a0d86858adf5d37ac9` |
| SHA3-384 | `7ccea2193b0d0f1bb876401e31f21cdae86ca6ad6abb9025e3d3533181e15cb5f4b01d0f4c07b3490a55137f2d6b16fd` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T192E633143ED501DEEBB7813CF9E19656D4E0B8B40B31C5DFABA45A93BD130D88C3A296` |
| SSDEEP | `393216:uwTxZ5TkWzwRxrWoIRXMCHWUjXdFcuI3/PGTAI:uwfGWzwnao+XMb8XgH/O7` |
| ICON-DHASH | `9adcf8f8dcf8e044` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_e08f40da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e08f40dadc8149249e559bf08d2506a67ca843783bb674a0d86858adf5d37ac9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 22:52:14"
  condition:
    hash.sha256(0, filesize) == "e08f40dadc8149249e559bf08d2506a67ca843783bb674a0d86858adf5d37ac9"
}
```

### Sample 87: `668c3ee84885c653`

| Field | Value |
|---|---|
| SHA-256 | `668c3ee84885c653d4b9a87676e3e10f5888ecd72ddbdcf2373823032f4c58a7` |
| Family label | `unknown` |
| File name | `avutil.dll` |
| File type | `dll` |
| First seen | `2026-07-16 22:23:35` |
| Reporter | `johnk3r` |
| Tags | `banker, dll, sicoobnet-menucooperado-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7e5cf04558486e5e7d0f54ec102d061` |
| SHA-1 | `b2e2062ef3315cbced347f5d83fe3c0eff5e4af6` |
| SHA-256 | `668c3ee84885c653d4b9a87676e3e10f5888ecd72ddbdcf2373823032f4c58a7` |
| SHA3-384 | `eee6efeb8fc5981f657cf790b34300cbf88fea4cbecfd5ead73aef37b087b632e3ee1ca601594b5e0e6a4d31d24dae5f` |
| IMPHASH | `0a274bd307be6658e9f8db2906d4022b` |
| TLSH | `T1DA7733CC42A4E458EAF5EB3434F7E1C45DB3E922D726761C0457DC8A4ADEE26BE403A1` |
| SSDEEP | `393216:QpsDjLEMQEdhRhyFygSLFTWhawzHW/nJJCTXXy:QpmLldhR8FygEFThUW/nb6X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_668c3ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668c3ee84885c653d4b9a87676e3e10f5888ecd72ddbdcf2373823032f4c58a7"
    family = "unknown"
    file_name = "avutil.dll"
    file_type = "dll"
    first_seen = "2026-07-16 22:23:35"
  condition:
    hash.sha256(0, filesize) == "668c3ee84885c653d4b9a87676e3e10f5888ecd72ddbdcf2373823032f4c58a7"
}
```

### Sample 88: `a82d1d67292f1f36`

| Field | Value |
|---|---|
| SHA-256 | `a82d1d67292f1f36e16577fe794d604ebaa9b93846117e4ff95143aef988a193` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74c1e987787b29490a50087b60736d8e` |
| SHA-1 | `595472fd9a16dbf222cca7935d524633d32964e2` |
| SHA-256 | `a82d1d67292f1f36e16577fe794d604ebaa9b93846117e4ff95143aef988a193` |
| SHA3-384 | `e4df33e477b95a1c789f497a259174c93e0e9216a13b871c9fe238c50419cd6307a98a2a0e8dd027bf51fcb0867d8005` |
| TLSH | `T10C931981F94B80F9D8434CB454ABF33FE730D9544230965AEF899F3ADA337525626A8C` |
| TELFHASH | `t14131a6fa1e620cd577d05803f34d56217d6cab5b242066a345b318703793586a6bbd39` |
| SSDEEP | `1536:I0Ev5p1oFzLgrypf6f5NQwmp0h/h9hvEhRRoWBoMGp6kRbE6qd5dPzUw1Q/:IH5pS6PQJpgCWMGp6kVEV7RzUw1Q/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_a82d1d67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a82d1d67292f1f36e16577fe794d604ebaa9b93846117e4ff95143aef988a193"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:11"
  condition:
    hash.sha256(0, filesize) == "a82d1d67292f1f36e16577fe794d604ebaa9b93846117e4ff95143aef988a193"
}
```

### Sample 89: `2ec51b9f4bd37c12`

| Field | Value |
|---|---|
| SHA-256 | `2ec51b9f4bd37c126e4b33c92135d4c98c6ffe719af6d1ebc33b0eff7099ad04` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `611903bc49358f006efce43e50a58c91` |
| SHA-1 | `a0a6edd6466b8bde7042487e16e01e743e394176` |
| SHA-256 | `2ec51b9f4bd37c126e4b33c92135d4c98c6ffe719af6d1ebc33b0eff7099ad04` |
| SHA3-384 | `786f6902cebff75057e5f1b0039339f1ea30f5c5039c44f75d3e975070e35e6f60cdb60a6e42614fbdecfc2b95084712` |
| TLSH | `T182A34B96B801EC6CFC1BD67A451B4A05F638F7604F524F73A267BC73A9A60D5082FE48` |
| SSDEEP | `3072:CYyqzisiwJrvUirw9OaTAf+qFODMiCY5bhOoE1:TAwJzYAugZY5htE1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_2ec51b9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec51b9f4bd37c126e4b33c92135d4c98c6ffe719af6d1ebc33b0eff7099ad04"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:10"
  condition:
    hash.sha256(0, filesize) == "2ec51b9f4bd37c126e4b33c92135d4c98c6ffe719af6d1ebc33b0eff7099ad04"
}
```

### Sample 90: `05f95e3a46bf7fc2`

| Field | Value |
|---|---|
| SHA-256 | `05f95e3a46bf7fc22e1b062ce87c770c1252fd38ae10e0aca1067fd7372d1c86` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16c82f428f011d50db867970e29144ca` |
| SHA-1 | `736f36b91d8ee4d5db6f89aa2a0d863232e19928` |
| SHA-256 | `05f95e3a46bf7fc22e1b062ce87c770c1252fd38ae10e0aca1067fd7372d1c86` |
| SHA3-384 | `667f5664168da62480e607d1477c70b93f15195cfcbd80627adf48b26dbe8935ff450dc15f0627fa5dbb7b88b5df0d5a` |
| TLSH | `T186933B46B892CA12C6C562BAFB1F828C371617F8D2DB3203DD159F747BC695A0E7B580` |
| TELFHASH | `t1c1519baaff640fcc67e9845052ee601a57fe308e0b24a8468e5ca70f89475d2b41e837` |
| SSDEEP | `1536:rC/gpTAn8v2I7ni0kRrJnClAo8Kxyn602ut7lEDHRYMjV4sdzuSt9etjbDVBvR1:rC/gpTAn8T7ni0kKlAoRxy60N7lED3jA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_05f95e3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05f95e3a46bf7fc22e1b062ce87c770c1252fd38ae10e0aca1067fd7372d1c86"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:08"
  condition:
    hash.sha256(0, filesize) == "05f95e3a46bf7fc22e1b062ce87c770c1252fd38ae10e0aca1067fd7372d1c86"
}
```

### Sample 91: `a97c73139ebc4308`

| Field | Value |
|---|---|
| SHA-256 | `a97c73139ebc430850adcd2e70381a8b810b47205145d49ac7ff1b201344db7f` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecce07806412210494f6f72db6279d0b` |
| SHA-1 | `7eb1486c84c8637e5c3673bdba8c793f903e6780` |
| SHA-256 | `a97c73139ebc430850adcd2e70381a8b810b47205145d49ac7ff1b201344db7f` |
| SHA3-384 | `5d57fe2c0f760273439517d4d5d0b40043ad70f9f9cb74ed3c4fc0b52edbebca347061b01852a29265c5a26f46622feb` |
| TLSH | `T173C3AE97F74B1452CC2106F80BCB6B9C6E6322228F6BD5E72D1D667729B90CF49063D2` |
| SSDEEP | `1536:xPLYF4iW3X+IPUHtbGFQudeojQnTBbOglG+KvsXoFgEv/LWZ:x8F4b9PW6FQwXjUTBbN0hvsYFgEvqZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_a97c7313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a97c73139ebc430850adcd2e70381a8b810b47205145d49ac7ff1b201344db7f"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:06"
  condition:
    hash.sha256(0, filesize) == "a97c73139ebc430850adcd2e70381a8b810b47205145d49ac7ff1b201344db7f"
}
```

### Sample 92: `42444bfa4b05d261`

| Field | Value |
|---|---|
| SHA-256 | `42444bfa4b05d26179c69d9e10ec80350c0a3cab34b2277ce573c9db2e6ac25e` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1275106502c7e12fce4973a3cd01d022` |
| SHA-1 | `31871e16b8745cd4d33b8c1246a1bcd4c22e57a5` |
| SHA-256 | `42444bfa4b05d26179c69d9e10ec80350c0a3cab34b2277ce573c9db2e6ac25e` |
| SHA3-384 | `9b6319f7ffa63b94daa220e8e03e334033a7d150dc426c31bbab7e83cd67899825d3fc7c57458ce202f9f1b1e7b3a846` |
| TLSH | `T1B9A35A327D79581BC4C4A63A22E74771F6F6478620B88A2F7C210E9DBF5066032A77B5` |
| SSDEEP | `1536:zbcwn1GalzjmL9Bnf2y/Q/vmGR30gzVnbVo+5540tpvSW:vzUalvcBJQHBRZ5bVoI4zW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_42444bfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42444bfa4b05d26179c69d9e10ec80350c0a3cab34b2277ce573c9db2e6ac25e"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:05"
  condition:
    hash.sha256(0, filesize) == "42444bfa4b05d26179c69d9e10ec80350c0a3cab34b2277ce573c9db2e6ac25e"
}
```

### Sample 93: `94bce2e2e785d54c`

| Field | Value |
|---|---|
| SHA-256 | `94bce2e2e785d54c50fd2d0f6a9702535c9ee8f145a94c666de7403303743fff` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f23e702a4414b9721950b9b6a32183a7` |
| SHA-1 | `0b644c1d4375a1ae241ad436d82390a6ae9696ee` |
| SHA-256 | `94bce2e2e785d54c50fd2d0f6a9702535c9ee8f145a94c666de7403303743fff` |
| SHA3-384 | `d3ad1613de4286932cfaf17481f15da43dd1858a7334d8931394a7ce71b53189d6f01aaa58c805eafe982f7273a15c45` |
| TLSH | `T1BFC31907BD42DE12E4D721B9FAAF904933136BB9D3EA7102CC209FA537C699B0B76511` |
| TELFHASH | `t1dd315fdae7441eec77da20e0c0dd400a6efe712b8b282802852e5f0fc543242bc1a83b` |
| SSDEEP | `3072:+ZHYWGEoEK1xMAJ5RnmGOuagvAKmtRdQUhBDWbMgc+:+7/od1xMYvnmTuagvAKmtIUnyLc+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_94bce2e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94bce2e2e785d54c50fd2d0f6a9702535c9ee8f145a94c666de7403303743fff"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:03"
  condition:
    hash.sha256(0, filesize) == "94bce2e2e785d54c50fd2d0f6a9702535c9ee8f145a94c666de7403303743fff"
}
```

### Sample 94: `025d6e0c9b314bc0`

| Field | Value |
|---|---|
| SHA-256 | `025d6e0c9b314bc0db7c6baf357afb738084940f6ec1f9f8ac4e09fb278173f9` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e88cb2ee1f7c5d3711717790a219f5e` |
| SHA-1 | `aac6516c935296ca32be19b6c3765f17f03e76ea` |
| SHA-256 | `025d6e0c9b314bc0db7c6baf357afb738084940f6ec1f9f8ac4e09fb278173f9` |
| SHA3-384 | `423ee2f7da0404b99cef6dba4a2cbbbf89b7795c6891f96463f40d5df41781facade4726877629078c5331dc0faa072b` |
| TLSH | `T1E9C3F609BF710EF7E8AFCD3755B84702249C5B0622A93BB6B974D418BB4654F06D38B8` |
| SSDEEP | `1536:+m2JrpexSJFOnS7DaLqFd5FlbpmFIACNlUn+WgvbdKjsZz9rRomYseVD:+m2JrpXOS7Da25bpmmAFibdoskt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_025d6e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "025d6e0c9b314bc0db7c6baf357afb738084940f6ec1f9f8ac4e09fb278173f9"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:01"
  condition:
    hash.sha256(0, filesize) == "025d6e0c9b314bc0db7c6baf357afb738084940f6ec1f9f8ac4e09fb278173f9"
}
```

### Sample 95: `e83da6e7d86f4715`

| Field | Value |
|---|---|
| SHA-256 | `e83da6e7d86f4715200b84427a1aa7c2d4187f48af70ef0ee024caaf36428809` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-16 22:12:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a7f6dc2f9d613539b63583cb943bd0d` |
| SHA-1 | `443734b8be442aff8c5208741feb68ada2f0a55e` |
| SHA-256 | `e83da6e7d86f4715200b84427a1aa7c2d4187f48af70ef0ee024caaf36428809` |
| SHA3-384 | `90e62951de4bb9be5b9dc0248c2d35d7caec275624c8e8e525534a701cb5e242d3fa241fc0d6361c805ee63017e259ae` |
| TLSH | `T18E934B46B892CA56C6C562B9BB1F818C331613F8C2EB3203DD15AF757BC795A0E7B580` |
| TELFHASH | `t1bf51afbaff240adc67da904052deb41a17fd31cf0f266897890c674f89429c5b02e42b` |
| SSDEEP | `1536:cFYpbANKE2e1iMUcbHTAQw51LktwZWutXvrCYNRQVMxVesKJaXcm6EoqfQL1:cFYpbANKRe1iMUITAQm1QezXvrnNmyxe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_e83da6e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e83da6e7d86f4715200b84427a1aa7c2d4187f48af70ef0ee024caaf36428809"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:00"
  condition:
    hash.sha256(0, filesize) == "e83da6e7d86f4715200b84427a1aa7c2d4187f48af70ef0ee024caaf36428809"
}
```

### Sample 96: `ceaac96b6574b9d3`

| Field | Value |
|---|---|
| SHA-256 | `ceaac96b6574b9d38ef11c725d20037178e9ffaab3133f310e4e9fe1178690d2` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-16 22:11:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87076d81ce4cf658c130bf35efda046d` |
| SHA-1 | `7390f18c9c2365af4487f01fcd07bc1477988167` |
| SHA-256 | `ceaac96b6574b9d38ef11c725d20037178e9ffaab3133f310e4e9fe1178690d2` |
| SHA3-384 | `a5b231e17ee833870934d7519174ede0f6593cd16d959918490c42e76b270e89c16c36e83fcb6d8782acedb92e7a7582` |
| TLSH | `T181934A07B58588FCC48AC2744A2FA936E131F45E13356A6B3BD4FF226F5AB10263DA54` |
| TELFHASH | `t1c53146703c8e19a860d39325b30ae2e4e92205706ae071e29e37bcf5de62f441d654f2` |
| SSDEEP | `1536:alUuunl/Q5Z7tTU9pq4dQkM8t5eCE1gF8ynQeU6wU7wHMKZs2J1GM9yz+IvTYCdg:alUuunQt94lM8t5eCE1gF8ynQeU6wU7K` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_ceaac96b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceaac96b6574b9d38ef11c725d20037178e9ffaab3133f310e4e9fe1178690d2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:58"
  condition:
    hash.sha256(0, filesize) == "ceaac96b6574b9d38ef11c725d20037178e9ffaab3133f310e4e9fe1178690d2"
}
```

### Sample 97: `31e1a03223438c81`

| Field | Value |
|---|---|
| SHA-256 | `31e1a03223438c819d343bbada505658bd34acbc9073764096dc044013e302bc` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-16 22:11:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4e9e45f50d85783b99b267a54971b80` |
| SHA-1 | `b80de60667aa9c9c47788a5e8480ea49826dab3b` |
| SHA-256 | `31e1a03223438c819d343bbada505658bd34acbc9073764096dc044013e302bc` |
| SHA3-384 | `96b2fd062cefc6cf5fb666ccfaf899d158ae15f3aa3d591b2bbb984339fab632e4456d54b86270e46542c29d4ff29857` |
| TLSH | `T16B839D63C59A2E88C691A3F1B4B1DF798343D45096030FBA15A7D6BD9487CCC718E3B9` |
| SSDEEP | `1536:Xi8E+rUu67e3R5asT+h7EfXEq3K+Ki6Jt7szo26CPqLnq:G+In7Cz+h4fXE7xiKqo26Lq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_31e1a032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31e1a03223438c819d343bbada505658bd34acbc9073764096dc044013e302bc"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:57"
  condition:
    hash.sha256(0, filesize) == "31e1a03223438c819d343bbada505658bd34acbc9073764096dc044013e302bc"
}
```

### Sample 98: `4bd17c2bf9c2cf17`

| Field | Value |
|---|---|
| SHA-256 | `4bd17c2bf9c2cf17a4728f0a7753761be3c788910041390b0e374e06c581a8c9` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-16 22:11:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0aa7146fd5064984013416deaa7a3dea` |
| SHA-1 | `932b62f07a4114e39700a7e8eae6b38c171aa33b` |
| SHA-256 | `4bd17c2bf9c2cf17a4728f0a7753761be3c788910041390b0e374e06c581a8c9` |
| SHA3-384 | `78f73d897e92e884f4c140d93e9189edbe656ca26eda4e04f2fe06db6e6ee59a9180f2f2607e475589ea1d7b07d5204e` |
| TLSH | `T113B33B07B992CA12D5D322B9BA6F904C33132BB9D3DA7203CC249FA477C79D70A7A515` |
| TELFHASH | `t1fbe026e2cb600e8ca3c1902491e73068fbfebada245091c6531e5f9ec453745b51e323` |
| SSDEEP | `3072:U0RSx7iDpDtGi7Chq1ai/IKOVZkLaqRIH:ULeDBtGFq1a7KOGRIH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_4bd17c2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd17c2bf9c2cf17a4728f0a7753761be3c788910041390b0e374e06c581a8c9"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:55"
  condition:
    hash.sha256(0, filesize) == "4bd17c2bf9c2cf17a4728f0a7753761be3c788910041390b0e374e06c581a8c9"
}
```

### Sample 99: `9febcd6b2e7829e8`

| Field | Value |
|---|---|
| SHA-256 | `9febcd6b2e7829e8be76fb01fff52136962570ea3b682322e266a861c057a014` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-16 22:11:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5cbfb227713bedaf52b0e55bc048aa38` |
| SHA-1 | `7c7d80575adeb00d0ff548716174d138063e5898` |
| SHA-256 | `9febcd6b2e7829e8be76fb01fff52136962570ea3b682322e266a861c057a014` |
| SHA3-384 | `1cf8be8ff5fb43cfe5fa73b571a40162711bac4ec014d0bd77fbf5ae322df94a9623dc097abbfe13e1f4f5559db3d22a` |
| TLSH | `T142938E00770C0E93C5636D74293F2BD1C39AE69122B5E6452E1F6F0BC1B6D72868AEDC` |
| SSDEEP | `1536:fxwk2kUkmSZeOcNOaSBgrLefMJIXa4c3m+0fMNPkYO1sqARjdF2aWBQET1:3gUcIXMNUgx2RBx1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_9febcd6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9febcd6b2e7829e8be76fb01fff52136962570ea3b682322e266a861c057a014"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:53"
  condition:
    hash.sha256(0, filesize) == "9febcd6b2e7829e8be76fb01fff52136962570ea3b682322e266a861c057a014"
}
```

### Sample 100: `1fad40f8b341ce60`

| Field | Value |
|---|---|
| SHA-256 | `1fad40f8b341ce60076d2111c2ac47b8478362498ed51fc5b9c5ceeef0f6d758` |
| Family label | `Gafgyt` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-16 22:11:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `558edb0f89ac1f0c96a57688897c36f9` |
| SHA-1 | `b996ca18ee7f47b8fa989ee0b931faf3b8c740ce` |
| SHA-256 | `1fad40f8b341ce60076d2111c2ac47b8478362498ed51fc5b9c5ceeef0f6d758` |
| SHA3-384 | `f0df62b0d0e1f04639faa1c53d61703a20aae14d7a4b86eb05dcce68592940725024741c33ec72bedf9fc75f83861de2` |
| TLSH | `T1E9C3E65E2E319F3EF76D82340BB74E35D395239B26D0CA41D1ACE9092E2434E681FB64` |
| TELFHASH | `t189217c18893827f0d7b11cde6bedff76e44070eb4a255e378e00e89e9a6d9428d00c2c` |
| SSDEEP | `1536:oxCziMV47HzHOLoc7jqrMR1VM+9pibuxrEQpeIE0T/mna9T/hqSbwYnPEben/56Q:ox/zuLouAHQpeIE0T/mnehqSbXP9vj` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_100_1fad40f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fad40f8b341ce60076d2111c2ac47b8478362498ed51fc5b9c5ceeef0f6d758"
    family = "Gafgyt"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:52"
  condition:
    hash.sha256(0, filesize) == "1fad40f8b341ce60076d2111c2ac47b8478362498ed51fc5b9c5ceeef0f6d758"
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
 * Generated: 2026-07-17T03:42:10.105897+00:00
 */

rule MalwareBazaar_unknown_001_f01dc226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f01dc226fd5602bc34e89dc712b84d8dc3783ff049d3a1344d698f1cfcb3dacb"
    family = "unknown"
    file_name = "DHL Shipping Document-2774038374-PDF.vbs"
    file_type = "vbs"
    first_seen = "2026-07-17 03:33:47"
  condition:
    hash.sha256(0, filesize) == "f01dc226fd5602bc34e89dc712b84d8dc3783ff049d3a1344d698f1cfcb3dacb"
}

rule MalwareBazaar_unknown_002_27698672
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "276986727cd341d97eecd625486862c423563b36038e6226ae0ea5a40c47f78d"
    family = "unknown"
    file_name = "EGPL-476-2026.vbs"
    file_type = "vbs"
    first_seen = "2026-07-17 03:32:48"
  condition:
    hash.sha256(0, filesize) == "276986727cd341d97eecd625486862c423563b36038e6226ae0ea5a40c47f78d"
}

rule MalwareBazaar_unknown_003_d8205619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8205619701059115b6f9ca0bb30157effcdea1819188b97519fe29c59724227"
    family = "unknown"
    file_name = "Phone+Simple+Cleaner_1.2.4.xapk"
    file_type = "xapk"
    first_seen = "2026-07-17 03:28:13"
  condition:
    hash.sha256(0, filesize) == "d8205619701059115b6f9ca0bb30157effcdea1819188b97519fe29c59724227"
}

rule MalwareBazaar_unknown_004_cec2a39e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cec2a39e52791bf8b7505f1fda1ed41cb2d23e78951e6df5c327f0cc937ea4e2"
    family = "unknown"
    file_name = "Super+Clean_1.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-17 03:27:23"
  condition:
    hash.sha256(0, filesize) == "cec2a39e52791bf8b7505f1fda1ed41cb2d23e78951e6df5c327f0cc937ea4e2"
}

rule MalwareBazaar_unknown_005_6b9650bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b9650bb8feaa29b1fdf076cf0b4f6aecdbe2bbcb40782a71b015ce6512c61f8"
    family = "unknown"
    file_name = "com.empir.cist.camera_1.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-17 03:26:40"
  condition:
    hash.sha256(0, filesize) == "6b9650bb8feaa29b1fdf076cf0b4f6aecdbe2bbcb40782a71b015ce6512c61f8"
}

rule MalwareBazaar_Mirai_006_199370e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "199370e9ef009d12fee9b3c4ad682dd95d2809d3081396a839d4316b9107b1ac"
    family = "Mirai"
    file_name = "tmpsl"
    file_type = "elf"
    first_seen = "2026-07-17 02:54:51"
  condition:
    hash.sha256(0, filesize) == "199370e9ef009d12fee9b3c4ad682dd95d2809d3081396a839d4316b9107b1ac"
}

rule MalwareBazaar_unknown_007_6affd659
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6affd6590f618b2ae670f46f6351036f419eea08e139d06354354d74be857ca6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 02:52:09"
  condition:
    hash.sha256(0, filesize) == "6affd6590f618b2ae670f46f6351036f419eea08e139d06354354d74be857ca6"
}

rule MalwareBazaar_unknown_008_5da44e36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da44e36790d8bb2ab51d7b70bbc25063d8236b959a3452cbb4bc41b5bcd4966"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 01:52:09"
  condition:
    hash.sha256(0, filesize) == "5da44e36790d8bb2ab51d7b70bbc25063d8236b959a3452cbb4bc41b5bcd4966"
}

rule MalwareBazaar_Mirai_009_3bf8bc35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bf8bc35c9909047deea7338c690480e8e2e36e5eb36b207c449080bda0e9a40"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-17 01:51:40"
  condition:
    hash.sha256(0, filesize) == "3bf8bc35c9909047deea7338c690480e8e2e36e5eb36b207c449080bda0e9a40"
}

rule MalwareBazaar_Mirai_010_94a7cc70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94a7cc706c15d397c1269f95c40b34d0ad7b9d4a90289bc1a133fc77323a3e98"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-17 01:50:54"
  condition:
    hash.sha256(0, filesize) == "94a7cc706c15d397c1269f95c40b34d0ad7b9d4a90289bc1a133fc77323a3e98"
}

rule MalwareBazaar_Mirai_011_7873a2d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7873a2d6270b9eb4b775d3a95a2b358d36ce2021fb09dc50ee538ff0782b8b2b"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-17 01:46:51"
  condition:
    hash.sha256(0, filesize) == "7873a2d6270b9eb4b775d3a95a2b358d36ce2021fb09dc50ee538ff0782b8b2b"
}

rule MalwareBazaar_Mirai_012_58c8bfd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58c8bfd399a9734077089dd88ef9efc22751ea002461b52ff744180fb3e366f2"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:43:39"
  condition:
    hash.sha256(0, filesize) == "58c8bfd399a9734077089dd88ef9efc22751ea002461b52ff744180fb3e366f2"
}

rule MalwareBazaar_Mirai_013_3f267bfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f267bfc1659d5ad927a7ba7cc278af09163e102449517040f8269cc4c485b66"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:42:54"
  condition:
    hash.sha256(0, filesize) == "3f267bfc1659d5ad927a7ba7cc278af09163e102449517040f8269cc4c485b66"
}

rule MalwareBazaar_Mirai_014_eb3f3fdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb3f3fdc3f19e5ee7dd861389b3fb1fbd6b27b869b0977a11c5e8ead42582f0f"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-17 01:42:53"
  condition:
    hash.sha256(0, filesize) == "eb3f3fdc3f19e5ee7dd861389b3fb1fbd6b27b869b0977a11c5e8ead42582f0f"
}

rule MalwareBazaar_Mirai_015_a784ce0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a784ce0b3b32c06ecfdf9f096bcb1876ed37ba124e393aeb03f1ca5ccf6dbf46"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 01:41:41"
  condition:
    hash.sha256(0, filesize) == "a784ce0b3b32c06ecfdf9f096bcb1876ed37ba124e393aeb03f1ca5ccf6dbf46"
}

rule MalwareBazaar_Mirai_016_2a1776c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a1776c73595bcee6974802751eff6d9c579b1ce189909a74bce7ab6128d7a91"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 01:40:50"
  condition:
    hash.sha256(0, filesize) == "2a1776c73595bcee6974802751eff6d9c579b1ce189909a74bce7ab6128d7a91"
}

rule MalwareBazaar_Mirai_017_504e8e15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "504e8e159761fa56a843801922b86e2c8c5c346c85062e56ed90901aaf3553de"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:26:58"
  condition:
    hash.sha256(0, filesize) == "504e8e159761fa56a843801922b86e2c8c5c346c85062e56ed90901aaf3553de"
}

rule MalwareBazaar_unknown_018_1cb66024
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cb6602444e604e0dfe8cb7b5240fb0e90536c503823293a9e9c1f3954aae038"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-17 01:23:07"
  condition:
    hash.sha256(0, filesize) == "1cb6602444e604e0dfe8cb7b5240fb0e90536c503823293a9e9c1f3954aae038"
}

rule MalwareBazaar_unknown_019_24c693f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24c693f26a9b6a79dfbb2622ccf7f3a15748a31b60ebafa3930252efa591dc52"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-17 01:21:14"
  condition:
    hash.sha256(0, filesize) == "24c693f26a9b6a79dfbb2622ccf7f3a15748a31b60ebafa3930252efa591dc52"
}

rule MalwareBazaar_Mirai_020_76feca35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76feca35c0f4edbce47b970cf3dea5cfe4ec3af628bb3baa4efa32c22cb195fc"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-17 01:14:54"
  condition:
    hash.sha256(0, filesize) == "76feca35c0f4edbce47b970cf3dea5cfe4ec3af628bb3baa4efa32c22cb195fc"
}

rule MalwareBazaar_Mirai_021_dfad56d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfad56d46b0379eaf32c1969204b70dc30d5f44a74bc49d952a330eb170c0d93"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-17 01:09:46"
  condition:
    hash.sha256(0, filesize) == "dfad56d46b0379eaf32c1969204b70dc30d5f44a74bc49d952a330eb170c0d93"
}

rule MalwareBazaar_Mirai_022_e899c163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e899c163318892d3d121b80e85b53c4b2d6361a27820b921a11d825413d457a4"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-17 01:09:03"
  condition:
    hash.sha256(0, filesize) == "e899c163318892d3d121b80e85b53c4b2d6361a27820b921a11d825413d457a4"
}

rule MalwareBazaar_Mirai_023_a12922f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a12922f8f8906ee5ebc6f0612236307e24a2a53a5f26f34b23e2ddab998fc304"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 01:07:47"
  condition:
    hash.sha256(0, filesize) == "a12922f8f8906ee5ebc6f0612236307e24a2a53a5f26f34b23e2ddab998fc304"
}

rule MalwareBazaar_Mirai_024_f8956e30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8956e30821ef8a73215795e607abbe14b6d3efa17f9ba47fcdafc44b1f20e91"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 01:07:07"
  condition:
    hash.sha256(0, filesize) == "f8956e30821ef8a73215795e607abbe14b6d3efa17f9ba47fcdafc44b1f20e91"
}

rule MalwareBazaar_unknown_025_2c97e2d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c97e2d57359fb344b5de8164fa93f8ec2e4cb758a908ec25a1ab742dca9a99c"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-17 01:07:05"
  condition:
    hash.sha256(0, filesize) == "2c97e2d57359fb344b5de8164fa93f8ec2e4cb758a908ec25a1ab742dca9a99c"
}

rule MalwareBazaar_Mirai_026_1f04bb3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f04bb3edad6c3ba22205bed96a5085aefb0611ec48c6eb73b57cc365ab3a16d"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:06:26"
  condition:
    hash.sha256(0, filesize) == "1f04bb3edad6c3ba22205bed96a5085aefb0611ec48c6eb73b57cc365ab3a16d"
}

rule MalwareBazaar_Mirai_027_b78a2354
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78a23549c477c5ebc564b25dd6871c6e1f1964302f5cbc4b5de190a8447319c"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-17 01:05:06"
  condition:
    hash.sha256(0, filesize) == "b78a23549c477c5ebc564b25dd6871c6e1f1964302f5cbc4b5de190a8447319c"
}

rule MalwareBazaar_Mirai_028_b0f13b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f13b57395ac71b39d1d041c1c7fe8c145d9e3b0783cb336f66ab1f3f1ec596"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-17 01:02:17"
  condition:
    hash.sha256(0, filesize) == "b0f13b57395ac71b39d1d041c1c7fe8c145d9e3b0783cb336f66ab1f3f1ec596"
}

rule MalwareBazaar_Mirai_029_3b03e32d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b03e32d06c84721bce47173fdb28283c185edf5a7b3a3b0c1282e424af0a40a"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-17 01:02:09"
  condition:
    hash.sha256(0, filesize) == "3b03e32d06c84721bce47173fdb28283c185edf5a7b3a3b0c1282e424af0a40a"
}

rule MalwareBazaar_Mirai_030_e8c0c3b7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c0c3b714243b977d7279d191686a355c2ef73bcda1dbbca1c4f751f33c2286"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-17 01:00:53"
  condition:
    hash.sha256(0, filesize) == "e8c0c3b714243b977d7279d191686a355c2ef73bcda1dbbca1c4f751f33c2286"
}

rule MalwareBazaar_Mirai_031_560409bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "560409bf7fd5c35647e55577c5746fb4e8242fc2885f21828ded731ce7d442ed"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-17 01:00:52"
  condition:
    hash.sha256(0, filesize) == "560409bf7fd5c35647e55577c5746fb4e8242fc2885f21828ded731ce7d442ed"
}

rule MalwareBazaar_Mirai_032_e34fd49b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e34fd49b7b29fe32d7730995313d3c95c41a638a9679fe3fc8f63a1e66d46753"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-17 00:57:56"
  condition:
    hash.sha256(0, filesize) == "e34fd49b7b29fe32d7730995313d3c95c41a638a9679fe3fc8f63a1e66d46753"
}

rule MalwareBazaar_Mirai_033_1c171182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c17118204be51503b5f6095c8ee14da3e4df8831b3fc973378e61d081a7120c"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-17 00:56:51"
  condition:
    hash.sha256(0, filesize) == "1c17118204be51503b5f6095c8ee14da3e4df8831b3fc973378e61d081a7120c"
}

rule MalwareBazaar_Mirai_034_5c8b6311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c8b631173fb1e60c3435613ac2620aa4e62fd10fb2f95ac07bb753d3355867b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-17 00:56:49"
  condition:
    hash.sha256(0, filesize) == "5c8b631173fb1e60c3435613ac2620aa4e62fd10fb2f95ac07bb753d3355867b"
}

rule MalwareBazaar_unknown_035_cc17b6dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc17b6dc8a38d09ecb5c13c5eb24dff13b5015fa4e084931a82fcf84502e756c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-17 00:55:08"
  condition:
    hash.sha256(0, filesize) == "cc17b6dc8a38d09ecb5c13c5eb24dff13b5015fa4e084931a82fcf84502e756c"
}

rule MalwareBazaar_unknown_036_e1568cae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-17 00:52:50"
  condition:
    hash.sha256(0, filesize) == "e1568cae97252fa9350ef2d2d381975c8bd29e11f126fb06bd64e92a73d7beb9"
}

rule MalwareBazaar_unknown_037_9de680fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9de680fe7c5e49f7e9192caf0f3432f8086e6de549c5737a9912a97cd69abac1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-17 00:52:08"
  condition:
    hash.sha256(0, filesize) == "9de680fe7c5e49f7e9192caf0f3432f8086e6de549c5737a9912a97cd69abac1"
}

rule MalwareBazaar_unknown_038_23ce81eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23ce81ebe09d6028b0e8259073855ef820e38f0107f4d6381bed182535095822"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-17 00:50:50"
  condition:
    hash.sha256(0, filesize) == "23ce81ebe09d6028b0e8259073855ef820e38f0107f4d6381bed182535095822"
}

rule MalwareBazaar_unknown_039_b81bda69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b81bda693566e7b4964f843c8d59e28cb75bc4d43faacbec6f0ef960040ee16d"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-17 00:50:49"
  condition:
    hash.sha256(0, filesize) == "b81bda693566e7b4964f843c8d59e28cb75bc4d43faacbec6f0ef960040ee16d"
}

rule MalwareBazaar_unknown_040_5947a934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5947a93487ce560122175027f194386b6362768e266376a26ce90148f806fee0"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-17 00:46:52"
  condition:
    hash.sha256(0, filesize) == "5947a93487ce560122175027f194386b6362768e266376a26ce90148f806fee0"
}

rule MalwareBazaar_Mirai_041_815d37f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815d37f2c17fbed0d44554177fc338f577901fecf43e101b8809b5540777095d"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-17 00:36:53"
  condition:
    hash.sha256(0, filesize) == "815d37f2c17fbed0d44554177fc338f577901fecf43e101b8809b5540777095d"
}

rule MalwareBazaar_Mirai_042_5e1dea6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e1dea6db2c27f33766997b67f3a2dc95ba58fa7e5851a30de8b074fe678dc31"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:35:44"
  condition:
    hash.sha256(0, filesize) == "5e1dea6db2c27f33766997b67f3a2dc95ba58fa7e5851a30de8b074fe678dc31"
}

rule MalwareBazaar_Mirai_043_c73cbed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c73cbed870744e026b4f09dd0e2e8f3ae22a74ea46199b1a0a076a39b5f3be40"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:34:53"
  condition:
    hash.sha256(0, filesize) == "c73cbed870744e026b4f09dd0e2e8f3ae22a74ea46199b1a0a076a39b5f3be40"
}

rule MalwareBazaar_Mirai_044_2e05529f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e05529f2e98504b0f04733be686c8628daa6032d56b8726573799aa48e5e0da"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-07-17 00:34:52"
  condition:
    hash.sha256(0, filesize) == "2e05529f2e98504b0f04733be686c8628daa6032d56b8726573799aa48e5e0da"
}

rule MalwareBazaar_unknown_045_64e65bae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64e65bae703a6b848b5cbd19bfd6f56cf085fea6341a1dc03fbf3fa520ed8da4"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-17 00:32:52"
  condition:
    hash.sha256(0, filesize) == "64e65bae703a6b848b5cbd19bfd6f56cf085fea6341a1dc03fbf3fa520ed8da4"
}

rule MalwareBazaar_Mirai_046_a1b7623d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1b7623d37a8540e38f18b56dffd692e84c1bcca672ed58bfec64921f7aa8e63"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-17 00:31:00"
  condition:
    hash.sha256(0, filesize) == "a1b7623d37a8540e38f18b56dffd692e84c1bcca672ed58bfec64921f7aa8e63"
}

rule MalwareBazaar_Mirai_047_3e24ad30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e24ad303b4fe1d1715656a959aa40aa036128f694fa059377bac2b247ba788c"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-17 00:30:47"
  condition:
    hash.sha256(0, filesize) == "3e24ad303b4fe1d1715656a959aa40aa036128f694fa059377bac2b247ba788c"
}

rule MalwareBazaar_Mirai_048_5baaccc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5baaccc34a67d2217d67b45da0776bf139f63f45f5f40adcbe39cedbc7a31c5f"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-17 00:25:55"
  condition:
    hash.sha256(0, filesize) == "5baaccc34a67d2217d67b45da0776bf139f63f45f5f40adcbe39cedbc7a31c5f"
}

rule MalwareBazaar_Mirai_049_07a35075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07a3507588c075ffe32b516d435cfd27a9080d9fda8ba20b441a04cc13a8c103"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-07-17 00:24:51"
  condition:
    hash.sha256(0, filesize) == "07a3507588c075ffe32b516d435cfd27a9080d9fda8ba20b441a04cc13a8c103"
}

rule MalwareBazaar_Mirai_050_685da360
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "685da3603fe49eb177b07a7c10b1da1dccdb99ff4d421c1cf299eea55107837a"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 00:13:44"
  condition:
    hash.sha256(0, filesize) == "685da3603fe49eb177b07a7c10b1da1dccdb99ff4d421c1cf299eea55107837a"
}

rule MalwareBazaar_Mirai_051_56724d08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56724d085143158238d02f1472e87786ff41e50f7a8d29fe254c427018065746"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-17 00:12:52"
  condition:
    hash.sha256(0, filesize) == "56724d085143158238d02f1472e87786ff41e50f7a8d29fe254c427018065746"
}

rule MalwareBazaar_Mirai_052_c68ac31b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c68ac31b40203f39c9a784ea8209736364ce9a05a9b06670938e66ade6e25d78"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:12:50"
  condition:
    hash.sha256(0, filesize) == "c68ac31b40203f39c9a784ea8209736364ce9a05a9b06670938e66ade6e25d78"
}

rule MalwareBazaar_Mirai_053_c9889d77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9889d7751721e0531e9221143ea1d9c20e3eda5dc18e88ddab6d52e3d729d74"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-07-17 00:11:05"
  condition:
    hash.sha256(0, filesize) == "c9889d7751721e0531e9221143ea1d9c20e3eda5dc18e88ddab6d52e3d729d74"
}

rule MalwareBazaar_unknown_054_424f302b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "424f302b4f6f7edb6d7b6539e961216e078a12b2ce6c6df33bdb347ae50f73e7"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-17 00:09:12"
  condition:
    hash.sha256(0, filesize) == "424f302b4f6f7edb6d7b6539e961216e078a12b2ce6c6df33bdb347ae50f73e7"
}

rule MalwareBazaar_Mirai_055_d7fd0e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7fd0e83e6509cc290a309bab475d70008b04be72a307435d86e426464ce969b"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 00:07:56"
  condition:
    hash.sha256(0, filesize) == "d7fd0e83e6509cc290a309bab475d70008b04be72a307435d86e426464ce969b"
}

rule MalwareBazaar_Mirai_056_e8e7b137
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c"
    family = "Mirai"
    file_name = "e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c"
    file_type = "elf"
    first_seen = "2026-07-17 00:06:18"
  condition:
    hash.sha256(0, filesize) == "e8e7b13785d70a3055fdebe8005305d6c76fca78530bc1f6497b4a76dc47806c"
}

rule MalwareBazaar_Mirai_057_667d249e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "667d249e882f6e189bb1ef23aa29b147d89bf7de8820c2ea7b98ad12a1c78f21"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-17 00:04:33"
  condition:
    hash.sha256(0, filesize) == "667d249e882f6e189bb1ef23aa29b147d89bf7de8820c2ea7b98ad12a1c78f21"
}

rule MalwareBazaar_unknown_058_79e70f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79e70f6eeddc2cb6a68a125ce45e985100cb51e35f66a327d97d5fa0e308327c"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-17 00:02:12"
  condition:
    hash.sha256(0, filesize) == "79e70f6eeddc2cb6a68a125ce45e985100cb51e35f66a327d97d5fa0e308327c"
}

rule MalwareBazaar_Mirai_059_199f3b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "199f3b730634be3c5259ec80111f7ac2b20e61e122dc56bf7516b75b965aab57"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-16 23:57:54"
  condition:
    hash.sha256(0, filesize) == "199f3b730634be3c5259ec80111f7ac2b20e61e122dc56bf7516b75b965aab57"
}

rule MalwareBazaar_Mirai_060_d5f9274b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5f9274b2974147a1bcb86fe6568e05302880dd9c6c71d2c77cda32599ec68aa"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-16 23:57:40"
  condition:
    hash.sha256(0, filesize) == "d5f9274b2974147a1bcb86fe6568e05302880dd9c6c71d2c77cda32599ec68aa"
}

rule MalwareBazaar_Mirai_061_5ea3509f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ea3509f840f6cc8b36e4930c7f6514253c3be358c7f83683c021d51fe6a2b97"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:06"
  condition:
    hash.sha256(0, filesize) == "5ea3509f840f6cc8b36e4930c7f6514253c3be358c7f83683c021d51fe6a2b97"
}

rule MalwareBazaar_Mirai_062_b228a7e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b228a7e7b1deba424f0a2764fc19c9d7181da226dec3bc3f9c16b0e66758ad6e"
    family = "Mirai"
    file_name = "nerv.mpsl"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:05"
  condition:
    hash.sha256(0, filesize) == "b228a7e7b1deba424f0a2764fc19c9d7181da226dec3bc3f9c16b0e66758ad6e"
}

rule MalwareBazaar_Mirai_063_c995c35c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c995c35c2566d952e457350412fedbdce454a96c4690f06c68c730df7f7bc5c6"
    family = "Mirai"
    file_name = "nerv.ppc"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:04"
  condition:
    hash.sha256(0, filesize) == "c995c35c2566d952e457350412fedbdce454a96c4690f06c68c730df7f7bc5c6"
}

rule MalwareBazaar_Mirai_064_c714ddde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c714ddde7d41e33700ce64966ad0673edcd92d5643f133919c9cff8532ebfea4"
    family = "Mirai"
    file_name = "nerv.arm4"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:02"
  condition:
    hash.sha256(0, filesize) == "c714ddde7d41e33700ce64966ad0673edcd92d5643f133919c9cff8532ebfea4"
}

rule MalwareBazaar_Mirai_065_18626892
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "186268920bb9c037bc928b21d405d552f7b0127c551ff795661ee342ac1f9029"
    family = "Mirai"
    file_name = "nerv.ppc440"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:01"
  condition:
    hash.sha256(0, filesize) == "186268920bb9c037bc928b21d405d552f7b0127c551ff795661ee342ac1f9029"
}

rule MalwareBazaar_Mirai_066_f2b7fc5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b7fc5bec0da916cad60ab71fedc56cfcf9e1f6a119aaa5fc3e856fa1d9ed1e"
    family = "Mirai"
    file_name = "nerv.arm6"
    file_type = "elf"
    first_seen = "2026-07-16 23:56:00"
  condition:
    hash.sha256(0, filesize) == "f2b7fc5bec0da916cad60ab71fedc56cfcf9e1f6a119aaa5fc3e856fa1d9ed1e"
}

rule MalwareBazaar_Mirai_067_2a2c89f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a2c89f18adebe537c277f96c0a4170de7e756ea3813b8bf1f141b6db9e10980"
    family = "Mirai"
    file_name = "nerv.arm5"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:58"
  condition:
    hash.sha256(0, filesize) == "2a2c89f18adebe537c277f96c0a4170de7e756ea3813b8bf1f141b6db9e10980"
}

rule MalwareBazaar_Mirai_068_75226ce6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75226ce6759ba3b83b867d9529fd9361b8886ae1c27b3ffa479a9a8e48d79926"
    family = "Mirai"
    file_name = "nerv.x86"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:57"
  condition:
    hash.sha256(0, filesize) == "75226ce6759ba3b83b867d9529fd9361b8886ae1c27b3ffa479a9a8e48d79926"
}

rule MalwareBazaar_Mirai_069_fda21128
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fda211282012512d84a383602f1b7bebd9bdc8f737da26388c5884c1e36e2920"
    family = "Mirai"
    file_name = "nerv.mips"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:56"
  condition:
    hash.sha256(0, filesize) == "fda211282012512d84a383602f1b7bebd9bdc8f737da26388c5884c1e36e2920"
}

rule MalwareBazaar_Mirai_070_a771462d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a771462d3aacd20a9c599533fcd83bb86f24f081a0e7b95055013f9e1944a80a"
    family = "Mirai"
    file_name = "nerv.sh4"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:54"
  condition:
    hash.sha256(0, filesize) == "a771462d3aacd20a9c599533fcd83bb86f24f081a0e7b95055013f9e1944a80a"
}

rule MalwareBazaar_Mirai_071_32bdd896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32bdd896bee92a8235ecc41a890208096d20fa5c834b30a4aa88fc9f31568c7c"
    family = "Mirai"
    file_name = "nerv.x86_64"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:53"
  condition:
    hash.sha256(0, filesize) == "32bdd896bee92a8235ecc41a890208096d20fa5c834b30a4aa88fc9f31568c7c"
}

rule MalwareBazaar_Mirai_072_835e224f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "835e224f2cc0d30c2bf23e403aa557bc94daa2000860b38a32762f75c65cabd0"
    family = "Mirai"
    file_name = "nerv.x86_32"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:52"
  condition:
    hash.sha256(0, filesize) == "835e224f2cc0d30c2bf23e403aa557bc94daa2000860b38a32762f75c65cabd0"
}

rule MalwareBazaar_unknown_073_1d918cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d918cd3a53d12a7342b8a5c952faf6f3dd31b43984376dc50376eef9250e8f1"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:50"
  condition:
    hash.sha256(0, filesize) == "1d918cd3a53d12a7342b8a5c952faf6f3dd31b43984376dc50376eef9250e8f1"
}

rule MalwareBazaar_Mirai_074_30b74bdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30b74bdbf27c10add54294d75e73d34ddca5bd389bd61a5c9c51e1bab2705ff8"
    family = "Mirai"
    file_name = "nerv.m68k"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:49"
  condition:
    hash.sha256(0, filesize) == "30b74bdbf27c10add54294d75e73d34ddca5bd389bd61a5c9c51e1bab2705ff8"
}

rule MalwareBazaar_Mirai_075_a266eed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a266eed844e439b943d2d734b2697905914a8a5478c3767fe7435da339db8173"
    family = "Mirai"
    file_name = "all.sh"
    file_type = "sh"
    first_seen = "2026-07-16 23:55:48"
  condition:
    hash.sha256(0, filesize) == "a266eed844e439b943d2d734b2697905914a8a5478c3767fe7435da339db8173"
}

rule MalwareBazaar_Mirai_076_b019e120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b019e12026ac88f8e95e5b579aaea7129659e1c97433d16bea769b29c2acf7f6"
    family = "Mirai"
    file_name = "nerv.arm7"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:47"
  condition:
    hash.sha256(0, filesize) == "b019e12026ac88f8e95e5b579aaea7129659e1c97433d16bea769b29c2acf7f6"
}

rule MalwareBazaar_Mirai_077_569aa5e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "569aa5e2595d7e43f98234445da9f7284c8d307b09f0c2d599cb2568763eb410"
    family = "Mirai"
    file_name = "nerv.sparc"
    file_type = "elf"
    first_seen = "2026-07-16 23:55:45"
  condition:
    hash.sha256(0, filesize) == "569aa5e2595d7e43f98234445da9f7284c8d307b09f0c2d599cb2568763eb410"
}

rule MalwareBazaar_Mirai_078_48c87b2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48c87b2b9f07b95acc572da0221641011d454c3f587001e820dbec71990a72cf"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 23:54:42"
  condition:
    hash.sha256(0, filesize) == "48c87b2b9f07b95acc572da0221641011d454c3f587001e820dbec71990a72cf"
}

rule MalwareBazaar_Mirai_079_9082d1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9082d1bbe9998076cbc823607eb229b2990fc9c0ef41225966761086583d2388"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 23:53:39"
  condition:
    hash.sha256(0, filesize) == "9082d1bbe9998076cbc823607eb229b2990fc9c0ef41225966761086583d2388"
}

rule MalwareBazaar_unknown_080_5d7cf169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7cf1694cbd34d61441e99e8efca3d64561a4a84b49de920a77119045725303"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 23:52:09"
  condition:
    hash.sha256(0, filesize) == "5d7cf1694cbd34d61441e99e8efca3d64561a4a84b49de920a77119045725303"
}

rule MalwareBazaar_Mirai_081_8f834303
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f8343033b9e1dc3f62527ab0f24ce3d774dc7ea3d54f2d5bc4805bb9360319c"
    family = "Mirai"
    file_name = "bot"
    file_type = "elf"
    first_seen = "2026-07-16 23:51:45"
  condition:
    hash.sha256(0, filesize) == "8f8343033b9e1dc3f62527ab0f24ce3d774dc7ea3d54f2d5bc4805bb9360319c"
}

rule MalwareBazaar_unknown_082_317343a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "317343a58620066fe067f7729b65d0afee20b114c3d4565e89257a409ee9fd27"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 23:48:26"
  condition:
    hash.sha256(0, filesize) == "317343a58620066fe067f7729b65d0afee20b114c3d4565e89257a409ee9fd27"
}

rule MalwareBazaar_unknown_083_27a3b0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27a3b0bd80b8038e73834b8824c88d5084f187a35037218192ca70d0dec8310e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-16 23:45:48"
  condition:
    hash.sha256(0, filesize) == "27a3b0bd80b8038e73834b8824c88d5084f187a35037218192ca70d0dec8310e"
}

rule MalwareBazaar_unknown_084_c0605974
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0605974f0c0efecb1cb7426588b72762746574b331781c5e29d9c599bc8ac2f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-16 23:42:03"
  condition:
    hash.sha256(0, filesize) == "c0605974f0c0efecb1cb7426588b72762746574b331781c5e29d9c599bc8ac2f"
}

rule MalwareBazaar_Mirai_085_b1ee45a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1ee45a84d93ac693f95caa82101559e9d5dabb7e5b15067ad58bf193c20707f"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-07-16 23:17:59"
  condition:
    hash.sha256(0, filesize) == "b1ee45a84d93ac693f95caa82101559e9d5dabb7e5b15067ad58bf193c20707f"
}

rule MalwareBazaar_unknown_086_e08f40da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e08f40dadc8149249e559bf08d2506a67ca843783bb674a0d86858adf5d37ac9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 22:52:14"
  condition:
    hash.sha256(0, filesize) == "e08f40dadc8149249e559bf08d2506a67ca843783bb674a0d86858adf5d37ac9"
}

rule MalwareBazaar_unknown_087_668c3ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "668c3ee84885c653d4b9a87676e3e10f5888ecd72ddbdcf2373823032f4c58a7"
    family = "unknown"
    file_name = "avutil.dll"
    file_type = "dll"
    first_seen = "2026-07-16 22:23:35"
  condition:
    hash.sha256(0, filesize) == "668c3ee84885c653d4b9a87676e3e10f5888ecd72ddbdcf2373823032f4c58a7"
}

rule MalwareBazaar_Mirai_088_a82d1d67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a82d1d67292f1f36e16577fe794d604ebaa9b93846117e4ff95143aef988a193"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:11"
  condition:
    hash.sha256(0, filesize) == "a82d1d67292f1f36e16577fe794d604ebaa9b93846117e4ff95143aef988a193"
}

rule MalwareBazaar_Mirai_089_2ec51b9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec51b9f4bd37c126e4b33c92135d4c98c6ffe719af6d1ebc33b0eff7099ad04"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:10"
  condition:
    hash.sha256(0, filesize) == "2ec51b9f4bd37c126e4b33c92135d4c98c6ffe719af6d1ebc33b0eff7099ad04"
}

rule MalwareBazaar_Mirai_090_05f95e3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05f95e3a46bf7fc22e1b062ce87c770c1252fd38ae10e0aca1067fd7372d1c86"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:08"
  condition:
    hash.sha256(0, filesize) == "05f95e3a46bf7fc22e1b062ce87c770c1252fd38ae10e0aca1067fd7372d1c86"
}

rule MalwareBazaar_Mirai_091_a97c7313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a97c73139ebc430850adcd2e70381a8b810b47205145d49ac7ff1b201344db7f"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:06"
  condition:
    hash.sha256(0, filesize) == "a97c73139ebc430850adcd2e70381a8b810b47205145d49ac7ff1b201344db7f"
}

rule MalwareBazaar_Mirai_092_42444bfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42444bfa4b05d26179c69d9e10ec80350c0a3cab34b2277ce573c9db2e6ac25e"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:05"
  condition:
    hash.sha256(0, filesize) == "42444bfa4b05d26179c69d9e10ec80350c0a3cab34b2277ce573c9db2e6ac25e"
}

rule MalwareBazaar_Mirai_093_94bce2e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94bce2e2e785d54c50fd2d0f6a9702535c9ee8f145a94c666de7403303743fff"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:03"
  condition:
    hash.sha256(0, filesize) == "94bce2e2e785d54c50fd2d0f6a9702535c9ee8f145a94c666de7403303743fff"
}

rule MalwareBazaar_Mirai_094_025d6e0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "025d6e0c9b314bc0db7c6baf357afb738084940f6ec1f9f8ac4e09fb278173f9"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:01"
  condition:
    hash.sha256(0, filesize) == "025d6e0c9b314bc0db7c6baf357afb738084940f6ec1f9f8ac4e09fb278173f9"
}

rule MalwareBazaar_Mirai_095_e83da6e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e83da6e7d86f4715200b84427a1aa7c2d4187f48af70ef0ee024caaf36428809"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-16 22:12:00"
  condition:
    hash.sha256(0, filesize) == "e83da6e7d86f4715200b84427a1aa7c2d4187f48af70ef0ee024caaf36428809"
}

rule MalwareBazaar_Mirai_096_ceaac96b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceaac96b6574b9d38ef11c725d20037178e9ffaab3133f310e4e9fe1178690d2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:58"
  condition:
    hash.sha256(0, filesize) == "ceaac96b6574b9d38ef11c725d20037178e9ffaab3133f310e4e9fe1178690d2"
}

rule MalwareBazaar_Mirai_097_31e1a032
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31e1a03223438c819d343bbada505658bd34acbc9073764096dc044013e302bc"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:57"
  condition:
    hash.sha256(0, filesize) == "31e1a03223438c819d343bbada505658bd34acbc9073764096dc044013e302bc"
}

rule MalwareBazaar_Mirai_098_4bd17c2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4bd17c2bf9c2cf17a4728f0a7753761be3c788910041390b0e374e06c581a8c9"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:55"
  condition:
    hash.sha256(0, filesize) == "4bd17c2bf9c2cf17a4728f0a7753761be3c788910041390b0e374e06c581a8c9"
}

rule MalwareBazaar_Mirai_099_9febcd6b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9febcd6b2e7829e8be76fb01fff52136962570ea3b682322e266a861c057a014"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:53"
  condition:
    hash.sha256(0, filesize) == "9febcd6b2e7829e8be76fb01fff52136962570ea3b682322e266a861c057a014"
}

rule MalwareBazaar_Gafgyt_100_1fad40f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fad40f8b341ce60076d2111c2ac47b8478362498ed51fc5b9c5ceeef0f6d758"
    family = "Gafgyt"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-16 22:11:52"
  condition:
    hash.sha256(0, filesize) == "1fad40f8b341ce60076d2111c2ac47b8478362498ed51fc5b9c5ceeef0f6d758"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

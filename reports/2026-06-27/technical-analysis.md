# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-27

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 633 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 633 |
| Unique family labels | 10 |
| Unique file types | 13 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 57 |
| Mirai | 22 |
| CoinMiner | 6 |
| Gafgyt | 6 |
| RustyStealer | 4 |
| ValleyRAT | 1 |
| GuLoader | 1 |
| WannaCry | 1 |
| Amadey | 1 |
| ConnectWise | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 35 |
| apk | 27 |
| exe | 19 |
| sh | 4 |
| vbs | 3 |
| js | 3 |
| unknown | 2 |
| msi | 2 |
| wsf | 1 |
| cab | 1 |

## Per-Sample Analysis

### Sample 1: `7c8d8eaa543c4e9b`

| Field | Value |
|---|---|
| SHA-256 | `7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891` |
| Family label | `unknown` |
| File name | `TurboPay%20BD%20Reader.apk` |
| File type | `apk` |
| First seen | `2026-06-27 04:00:28` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f506536b95f1af75bd93f75530385461` |
| SHA-1 | `2b87d75efdbfd1df2332a13fbbef54fc3c659bad` |
| SHA-256 | `7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891` |
| SHA3-384 | `a21b3fe915bebaa2103fe7a42f8fc47bc145154a62767d13617b1698e8722783250f92df8435cc04977938b63f1c472b` |
| TLSH | `T118A61285BB44EA2BC477703205BA9722558B4C068E83D743AA587E0C6DF7AD41F4EFC9` |
| SSDEEP | `196608:ejaEwhKKomLSjxjGY6EA2XCp8AsbtyQYvjJCpXm4p5Ta/zCzYePXi:H3UdAiptUvj0BpgKVi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_7c8d8eaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
    family = "unknown"
    file_name = "TurboPay%20BD%20Reader.apk"
    file_type = "apk"
    first_seen = "2026-06-27 04:00:28"
  condition:
    hash.sha256(0, filesize) == "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
}
```

### Sample 2: `ac57da29a3b20679`

| Field | Value |
|---|---|
| SHA-256 | `ac57da29a3b20679113c7ff33ac81c977c1b964863f8310d3fdf5b351fbfd8f2` |
| Family label | `unknown` |
| File name | `tickr.apk` |
| File type | `apk` |
| First seen | `2026-06-27 04:00:15` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69ac5b7031a8ccffdfdb62153f14bfe0` |
| SHA-1 | `81cd99afd6b23390c59732f1f0a6cf7042439bc6` |
| SHA-256 | `ac57da29a3b20679113c7ff33ac81c977c1b964863f8310d3fdf5b351fbfd8f2` |
| SHA3-384 | `9df44aa0b0d2294e17e5598d0bf624532c7716c0cc8dc8d3898dbdeaaf246a4473ddf1a6d3094f34055f22f1abe4d176` |
| TLSH | `T183A312DBDBA8E876CD2E5C3588F4F56AEF7253B39060C3475B17A224AD944B10DB041E` |
| SSDEEP | `1536:L9UwBx84E4uAXQlcWrZvS00eV688DANSct9eIxEnan7eI3BnaA:KwBMAghNZV68C69/xvX3daA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_ac57da29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac57da29a3b20679113c7ff33ac81c977c1b964863f8310d3fdf5b351fbfd8f2"
    family = "unknown"
    file_name = "tickr.apk"
    file_type = "apk"
    first_seen = "2026-06-27 04:00:15"
  condition:
    hash.sha256(0, filesize) == "ac57da29a3b20679113c7ff33ac81c977c1b964863f8310d3fdf5b351fbfd8f2"
}
```

### Sample 3: `59afd76ba4c60df3`

| Field | Value |
|---|---|
| SHA-256 | `59afd76ba4c60df30d59b1cd3db92f203040ed0d4e84279434bd702c919e9273` |
| Family label | `ValleyRAT` |
| File name | `39B698A4A2EC18E256B2AD8503DE9E4D.exe` |
| File type | `exe` |
| First seen | `2026-06-27 04:00:09` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39b698a4a2ec18e256b2ad8503de9e4d` |
| SHA-1 | `32cd6da281fc30ea7f10d084a8d1783559b5106f` |
| SHA-256 | `59afd76ba4c60df30d59b1cd3db92f203040ed0d4e84279434bd702c919e9273` |
| SHA3-384 | `24fb00033fd8bb3d0d18ce1bdd84d1a42e2a1edf9bda37ce40e8d79329c0eb82ee5c2b88ae0744dab31ac8acee72bf58` |
| IMPHASH | `40ab50289f7ef5fae60801f88d4541fc` |
| TLSH | `T17E95C023B28BA83DEC5D0B3B05B2A15594FB6E216426BD1787E4B49CCF351601E3E787` |
| SSDEEP | `24576:iaE+hTNrCHtLfTfuM7Djr5QpYrao2rupZdH+4xAiZQmXFOKzE2/d++HFkPIIE8Y1:a+MRvH7nKSFO4L4+HFPIUukqiRl` |
| ICON-DHASH | `133b7b63634b5943` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_003_59afd76b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59afd76ba4c60df30d59b1cd3db92f203040ed0d4e84279434bd702c919e9273"
    family = "ValleyRAT"
    file_name = "39B698A4A2EC18E256B2AD8503DE9E4D.exe"
    file_type = "exe"
    first_seen = "2026-06-27 04:00:09"
  condition:
    hash.sha256(0, filesize) == "59afd76ba4c60df30d59b1cd3db92f203040ed0d4e84279434bd702c919e9273"
}
```

### Sample 4: `1ed58d5794a5f8e2`

| Field | Value |
|---|---|
| SHA-256 | `1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0` |
| Family label | `unknown` |
| File name | `sms-spy-v5.apk` |
| File type | `apk` |
| First seen | `2026-06-27 04:00:08` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd1d58283783119601b96d6509ecbece` |
| SHA-1 | `9133e735bfbb7e67764e47e1548992dabb1b0a7d` |
| SHA-256 | `1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0` |
| SHA3-384 | `b1cb39bcde6c28f5dbfff0fb28d0a6f3d841ed31f95a231bad2a21c5ea67b834e743548e19f337bb455d2d28b65902a3` |
| TLSH | `T1BD66F088FB88D92FC5775532457A6322814B4C0A9E83EB53B959720C2CB76D50F8EBCD` |
| SSDEEP | `98304:RWL+A0GH2oajAlhMiIMWC/AViJ/XDC3Que/C+pYMGSKKce4MtZZAOY9AaDcPpPnX:HbMfJZf9zC38/CfMGSuKZC0PZG/hbpL8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_1ed58d57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
    family = "unknown"
    file_name = "sms-spy-v5.apk"
    file_type = "apk"
    first_seen = "2026-06-27 04:00:08"
  condition:
    hash.sha256(0, filesize) == "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
}
```

### Sample 5: `20dbcab2dc3f9e4e`

| Field | Value |
|---|---|
| SHA-256 | `20dbcab2dc3f9e4ec9a7d55876b536fa1fcc5f6dc00f6181b5cff7c9338f45c9` |
| Family label | `GuLoader` |
| File name | `2f426d2fb00858d8649cf99eb2e2aac6.exe` |
| File type | `exe` |
| First seen | `2026-06-27 04:00:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, GuLoader, RAT, RemcosRAT, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f426d2fb00858d8649cf99eb2e2aac6` |
| SHA-1 | `d234740fdb4a0860d18bae49d82827bef3dd28b1` |
| SHA-256 | `20dbcab2dc3f9e4ec9a7d55876b536fa1fcc5f6dc00f6181b5cff7c9338f45c9` |
| SHA3-384 | `77e4c283f4545efdb9ab316595bb22c44678fd09d81d96b1c4d9b5ee147504066ccb7c6dda1553c4948bd7633c6b9e1b` |
| IMPHASH | `f4639a0b3116c2cfc71144b88a929cfd` |
| TLSH | `T12EA48D41F8149CE6F8395672687F8DB609E13D3B46E019AE27DFB37A14F2212501BE1E` |
| SSDEEP | `6144:7XsKoGShOkrI7LtxQ+/yqAkx9xjb0SNEhIXpjdWBP4L:7XOeUEp0SahIXeBP4L` |
| ICON-DHASH | `04ece084ca1aba7c` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_005_20dbcab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20dbcab2dc3f9e4ec9a7d55876b536fa1fcc5f6dc00f6181b5cff7c9338f45c9"
    family = "GuLoader"
    file_name = "2f426d2fb00858d8649cf99eb2e2aac6.exe"
    file_type = "exe"
    first_seen = "2026-06-27 04:00:06"
  condition:
    hash.sha256(0, filesize) == "20dbcab2dc3f9e4ec9a7d55876b536fa1fcc5f6dc00f6181b5cff7c9338f45c9"
}
```

### Sample 6: `f27b5c92c0e34c5a`

| Field | Value |
|---|---|
| SHA-256 | `f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2` |
| Family label | `unknown` |
| File name | `punnitoot.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:59:57` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `545dc2ce39c12fddcfc5a9d25ea3abe8` |
| SHA-1 | `670fd706b61d716d122c23fb869b8c4ac1f2850c` |
| SHA-256 | `f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2` |
| SHA3-384 | `88aee57c903e4601804d0ebf601ebaffba88c226578649817a8ddb8fe16c7c8281e461da76585e4ffadd7ac15cd4893c` |
| TLSH | `T1AF560145BB48E92BD477703245BA5722558B8D068E83DB53AA443E0C6CB7AC41F8EFCD` |
| SSDEEP | `98304:GtuO8ftRrPg7QW2a7U8AvkezXEEppppTWE3dOST3vjJCpXujHUBmyOT2U4X13ENL:G17QP8AsstWa9vjJCpXmUBmTanE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_f27b5c92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
    family = "unknown"
    file_name = "punnitoot.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:57"
  condition:
    hash.sha256(0, filesize) == "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
}
```

### Sample 7: `649b4a4044a9ead4`

| Field | Value |
|---|---|
| SHA-256 | `649b4a4044a9ead43588f78a85576f51a63de847a4620920b06fc4da8ae2989c` |
| Family label | `unknown` |
| File name | `Paytm (1).apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:59:46` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5750b2ad2f8983b3c73b4089faae10d` |
| SHA-1 | `f8ec214cd457cd3ee0abb198ed8c7f4819e0337f` |
| SHA-256 | `649b4a4044a9ead43588f78a85576f51a63de847a4620920b06fc4da8ae2989c` |
| SHA3-384 | `39299b57cdd6edc18d8a8eb3b9fa4d04cbdb7957adacecf584433c61967a3d848b02356e16c19a2e46668e38873e37d0` |
| TLSH | `T199270243F78E492AE9F3B9F4028F2372A6165C58476255CB5E01F2046DB36E4AF39BC1` |
| SSDEEP | `393216:RpRUm6Gt9pdgmjAZtz04n69YudxDOtU7wpiozBofen:RpRUmHmZp9QhdBio2n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_649b4a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649b4a4044a9ead43588f78a85576f51a63de847a4620920b06fc4da8ae2989c"
    family = "unknown"
    file_name = "Paytm (1).apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:46"
  condition:
    hash.sha256(0, filesize) == "649b4a4044a9ead43588f78a85576f51a63de847a4620920b06fc4da8ae2989c"
}
```

### Sample 8: `6db0e9536318dc39`

| Field | Value |
|---|---|
| SHA-256 | `6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd` |
| Family label | `unknown` |
| File name | `my horror Aaron 0.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:59:23` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1eda0754c8c136070328dc89a2a77fca` |
| SHA-1 | `a91ed738f3ba5345a5e1b9c2c7c838bafc077cd7` |
| SHA-256 | `6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd` |
| SHA3-384 | `223752085ff497107a675f1caccb5d878d168548c7e061bd19dfeb97dc34fa66b6e7c0e73974c717c9d3cceb31a191fd` |
| TLSH | `T160560189BB58E72BC477903745EA5332558B4D1B8E8297836824720C7DB7AF40F5AFC8` |
| SSDEEP | `98304:Ny4+5i0CFxKAFZcjLQLEvxCd2Zr0MKgMyM1dFAJPDTu+odCzyxkai11E+9KhXiSP:NUOxK2ZcQvp1dMnKQ1T8jY2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_6db0e953
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
    family = "unknown"
    file_name = "my horror Aaron 0.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:23"
  condition:
    hash.sha256(0, filesize) == "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
}
```

### Sample 9: `3c29a7a2b35b47e8`

| Field | Value |
|---|---|
| SHA-256 | `3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647` |
| Family label | `unknown` |
| File name | `Installer.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:59:13` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83d14fc38fdc4ca662f6abc80c3fc30f` |
| SHA-1 | `53622c600a07f88b81d31f19b6863fd0ceec8f8f` |
| SHA-256 | `3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647` |
| SHA3-384 | `873011175e7615a466ea8dc2902fab3cca3bdc6d2ecdebb67fd7312f488ffedefd82103a5ff33aa08fce21c46ad777cf` |
| TLSH | `T10E66D089BB89D92BC4777436517AA322415B4C068E83A783BD447E0C6CB79C51F8BECD` |
| SSDEEP | `98304:8LStO8ftRrd5CiIMWC/AViJ/XDC3Que/C+pYMGSKKce4MtsZAOY9AaDcPpPnG/hJ:8WXbZf9zC38/CfMGSurZC0PZG/hbpa0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_3c29a7a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
    family = "unknown"
    file_name = "Installer.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:13"
  condition:
    hash.sha256(0, filesize) == "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
}
```

### Sample 10: `99ff6067685b9573`

| Field | Value |
|---|---|
| SHA-256 | `99ff6067685b9573c9e09e61b4ed910b8a74481bec345cfaa4037ae4a1155495` |
| Family label | `unknown` |
| File name | `emoji2entity.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:59:03` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `851e6c8180c8b5f97a4146648c7912ce` |
| SHA-1 | `4c39409f2aedd629065727cdeb1fbb9a602503c4` |
| SHA-256 | `99ff6067685b9573c9e09e61b4ed910b8a74481bec345cfaa4037ae4a1155495` |
| SHA3-384 | `95ec53ba478f3e3730a17fc4a6b07a7d5287340f51da83fda76c923ee39a6c6ed37853fbfb2596d5651c27a0ba12d33b` |
| TLSH | `T16FA302AB9FA8E952CE2ECC7C94B8E13EEFB15352E4F0C387091252116F929754DD121E` |
| SSDEEP | `1536:D9yZIUwBx84E4uAXQlcWrZvS00eV688DANSct9eI/mcD61pSr:565wBMAghNZV68C69/qpSr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_99ff6067
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ff6067685b9573c9e09e61b4ed910b8a74481bec345cfaa4037ae4a1155495"
    family = "unknown"
    file_name = "emoji2entity.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:03"
  condition:
    hash.sha256(0, filesize) == "99ff6067685b9573c9e09e61b4ed910b8a74481bec345cfaa4037ae4a1155495"
}
```

### Sample 11: `836f2b13d8481e94`

| Field | Value |
|---|---|
| SHA-256 | `836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2` |
| Family label | `unknown` |
| File name | `Brawl Stars Pros.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:58:57` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c70ea27947382e4be16982503e9e8aad` |
| SHA-1 | `148487e79337d98abe8105fa23e7f7c0f79302a5` |
| SHA-256 | `836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2` |
| SHA3-384 | `ef69b54d24748c1c8e57c0a2bf6aa75b1e9a0441945d6afda3ef0363bf10f73134ef225b7f8a6f8ac3d32205d215de5b` |
| TLSH | `T12644124673A985E6D5BE40F88C24873FEEF2627285D09B3F074CA61C1C754F40E5466A` |
| SSDEEP | `6144:hOwyinq4NfUiKRZPGmLZ2wo8cAAGaNDHVVhN9CK/JBe4dq:hO8qPiKvXZ2woNGG1VhN4aFdq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_836f2b13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2"
    family = "unknown"
    file_name = "Brawl Stars Pros.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:58:57"
  condition:
    hash.sha256(0, filesize) == "836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2"
}
```

### Sample 12: `f8b875e84dcd83ae`

| Field | Value |
|---|---|
| SHA-256 | `f8b875e84dcd83ae2f858ea6e496da4fee407c5b6cc819563bb7ac1458729ee3` |
| Family label | `unknown` |
| File name | `BOOYAH ZONE_2.1.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:58:47` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9cfa6dffcf9c7df75b776203b807367` |
| SHA-1 | `11e3b281b44b38193c96c35fc448e83f0736fbd8` |
| SHA-256 | `f8b875e84dcd83ae2f858ea6e496da4fee407c5b6cc819563bb7ac1458729ee3` |
| SHA3-384 | `ce76745dfaa0478150dd5f1cb303b734173cae7bb741b849499f7e922a2085574b9e026f03786eba8bde421e821053ff` |
| TLSH | `T189F623C6FBC8D82BC4339132C9AA47A6518B0C168A839F536E54764C58F7AD42F59FCC` |
| SSDEEP | `196608:nYpHFQQJ7WeWZ9BCcL122mP5LY38dr4P3RjKY39VsKMIBD1fKCm41R59ZWEhvfO:YtFQQ/W5ZAXPy3HZjPcIB5yfoJWEpm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_f8b875e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b875e84dcd83ae2f858ea6e496da4fee407c5b6cc819563bb7ac1458729ee3"
    family = "unknown"
    file_name = "BOOYAH ZONE_2.1.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:58:47"
  condition:
    hash.sha256(0, filesize) == "f8b875e84dcd83ae2f858ea6e496da4fee407c5b6cc819563bb7ac1458729ee3"
}
```

### Sample 13: `faf71cb7a1ccb818`

| Field | Value |
|---|---|
| SHA-256 | `faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19` |
| Family label | `unknown` |
| File name | `bfludo.apk` |
| File type | `apk` |
| First seen | `2026-06-27 03:58:31` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc599a755eb40a774941502bb90bd984` |
| SHA-1 | `28203db44d7e6b0b6ce717e7366e20938b18d55e` |
| SHA-256 | `faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19` |
| SHA3-384 | `d8654d67d815416cab211e16ccee37889be1b654d46d4576a4f490ff11555b6b3936ca08445a4ecb254fa0adea1d4a1a` |
| TLSH | `T137353356A3FE16AADD4371F0477B47007C582FDFE9A262E11F405AD418DE4AB2C9A323` |
| SSDEEP | `24576:BxivCXO1x/UVBP5u82mKB03+nBeLfF7j9PvlAs:BmWP0YOgLRjVN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_faf71cb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19"
    family = "unknown"
    file_name = "bfludo.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:58:31"
  condition:
    hash.sha256(0, filesize) == "faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19"
}
```

### Sample 14: `00a99866c7a6525c`

| Field | Value |
|---|---|
| SHA-256 | `00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1` |
| Family label | `unknown` |
| File name | `00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1` |
| File type | `elf` |
| First seen | `2026-06-27 03:26:02` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c035dfee417886ff4bc24d35ff531f5` |
| SHA-1 | `dd8e134f7f2ce639fa617de49eb299f165b45f6f` |
| SHA-256 | `00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1` |
| SHA3-384 | `94b4442ada6cd686eda18f0da8e1369669bcc8e271edc42924bf2241470beb730ae59209398111d2467f15de30bdb867` |
| TLSH | `T13727CE77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ2:cqYUQuVDt0TZEJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_00a99866
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1"
    family = "unknown"
    file_name = "00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1"
    file_type = "elf"
    first_seen = "2026-06-27 03:26:02"
  condition:
    hash.sha256(0, filesize) == "00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1"
}
```

### Sample 15: `f3eb87983169d29f`

| Field | Value |
|---|---|
| SHA-256 | `f3eb87983169d29f6eedf685922a02146f575bcc695b4bb0fe54019f09d3e8d2` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 02:47:18` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5192e8a1fbe21cfcb28ceb4c69219c09` |
| SHA-1 | `b73545164f143d3d93bd1726653c62b0d828bf92` |
| SHA-256 | `f3eb87983169d29f6eedf685922a02146f575bcc695b4bb0fe54019f09d3e8d2` |
| SHA3-384 | `d862a938ee4cf98a624581fa6011a38b9e0727fd87700786875c2e30a0bf03a247daf6c42c50d9a59c4c85440a51fddf` |
| IMPHASH | `79fc34079e4f2426d5934af60b648369` |
| TLSH | `T11866E103E5F78EF4C22BE67D46625333A92474881E32B11C6995F36B5FE0938A19DB70` |
| SSDEEP | `98304:9U8W7UFHNxZemy4hjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErzvR/KJM:pI0demyhjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_015_f3eb8798
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3eb87983169d29f6eedf685922a02146f575bcc695b4bb0fe54019f09d3e8d2"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:47:18"
  condition:
    hash.sha256(0, filesize) == "f3eb87983169d29f6eedf685922a02146f575bcc695b4bb0fe54019f09d3e8d2"
}
```

### Sample 16: `fa2a09342548fe01`

| Field | Value |
|---|---|
| SHA-256 | `fa2a09342548fe01c57030f6d69dc38997fcd3547855701afeb6519f3e390c18` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 02:35:58` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f7d062922f5cc9a17ad53f26fd0fb1b` |
| SHA-1 | `78511dc7a946383a4555eda16495cff4745692c8` |
| SHA-256 | `fa2a09342548fe01c57030f6d69dc38997fcd3547855701afeb6519f3e390c18` |
| SHA3-384 | `f2b9147aa31795a9c39e88b942115e4cb255de99334c773626b754e58c172c8cac7a7da3f1b65849e01338fba9c2529c` |
| IMPHASH | `79fc34079e4f2426d5934af60b648369` |
| TLSH | `T13E66E103E5F78EF4C21BE67D46629333A92474881E32B11C6995F36B5FE0938A19DB70` |
| SSDEEP | `98304:bU8W7/FHNxZemy4hjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErzvR/KJM:vIxdemyhjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_016_fa2a0934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa2a09342548fe01c57030f6d69dc38997fcd3547855701afeb6519f3e390c18"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:35:58"
  condition:
    hash.sha256(0, filesize) == "fa2a09342548fe01c57030f6d69dc38997fcd3547855701afeb6519f3e390c18"
}
```

### Sample 17: `f2deee4f7cb4770c`

| Field | Value |
|---|---|
| SHA-256 | `f2deee4f7cb4770c9e909c5319ec1357cee341dd442ebf51c644d6bf16f6709f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-27 02:21:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70c3c3576a79371eadab9419caa15ed6` |
| SHA-1 | `4e5fedcdb08547301d009afa1ddc5c205dab9b08` |
| SHA-256 | `f2deee4f7cb4770c9e909c5319ec1357cee341dd442ebf51c644d6bf16f6709f` |
| SHA3-384 | `238cd1365916e0ac9e13202974252f8c7ba36a2e501aac4d0236cbd1a5ed0cfa3372970895b949333f3a7c7d6d4149fb` |
| TLSH | `T18A137D6966857C24AE99883B1C7E2F0CB9A983E1310451DDBFCB3CF58C19B9CE21971D` |
| SSDEEP | `768:Y+s9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:Y+Bco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_f2deee4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2deee4f7cb4770c9e909c5319ec1357cee341dd442ebf51c644d6bf16f6709f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-27 02:21:57"
  condition:
    hash.sha256(0, filesize) == "f2deee4f7cb4770c9e909c5319ec1357cee341dd442ebf51c644d6bf16f6709f"
}
```

### Sample 18: `ba852441acba7f4e`

| Field | Value |
|---|---|
| SHA-256 | `ba852441acba7f4e928215426a94f44f6f5b74dbf21b323087e007f9baf0645f` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 02:21:52` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f62887e1a794ddaea9ac9aaf8d94234b` |
| SHA-1 | `d3ebb6839607136507a053f1f1f922886a079016` |
| SHA-256 | `ba852441acba7f4e928215426a94f44f6f5b74dbf21b323087e007f9baf0645f` |
| SHA3-384 | `674db040ad82c183492e8850ac376d502bc1b0dc64dbfb0b9abcf040689a2330de9549f02de52d75aab51ac0fc48d66a` |
| IMPHASH | `79fc34079e4f2426d5934af60b648369` |
| TLSH | `T16F66E103E5F78EF4C21BE67D46625333A924B4881E32B11C6995F36B5FE0938A19DB70` |
| SSDEEP | `98304:XU8W7tFHNxZemy4hjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErzvR/KJM:zI/demyhjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_018_ba852441
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba852441acba7f4e928215426a94f44f6f5b74dbf21b323087e007f9baf0645f"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:21:52"
  condition:
    hash.sha256(0, filesize) == "ba852441acba7f4e928215426a94f44f6f5b74dbf21b323087e007f9baf0645f"
}
```

### Sample 19: `40479b05e94cf5a4`

| Field | Value |
|---|---|
| SHA-256 | `40479b05e94cf5a4895d68867d9fdaebe1e2d7f9d632b76cb57041ea1fe20c71` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 02:15:36` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b532a2bffe54bf4de2e8029e84041c3` |
| SHA-1 | `e499574f0ee36f979527a2a434b16936dc9ef9a4` |
| SHA-256 | `40479b05e94cf5a4895d68867d9fdaebe1e2d7f9d632b76cb57041ea1fe20c71` |
| SHA3-384 | `47c7eecdddb76268db25badc8d2baa2c3fea3971d71c42c795bee1d05721f82a3ca5ec97c419afa07eed1fad1ca93665` |
| IMPHASH | `79fc34079e4f2426d5934af60b648369` |
| TLSH | `T14C66E103E5F78EF4C21BE67D46629333A92474881E32B11C6995F36B5FE0938A19DB70` |
| SSDEEP | `98304:IU8W7IFHNxZemy4hjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErzvR/KJM:EI4demyhjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_019_40479b05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40479b05e94cf5a4895d68867d9fdaebe1e2d7f9d632b76cb57041ea1fe20c71"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:15:36"
  condition:
    hash.sha256(0, filesize) == "40479b05e94cf5a4895d68867d9fdaebe1e2d7f9d632b76cb57041ea1fe20c71"
}
```

### Sample 20: `992c26a5cc1ca754`

| Field | Value |
|---|---|
| SHA-256 | `992c26a5cc1ca754400a33b9973acd1c24a26997c0a19d1e2a2feaa62586f074` |
| Family label | `unknown` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-06-27 02:04:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6de6606b1631db719470e5fb0f031ae6` |
| SHA-1 | `9751a52697847b867a701bd1ec575cf2c7d4a987` |
| SHA-256 | `992c26a5cc1ca754400a33b9973acd1c24a26997c0a19d1e2a2feaa62586f074` |
| SHA3-384 | `6fba30f7d7bc004a897699154693c67198c50eec0456bc894da7b7c887b08034cb71a5b8ecd77cea6ce538e77feaa941` |
| TLSH | `T11243F846B9829E11C9D4037BFE1E118D33137798D3EEB212DE116F21BBCE56B0A6B461` |
| TELFHASH | `t1c5d05e1226e943d892f0180382ee6b3e3a07b0553f4109689f633e8e4249fc25934c30` |
| SSDEEP | `1536:IVnQOt1RzAVwh4NuYzUviTpOteNTeTiI7iIDz8J7KwbZn:/Ot1pAVwh4MWCigPDz8J7KwbZn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_992c26a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "992c26a5cc1ca754400a33b9973acd1c24a26997c0a19d1e2a2feaa62586f074"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-27 02:04:55"
  condition:
    hash.sha256(0, filesize) == "992c26a5cc1ca754400a33b9973acd1c24a26997c0a19d1e2a2feaa62586f074"
}
```

### Sample 21: `5dde1b0de96d85a8`

| Field | Value |
|---|---|
| SHA-256 | `5dde1b0de96d85a8dd0b3582dd9d32f095d0164f2b6d73e462415046ed19af6a` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-27 01:57:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9eceb81bab3f5a991b3f893b3dada13` |
| SHA-1 | `11cab6aea9a2d396f2682afd702f13800a05166b` |
| SHA-256 | `5dde1b0de96d85a8dd0b3582dd9d32f095d0164f2b6d73e462415046ed19af6a` |
| SHA3-384 | `2fc89e8f5bf26a0c6905923ec8d7abe79e52d781163c0e4d7fce9f092f8968d92544d2f7fb5a1468aefb4d97e4c1e9fe` |
| TLSH | `T1A563F645B982AF01D4D913BBFE1E018D33536798E3EEB112DE116F21A7CA61B0B7B451` |
| TELFHASH | `t1ddd0a790559565cc73e08b0243ca9a1cf971a15d39181a218a4777de065ffc16627436` |
| SSDEEP | `1536:byhncbk1Sz6pvhFk7gO2dBZh2kTl4OR0rekGPllwbi9LHXk5wbZn:Bbk1U6pvhFJBd1Xl4OR0reOQLH05wbZn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_5dde1b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dde1b0de96d85a8dd0b3582dd9d32f095d0164f2b6d73e462415046ed19af6a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-27 01:57:58"
  condition:
    hash.sha256(0, filesize) == "5dde1b0de96d85a8dd0b3582dd9d32f095d0164f2b6d73e462415046ed19af6a"
}
```

### Sample 22: `b626c4317ff6d4ca`

| Field | Value |
|---|---|
| SHA-256 | `b626c4317ff6d4ca1ec04471421bef1d0261c59d77cb0bc0cf3c1e077d984865` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 01:49:26` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50a332343d5e3e038378262f73bc9e79` |
| SHA-1 | `35c12d0508cbf7ddf43a4b22b5df2c96309d4205` |
| SHA-256 | `b626c4317ff6d4ca1ec04471421bef1d0261c59d77cb0bc0cf3c1e077d984865` |
| SHA3-384 | `beb05b254c185f1640843015b24d043768e0f2e0bfa9977a2ea09f56dd1bc8e8f8243d6359d28c33f289ede70cfc8a94` |
| IMPHASH | `79fc34079e4f2426d5934af60b648369` |
| TLSH | `T1BB66E103E5F78EF4C21BEA7D46625333A92474881E32B11C6995F36B5FE0938A19DB70` |
| SSDEEP | `98304:RU8W74FHNxZemy4hjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErzvR/KJM:1Iodemyhjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_022_b626c431
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b626c4317ff6d4ca1ec04471421bef1d0261c59d77cb0bc0cf3c1e077d984865"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 01:49:26"
  condition:
    hash.sha256(0, filesize) == "b626c4317ff6d4ca1ec04471421bef1d0261c59d77cb0bc0cf3c1e077d984865"
}
```

### Sample 23: `b3f4e9f001c0d227`

| Field | Value |
|---|---|
| SHA-256 | `b3f4e9f001c0d227b00dad00914eddb52280dd07f92ee13e54039eae5eb32133` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-06-27 01:41:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0702af8e555ded8476b7482c839b7cd4` |
| SHA-1 | `98f54f282b3ec298332db9d6234ca2fbee424fe6` |
| SHA-256 | `b3f4e9f001c0d227b00dad00914eddb52280dd07f92ee13e54039eae5eb32133` |
| SHA3-384 | `113525540c50bcaa0eae7d63573a65a4015413a243d669d10b293cfe0ff0b6c4284752414e1a1a8ecc5e68518eba75a1` |
| TLSH | `T14753620EAF601EF7EC6BCD3716E81B49308C641A11A93F397A74D918FA4A20B55E3C75` |
| SSDEEP | `768:qjgRzuSwtad8/8qEiFoD05fRMPiLg1aeUqe2AWqDtXiuomCz5SwbZnl:qjgZj3OFoDIR1jhq5AWmXCgwbZnl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_b3f4e9f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3f4e9f001c0d227b00dad00914eddb52280dd07f92ee13e54039eae5eb32133"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-06-27 01:41:00"
  condition:
    hash.sha256(0, filesize) == "b3f4e9f001c0d227b00dad00914eddb52280dd07f92ee13e54039eae5eb32133"
}
```

### Sample 24: `f04d5131819615b0`

| Field | Value |
|---|---|
| SHA-256 | `f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf` |
| Family label | `unknown` |
| File name | `Видеозапись(3).apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:22:44` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `879492ce87ef05e79ed37a3e341a7c1a` |
| SHA-1 | `a2f03e8ae41a544c5e405e2d65eac8a9d818f274` |
| SHA-256 | `f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf` |
| SHA3-384 | `bcdf812af9b43c90ca9178038b6bab4618cb21fe1414273bfd753e814dd137766f75b831cc01fa1a1ad3152918bed1b0` |
| TLSH | `T109862346EB29E84EC0FB56374A36027542479D2E879396C75DEDB37818739C07EE2E80` |
| SSDEEP | `196608:wVRKI79uDPPnCOQYMH4b8b1F1DfwXvw8NGRe/gn9JdJuI02A:oK/bnK4gZbYqe/g9xE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_f04d5131
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf"
    family = "unknown"
    file_name = "Видеозапись(3).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:44"
  condition:
    hash.sha256(0, filesize) == "f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf"
}
```

### Sample 25: `82621c55f48c0309`

| Field | Value |
|---|---|
| SHA-256 | `82621c55f48c03093f5682ea1b3a6c5e5ac48a1c964643d7ce67fe41ccdba387` |
| Family label | `unknown` |
| File name | `triadaShowcase.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:22:33` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5abb7bb7eb2d4d124289270172090c2` |
| SHA-1 | `18c1685508c6c90fac1b41ad47f9b395178298f8` |
| SHA-256 | `82621c55f48c03093f5682ea1b3a6c5e5ac48a1c964643d7ce67fe41ccdba387` |
| SHA3-384 | `d62ea1286883265289e447721175894bb59ff74d0fdaffbcd06fb372eae3f3e0d78d4936c92bf9888cc55135b53523cd` |
| TLSH | `T18EC3129BBF48D833DA2E1C3C89B8E17BBEB1679560D0C7872F12C25269854B24DB051F` |
| SSDEEP | `1536:EWcd0+sUwBx84E4uAXQlcWrZvS00eV688DANSct9eIJWqZrDqWQa6bI:EWcbwBMAghNZV68C69/JWqJDgI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_82621c55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82621c55f48c03093f5682ea1b3a6c5e5ac48a1c964643d7ce67fe41ccdba387"
    family = "unknown"
    file_name = "triadaShowcase.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:33"
  condition:
    hash.sha256(0, filesize) == "82621c55f48c03093f5682ea1b3a6c5e5ac48a1c964643d7ce67fe41ccdba387"
}
```

### Sample 26: `906896b11849040c`

| Field | Value |
|---|---|
| SHA-256 | `906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc` |
| Family label | `unknown` |
| File name | `Stealer.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:22:28` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30456e5840b3e0b2ba8b17536f9dd267` |
| SHA-1 | `4a13b036480b509264a5c89eb58f1ae2f90c84ce` |
| SHA-256 | `906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc` |
| SHA3-384 | `fc0661e2bdf2184af39f6a9d2b2dd99dd56309e2eab5f03501453fb3c5a7d46a5df091bce9fae872ee6e0f4762254848` |
| TLSH | `T1BB9423FBE918B5A2D24E6C76903F9D1BFB79D38378B4C9EA18A050D0C670595C19AC0F` |
| SSDEEP | `6144:JhN9CK/1dD5wYFx/i26Fu6VNNDBU3TqiukWk4/XZ/plBUJYWZ9NiU3:JhN4a1d1wOx/ixu0NNznlPZh0L9NV3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_906896b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc"
    family = "unknown"
    file_name = "Stealer.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:28"
  condition:
    hash.sha256(0, filesize) == "906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc"
}
```

### Sample 27: `0bf4779a000a63a1`

| Field | Value |
|---|---|
| SHA-256 | `0bf4779a000a63a12e5d22ef884df612a5b9823ba69d008fa137312955eba65e` |
| Family label | `unknown` |
| File name | `startuptest.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:22:20` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3464c4920db76c63ef01c102ec3be3f` |
| SHA-1 | `b4d34b06a8ee6516fc29ba46a399c637e7934077` |
| SHA-256 | `0bf4779a000a63a12e5d22ef884df612a5b9823ba69d008fa137312955eba65e` |
| SHA3-384 | `275499ae3c30f2be9c9b33934ef06ad0c8dfd89d1953fa4a60fc9d7c09f92ac166e7248c7c6388ec61848ea661da421d` |
| TLSH | `T15CB302D3DB44D95ACE7DB478D8B8E137FFD2976290A09B872A1251308DA68F10DB102F` |
| SSDEEP | `1536:xvFCdJgUwBx84E4uAXQlcWrZvS00eV688DANSct9eIjcngynCtYr6QcA4/:xIwBMAghNZV68C69/jcHncnQn4/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_0bf4779a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bf4779a000a63a12e5d22ef884df612a5b9823ba69d008fa137312955eba65e"
    family = "unknown"
    file_name = "startuptest.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:20"
  condition:
    hash.sha256(0, filesize) == "0bf4779a000a63a12e5d22ef884df612a5b9823ba69d008fa137312955eba65e"
}
```

### Sample 28: `bede3630686cc90e`

| Field | Value |
|---|---|
| SHA-256 | `bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e` |
| Family label | `unknown` |
| File name | `SimpleMiner_XMR.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:22:13` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdd029dee2aed15be39de35afb848c78` |
| SHA-1 | `5302b8feea5707371e5b0ba616e1591151048951` |
| SHA-256 | `bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e` |
| SHA3-384 | `df75589ff21666a6a5969a995989c70597acc16395e80816ce5c9423bff5c1be8a2d152f27bcc929ca0eade734880200` |
| TLSH | `T1E6A302D3BF18F8A7D95F5C79C8B5E636FFB06B62A5A0C74F1B12911028A50B00DA095E` |
| SSDEEP | `1536:zZL05NUSUwBx84E4uAXQlcWrZvS00eV688DANSct9eIKRXnkijnD1LYQamKz:1JwBMAghNZV68C69/kfjhraX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_bede3630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e"
    family = "unknown"
    file_name = "SimpleMiner_XMR.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:13"
  condition:
    hash.sha256(0, filesize) == "bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e"
}
```

### Sample 29: `fbfab254dc250f89`

| Field | Value |
|---|---|
| SHA-256 | `fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794` |
| Family label | `unknown` |
| File name | `SheetCrypt.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:22:05` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `474c199ff6f0f72cc2445595a3fff96d` |
| SHA-1 | `c43dc3e9dfc223dcdafbe15684177edece78680d` |
| SHA-256 | `fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794` |
| SHA3-384 | `80950e8c6651c7fc2c0ec4aff7a5a3dd9a1525bda6ab3c07d1303dec762a6b987826d60692fd14f7d0e1c94192961954` |
| TLSH | `T1A58523AB87F97525ED31AAB6D0D16331FE776371D687A3C3169AC12D0C243AB08B50C6` |
| SSDEEP | `24576:qwmEcM28Dpn5Uoo7lZR3aubqMXfbWFMBKrUd5rhik31rGR4ESveTL/GRD8QpZRiI:OMdFalZYub4oKQ7VJ3Fjve/2wQpiBqZx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_fbfab254
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794"
    family = "unknown"
    file_name = "SheetCrypt.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:05"
  condition:
    hash.sha256(0, filesize) == "fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794"
}
```

### Sample 30: `a571605812fbd816`

| Field | Value |
|---|---|
| SHA-256 | `a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74` |
| Family label | `unknown` |
| File name | `PoletDidlo.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:56` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8447175e0c37826c2d5d8487d5272700` |
| SHA-1 | `47e4e2674b86971bbf15640d20e0da9c92194d1a` |
| SHA-256 | `a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74` |
| SHA3-384 | `7104731b7a77f9efab3ba0d92386c68b0170b6b002de9c61487576a9bfa233b9f643086c10bce54d60822490e7f4a249` |
| TLSH | `T1D5453365A7B6C14DFA1F367DFC4F1104EDC222388F39E7144C168E21847CAA5B6AAD0E` |
| SSDEEP | `24576:17KsyH4/Mk69S9nQq5iUH9vI/2rkgHyoLiqmYLLOI307ASTKLhVJHf:Zd1Xjdzc2jL+YLYAfhzf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_a5716058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74"
    family = "unknown"
    file_name = "PoletDidlo.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:56"
  condition:
    hash.sha256(0, filesize) == "a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74"
}
```

### Sample 31: `926d3c5cc0c4f93c`

| Field | Value |
|---|---|
| SHA-256 | `926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b` |
| Family label | `unknown` |
| File name | `MinvyRatClient.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:45` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45c887c11f36570a34291b4ccc7858df` |
| SHA-1 | `1ef628a54157f6963549a480b8466da39ff78b51` |
| SHA-256 | `926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b` |
| SHA3-384 | `9d8c66b543aab990fd2a0173f5c4bacc07c07644f66174aa8144ed78483bc7e1f07109de43e0c42f0c0790a427289205` |
| TLSH | `T12035239B8B9C4C3FF86FAC3A41AADF75C99136197F01C9E650418A12F63B153A3F4A44` |
| SSDEEP | `24576:hkKU0x/fG1vW4IQMxCznkkY2h4iiCDeACsrIICTtp1Vo6U4pH/GhD7rf:hkK7JG17IQMAzn62h4UVMICTth/pfGl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_926d3c5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b"
    family = "unknown"
    file_name = "MinvyRatClient.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:45"
  condition:
    hash.sha256(0, filesize) == "926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b"
}
```

### Sample 32: `db317a9cb1a5fe66`

| Field | Value |
|---|---|
| SHA-256 | `db317a9cb1a5fe669f01022e31d426240f675c3834426b23b83bcf56a5ecaa5b` |
| Family label | `unknown` |
| File name | `loader_1_2_9_3_Panel.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:35` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90fb7057bfafb8497ac9013977042565` |
| SHA-1 | `1b9e603ee29b5b596a626efae653a7ee9efcee96` |
| SHA-256 | `db317a9cb1a5fe669f01022e31d426240f675c3834426b23b83bcf56a5ecaa5b` |
| SHA3-384 | `c9e1d4490c9027d4f1dded6bf554c2581f8319c2c24aa9a5c63100ae77b6d12bab05d8e7ffd04bc82ffc51fa5b77f275` |
| TLSH | `T10DC312A6BBA4EDA6D97E9C7A8DF0D619FFB1E342D0E147970F06D21019948B40CB580F` |
| SSDEEP | `1536:/+jtMEA3Z2U5VdT6BIUwBx84E4uAXQlcWrZvS00eV688DANSct9eIYf0cdcuNOQx:WjWdJp7h6DwBMAghNZV68C69/fcqMOQx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_db317a9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db317a9cb1a5fe669f01022e31d426240f675c3834426b23b83bcf56a5ecaa5b"
    family = "unknown"
    file_name = "loader_1_2_9_3_Panel.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:35"
  condition:
    hash.sha256(0, filesize) == "db317a9cb1a5fe669f01022e31d426240f675c3834426b23b83bcf56a5ecaa5b"
}
```

### Sample 33: `50d8632433d3954b`

| Field | Value |
|---|---|
| SHA-256 | `50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701` |
| Family label | `unknown` |
| File name | `Limbo.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:29` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `532e184b94fdcc7c523c2c23bdac827d` |
| SHA-1 | `d5588c900ab5f9dfe8a2fcd394de162fd8b8e242` |
| SHA-256 | `50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701` |
| SHA3-384 | `e331aa052ad7387539d3262c352d55e3468a6a95aad3b794b7f3e888c95559f7fe23d2da6a0cb1e2f3e37daf3da66874` |
| TLSH | `T15C36336EC366AC9FF2575A344ED70620CF924F59959675DF2208F306E0F322767E2282` |
| SSDEEP | `98304:pHG0YBPOlV2WMzao22onlgNP54dylcbM7F99ZXj:AFBPOlZMjwoRZlcb6/Bj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_50d86324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701"
    family = "unknown"
    file_name = "Limbo.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:29"
  condition:
    hash.sha256(0, filesize) == "50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701"
}
```

### Sample 34: `23d668f31429fe38`

| Field | Value |
|---|---|
| SHA-256 | `23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7` |
| Family label | `unknown` |
| File name | `Eternal Hacker Panel Loader _ 1_5(fix).apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:19` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bcde3d0e2530011f65eaa18716ffd5e` |
| SHA-1 | `f4488af2339dab83dc6a97adb10547bfc38086a7` |
| SHA-256 | `23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7` |
| SHA3-384 | `6b947c22bf4934c7021281787e6c80ccd474f368e98beb955bde703ef1d12472c80b0b92b3dcee42fd0a3edc812c364b` |
| TLSH | `T1E9563312A240B52DFBA69BB48FB742B2F8360FA47455BF357329B3328173136D710A56` |
| SSDEEP | `98304:J71lak0b3t88lreBG4PQTDR3Y5XCGl5aG+280+5SwXyEOOCFwmxtrm1gJGhT:Jh0b3HeBG4IHK4GtZ5UoOM41CGhT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_23d668f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7"
    family = "unknown"
    file_name = "Eternal Hacker Panel Loader _ 1_5(fix).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:19"
  condition:
    hash.sha256(0, filesize) == "23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7"
}
```

### Sample 35: `0b47e13b4cb4d894`

| Field | Value |
|---|---|
| SHA-256 | `0b47e13b4cb4d8943f45a94f1489294f61e0715a69614bc88c195b01daae6d68` |
| Family label | `unknown` |
| File name | `Doxgram_New_1 701 (Fix).apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:09` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `894d5a8b8bc28de22969bc44c008716b` |
| SHA-1 | `2cf46e09d07d35e8373a62b7b22c705606714085` |
| SHA-256 | `0b47e13b4cb4d8943f45a94f1489294f61e0715a69614bc88c195b01daae6d68` |
| SHA3-384 | `ec5189cf498cafc2012e808fcec831ba620eb28fe554e95180f75f7cf742ba569f313d3d882b4e284f8a83ffa9eb442f` |
| TLSH | `T1849423FBD954B5A3D74E5E35F03F9E17FB79938668B58AE6086010E1C5B01A9C0CA80F` |
| SSDEEP | `6144:JxcuhN9CK/xdD5wYFx/i26Bu6VNNDBU3TqiukWk4/XZ/plhUJYWQYd+wpDmm:NhN4axd1wOx/itu0NNznlPZhIWYd+qSm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_0b47e13b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b47e13b4cb4d8943f45a94f1489294f61e0715a69614bc88c195b01daae6d68"
    family = "unknown"
    file_name = "Doxgram_New_1 701 (Fix).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:09"
  condition:
    hash.sha256(0, filesize) == "0b47e13b4cb4d8943f45a94f1489294f61e0715a69614bc88c195b01daae6d68"
}
```

### Sample 36: `86acd31a7de65743`

| Field | Value |
|---|---|
| SHA-256 | `86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0` |
| Family label | `unknown` |
| File name | `djzrjdshks.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:21:04` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d18a4bfec6e553bbc877ade088deeb1` |
| SHA-1 | `824a69c46561e246a67ed78e9d1cd426d82240a7` |
| SHA-256 | `86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0` |
| SHA3-384 | `0abeab181d69ba34186d4536d42c5b35d5f2de53877ca0070b7db861b5c1ae7b3a350eedcec92375aa38925941b5d754` |
| TLSH | `T1294402D4B74878F0C56E95BB41F82838A69D7D8E90A4DB07353E39439FF04602ECA56E` |
| SSDEEP | `3072:Jcb6J3g65Z1ihjsI915MD9kZ0rgl2/OFuT6Wl/uNwBMAghNZV68C69/sg8kohRX:DJ3TiZXfcYUY3fW9udhN9CK/THohRX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_86acd31a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0"
    family = "unknown"
    file_name = "djzrjdshks.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:04"
  condition:
    hash.sha256(0, filesize) == "86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0"
}
```

### Sample 37: `01dcbe196953883b`

| Field | Value |
|---|---|
| SHA-256 | `01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0` |
| Family label | `unknown` |
| File name | `DeltaRBX(Fix53).apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:20:58` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `333c3da130fc50a0ba6e2c06fb192be0` |
| SHA-1 | `edd54e8af648537adb00c2a725ff929209d16b67` |
| SHA-256 | `01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0` |
| SHA3-384 | `4be13c7f6f6b14e8e34a1da3c7db57afa2731e8fa152dfad8ab2d77a1f6ff2f366f81aafd500c7d69702eff77ae26337` |
| TLSH | `T19346F185F754AB2BC837913349EA5231558B4D4B8E82D7836918730C78B7AF41F9ABCC` |
| SSDEEP | `98304:H4IflWqd2Zr5WKgMPM1aLB49H42+WdCzyxkAi11t+9ehX6riBOQ7WHWSB:YqlkG1ay6cC1g4CiWB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_01dcbe19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
    family = "unknown"
    file_name = "DeltaRBX(Fix53).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:20:58"
  condition:
    hash.sha256(0, filesize) == "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
}
```

### Sample 38: `590c3fd1f5355493`

| Field | Value |
|---|---|
| SHA-256 | `590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f` |
| Family label | `unknown` |
| File name | `apktool_1_0.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:20:48` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89d84449956abd71561184417393e44f` |
| SHA-1 | `c3ad4c45053435fb82066ceab69ab6b340659543` |
| SHA-256 | `590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f` |
| SHA3-384 | `fbcc7160d3e7b905a84181d90a7ff77522e2a5dd0fca9f11960e8521d4cdac71dbd01809083e98e0fb57e06036c6390b` |
| TLSH | `T1A8B302E2AB44DC9BCE6F58B5C8F8E436FFE3636280F0DB0B1A1291215D955F108A112F` |
| SSDEEP | `1536:BGvFCdJeUwBx84E4uAXQlcWrZvS00eV688DANSct9eITxhwUDLRak:BGqwBMAghNZV68C69/Tnwy4k` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_590c3fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f"
    family = "unknown"
    file_name = "apktool_1_0.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:20:48"
  condition:
    hash.sha256(0, filesize) == "590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f"
}
```

### Sample 39: `11ef87f842857ace`

| Field | Value |
|---|---|
| SHA-256 | `11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415` |
| Family label | `unknown` |
| File name | `AndUnlocker1_0.apk` |
| File type | `apk` |
| First seen | `2026-06-27 01:20:43` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bac8f69369e72bb70be3aaa67b75739` |
| SHA-1 | `0e78e30d92e4e910b497b135da9d20d1fad49612` |
| SHA-256 | `11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415` |
| SHA3-384 | `ad3c31de91464734ee7a12143f3629a96494682eeb2467bcaaf51a537eba109830ddc29548985325b251ac47d1b3f311` |
| TLSH | `T10616E089BB48AB2FC477543345E65236614B4D4B8E83D6836868720C79B7AF40F5EFC8` |
| SSDEEP | `98304:MMPd2ZrM4XKgMPM1aLB49H42+WdCzyxkAi11t+9ehX69j:MGG1ay6cC1g4Kj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_11ef87f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
    family = "unknown"
    file_name = "AndUnlocker1_0.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:20:43"
  condition:
    hash.sha256(0, filesize) == "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
}
```

### Sample 40: `28955cde4d05589d`

| Field | Value |
|---|---|
| SHA-256 | `28955cde4d05589d984605220f120878154bc081f95ed5c982baf976dd83c4da` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-27 01:00:18` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5472d990d2211e81c63c1e0458b29943` |
| SHA-1 | `ab408dc389146220c4fdca56e2d47394386c570d` |
| SHA-256 | `28955cde4d05589d984605220f120878154bc081f95ed5c982baf976dd83c4da` |
| SHA3-384 | `510e3f9864db869e2893437dfdbaad48ddcb7363e4dcae135152640d8896acb77d6ccfa159efa8c1a3ef7986a81112f8` |
| IMPHASH | `23db922d0730904371b565e7673258af` |
| TLSH | `T144A6F67B2263C168C11EA23EC4DACF40B5F373B91FF2C1E7429147696B559C1AD7AA20` |
| SSDEEP | `49152:mshpAfs/ryRxY03kjzpalshD0SuZFGBT3vrRoeowspRdN+dWnYqBOaTkjMKdIgAX:i1F+oeodcMKdICVNW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_28955cde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28955cde4d05589d984605220f120878154bc081f95ed5c982baf976dd83c4da"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 01:00:18"
  condition:
    hash.sha256(0, filesize) == "28955cde4d05589d984605220f120878154bc081f95ed5c982baf976dd83c4da"
}
```

### Sample 41: `b18cf21b9e159b07`

| Field | Value |
|---|---|
| SHA-256 | `b18cf21b9e159b07778aad026f369c39bc24c4b221b9c9383497942cecbdc6d2` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-06-27 00:53:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71277d67e9a936e997a57827a57080df` |
| SHA-1 | `b421f1919a9453b848d1e1eda8b53880f165d50f` |
| SHA-256 | `b18cf21b9e159b07778aad026f369c39bc24c4b221b9c9383497942cecbdc6d2` |
| SHA3-384 | `6c7ee9c96b9ca728b7f039d4d500afdd54e068f98ce9dd460848415229aebd258186eebddc42001167bcf2cabe7ff910` |
| TLSH | `T16401ABCAC460A800419ADA5C36A76154F420C3CF164A8F76BFAC6D2EEB84D04B026FA4` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkarf8CopN17CLayBeXCRO6COpmCyVbjT6X:kXCKysE2hi0ziQvZoharEb4cuH4YX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_b18cf21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b18cf21b9e159b07778aad026f369c39bc24c4b221b9c9383497942cecbdc6d2"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-06-27 00:53:19"
  condition:
    hash.sha256(0, filesize) == "b18cf21b9e159b07778aad026f369c39bc24c4b221b9c9383497942cecbdc6d2"
}
```

### Sample 42: `bca3e5ca3be21f84`

| Field | Value |
|---|---|
| SHA-256 | `bca3e5ca3be21f841fb6f5e1bd8c0bac3850a68cdd517059783978f879b5e669` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-06-27 00:19:15` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35ade1b85d2f4a3563622625c1af0862` |
| SHA-1 | `1f94f56c37691f19ca57090f93a5ff764533baf9` |
| SHA-256 | `bca3e5ca3be21f841fb6f5e1bd8c0bac3850a68cdd517059783978f879b5e669` |
| SHA3-384 | `9e6fc3c63cc7e41823d6ca14cf126b7b923f053ffbc01d59359d65f058d6ec2223c68693896a4e9c6d44ca2abd651412` |
| TLSH | `T1CED05EA2A57312F420669914F2A2A800B115876E4C8A865DBA4B38B45E8834AF1D16D2` |
| SSDEEP | `6:hTCYUDtvqu6teuFAulNXYq9DG+NjVsNXYrkJ:VCpvq64Piq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_bca3e5ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca3e5ca3be21f841fb6f5e1bd8c0bac3850a68cdd517059783978f879b5e669"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-27 00:19:15"
  condition:
    hash.sha256(0, filesize) == "bca3e5ca3be21f841fb6f5e1bd8c0bac3850a68cdd517059783978f879b5e669"
}
```

### Sample 43: `de138420498fbfad`

| Field | Value |
|---|---|
| SHA-256 | `de138420498fbfad575b7c47f0eb80b5196d3741e1344b2d11468ad945e2c7ec` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-27 00:09:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b8ba0109a86adf7dc8a6374826d2a1d` |
| SHA-1 | `c599e4a3b9ac56a0c7eefd8217527f8e60cb7c75` |
| SHA-256 | `de138420498fbfad575b7c47f0eb80b5196d3741e1344b2d11468ad945e2c7ec` |
| SHA3-384 | `4494edd2d4e5c44a54f24da9ca7479ed81a2063390d872d2472d951d10a82f3392fda38089b7f2360a63fea173e1a7cc` |
| TLSH | `T1C0535F1E2E618FADF76C873547B74E21B24823D216E2C601D15DEA015EA034EB85FBBD` |
| TELFHASH | `t1e7f0175c493812f0d3865c9dbbedff79d45580ee4a666e378d00e8afeb219468c01d2c` |
| SSDEEP | `768:0x+8cEhesDsXopQiQpPs4Z49/WSsGKYD8U/7c6wMi1/GICFGf20bxAJTbUdwbZn/:0xNhe9T9pkzlBgUot3GInwbUdwbZn/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_de138420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de138420498fbfad575b7c47f0eb80b5196d3741e1344b2d11468ad945e2c7ec"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-27 00:09:06"
  condition:
    hash.sha256(0, filesize) == "de138420498fbfad575b7c47f0eb80b5196d3741e1344b2d11468ad945e2c7ec"
}
```

### Sample 44: `8da466b43acd48b6`

| Field | Value |
|---|---|
| SHA-256 | `8da466b43acd48b67e37d1acb3944d966f45bef9658c835d983d2d2017ee7921` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 23:54:32` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX4.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f98ff4f205de5b49d3714b1114a066b` |
| SHA-1 | `7c07949a68c4104c13a1095ae856f026bed131e1` |
| SHA-256 | `8da466b43acd48b67e37d1acb3944d966f45bef9658c835d983d2d2017ee7921` |
| SHA3-384 | `346a904484c49299b4b510bcc18684fd689e63943df5d3c01c30913c0c70068ec9211ba3c7deca721571791688199b7e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16BE57B07BDE008E9C0AAA33189B6965A7B75BC490F3227D72E50B7B82F763D05D35B14` |
| SSDEEP | `49152:c1NYdPqmN6tlROByDMpz/R2TU2nfh6Fqk5/3Y+9Fg3oTqb:cUcG2TU2fkFqkJ3YTb` |
| ICON-DHASH | `e4b3ccd46c36935a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_8da466b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8da466b43acd48b67e37d1acb3944d966f45bef9658c835d983d2d2017ee7921"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 23:54:32"
  condition:
    hash.sha256(0, filesize) == "8da466b43acd48b67e37d1acb3944d966f45bef9658c835d983d2d2017ee7921"
}
```

### Sample 45: `576f3ff7e34e66f6`

| Field | Value |
|---|---|
| SHA-256 | `576f3ff7e34e66f6298efbb5b9ccda4d2c27adeb9040ba9c85012c9f555f2d4f` |
| Family label | `RustyStealer` |
| File name | `SecuriteInfo.com.Trojan.GenericKD.80634618.26841.10932` |
| File type | `exe` |
| First seen | `2026-06-26 23:48:23` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fc4a02f1bbb142af490bb2d0d046cdf` |
| SHA-1 | `c8ade7c35ea5723eeef0d517fbbda2e8847f6479` |
| SHA-256 | `576f3ff7e34e66f6298efbb5b9ccda4d2c27adeb9040ba9c85012c9f555f2d4f` |
| SHA3-384 | `62704c4ef9bae831febaad8e62d80eaff0803b7a6eb223670115511b76f520bb3f55c3352b846295c1b81fd31bfc510d` |
| IMPHASH | `532cc1f671bb30c461b49580820593c1` |
| TLSH | `T13E863302717614F8E66BC138D3499B529B36309D0F364EFF225516282F36BE92D39F98` |
| SSDEEP | `196608:N2ZxifyYl4j7L+iwJ7/8aRYJ+YVttiq6fIF8+SJDMIFgW:mx+Xl07twJ7/LY58TIF8+SpMA` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_045_576f3ff7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576f3ff7e34e66f6298efbb5b9ccda4d2c27adeb9040ba9c85012c9f555f2d4f"
    family = "RustyStealer"
    file_name = "SecuriteInfo.com.Trojan.GenericKD.80634618.26841.10932"
    file_type = "exe"
    first_seen = "2026-06-26 23:48:23"
  condition:
    hash.sha256(0, filesize) == "576f3ff7e34e66f6298efbb5b9ccda4d2c27adeb9040ba9c85012c9f555f2d4f"
}
```

### Sample 46: `795dc62407f9db38`

| Field | Value |
|---|---|
| SHA-256 | `795dc62407f9db38cf3aa0f70313c14776e2c8d656b5c6ca859bc0b346a204f9` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 22:49:13` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2af7fda2a30959173439302db23a1c5` |
| SHA-1 | `d89316c61ccbfabf695f792f94632b100db27aa2` |
| SHA-256 | `795dc62407f9db38cf3aa0f70313c14776e2c8d656b5c6ca859bc0b346a204f9` |
| SHA3-384 | `c9a096b15d1eef16f04e7adb54d92da1ea3e566f6670a9dcf3a21cdd69f6e8606d57e2d77d954ace597dd54d823cb441` |
| IMPHASH | `a44f295602e9f29bcf58a82a297b8b1e` |
| TLSH | `T186863311B95592F8D016C0B447898FB16D36B8A15F76A3AF0261437C1E3EFEA5F39E20` |
| SSDEEP | `196608:F8MO33oRamROWoze0/mkZG5nYXUw/+raDnCKK77KqZy6j76N:+v33EOWozvrjXxaabCV77TfP6` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_046_795dc624
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795dc62407f9db38cf3aa0f70313c14776e2c8d656b5c6ca859bc0b346a204f9"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 22:49:13"
  condition:
    hash.sha256(0, filesize) == "795dc62407f9db38cf3aa0f70313c14776e2c8d656b5c6ca859bc0b346a204f9"
}
```

### Sample 47: `5b834b5dd162fe16`

| Field | Value |
|---|---|
| SHA-256 | `5b834b5dd162fe166bd4bf2d4b41515e4b7a902566b39905c9d8cc1f89a742b8` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-26 22:37:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f64e532da7b7571b2990dae8d7d5212b` |
| SHA-1 | `8080ff4a0881be026cbbcfb8bfeddb6e62ba9c4b` |
| SHA-256 | `5b834b5dd162fe166bd4bf2d4b41515e4b7a902566b39905c9d8cc1f89a742b8` |
| SHA3-384 | `0c4448ed71ac4ae30f4aff23a769fd546ff95ba8bc1d88ca28b76fe14b35c506e64f962f1d9a315b1596a3513fbb1805` |
| TLSH | `T1F523F981BD829917CAD84377FA0E42CD372573C8E2ED7227DD226F11B7CA52B096B161` |
| TELFHASH | `t132d0a731769913e436c4040a9984eb1f6b49715955464d4467821b9d5f5bd112516930` |
| SSDEEP | `768:NuPLlmwT3+tW2u0t51oM5y6w+sEdp+9wnDX2FGXo1XuTCt1o1Nfyt9wfC0wbZn:4TlmA3+tW2u0t5aGs+BnDmgo1Xno1xpe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_5b834b5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b834b5dd162fe166bd4bf2d4b41515e4b7a902566b39905c9d8cc1f89a742b8"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-26 22:37:11"
  condition:
    hash.sha256(0, filesize) == "5b834b5dd162fe166bd4bf2d4b41515e4b7a902566b39905c9d8cc1f89a742b8"
}
```

### Sample 48: `2e86f0c9eac76638`

| Field | Value |
|---|---|
| SHA-256 | `2e86f0c9eac76638eec0a2d7c85ab569d2a012e94f44b7a6a54d0061e6834f22` |
| Family label | `unknown` |
| File name | `prefetch_9103.bat` |
| File type | `unknown` |
| First seen | `2026-06-26 22:35:03` |
| Reporter | `BastianHein_` |
| Tags | `Dropped` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93447c9e4c5345572e9e33941ab7a798` |
| SHA-256 | `2e86f0c9eac76638eec0a2d7c85ab569d2a012e94f44b7a6a54d0061e6834f22` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_2e86f0c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e86f0c9eac76638eec0a2d7c85ab569d2a012e94f44b7a6a54d0061e6834f22"
    family = "unknown"
    file_name = "prefetch_9103.bat"
    file_type = "unknown"
    first_seen = "2026-06-26 22:35:03"
  condition:
    hash.sha256(0, filesize) == "2e86f0c9eac76638eec0a2d7c85ab569d2a012e94f44b7a6a54d0061e6834f22"
}
```

### Sample 49: `90a4100a7cd32dc4`

| Field | Value |
|---|---|
| SHA-256 | `90a4100a7cd32dc4581cc636b6c06ce6caa2ff632e4319b7ce9027aab100a021` |
| Family label | `unknown` |
| File name | `cacherelay93.dat` |
| File type | `unknown` |
| First seen | `2026-06-26 22:31:59` |
| Reporter | `BastianHein_` |
| Tags | `Dropped` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66fd6a8388bb340357bd643e0f28f5fd` |
| SHA-256 | `90a4100a7cd32dc4581cc636b6c06ce6caa2ff632e4319b7ce9027aab100a021` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_90a4100a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90a4100a7cd32dc4581cc636b6c06ce6caa2ff632e4319b7ce9027aab100a021"
    family = "unknown"
    file_name = "cacherelay93.dat"
    file_type = "unknown"
    first_seen = "2026-06-26 22:31:59"
  condition:
    hash.sha256(0, filesize) == "90a4100a7cd32dc4581cc636b6c06ce6caa2ff632e4319b7ce9027aab100a021"
}
```

### Sample 50: `1cdd76661e2b39c3`

| Field | Value |
|---|---|
| SHA-256 | `1cdd76661e2b39c39e2e6e52210c5f3bdc14ac0d62857583e4f4cae423ccf960` |
| Family label | `Gafgyt` |
| File name | `x-3.2-.Sakura` |
| File type | `elf` |
| First seen | `2026-06-26 22:11:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37bc2c1f2698fbf9747006007a2ee0d5` |
| SHA-1 | `3a608105323971eb3f6fda703565513e53b8fe0b` |
| SHA-256 | `1cdd76661e2b39c39e2e6e52210c5f3bdc14ac0d62857583e4f4cae423ccf960` |
| SHA3-384 | `1431bd87435af9e63deaf26d8690d3f905b8da01846d0c45edec821b929be3f1923d03c99df91bc66290d5e0437c2ccb` |
| TLSH | `T13E932B46F743C6B3C8431BB10297AA690931F97A0A2E9F4AF31D3CF4AB134D97116B56` |
| TELFHASH | `t16721ee0271eaca296bb356246cb847f116966a233391be71bf1dc4c494370027974ecb` |
| SSDEEP | `1536:MrOiwR1lgnK1qWuMOWJ+a5MZ/0uVMmubDqg1O6RxPmmq+P0Gz+JwLfvKm:MrURcKthOWJN5MRFeHbFBxPmmJP0Gz+y` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_050_1cdd7666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cdd76661e2b39c39e2e6e52210c5f3bdc14ac0d62857583e4f4cae423ccf960"
    family = "Gafgyt"
    file_name = "x-3.2-.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:11:13"
  condition:
    hash.sha256(0, filesize) == "1cdd76661e2b39c39e2e6e52210c5f3bdc14ac0d62857583e4f4cae423ccf960"
}
```

### Sample 51: `8016af3ff04c12e7`

| Field | Value |
|---|---|
| SHA-256 | `8016af3ff04c12e7c43a36aa11dce4fdd6fedc171b2e069bf625ab144f44063f` |
| Family label | `Gafgyt` |
| File name | `a-r.m-4.Sakura` |
| File type | `elf` |
| First seen | `2026-06-26 22:11:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c044c9606a6c263d32d0e3545317b0d9` |
| SHA-1 | `56cc7f23f1225df43c350447eb11fdf70efcb988` |
| SHA-256 | `8016af3ff04c12e7c43a36aa11dce4fdd6fedc171b2e069bf625ab144f44063f` |
| SHA3-384 | `d297795b9fc5ed8bc0d000c8e2e10817cdbcd9dafbf26701bfdfea20100bdd85ac5b8040e6e5e46655894fe237321b34` |
| TLSH | `T1A2C30A44F941872BC2E327BAE78E438D3B355A9497DB332569386EF42FC17982D29530` |
| TELFHASH | `t1b3210d0371faca292bb356346cb842f112956a233391be71bf1dc4c494370027974ecb` |
| SSDEEP | `3072:0mTe1c/r2e7rC8fVhhin3b0BPz5bNmbAAQVhPRtXJfo:j/r2e7rjfBinGrmbAAQVhPRtXJfo` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_051_8016af3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8016af3ff04c12e7c43a36aa11dce4fdd6fedc171b2e069bf625ab144f44063f"
    family = "Gafgyt"
    file_name = "a-r.m-4.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:11:11"
  condition:
    hash.sha256(0, filesize) == "8016af3ff04c12e7c43a36aa11dce4fdd6fedc171b2e069bf625ab144f44063f"
}
```

### Sample 52: `588da75109cfc5a8`

| Field | Value |
|---|---|
| SHA-256 | `588da75109cfc5a82d79b7433218e0a891e7e987d0ab30549a348dcacc029b5a` |
| Family label | `Gafgyt` |
| File name | `x-8.6-.Sakura` |
| File type | `elf` |
| First seen | `2026-06-26 22:10:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ae65d11269d3c5291111c042e52b4b9` |
| SHA-1 | `5325beddc072ba188325748c88b5d43932ac88c3` |
| SHA-256 | `588da75109cfc5a82d79b7433218e0a891e7e987d0ab30549a348dcacc029b5a` |
| SHA3-384 | `a609948a33fbd13c8160e374c8fbac8540a42ef87769e664fff7f918e246076d855832e77d7d7dd35947c21b8fd4f720` |
| TLSH | `T11FA33927B242C6BFC08752B52BDB99A19473B8F81B32721B73D47DB52B168C92D19B01` |
| TELFHASH | `t16721ee0271eaca296bb356246cb847f116966a233391be71bf1dc4c494370027974ecb` |
| SSDEEP | `3072:0t9+V3oPXrtxswdkMjhMnficLwNhaOflUmrxppXFZYZrgo:4PXRXkM2fx2a7mrxppXFZYZrgo` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_052_588da751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "588da75109cfc5a82d79b7433218e0a891e7e987d0ab30549a348dcacc029b5a"
    family = "Gafgyt"
    file_name = "x-8.6-.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:09"
  condition:
    hash.sha256(0, filesize) == "588da75109cfc5a82d79b7433218e0a891e7e987d0ab30549a348dcacc029b5a"
}
```

### Sample 53: `ceade2e6f3cc9417`

| Field | Value |
|---|---|
| SHA-256 | `ceade2e6f3cc94173e8f6a7b065f359328dfcde8dd3931beeb26822627cd343a` |
| Family label | `Gafgyt` |
| File name | `s-h.4-.Sakura` |
| File type | `elf` |
| First seen | `2026-06-26 22:10:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `402cb10e41e496fa617e839663ef9925` |
| SHA-1 | `e96bc849a58ed58458504c2808d29a082910aba5` |
| SHA-256 | `ceade2e6f3cc94173e8f6a7b065f359328dfcde8dd3931beeb26822627cd343a` |
| SHA3-384 | `a373a4e9f343b61e4d21e40db9b603e33c84dc0573706542d0338bf3e151d14570a438b8e9fdc9d5af21d483dcdef3ef` |
| TLSH | `T132A33947B9619FB3C0829AB565FB4A304713E8955F4F2A5A31785AF4034F4DEB80EF24` |
| TELFHASH | `t1da210d0371faca292bb355346cb842f112956a233391be71bf1ec4c494370027974ecb` |
| SSDEEP | `3072:6f2QPyhYfaTzpTX6dblcxTP4/mzK0POjBfk9o:42Q6mszpDsc9w/mzK0POjBfk9o` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_053_ceade2e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceade2e6f3cc94173e8f6a7b065f359328dfcde8dd3931beeb26822627cd343a"
    family = "Gafgyt"
    file_name = "s-h.4-.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:07"
  condition:
    hash.sha256(0, filesize) == "ceade2e6f3cc94173e8f6a7b065f359328dfcde8dd3931beeb26822627cd343a"
}
```

### Sample 54: `9dd42a8f746ee23c`

| Field | Value |
|---|---|
| SHA-256 | `9dd42a8f746ee23cca69f4b1471117906c3a2868cf4e8a247b0cb39869146f21` |
| Family label | `Gafgyt` |
| File name | `m-p.s-l.Sakura` |
| File type | `elf` |
| First seen | `2026-06-26 22:10:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33feba392bb39657a51b0ff3cfcc2c15` |
| SHA-1 | `d79f79b9c90ec3fdfc51d0955762dba379ec4545` |
| SHA-256 | `9dd42a8f746ee23cca69f4b1471117906c3a2868cf4e8a247b0cb39869146f21` |
| SHA3-384 | `a6498392ee8432063c0037e66162082577791daa8a8b3b3301d866f86cc7e1e6ab4b834f59d7784501fea0f507e2cab2` |
| TLSH | `T188E3965ABB619EB7DC1ECE33069A5502118CE58612E96F6FB2B4C52CF74B84F08E3C54` |
| TELFHASH | `t1a9210d4371faca292bb356346cb842f112956a233391be71bf1dc5c494370027974ecb` |
| SSDEEP | `1536:vPeTGez2Dd/4lJHKEWMko6Md3jNMZgH+spYOBLFrxLFgMWmMkdVcG1DKW01so:v8z2DYpR68Mqn1F1JgfmMOVcG1DJ01so` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_054_9dd42a8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd42a8f746ee23cca69f4b1471117906c3a2868cf4e8a247b0cb39869146f21"
    family = "Gafgyt"
    file_name = "m-p.s-l.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:06"
  condition:
    hash.sha256(0, filesize) == "9dd42a8f746ee23cca69f4b1471117906c3a2868cf4e8a247b0cb39869146f21"
}
```

### Sample 55: `f443b4c302cc5f9b`

| Field | Value |
|---|---|
| SHA-256 | `f443b4c302cc5f9b0b97bd8636c93a12eb21674cfbac2711e8f23b02664d149a` |
| Family label | `Gafgyt` |
| File name | `a-r.m-5.Sakura` |
| File type | `elf` |
| First seen | `2026-06-26 22:10:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f459004b0f0cfff6cbbf6162272a36f5` |
| SHA-1 | `88e4413fc5c596e1da817665d6cf8fa0c62618a2` |
| SHA-256 | `f443b4c302cc5f9b0b97bd8636c93a12eb21674cfbac2711e8f23b02664d149a` |
| SHA3-384 | `bebfcea7953923503d1e29c3a15d5a9cbad7eec97d88cc1ff72b63193b927cd141702071e33e438aa2ffd1b5d2cd30eb` |
| TLSH | `T1B8B32A44F8418B6BC3D327BAE7CE478D3B315A9457DB33116A38AEF42BC17992D29520` |
| TELFHASH | `t1b3210d0371faca292bb356346cb842f112956a233391be71bf1dc4c494370027974ecb` |
| SSDEEP | `3072:ghRUKoPkU2/dNFRwH+BxhwnT7V6mVJTQwOPHCXQ3o:gIkU2/dzKeBLwnfV6mVJTQwOPHCXQ3o` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_055_f443b4c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f443b4c302cc5f9b0b97bd8636c93a12eb21674cfbac2711e8f23b02664d149a"
    family = "Gafgyt"
    file_name = "a-r.m-5.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:05"
  condition:
    hash.sha256(0, filesize) == "f443b4c302cc5f9b0b97bd8636c93a12eb21674cfbac2711e8f23b02664d149a"
}
```

### Sample 56: `7fd2a7e4824e8865`

| Field | Value |
|---|---|
| SHA-256 | `7fd2a7e4824e8865bfc506cd3895719ff68d082910b619917fd09941ab96542a` |
| Family label | `unknown` |
| File name | `Check.wsf` |
| File type | `wsf` |
| First seen | `2026-06-26 22:06:28` |
| Reporter | `BastianHein_` |
| Tags | `Dropped, wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc2bd784448979a036a7e9e9a8db02c6` |
| SHA-1 | `ab0e7ab2806f9c2df4e42520c6cb995e63621d1c` |
| SHA-256 | `7fd2a7e4824e8865bfc506cd3895719ff68d082910b619917fd09941ab96542a` |
| SHA3-384 | `eadc7985238b723b0144168edff5aede45753895dc6403f11d739ed352e56971287fe3d1bddc993dfa49fb2bd7976a22` |
| TLSH | `T12542B98F604F52F989FBCB636906ED79D23C411392601404784DC1A70FB6BE6927A6FC` |
| SSDEEP | `96:obFCybiC4bFCpbFCpbFCpbFCpbFCpbFCpbFCXlYdJj/DP8x7TzMa/RUhRO0G6ini:2OJXPKYa/RSHinAdLjcgqJQP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_7fd2a7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fd2a7e4824e8865bfc506cd3895719ff68d082910b619917fd09941ab96542a"
    family = "unknown"
    file_name = "Check.wsf"
    file_type = "wsf"
    first_seen = "2026-06-26 22:06:28"
  condition:
    hash.sha256(0, filesize) == "7fd2a7e4824e8865bfc506cd3895719ff68d082910b619917fd09941ab96542a"
}
```

### Sample 57: `aba53ac926aec982`

| Field | Value |
|---|---|
| SHA-256 | `aba53ac926aec982a32be2012d84e931a4499d8bbc5c5c652fe3928c1132c134` |
| Family label | `unknown` |
| File name | `files.cab` |
| File type | `cab` |
| First seen | `2026-06-26 22:06:11` |
| Reporter | `BastianHein_` |
| Tags | `cab, Dropped` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23179b38e5f7f63cd8962aa335f9ed74` |
| SHA-1 | `3c080bfa2d5ff741b6ab42e8f7eac16251e312d4` |
| SHA-256 | `aba53ac926aec982a32be2012d84e931a4499d8bbc5c5c652fe3928c1132c134` |
| SHA3-384 | `e9598efa89b844385cacbd94f060eb2f1a4554112dbc39ffa72a69cfe8ac88478f56d0c9d214db19aecd3efdf5edc951` |
| TLSH | `T1C4B6339B67BD8C7BE3999C35883706C9AA21F308B74502C6374DD8AFACD211D79A5D30` |
| SSDEEP | `196608:G5LmCKBWJxONXVy2SxI4BYU1gVw0gSHC7JwMPBkCE8i1msP3n4uFZEOhExaD:G5L/UVyfxBBYU1WwtSUPy8iN/HyaD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `cab`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_aba53ac9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba53ac926aec982a32be2012d84e931a4499d8bbc5c5c652fe3928c1132c134"
    family = "unknown"
    file_name = "files.cab"
    file_type = "cab"
    first_seen = "2026-06-26 22:06:11"
  condition:
    hash.sha256(0, filesize) == "aba53ac926aec982a32be2012d84e931a4499d8bbc5c5c652fe3928c1132c134"
}
```

### Sample 58: `722cd9ed22abf487`

| Field | Value |
|---|---|
| SHA-256 | `722cd9ed22abf4871c76f928fde01ee5b649905765afdce51f6e56bad1d757ea` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 21:55:45` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a30a24b3c6dc7c581c964840c3ea0d40` |
| SHA-1 | `3f1d08bb570aa77b31cf560928f39c5640a53990` |
| SHA-256 | `722cd9ed22abf4871c76f928fde01ee5b649905765afdce51f6e56bad1d757ea` |
| SHA3-384 | `58d99f600c3d47e8762178572f6c8c2a67a7df6cc935ec1262aa553f469f80db5063992a89ec5929e29b9b0dad8e7f2e` |
| IMPHASH | `6929002bee55502723db77da3b156a93` |
| TLSH | `T11856E103E5F78EF4C21BE67D46629332AD2474881E32B11C6995F36B5FE0938A19DB70` |
| SSDEEP | `98304:NENOtZdFHNxZemy4hjcnjHJuuoUZYV6jPQ9+A5VRg7h4guEiAcmt+jInErzvR/KS:s+Zvdemyhjpu6a67buEjcmUInErzvF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_058_722cd9ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "722cd9ed22abf4871c76f928fde01ee5b649905765afdce51f6e56bad1d757ea"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:55:45"
  condition:
    hash.sha256(0, filesize) == "722cd9ed22abf4871c76f928fde01ee5b649905765afdce51f6e56bad1d757ea"
}
```

### Sample 59: `be31cb864127a723`

| Field | Value |
|---|---|
| SHA-256 | `be31cb864127a72378b5eb989a68f4ef52b2f09430170fd1d4d090f272d2235e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 21:53:56` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd10dad714d3276dc8bb6237152ee9cf` |
| SHA-1 | `ed96ae506eb4cdb1f919c68b0af2da83c214d60c` |
| SHA-256 | `be31cb864127a72378b5eb989a68f4ef52b2f09430170fd1d4d090f272d2235e` |
| SHA3-384 | `ad4f0158a1b25370bc375ab29cbe1d7be24348bb7afac55a0918f23f401498a8f3b80f665f62ce458b9f27792c053c30` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T122F58C07BCE158E9C0AAA33188B651AA7B75BC490F3127D72E90B7782F727D05D36B14` |
| SSDEEP | `49152:C8H4Duxz/ahCWND8TjrA/n+OfjOdJ5HREzKHf3tvsW0eX3tvns83QYhRbq5J2BV:CB4A/dOlHRbHf9BlnP3Qrs3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_be31cb86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be31cb864127a72378b5eb989a68f4ef52b2f09430170fd1d4d090f272d2235e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:53:56"
  condition:
    hash.sha256(0, filesize) == "be31cb864127a72378b5eb989a68f4ef52b2f09430170fd1d4d090f272d2235e"
}
```

### Sample 60: `dba680270005c06d`

| Field | Value |
|---|---|
| SHA-256 | `dba680270005c06d212e4a5f5d632f363f563c9d0c00bafc7c1a43ec2de17f48` |
| Family label | `unknown` |
| File name | `DVSKZy.vbs` |
| File type | `vbs` |
| First seen | `2026-06-26 21:47:49` |
| Reporter | `BastianHein_` |
| Tags | `Dropped, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f56871b9b70e1d23cc87999ba25de8b` |
| SHA-1 | `8da4f992296c82e3afe5df287607ed74c8d4ee0b` |
| SHA-256 | `dba680270005c06d212e4a5f5d632f363f563c9d0c00bafc7c1a43ec2de17f48` |
| SHA3-384 | `9df7051cdc420e3b99b9cd3e1cdaa8111044fb176264a8abf8920e7d31d4acc7b8a7ef711d755618094e4046a690c4de` |
| TLSH | `T11AE0E56ADA1DD553E63E89603C6B0B257CE6C89D8CA1E8D44014E1FB22D48917A9852F` |
| SSDEEP | `12:LV3dJrgPmzpmv3kvRHd431+3s3ptGadb9TAtZn:L1LDov3YHK3w3s3TGax9TAv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_dba68027
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba680270005c06d212e4a5f5d632f363f563c9d0c00bafc7c1a43ec2de17f48"
    family = "unknown"
    file_name = "DVSKZy.vbs"
    file_type = "vbs"
    first_seen = "2026-06-26 21:47:49"
  condition:
    hash.sha256(0, filesize) == "dba680270005c06d212e4a5f5d632f363f563c9d0c00bafc7c1a43ec2de17f48"
}
```

### Sample 61: `5a478e3305d575eb`

| Field | Value |
|---|---|
| SHA-256 | `5a478e3305d575ebd2e29ec4bc8c5981c7e5abdaa717cd3a694b2637323516c3` |
| Family label | `unknown` |
| File name | `hFObmbDTio.js` |
| File type | `js` |
| First seen | `2026-06-26 21:47:33` |
| Reporter | `BastianHein_` |
| Tags | `Dropped, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `950e2246d5e9c966e57cdf6cad96e21e` |
| SHA-1 | `8b77f1b4ecdd1db1089bb86ff3681c12054b71e4` |
| SHA-256 | `5a478e3305d575ebd2e29ec4bc8c5981c7e5abdaa717cd3a694b2637323516c3` |
| SHA3-384 | `8128b4b930e864a491d82fbd922c4629cf916e340ff31f7209b67693b42701e5f5c69770a39bf4509c4312cec7ac37f9` |
| TLSH | `T14484F12193D17C84114B8FA3B71AE3E8EF0F3F3C7194099BC1187D64AAAD61C9994B76` |
| SSDEEP | `6144:TSR3GUrNcqwjgODj6sixBqh2Bo/rRlukQh6espJsxiKTn4OlgoASiMG:TSZGUrNWjfj6sixBqh2BoTRlujGs0KTa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_5a478e33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a478e3305d575ebd2e29ec4bc8c5981c7e5abdaa717cd3a694b2637323516c3"
    family = "unknown"
    file_name = "hFObmbDTio.js"
    file_type = "js"
    first_seen = "2026-06-26 21:47:33"
  condition:
    hash.sha256(0, filesize) == "5a478e3305d575ebd2e29ec4bc8c5981c7e5abdaa717cd3a694b2637323516c3"
}
```

### Sample 62: `903eb1ce068f0d66`

| Field | Value |
|---|---|
| SHA-256 | `903eb1ce068f0d66a2215086b5d1aff18c8472833b74dad47bc5f388aaf21ca3` |
| Family label | `unknown` |
| File name | `bPQHHcxgbPUbB.js` |
| File type | `js` |
| First seen | `2026-06-26 21:47:10` |
| Reporter | `BastianHein_` |
| Tags | `Dropped, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `508a2d8b4edcdeac5ce9822d61182952` |
| SHA-1 | `69ab0cb4f0966683efe4448790b64a5528fb5b19` |
| SHA-256 | `903eb1ce068f0d66a2215086b5d1aff18c8472833b74dad47bc5f388aaf21ca3` |
| SHA3-384 | `fc8a3105d50a052cc9250868dbedeeec21710e9f5f4ab178f68f1cefe87fc25c207a5849fb93f88d4f71352881811374` |
| TLSH | `T1B485AFCDA48F74D4B8E587F16BDA7F6BC5AB10E32C81FD0E702092744E04579AB9E819` |
| SSDEEP | `49152:QlvAC7pRcb25oXRKoV8KQWMmrsyUE7Li+ZdCD4:L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_903eb1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "903eb1ce068f0d66a2215086b5d1aff18c8472833b74dad47bc5f388aaf21ca3"
    family = "unknown"
    file_name = "bPQHHcxgbPUbB.js"
    file_type = "js"
    first_seen = "2026-06-26 21:47:10"
  condition:
    hash.sha256(0, filesize) == "903eb1ce068f0d66a2215086b5d1aff18c8472833b74dad47bc5f388aaf21ca3"
}
```

### Sample 63: `8e730cdde5708b27`

| Field | Value |
|---|---|
| SHA-256 | `8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187` |
| Family label | `unknown` |
| File name | `8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187` |
| File type | `elf` |
| First seen | `2026-06-26 21:46:02` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8116bbec6de3e9fe349fed0d0396d663` |
| SHA-1 | `0c7b61989e17f1c9e364ab887e9f5f2f5b62b2eb` |
| SHA-256 | `8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187` |
| SHA3-384 | `0c37bdf76866dbd488f8dc61087eaa181e86a25526038de7a429aed609094de4a1a09d576aff2fe1601c39decaf60518` |
| TLSH | `T15457DF7792067CEDE9B94DB4C41015816DA878874778A3C7BAC8B0F666EB6D08D3E730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ4:cqYUQuVDt0TZEAoP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_8e730cdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187"
    family = "unknown"
    file_name = "8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187"
    file_type = "elf"
    first_seen = "2026-06-26 21:46:02"
  condition:
    hash.sha256(0, filesize) == "8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187"
}
```

### Sample 64: `b48ff07c855be9ab`

| Field | Value |
|---|---|
| SHA-256 | `b48ff07c855be9ab7b513c70dadfb4d0380f78477ade7b5e424933bc82cf9664` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 21:16:18` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4383e880ce10d524e1edad8f058d23bc` |
| SHA-1 | `52f34fdc10af481b6eb396971fe52ef57bf58d78` |
| SHA-256 | `b48ff07c855be9ab7b513c70dadfb4d0380f78477ade7b5e424933bc82cf9664` |
| SHA3-384 | `dc03624cb403f05d1442e55827ee434b47553dc873fb54f3c4a6f2e9e9e548609e84dffce3a687be446ab93b07e3088a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14DF58C0BBCE108FAC0D9A23189B6425A7B74BC490F3623D72E90B7782E767D05C76B55` |
| SSDEEP | `49152:ZXyyE+U4UMjNXphiypDYkjmehiYvW8eJAissBt1L9pvLYePNaPT6tF:ZQHylDi1Rqis2tBL0m3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_b48ff07c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48ff07c855be9ab7b513c70dadfb4d0380f78477ade7b5e424933bc82cf9664"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:16:18"
  condition:
    hash.sha256(0, filesize) == "b48ff07c855be9ab7b513c70dadfb4d0380f78477ade7b5e424933bc82cf9664"
}
```

### Sample 65: `62ae6518076f30d4`

| Field | Value |
|---|---|
| SHA-256 | `62ae6518076f30d48eebc7a111f2cf7df2d0f29f8a7e82d9dea57141b18fa24c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 21:10:45` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, F, MIX3.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7167e8aabfd40846e1e9d22f2878f2ea` |
| SHA-1 | `e7e16c034e6ebab9512e0b73f92a953dd41411e2` |
| SHA-256 | `62ae6518076f30d48eebc7a111f2cf7df2d0f29f8a7e82d9dea57141b18fa24c` |
| SHA3-384 | `03bf8a709000f9f71bd375cfb8cfbb1774a2b74f51d0b66edee5eb3ab981ab3e2ca76fc107885afd263dce90d70c0523` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E5062706699008F6C09AA23D94B7519A7E25BC0B0B3DE7D7EAD076782E763C0397573C` |
| SSDEEP | `49152:KD3CWAKPTbmBa66/mWP8N/cbCDkwYqLd6QfSdYfz15jAxNa:KB9PiDkwYafSdQGa` |
| ICON-DHASH | `68c4d4c8c0c8a4a4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_62ae6518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ae6518076f30d48eebc7a111f2cf7df2d0f29f8a7e82d9dea57141b18fa24c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:10:45"
  condition:
    hash.sha256(0, filesize) == "62ae6518076f30d48eebc7a111f2cf7df2d0f29f8a7e82d9dea57141b18fa24c"
}
```

### Sample 66: `c097558130cf9579`

| Field | Value |
|---|---|
| SHA-256 | `c097558130cf957989c38f44e1a542412c4964d380fdba85197d83d5a83a8c56` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 21:10:12` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX0.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `871252e0dc4ef2ac5167a5577013ee74` |
| SHA-1 | `10356375b28da7e6bd64f21e13bda2b540a94f1a` |
| SHA-256 | `c097558130cf957989c38f44e1a542412c4964d380fdba85197d83d5a83a8c56` |
| SHA3-384 | `1cb51c47cdee79dff5b4a05597151ca8b87a68879c876c428af829cfe1c199de875e4de355ccbebff3f884f63d03e147` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19DF58C46BDE148E5C09AD23188B651AA7BB4BC090F3627D72E90BB783F763D05D36B14` |
| SSDEEP | `49152:2Zjcu3+X+qHG6SJVDlmv9GQXHdP4Ggl3DrzXydmFxiAU4guvmwKUIv0FbuUhwYci:2RU88v6DRR5u1u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_c0975581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c097558130cf957989c38f44e1a542412c4964d380fdba85197d83d5a83a8c56"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:10:12"
  condition:
    hash.sha256(0, filesize) == "c097558130cf957989c38f44e1a542412c4964d380fdba85197d83d5a83a8c56"
}
```

### Sample 67: `39fec39c77cc6e2b`

| Field | Value |
|---|---|
| SHA-256 | `39fec39c77cc6e2ba2c37b15485d7b7e6ec51f7aea047865adc414f52422529e` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 20:52:32` |
| Reporter | `abuse_ch` |
| Tags | `exe, RustyStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4e5c36f5582c01dbccb562393f6ba26` |
| SHA-1 | `83cb48f03b5f2c2f4135d5be936f8eb40bb03ad7` |
| SHA-256 | `39fec39c77cc6e2ba2c37b15485d7b7e6ec51f7aea047865adc414f52422529e` |
| SHA3-384 | `7d906e5036658e2bfcc8f78defab78f34675793f2111759d0dc8fa3a646497455d758db82cae6459dc9f9afe179ab3f8` |
| IMPHASH | `9e19b5d9beb246a4b37cb8d4ae8a43f8` |
| TLSH | `T195663947E1A290ECC06AC17C831BA633F631B8498534FAAB5BD4CB312E75F506B5DB19` |
| SSDEEP | `98304:BeHSA1xtkOQPL+dBiRU4jlFwcAyKL1vCRAM/TG+I0:Be29zbFkyACdGm` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_067_39fec39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39fec39c77cc6e2ba2c37b15485d7b7e6ec51f7aea047865adc414f52422529e"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 20:52:32"
  condition:
    hash.sha256(0, filesize) == "39fec39c77cc6e2ba2c37b15485d7b7e6ec51f7aea047865adc414f52422529e"
}
```

### Sample 68: `e00cd20d10209b8f`

| Field | Value |
|---|---|
| SHA-256 | `e00cd20d10209b8f2744523ebeb5932bdbf969dfee9ceee9aa659c0b10e3369f` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 20:52:15` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file, RustyStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a725c940cf743957fe8d061dee5e3509` |
| SHA-1 | `3526b193e70eb708c42c8393550a0db7a74d142d` |
| SHA-256 | `e00cd20d10209b8f2744523ebeb5932bdbf969dfee9ceee9aa659c0b10e3369f` |
| SHA3-384 | `5aa7927651ce20a718b81d17229ddf24ed33d62b9947c7b645cdd8dd31840ad9bed63c05c112c9e7a3f2903a3645bc74` |
| IMPHASH | `55efd29c0f070c5d716b6d37ecb2ab4f` |
| TLSH | `T1DCD53360110FE7EBDA12AC30678607E5931416CF1BCD601A3DAAB6F4A9736F22376746` |
| SSDEEP | `49152:pCIWqK45TFK9ficehbhOliFDXyz2N6CStMOAY6dKynsbU5Y7kAEnSL5r1u:SqK+09fhehsmCzl3zAY6AqWXE85h` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_068_e00cd20d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e00cd20d10209b8f2744523ebeb5932bdbf969dfee9ceee9aa659c0b10e3369f"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 20:52:15"
  condition:
    hash.sha256(0, filesize) == "e00cd20d10209b8f2744523ebeb5932bdbf969dfee9ceee9aa659c0b10e3369f"
}
```

### Sample 69: `2f96d4220d7c716e`

| Field | Value |
|---|---|
| SHA-256 | `2f96d4220d7c716ef6b0763052f8f8f4ffa296ffb8be68dbed5ea7c02887a8a5` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-06-26 20:31:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bcfb246449885a0d61aec7ef9874045` |
| SHA-1 | `eb44005f577d720f088aacbad63049cdea90af6b` |
| SHA-256 | `2f96d4220d7c716ef6b0763052f8f8f4ffa296ffb8be68dbed5ea7c02887a8a5` |
| SHA3-384 | `51d9d14b4efa040fc66904c3216d0f0f87b05f0c4dec5e6aab93413baa2f7143ddba3248ae3bc38ad4a38357918fc5b1` |
| TLSH | `T1C0140742BD51AB23C1E232B7FBAE428937196B69D1EB72079C317F5037C68DA0D76241` |
| TELFHASH | `t1f13155b19f681abc63d0c29493de713d576975e92b8234064e919b0b8807ec0b01f833` |
| SSDEEP | `3072:KfVG24mHzcm1ZvlqqHPWWf+YRaW+EuAKftNkKFTgbwQ/UF3:KfMWf1ANEuAStNkKtgb1/UF3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_2f96d422
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f96d4220d7c716ef6b0763052f8f8f4ffa296ffb8be68dbed5ea7c02887a8a5"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-26 20:31:01"
  condition:
    hash.sha256(0, filesize) == "2f96d4220d7c716ef6b0763052f8f8f4ffa296ffb8be68dbed5ea7c02887a8a5"
}
```

### Sample 70: `a150c4ff04cd3731`

| Field | Value |
|---|---|
| SHA-256 | `a150c4ff04cd3731328486fc03598eb1f366fffc6a31f66e2b27a560769e54ce` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-06-26 20:30:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a9859984842510ab614932f62a16094` |
| SHA-1 | `b926586065e6dfbfed97ebff63ca48329f2364d1` |
| SHA-256 | `a150c4ff04cd3731328486fc03598eb1f366fffc6a31f66e2b27a560769e54ce` |
| SHA3-384 | `041eb3f610507e0298d3912fe936c33507e74b09e361ab064cea4823f3e80f5667a65500600d28b048ef37957f6b8143` |
| TLSH | `T11453F1E6C2010497A6B618B0FE74838FE74A743495F5B9BC9624CB1F214F4798E58F1E` |
| SSDEEP | `768:XdI1YNtsHlPABBMKzrKwZZk624GCQ+3e8mgBKuThaIQDoqs66oRQA1RveU2PIOyK:tIM6lPABGgb7kv4G/pgBKDvqmM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_a150c4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a150c4ff04cd3731328486fc03598eb1f366fffc6a31f66e2b27a560769e54ce"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-26 20:30:03"
  condition:
    hash.sha256(0, filesize) == "a150c4ff04cd3731328486fc03598eb1f366fffc6a31f66e2b27a560769e54ce"
}
```

### Sample 71: `213825dd74de93e7`

| Field | Value |
|---|---|
| SHA-256 | `213825dd74de93e765db54061e185ca92e3715775adfe2a604dc5000e31385ce` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-26 20:29:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2b2a4ed97d656b65257df94a7ff16d8` |
| SHA-1 | `2d89fae3fe2034c800f5e4206933ccaaf35ad23e` |
| SHA-256 | `213825dd74de93e765db54061e185ca92e3715775adfe2a604dc5000e31385ce` |
| SHA3-384 | `eec678cb608dadbb69a6b9299a341455f5c718246719faa5ec5a5b9b87dceae4d60926cc2c8fbcc2fcd851ac067c4cb5` |
| TLSH | `T1E2141902771C0E03D1A36EF0263B27E083ABE96118F5A684751EBFC99371DB26545EDA` |
| SSDEEP | `3072:ot06fz3K6sGogqOxrl5i6lI6tBlv2pzKk:ot06r3K6swXxrlQ6lIqBMpzKk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_213825dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "213825dd74de93e765db54061e185ca92e3715775adfe2a604dc5000e31385ce"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-26 20:29:40"
  condition:
    hash.sha256(0, filesize) == "213825dd74de93e765db54061e185ca92e3715775adfe2a604dc5000e31385ce"
}
```

### Sample 72: `d2102df636e277ae`

| Field | Value |
|---|---|
| SHA-256 | `d2102df636e277ae48b10aa3b957b555316ac94ddd27131c840f737d5411fedc` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-26 20:29:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `25b1910300664920af458a7623d6a0ce` |
| SHA-1 | `e2ff803e2519690ca2daac37a6cd155da9d00fcb` |
| SHA-256 | `d2102df636e277ae48b10aa3b957b555316ac94ddd27131c840f737d5411fedc` |
| SHA3-384 | `c978a95d5b699370dafff48141b0f132896fe9c04cdb219b5c37326d1ea88ca6d5637f1e6a161c84bd55876ccba46e4c` |
| TLSH | `T197530292C70A97C8F3596F52D1100B805BC2D7CAB5FBC1E29442EB21AE15274D63E9FD` |
| SSDEEP | `1536:Q9JwLheaUAufPJU2ZBcU6DDzhG6wGDbHjZQmZbWcoY4u+qgw0VucY:8JwLhPfMUkh6Do6wkSmAC4u+qgw2uB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_d2102df6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2102df636e277ae48b10aa3b957b555316ac94ddd27131c840f737d5411fedc"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-26 20:29:05"
  condition:
    hash.sha256(0, filesize) == "d2102df636e277ae48b10aa3b957b555316ac94ddd27131c840f737d5411fedc"
}
```

### Sample 73: `9d48fad78597d426`

| Field | Value |
|---|---|
| SHA-256 | `9d48fad78597d426f827c79d8c5487eef94537bdc101eedf9ae21f0e038f4edc` |
| Family label | `Mirai` |
| File name | `barm7` |
| File type | `elf` |
| First seen | `2026-06-26 20:28:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca07a9959ea5c6ed8bdc4ed6beb2bcfc` |
| SHA-1 | `08375b9e00c1900bb20566445e97b83c8ddadbf8` |
| SHA-256 | `9d48fad78597d426f827c79d8c5487eef94537bdc101eedf9ae21f0e038f4edc` |
| SHA3-384 | `04bba641154e8057df9053aa8c08effe032358b725da4e177d8214b4c49fa66d8523a6e2e1cf8d4ff1db792cbe9c576b` |
| TLSH | `T1A0E44A46F8809F62C6D426B6F75D42A833074B79D3EB72069E155B3137EB86B0F3A601` |
| TELFHASH | `t15be06801b280788a52f9484ad1ebe26b92313258ca8a304593acaf4b1467d48715e433` |
| SSDEEP | `12288:LfdAWq4gmAAXxUqqYeRi/gEcEHE7eZbBrTzM69jnwp8p3nxHT:LVAWq4gmvUqTkoglEk7Wbhzgkx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_9d48fad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d48fad78597d426f827c79d8c5487eef94537bdc101eedf9ae21f0e038f4edc"
    family = "Mirai"
    file_name = "barm7"
    file_type = "elf"
    first_seen = "2026-06-26 20:28:07"
  condition:
    hash.sha256(0, filesize) == "9d48fad78597d426f827c79d8c5487eef94537bdc101eedf9ae21f0e038f4edc"
}
```

### Sample 74: `d435698c0c6075d6`

| Field | Value |
|---|---|
| SHA-256 | `d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f` |
| Family label | `WannaCry` |
| File name | `d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f.dll` |
| File type | `dll` |
| First seen | `2026-06-26 20:28:02` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0b020c2c49fc3930f342653085e6549` |
| SHA-1 | `0f8de96b51d4464fa9e83e1d2c33c1dd492c54b7` |
| SHA-256 | `d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f` |
| SHA3-384 | `b95e8fd12f2465c04b2809e67235ce7bf380f77a92f220f857a8351f9b102d660d6ff20e88c6de42de7aaeff0e4f8510` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1FE3623DA75AC60F8D1167374A4778E26A2B77C6D21BD9B0F9B808B210C03B61FB54B53` |
| SSDEEP | `24576:RbLgurgDdmMSirYbcMVgef0QeQjG/D8kIqRY:RnsEMSPbcxVQej/1` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_074_d435698c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f"
    family = "WannaCry"
    file_name = "d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f.dll"
    file_type = "dll"
    first_seen = "2026-06-26 20:28:02"
  condition:
    hash.sha256(0, filesize) == "d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f"
}
```

### Sample 75: `8d8cb1fc6861afc1`

| Field | Value |
|---|---|
| SHA-256 | `8d8cb1fc6861afc1afe5facdc700272f013abd1b97c3076a309175a730917bb0` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-26 20:09:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74e559fb0e4d3e020f75106cd6d5551e` |
| SHA-1 | `abb306679eda185a8a2b578ecf67c3d122db137a` |
| SHA-256 | `8d8cb1fc6861afc1afe5facdc700272f013abd1b97c3076a309175a730917bb0` |
| SHA3-384 | `e4d5bd174444f1991df902acd22e068312cd15496bb8d8c279ffbf026964b1011e04e53865b93870918ac059926dcd2e` |
| TLSH | `T13B231813215089FDC959827147BFA52BF932F0BE4135F38D6BA47E22ED4AD310A5E4CA` |
| TELFHASH | `t1a901d6b33a7559a0f1dbe4667301d8481d250e2081e174f7aa7076fbdb107010a7582f` |
| SSDEEP | `768:THrJP0Sgz2doZ+huIjx6jKv/zUbguTVPIJ75zkHTjzgzegMzbgOVEr7eTBn:hcJMuSv/zU9Ta756TYO0OVs7eTBn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_8d8cb1fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d8cb1fc6861afc1afe5facdc700272f013abd1b97c3076a309175a730917bb0"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-26 20:09:04"
  condition:
    hash.sha256(0, filesize) == "8d8cb1fc6861afc1afe5facdc700272f013abd1b97c3076a309175a730917bb0"
}
```

### Sample 76: `f271ef8ef53476e8`

| Field | Value |
|---|---|
| SHA-256 | `f271ef8ef53476e81b33f00aaec737e14edb942a8447e79565bb468e88ce04b5` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-26 20:04:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f3d3ea78ab64ee3e600d3daae967dfd` |
| SHA-1 | `3cd20cfdcbc6d52530588b092871f9b8ed5c40ce` |
| SHA-256 | `f271ef8ef53476e81b33f00aaec737e14edb942a8447e79565bb468e88ce04b5` |
| SHA3-384 | `9ebea49b0b72e905ab7d024a13a55e63e87e4a6b3009628b67742a89649a2e6561993570cd536d12685840e8feef9706` |
| TLSH | `T1C4247C99BA4F7E82D2C6D3F89F8BCB91312731958A4682F53D01132DC5C6DD98CE2B91` |
| SSDEEP | `3072:YfDjt09HLyWCE5lZTmYqFlwFEOpUCt9OqveGevJjBtljq2o:StWybEXJmY+qFEOpUe4eeG8VDjqX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f271ef8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f271ef8ef53476e81b33f00aaec737e14edb942a8447e79565bb468e88ce04b5"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-26 20:04:38"
  condition:
    hash.sha256(0, filesize) == "f271ef8ef53476e81b33f00aaec737e14edb942a8447e79565bb468e88ce04b5"
}
```

### Sample 77: `dbf7bd71c9f72fc1`

| Field | Value |
|---|---|
| SHA-256 | `dbf7bd71c9f72fc15797cbee3843127bb58008861cbf199181fc8d434a557e41` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-26 20:04:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ee382f0228244f1cbabb81d26ed507f` |
| SHA-1 | `066ef127006da5750c2556d5e39b6683861ec7bb` |
| SHA-256 | `dbf7bd71c9f72fc15797cbee3843127bb58008861cbf199181fc8d434a557e41` |
| SHA3-384 | `8494ae954bb8471f3ef0feecf18773a3e5746a85acf75afa2c115f6103ff11a12129093a8aad4c8bf62da1afdcce1488` |
| TLSH | `T1528302A2411A0713E290EB753492CF21F5E8A6A6D4C763BE1A53B5DDFFA1610CC8D13C` |
| SSDEEP | `1536:dqld0SkbNYoR23rUcifJg8CGr8siiVQjeQFEiTEIvtSbgP8SoDno:dqld0LBYscif28n3seA/PAbgPD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_dbf7bd71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf7bd71c9f72fc15797cbee3843127bb58008861cbf199181fc8d434a557e41"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-26 20:04:11"
  condition:
    hash.sha256(0, filesize) == "dbf7bd71c9f72fc15797cbee3843127bb58008861cbf199181fc8d434a557e41"
}
```

### Sample 78: `7e3432eeefe91570`

| Field | Value |
|---|---|
| SHA-256 | `7e3432eeefe91570948db274d03fe6e0e73afd31592f5ce7244ba000e9d816ce` |
| Family label | `unknown` |
| File name | `Request For Quotation. #IMESA.vbs` |
| File type | `vbs` |
| First seen | `2026-06-26 20:02:24` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3fe4942c16f07f67e1ff70b2d10fdb0` |
| SHA-1 | `e6472a4ca66e1dd8c0a6777950d632c827d4eeb5` |
| SHA-256 | `7e3432eeefe91570948db274d03fe6e0e73afd31592f5ce7244ba000e9d816ce` |
| SHA3-384 | `11c9388d47e6f41474acc86e630ac26b4652d8ef36de917a870fa8e9fae3e841bc53b38b9566ba61d22cf4c4175908c9` |
| TLSH | `T17D853B38ECEA402EF173EE698AD879A7E95FB663370E545D1091034B4713942EDD223E` |
| SSDEEP | `24576:B7B2xw0xgoXLu0iBxoAfnGIdGFpLzknX6A160dINq3ffw:BlqT9dAGbodjdKiw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_7e3432ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e3432eeefe91570948db274d03fe6e0e73afd31592f5ce7244ba000e9d816ce"
    family = "unknown"
    file_name = "Request For Quotation. #IMESA.vbs"
    file_type = "vbs"
    first_seen = "2026-06-26 20:02:24"
  condition:
    hash.sha256(0, filesize) == "7e3432eeefe91570948db274d03fe6e0e73afd31592f5ce7244ba000e9d816ce"
}
```

### Sample 79: `7b7cc6ddaaf7883d`

| Field | Value |
|---|---|
| SHA-256 | `7b7cc6ddaaf7883d131dcf43677381da5707ca6d534b5b2aaae4ec9033a69ec6` |
| Family label | `Amadey` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-26 20:01:31` |
| Reporter | `Bitsight` |
| Tags | `1TEST.file, A, Amadey, dropped-by-GCleaner, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `993f015fc9f5a9f683c32541e0039627` |
| SHA-1 | `ebdf48efba35c32ff7bee9db6897aa2d98591a17` |
| SHA-256 | `7b7cc6ddaaf7883d131dcf43677381da5707ca6d534b5b2aaae4ec9033a69ec6` |
| SHA3-384 | `b10f116dd7bceda5ac55d9695319c964bb55eca19a58146d4b98d97f9f5b6630ad68d33046aeac66e37f4ae52b6c7694` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T198D54B41FEC744F6E9031672D5A763AF2339AE050F399B87EB407A79E9372D58822305` |
| SSDEEP | `49152:druty7BFNsjotSJhushpCTLYZbsJvJA2HmH1v:Rsy7XNoqu3eNJLGV` |

#### Technical Assessment

- The sample is tracked as `Amadey` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Amadey_079_7b7cc6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b7cc6ddaaf7883d131dcf43677381da5707ca6d534b5b2aaae4ec9033a69ec6"
    family = "Amadey"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 20:01:31"
  condition:
    hash.sha256(0, filesize) == "7b7cc6ddaaf7883d131dcf43677381da5707ca6d534b5b2aaae4ec9033a69ec6"
}
```

### Sample 80: `c60d7f885f481f6e`

| Field | Value |
|---|---|
| SHA-256 | `c60d7f885f481f6e8194f01551640da1e45e493c90edebeecfa0deb7a89b838a` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-26 19:59:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e720a6cbb70f8494ad6c001331920e99` |
| SHA-1 | `2306ccdeff8c4c19a9ad13d58a5aaaee46be9f5d` |
| SHA-256 | `c60d7f885f481f6e8194f01551640da1e45e493c90edebeecfa0deb7a89b838a` |
| SHA3-384 | `1146c7d53a70047a175ad5e5df36b90c3ceacbd01b7df422c0e6521b29be5e4ed062945267eeaef39f1adca13fe33b6c` |
| TLSH | `T16D44E806AF610FF7D8ABCD3306EA1B0129CC681B26A53F36B674D968B50B54B19C3D74` |
| SSDEEP | `3072:QO2sGGqR75Q7G3KNkYQDNJ49/qKKGzB1E5EwvLxwI2EhA:QzsB2NQC3q/9RKk1m9CI2EhA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_c60d7f88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60d7f885f481f6e8194f01551640da1e45e493c90edebeecfa0deb7a89b838a"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-26 19:59:31"
  condition:
    hash.sha256(0, filesize) == "c60d7f885f481f6e8194f01551640da1e45e493c90edebeecfa0deb7a89b838a"
}
```

### Sample 81: `18feb21998dca471`

| Field | Value |
|---|---|
| SHA-256 | `18feb21998dca47116dafc1a73d1873514c23f4d120c8f98282d690c2c061c5f` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-26 19:58:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41e830222ab135a165a76710c90560d4` |
| SHA-1 | `7c3aea36a85bd108828bf4aa15ef04932a7b74a6` |
| SHA-256 | `18feb21998dca47116dafc1a73d1873514c23f4d120c8f98282d690c2c061c5f` |
| SHA3-384 | `c6b782b3639fe79b90bd695a3adab9cf0c2fa691331c6200270e06c7a7a3f67f2bff5db37063def5f6c94dc1ccf3b666` |
| TLSH | `T1C263021E92ED379ED42DA9FF76FB132C2C80F4C1251206691F798565CA57802EDEE428` |
| SSDEEP | `1536:BlCzKFmFNBRRxFODz9VzLPAtPtUCQLCthQPpwxAp3VFjXWOknJnXSLp:fCzlfxADz7zLo/UCLhByVVlkVSV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_18feb219
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18feb21998dca47116dafc1a73d1873514c23f4d120c8f98282d690c2c061c5f"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-26 19:58:57"
  condition:
    hash.sha256(0, filesize) == "18feb21998dca47116dafc1a73d1873514c23f4d120c8f98282d690c2c061c5f"
}
```

### Sample 82: `08b40c951747b139`

| Field | Value |
|---|---|
| SHA-256 | `08b40c951747b139fafb060bde6c9eebcce49d0502496367edc192679d0ec790` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-26 19:45:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ded5d3bcb7f9c8c174881af37c7fb3a7` |
| SHA-1 | `047b1b24adfea46a2d20a5bbf08ea218d6bee937` |
| SHA-256 | `08b40c951747b139fafb060bde6c9eebcce49d0502496367edc192679d0ec790` |
| SHA3-384 | `7ad9aea2142361c69e2dd93a14235104dc31692b7c28be1ff8019d6be4f8803a77f241b0b237063eccdf1f73b95cb207` |
| TLSH | `T17944941F2E22DF6EF7A9867007B78E30975C36D626E1D680E26CD6105E502CD641FFA8` |
| TELFHASH | `t1b341c318197813e0a6656c5d049dff76d6a730eb7e162c278e11e86eab69e435d10c0c` |
| SSDEEP | `6144:YtaTQfMdO2jBUOCARhGwzBLDaB378/TB3RjL:YtxwGGaB374L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_08b40c95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08b40c951747b139fafb060bde6c9eebcce49d0502496367edc192679d0ec790"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-26 19:45:54"
  condition:
    hash.sha256(0, filesize) == "08b40c951747b139fafb060bde6c9eebcce49d0502496367edc192679d0ec790"
}
```

### Sample 83: `f5c35c91c3890f1f`

| Field | Value |
|---|---|
| SHA-256 | `f5c35c91c3890f1f1d3886dfcb6f878d2be57ecc4485542e4a5c92188488452f` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-26 19:44:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85b79ce96ca7538d15490ff7c134215c` |
| SHA-1 | `2815144939123218d65b30fcf00726343f2a53b8` |
| SHA-256 | `f5c35c91c3890f1f1d3886dfcb6f878d2be57ecc4485542e4a5c92188488452f` |
| SHA3-384 | `9033e841f574464e3c3b59c8bb9f8f9dfbb9e2acf3cc9541639e1638641e2fce0f3b21ef80a709e21f213ab4b5b47990` |
| TLSH | `T16763020C6485057AEE5656B9CBA317FE3E208E178477CC4E1878C5825B4B9E6FC83EC9` |
| SSDEEP | `1536:OMLXRLdfRm5S+PM88fs/+CCZg4KwmFklnqNVSTG:vFdJmfEk2ZqKlnIVsG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_f5c35c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c35c91c3890f1f1d3886dfcb6f878d2be57ecc4485542e4a5c92188488452f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-26 19:44:59"
  condition:
    hash.sha256(0, filesize) == "f5c35c91c3890f1f1d3886dfcb6f878d2be57ecc4485542e4a5c92188488452f"
}
```

### Sample 84: `7dc478626946985d`

| Field | Value |
|---|---|
| SHA-256 | `7dc478626946985d859ed3ff34ad2804fcf456fcba03edf43668a97dd091bf8a` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-06-26 19:40:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61a351e533854888892aa1b9654020d7` |
| SHA-1 | `237d107a05b1c826776b198a10cf75c28df114d6` |
| SHA-256 | `7dc478626946985d859ed3ff34ad2804fcf456fcba03edf43668a97dd091bf8a` |
| SHA3-384 | `e28e98b140a16231c7e0a080f3fa76f8b7958a407737e4fd04c039655848a7e94d2e3d54d8866dd180cf6519cfe985e2` |
| TLSH | `T13A53620AAF611EF7EC6FCD3716F41B49308C641A11A97F397A74D928FA0A21B05E3875` |
| SSDEEP | `768:1KgA4byLC8MW8dexXYu1IJNg5rR3YTqGaremed2ePMIN6y2XiPo+Oz1lwbZn1:1KgAKYb1IJN4R3dBw2oMiffObwbZn1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_7dc47862
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc478626946985d859ed3ff34ad2804fcf456fcba03edf43668a97dd091bf8a"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-06-26 19:40:00"
  condition:
    hash.sha256(0, filesize) == "7dc478626946985d859ed3ff34ad2804fcf456fcba03edf43668a97dd091bf8a"
}
```

### Sample 85: `1b0027fc3d2a78fc`

| Field | Value |
|---|---|
| SHA-256 | `1b0027fc3d2a78fcfb4d236e5bb44370a3bd6ea107276c483fbef0daa1687c2b` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-06-26 19:39:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60e917482d2571859753fbeb1736373d` |
| SHA-1 | `bbb448fb99ccaeb3293ed80f23aac4f550d3425d` |
| SHA-256 | `1b0027fc3d2a78fcfb4d236e5bb44370a3bd6ea107276c483fbef0daa1687c2b` |
| SHA3-384 | `14bf5526eb01a4c8d4a82c68c43829a8ec6fd53cc0f14eab8d77bc19754f48605a930f3fa19fce4977b4a3e089579266` |
| TLSH | `T1D8246B437B878FA3C2246A754AF382389AD937170AA7C4E7C3B95B0167655903C2DFC9` |
| TELFHASH | `t1214192319b3c8816a8e2cea4eced1721921fc55155409a33ef30c68c446b4eda62bf5f` |
| SSDEEP | `3072:TKS1vXazWUUH9BzUl2YYUZFex1zI4MRusrxScjuM+w1qgb995F2M3iosDnLLcj09:t1vqz+dBzUl2OWzagcjawFBqnLLy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_1b0027fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b0027fc3d2a78fcfb4d236e5bb44370a3bd6ea107276c483fbef0daa1687c2b"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-06-26 19:39:00"
  condition:
    hash.sha256(0, filesize) == "1b0027fc3d2a78fcfb4d236e5bb44370a3bd6ea107276c483fbef0daa1687c2b"
}
```

### Sample 86: `92420aeb6fcb2cbd`

| Field | Value |
|---|---|
| SHA-256 | `92420aeb6fcb2cbd3f8b4b645f08c9fd7173fb258439f5de6b91dc45dd72d209` |
| Family label | `unknown` |
| File name | `a-software85659014.msi` |
| File type | `msi` |
| First seen | `2026-06-26 19:25:38` |
| Reporter | `CNGaoLing` |
| Tags | `GH0ST, GH0STRAT, msi, SilverFox` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d041a2bc3d3ea600cfb91b5b5f140036` |
| SHA-1 | `08bd771ddd0b4ed12705e369c6617a13afb8432b` |
| SHA-256 | `92420aeb6fcb2cbd3f8b4b645f08c9fd7173fb258439f5de6b91dc45dd72d209` |
| SHA3-384 | `363bf8e9079eb21a76d29b3fd83f4924aed1de9f11908cf553bcb93b7d7f40f17035c75ab0f6f6964b8f32f5bae54d99` |
| TLSH | `T117563356BDC76978D0D7C7B5579A212D30297FCA8F688C6B73E87A1C0D72200A4F6389` |
| SSDEEP | `98304:CQfQ3Vu6lqX9LTEZpY84XSvl4vHguz/LtjHRJSreQkMSQ1xEl/AWug:CBVumqhIt9gAuz06QZ1aAWug` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_92420aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92420aeb6fcb2cbd3f8b4b645f08c9fd7173fb258439f5de6b91dc45dd72d209"
    family = "unknown"
    file_name = "a-software85659014.msi"
    file_type = "msi"
    first_seen = "2026-06-26 19:25:38"
  condition:
    hash.sha256(0, filesize) == "92420aeb6fcb2cbd3f8b4b645f08c9fd7173fb258439f5de6b91dc45dd72d209"
}
```

### Sample 87: `5210829b2e77f77f`

| Field | Value |
|---|---|
| SHA-256 | `5210829b2e77f77fb73d91eabdb98cadad7bbff09d7a38e8c224be275d57027f` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-26 19:22:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aecbde24d3e810cbf62289981c36de9a` |
| SHA-1 | `c16776269ab75e55af52bde0fbf8c719bbb235cc` |
| SHA-256 | `5210829b2e77f77fb73d91eabdb98cadad7bbff09d7a38e8c224be275d57027f` |
| SHA3-384 | `4c9fe7996f6c06d52b4fffb6de660b0fd837a41836e9bb713103fe0225fdbfe38e9013886c6727f106a5c6aa665407e2` |
| TLSH | `T1BA247D03B6A254FDC08AC4F0436FA316EE3774A9461B75F77B847B312916EB18E09792` |
| TELFHASH | `t1d8510f341ed2751d53a2c70bb31b6f2afe761426c5eab6d4ab27ad946d03b480c53021` |
| SSDEEP | `6144:+0qdsO7NGBRdhen/RaLVPMyF2THoXVdqGZmd:+0CEr4qVdpm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_5210829b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5210829b2e77f77fb73d91eabdb98cadad7bbff09d7a38e8c224be275d57027f"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-26 19:22:36"
  condition:
    hash.sha256(0, filesize) == "5210829b2e77f77fb73d91eabdb98cadad7bbff09d7a38e8c224be275d57027f"
}
```

### Sample 88: `78b674dc41c0396a`

| Field | Value |
|---|---|
| SHA-256 | `78b674dc41c0396a6a0fb9777155259d46509e4370ebcab97a4807f0ddf2d539` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-26 19:22:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47e9ce5f4a20a62b4061a5291f0f11fb` |
| SHA-1 | `d4ce7701d4ffe67a96a39434c3b47cea82f837ce` |
| SHA-256 | `78b674dc41c0396a6a0fb9777155259d46509e4370ebcab97a4807f0ddf2d539` |
| SHA3-384 | `7beaae7f2a87042c3a15363d3d3f80d0c92745b4fc2ed83fdeb15ae257816d66b91b6e041564b4f7b713476acdcb2203` |
| TLSH | `T1C183022DF61AE65AE42E94F5362F5BD0AF25D430590A84F10F6BC83C48E6AD44C2DF06` |
| SSDEEP | `1536:Ud4nI6PZdUyFVYTxcpI3R4qC2bbtktAgHyIr9lEO8ADp8:7vdUS1I3Rs2bbcA6rLTN8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_78b674dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78b674dc41c0396a6a0fb9777155259d46509e4370ebcab97a4807f0ddf2d539"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-26 19:22:03"
  condition:
    hash.sha256(0, filesize) == "78b674dc41c0396a6a0fb9777155259d46509e4370ebcab97a4807f0ddf2d539"
}
```

### Sample 89: `8af73d551cab2ccb`

| Field | Value |
|---|---|
| SHA-256 | `8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3` |
| Family label | `unknown` |
| File name | `8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3` |
| File type | `elf` |
| First seen | `2026-06-26 19:08:46` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a67f1bbfceaf2a8a16944f71a0e1e23` |
| SHA-1 | `24b4ecf86a5e1a0aa006603bc1554f57da6afe30` |
| SHA-256 | `8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3` |
| SHA3-384 | `322e1ea24dfb5f5374ddaf8c69aa7425dc16dce5cf43d8cc47e6d07d8625cf930e8d9d66a39cbf317f188247d93c655f` |
| TLSH | `T16F17BE77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQm:cqYUQuVDt0TZEd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_8af73d55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3"
    family = "unknown"
    file_name = "8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3"
    file_type = "elf"
    first_seen = "2026-06-26 19:08:46"
  condition:
    hash.sha256(0, filesize) == "8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3"
}
```

### Sample 90: `a1913214f517254c`

| Field | Value |
|---|---|
| SHA-256 | `a1913214f517254c854ebc0ca8aaac737d89a633fed786c83d2b9f6bb8b7f398` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-06-26 18:49:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6be29c192262c9b6987f1df5562eeae1` |
| SHA-1 | `10d43cd21ef438113a727f96ab5f06a4e4b280bd` |
| SHA-256 | `a1913214f517254c854ebc0ca8aaac737d89a633fed786c83d2b9f6bb8b7f398` |
| SHA3-384 | `6d16fdb41c5d33a47a360cf3ec0cb0cffb28338821e5795dc6fb80d71e0f82c323ca6ed5c3a1f6b7e474c4b4d45d4c9a` |
| TLSH | `T15734D791A4118ADFCE0158FA77AC4F342B817C70861B1FBD5D5194A8A28F8DFF1C6BA4` |
| SSDEEP | `3072:npLc2NZ2iPQo7OTqrdG08IPeEv7UGKlckf5TglWH1ZloEs:nhcgIiecd8I2M7UGKlcqmQVYEs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_a1913214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1913214f517254c854ebc0ca8aaac737d89a633fed786c83d2b9f6bb8b7f398"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-26 18:49:20"
  condition:
    hash.sha256(0, filesize) == "a1913214f517254c854ebc0ca8aaac737d89a633fed786c83d2b9f6bb8b7f398"
}
```

### Sample 91: `1b45f9d89cf03c56`

| Field | Value |
|---|---|
| SHA-256 | `1b45f9d89cf03c56afa6ec5cce472e4b36680d792a47f728ee30ef993cf16648` |
| Family label | `unknown` |
| File name | `check_bot_m` |
| File type | `sh` |
| First seen | `2026-06-26 18:47:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cecac625fd8738c61c3ddf0d0d4b716b` |
| SHA-1 | `e281e054f83bdc08db0ec8784d7216884ce7bc18` |
| SHA-256 | `1b45f9d89cf03c56afa6ec5cce472e4b36680d792a47f728ee30ef993cf16648` |
| SHA3-384 | `5614d53ba57848fd07783aa09fd4521d00a5b2f969a7ce422a72dce81c2198a52722630b66479e2f1e8b1c6798e60b92` |
| TLSH | `T159E2D4AA8891DD64C2E5DF2459FE3783B209268FECD3048A1326371D570ECACD1DB25B` |
| SSDEEP | `384:o8DvSH1Zx9r9DxwSmOJ/bQwxCQhG6JEXscloecOBvQZVgWKPBj1Beoc:osED9L2QtG6iXsclkgzPBj1ooc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_1b45f9d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b45f9d89cf03c56afa6ec5cce472e4b36680d792a47f728ee30ef993cf16648"
    family = "unknown"
    file_name = "check_bot_m"
    file_type = "sh"
    first_seen = "2026-06-26 18:47:10"
  condition:
    hash.sha256(0, filesize) == "1b45f9d89cf03c56afa6ec5cce472e4b36680d792a47f728ee30ef993cf16648"
}
```

### Sample 92: `a0a88574ece61c4b`

| Field | Value |
|---|---|
| SHA-256 | `a0a88574ece61c4b43691f3136d01a691436f875482bc3989af0d782847508ab` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-06-26 18:33:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b017f1035365c245027927a6a48c0d56` |
| SHA-1 | `2a7f6cc2050b7582f0695490c72254233e91c06f` |
| SHA-256 | `a0a88574ece61c4b43691f3136d01a691436f875482bc3989af0d782847508ab` |
| SHA3-384 | `0f5db9e4bdb4cfba055039d7a235ac438bfcb0e3a6ee0b45a3b57fa0f34dbbce62afb482cc38817b9e4b63a4fedca292` |
| TLSH | `T195140752BD51AF23C1E232B7FB9E428937156B69C1EB7206DC227F503BC68DA0D76241` |
| SSDEEP | `3072:83qniVmbPUxwFYsJdALMhHkfei5x7l3uAAFvI+T+APJZNGvu23:83OhEfjrZ3uAAdI+T+uJZcvu23` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_a0a88574
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0a88574ece61c4b43691f3136d01a691436f875482bc3989af0d782847508ab"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-26 18:33:41"
  condition:
    hash.sha256(0, filesize) == "a0a88574ece61c4b43691f3136d01a691436f875482bc3989af0d782847508ab"
}
```

### Sample 93: `f000c9c9af23d705`

| Field | Value |
|---|---|
| SHA-256 | `f000c9c9af23d705e397a04afea2cb9be350b4d756f0d392ddff5b63755c6bc8` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-06-26 18:32:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a4aca6eeae708cd1fde9692c88ea073` |
| SHA-1 | `e16d945959fdceb3f3de2ea3ec27409c3cf9d2cd` |
| SHA-256 | `f000c9c9af23d705e397a04afea2cb9be350b4d756f0d392ddff5b63755c6bc8` |
| SHA3-384 | `572cc065cbb6addada53bd34f538efea27b581bfc9dc4becd1408c892a439169f0150621de77ff9fc7245ac0ea1dc5db` |
| TLSH | `T1E553F143D19B604AD5351EB269A851C17AA3F430F176307630488B9DBADB00ABBBDF5F` |
| SSDEEP | `1536:4KraG14a/cjTv8Vj3Q4OjATYs1uhNq9kjCe6Ep//U2vACEk7yxza:bP5/ACjg5vhNz6Ep//U4ACAza` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_f000c9c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f000c9c9af23d705e397a04afea2cb9be350b4d756f0d392ddff5b63755c6bc8"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-26 18:32:32"
  condition:
    hash.sha256(0, filesize) == "f000c9c9af23d705e397a04afea2cb9be350b4d756f0d392ddff5b63755c6bc8"
}
```

### Sample 94: `15df91e37347dcb7`

| Field | Value |
|---|---|
| SHA-256 | `15df91e37347dcb779f9d62f9a5655fc05a6834037dca4ff13fcc8dbe92f3453` |
| Family label | `unknown` |
| File name | `sample.ps1` |
| File type | `ps1` |
| First seen | `2026-06-26 18:28:17` |
| Reporter | `BastianHein_` |
| Tags | `Overlordrat, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6e8402219815e53ce0a6fb04c1c8289` |
| SHA-1 | `0b31f810e02ee92e6150fd8849256b387054c419` |
| SHA-256 | `15df91e37347dcb779f9d62f9a5655fc05a6834037dca4ff13fcc8dbe92f3453` |
| SHA3-384 | `6ac050e3da596887d850f8a83b0f9d49e5694ef0c7df20e95ecf51eb9950802207a09f09c0411584f0a610afaeea2f7e` |
| TLSH | `T1FDE0CDC7470F9DB5AD61C0A60555314897C448179EEE19415F9A7020D5C36DD77891B8` |
| SSDEEP | `6:P2ijPeanSHPeanSKZJbvvgi0fQLQh+Ws3KRpr3Smfr3Smfr3SReg282cnmfW12:P2im6KZ0Ucs3KRpm4m4mRT9nD0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_15df91e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15df91e37347dcb779f9d62f9a5655fc05a6834037dca4ff13fcc8dbe92f3453"
    family = "unknown"
    file_name = "sample.ps1"
    file_type = "ps1"
    first_seen = "2026-06-26 18:28:17"
  condition:
    hash.sha256(0, filesize) == "15df91e37347dcb779f9d62f9a5655fc05a6834037dca4ff13fcc8dbe92f3453"
}
```

### Sample 95: `f251d75cbea7ce99`

| Field | Value |
|---|---|
| SHA-256 | `f251d75cbea7ce997ba95ced1af1b852180a7e3c276e8984b0ba5c6234b7390d` |
| Family label | `unknown` |
| File name | `David_Jones_2025_Tax_Documents.pdf.js` |
| File type | `js` |
| First seen | `2026-06-26 18:21:20` |
| Reporter | `BastianHein_` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9455c087b3e05fc8c59e2ff51ef41b6` |
| SHA-1 | `ae018f562f77602ea6aba59b6f380721ad8ec973` |
| SHA-256 | `f251d75cbea7ce997ba95ced1af1b852180a7e3c276e8984b0ba5c6234b7390d` |
| SHA3-384 | `ea8227e2a8f63ffb8838143d2d28f1b002d81894d88a2aa8623c57fdb641ad0202574a52e8734eee3d77831088394123` |
| TLSH | `T16637132F193B4DB6EBB91C095DBB56DA3C5D5C80C8ACB2E1D3E9BE24DBC9704204D684` |
| SSDEEP | `49152:qls5lsTlsJlsYls9ls1lsklsjlsvlsolsAls+lsglstlsHlsHlsals8lsWlsglsK:W` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_f251d75c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f251d75cbea7ce997ba95ced1af1b852180a7e3c276e8984b0ba5c6234b7390d"
    family = "unknown"
    file_name = "David_Jones_2025_Tax_Documents.pdf.js"
    file_type = "js"
    first_seen = "2026-06-26 18:21:20"
  condition:
    hash.sha256(0, filesize) == "f251d75cbea7ce997ba95ced1af1b852180a7e3c276e8984b0ba5c6234b7390d"
}
```

### Sample 96: `5b1cd0bd500ca70a`

| Field | Value |
|---|---|
| SHA-256 | `5b1cd0bd500ca70ae871d015ea1c11b0720056a9da86b023a06024ccd6265543` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-26 18:15:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `508604a1ac0553df5e15593a5b04c25a` |
| SHA-1 | `e66b7c65ffabb4688f95d30c54aabed392f50cfa` |
| SHA-256 | `5b1cd0bd500ca70ae871d015ea1c11b0720056a9da86b023a06024ccd6265543` |
| SHA3-384 | `269b09f9eac349fbbfde3f2e222e20bb45f7d25f4bb58cca72406e2b2e7c70db3670bad7b20fa205cac0ec8f3504fa92` |
| TLSH | `T1C7F3F981FA43CBF6E44706F012B7A7335931FC3A442BE686DB65FE7269619C0E609358` |
| TELFHASH | `t1b85167b75a656fec27d0dc10c78f2714ee0da16b3810317e06a716d432b2a427575cba` |
| SSDEEP | `3072:UZHN8qufevAmuBkgjJ2SCyUeIdqrxGglK+EImxWpTiIknXKTA0IzF3mrm3iiGNTE:qt8qufevAmuBkgjJ2SCJeIdqrxLlK+E2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_5b1cd0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b1cd0bd500ca70ae871d015ea1c11b0720056a9da86b023a06024ccd6265543"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-26 18:15:59"
  condition:
    hash.sha256(0, filesize) == "5b1cd0bd500ca70ae871d015ea1c11b0720056a9da86b023a06024ccd6265543"
}
```

### Sample 97: `6b5feef2f1ca3e77`

| Field | Value |
|---|---|
| SHA-256 | `6b5feef2f1ca3e77a5b1f8e066ebe820e829793d3c4b8c68525265bfe6fc888c` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-26 18:15:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6b4d0f0acb7f902d6ee8e31b792dcb6` |
| SHA-1 | `e4cfc5cfbe0e25cc97d05ac4c26b104b5815f16c` |
| SHA-256 | `6b5feef2f1ca3e77a5b1f8e066ebe820e829793d3c4b8c68525265bfe6fc888c` |
| SHA3-384 | `f7f7c7a32b85ada448e280be27d542bf2d08cd10b678457352c8d805dd6f39710065609ae84aa5b40dbafc1e2be1b940` |
| TLSH | `T1EC43F1EFF7FE84929034507D4A6D36358C103259B2D1FB9520B8922B9CF3F46699E07A` |
| SSDEEP | `1536:RmFliRfHS00OpeD2U3XVS7P0YNG/bnEBmYHy3tZ2JxLs+nouy8ou:RVS72U3XVIP0DnrYEgoeoutP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_6b5feef2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b5feef2f1ca3e77a5b1f8e066ebe820e829793d3c4b8c68525265bfe6fc888c"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-26 18:15:11"
  condition:
    hash.sha256(0, filesize) == "6b5feef2f1ca3e77a5b1f8e066ebe820e829793d3c4b8c68525265bfe6fc888c"
}
```

### Sample 98: `f801da45bc7d36c3`

| Field | Value |
|---|---|
| SHA-256 | `f801da45bc7d36c3a81b7a23ec4ed85dea9e95b82cf2a75effb0194ea5d05b52` |
| Family label | `unknown` |
| File name | `nettt.bat` |
| File type | `bat` |
| First seen | `2026-06-26 18:14:58` |
| Reporter | `BastianHein_` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61abe5b274a31c313f2e4f86e91a3609` |
| SHA-1 | `4d519f33eb6ad3bb3979624d6f3e5b36381fb7d4` |
| SHA-256 | `f801da45bc7d36c3a81b7a23ec4ed85dea9e95b82cf2a75effb0194ea5d05b52` |
| SHA3-384 | `75828f016c4d5d0b63213ac648aa24c8079883aee64b4ac409a8cee57c66b9ba2da944e9bbce8cf1e387b52ebbb244ae` |
| TLSH | `T1C831DF46402E4D2FC3B5557ADEE235856687C063C85C5DCA799DC7082F7216B1B22FCA` |
| SSDEEP | `48:+W/0Gg13xgaycslSSRwb6XF+jlRgaCLcSd:pM3xga9slVKegjlRga2nd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_f801da45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f801da45bc7d36c3a81b7a23ec4ed85dea9e95b82cf2a75effb0194ea5d05b52"
    family = "unknown"
    file_name = "nettt.bat"
    file_type = "bat"
    first_seen = "2026-06-26 18:14:58"
  condition:
    hash.sha256(0, filesize) == "f801da45bc7d36c3a81b7a23ec4ed85dea9e95b82cf2a75effb0194ea5d05b52"
}
```

### Sample 99: `3c54bcae35db1c09`

| Field | Value |
|---|---|
| SHA-256 | `3c54bcae35db1c091af07cb1fee2040430b26b1c7f2d28a3b176e211ba43ea02` |
| Family label | `unknown` |
| File name | `runnerr.vbs` |
| File type | `vbs` |
| First seen | `2026-06-26 18:14:28` |
| Reporter | `BastianHein_` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59269a5f9ec13878d9f060ff0d7ae647` |
| SHA-1 | `7bf9bc5986c7689aaba4b247a67524c5c05b80fa` |
| SHA-256 | `3c54bcae35db1c091af07cb1fee2040430b26b1c7f2d28a3b176e211ba43ea02` |
| SHA3-384 | `a4bbd6075031d89d3269ea13ddc992cdded30c1f000167cb2f32e8a35a96889a4f25527943244a83da55f63eb614e0e6` |
| TLSH | `T19FD022AA0025CD2B578BC1F48320129C89BBD3125EB0D87AC760CC0882849E26313EDA` |
| SSDEEP | `6:j+K13NqcN7fBNLfdMGFlIPRFM1ERHSr1ERcWAf1wUs:KK1YcN1VfdMGWI1T1j19s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_3c54bcae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c54bcae35db1c091af07cb1fee2040430b26b1c7f2d28a3b176e211ba43ea02"
    family = "unknown"
    file_name = "runnerr.vbs"
    file_type = "vbs"
    first_seen = "2026-06-26 18:14:28"
  condition:
    hash.sha256(0, filesize) == "3c54bcae35db1c091af07cb1fee2040430b26b1c7f2d28a3b176e211ba43ea02"
}
```

### Sample 100: `8369bca0547312a9`

| Field | Value |
|---|---|
| SHA-256 | `8369bca0547312a9ba1fe95848db1387a1191c8d91e91cee137c94d9ae888644` |
| Family label | `ConnectWise` |
| File name | `~temp.msi` |
| File type | `msi` |
| First seen | `2026-06-26 18:01:49` |
| Reporter | `BastianHein_` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8394b6b5b743b2754617e284bdeed23` |
| SHA-1 | `4899938950f416eb43ad8db38133b0f622764922` |
| SHA-256 | `8369bca0547312a9ba1fe95848db1387a1191c8d91e91cee137c94d9ae888644` |
| SHA3-384 | `b359e89aa36ba5d01956b141e0ae07bdd0b44b4d4b4b4848c2d7e80fc759d1ccd895fe58ccfea4f9f7a80f3a33132c52` |
| TLSH | `T1BFA623216BF88174F1FB2A78E97D80B14A36BC648A26C05F0774395E28B0F54D6B6737` |
| SSDEEP | `196608:VnCtVYqI5MvbWEpKkqZIJqKKnCtVYqI5MvbWEpKkqdnCtVYqI5MvbWEpKkqcnCtO:lCXvI5MvHx1JwCXvI5MvHx6CXvI5MvH4` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_100_8369bca0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8369bca0547312a9ba1fe95848db1387a1191c8d91e91cee137c94d9ae888644"
    family = "ConnectWise"
    file_name = "~temp.msi"
    file_type = "msi"
    first_seen = "2026-06-26 18:01:49"
  condition:
    hash.sha256(0, filesize) == "8369bca0547312a9ba1fe95848db1387a1191c8d91e91cee137c94d9ae888644"
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
 * Generated: 2026-06-27T04:28:53.886518+00:00
 */

rule MalwareBazaar_unknown_001_7c8d8eaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
    family = "unknown"
    file_name = "TurboPay%20BD%20Reader.apk"
    file_type = "apk"
    first_seen = "2026-06-27 04:00:28"
  condition:
    hash.sha256(0, filesize) == "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
}

rule MalwareBazaar_unknown_002_ac57da29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac57da29a3b20679113c7ff33ac81c977c1b964863f8310d3fdf5b351fbfd8f2"
    family = "unknown"
    file_name = "tickr.apk"
    file_type = "apk"
    first_seen = "2026-06-27 04:00:15"
  condition:
    hash.sha256(0, filesize) == "ac57da29a3b20679113c7ff33ac81c977c1b964863f8310d3fdf5b351fbfd8f2"
}

rule MalwareBazaar_ValleyRAT_003_59afd76b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59afd76ba4c60df30d59b1cd3db92f203040ed0d4e84279434bd702c919e9273"
    family = "ValleyRAT"
    file_name = "39B698A4A2EC18E256B2AD8503DE9E4D.exe"
    file_type = "exe"
    first_seen = "2026-06-27 04:00:09"
  condition:
    hash.sha256(0, filesize) == "59afd76ba4c60df30d59b1cd3db92f203040ed0d4e84279434bd702c919e9273"
}

rule MalwareBazaar_unknown_004_1ed58d57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
    family = "unknown"
    file_name = "sms-spy-v5.apk"
    file_type = "apk"
    first_seen = "2026-06-27 04:00:08"
  condition:
    hash.sha256(0, filesize) == "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
}

rule MalwareBazaar_GuLoader_005_20dbcab2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20dbcab2dc3f9e4ec9a7d55876b536fa1fcc5f6dc00f6181b5cff7c9338f45c9"
    family = "GuLoader"
    file_name = "2f426d2fb00858d8649cf99eb2e2aac6.exe"
    file_type = "exe"
    first_seen = "2026-06-27 04:00:06"
  condition:
    hash.sha256(0, filesize) == "20dbcab2dc3f9e4ec9a7d55876b536fa1fcc5f6dc00f6181b5cff7c9338f45c9"
}

rule MalwareBazaar_unknown_006_f27b5c92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
    family = "unknown"
    file_name = "punnitoot.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:57"
  condition:
    hash.sha256(0, filesize) == "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
}

rule MalwareBazaar_unknown_007_649b4a40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649b4a4044a9ead43588f78a85576f51a63de847a4620920b06fc4da8ae2989c"
    family = "unknown"
    file_name = "Paytm (1).apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:46"
  condition:
    hash.sha256(0, filesize) == "649b4a4044a9ead43588f78a85576f51a63de847a4620920b06fc4da8ae2989c"
}

rule MalwareBazaar_unknown_008_6db0e953
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
    family = "unknown"
    file_name = "my horror Aaron 0.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:23"
  condition:
    hash.sha256(0, filesize) == "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
}

rule MalwareBazaar_unknown_009_3c29a7a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
    family = "unknown"
    file_name = "Installer.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:13"
  condition:
    hash.sha256(0, filesize) == "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
}

rule MalwareBazaar_unknown_010_99ff6067
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ff6067685b9573c9e09e61b4ed910b8a74481bec345cfaa4037ae4a1155495"
    family = "unknown"
    file_name = "emoji2entity.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:59:03"
  condition:
    hash.sha256(0, filesize) == "99ff6067685b9573c9e09e61b4ed910b8a74481bec345cfaa4037ae4a1155495"
}

rule MalwareBazaar_unknown_011_836f2b13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2"
    family = "unknown"
    file_name = "Brawl Stars Pros.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:58:57"
  condition:
    hash.sha256(0, filesize) == "836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2"
}

rule MalwareBazaar_unknown_012_f8b875e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b875e84dcd83ae2f858ea6e496da4fee407c5b6cc819563bb7ac1458729ee3"
    family = "unknown"
    file_name = "BOOYAH ZONE_2.1.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:58:47"
  condition:
    hash.sha256(0, filesize) == "f8b875e84dcd83ae2f858ea6e496da4fee407c5b6cc819563bb7ac1458729ee3"
}

rule MalwareBazaar_unknown_013_faf71cb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19"
    family = "unknown"
    file_name = "bfludo.apk"
    file_type = "apk"
    first_seen = "2026-06-27 03:58:31"
  condition:
    hash.sha256(0, filesize) == "faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19"
}

rule MalwareBazaar_unknown_014_00a99866
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1"
    family = "unknown"
    file_name = "00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1"
    file_type = "elf"
    first_seen = "2026-06-27 03:26:02"
  condition:
    hash.sha256(0, filesize) == "00a99866c7a6525cee1a3ca03c4f6362c5c94af5e52494a95f27beb2523fc6e1"
}

rule MalwareBazaar_CoinMiner_015_f3eb8798
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3eb87983169d29f6eedf685922a02146f575bcc695b4bb0fe54019f09d3e8d2"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:47:18"
  condition:
    hash.sha256(0, filesize) == "f3eb87983169d29f6eedf685922a02146f575bcc695b4bb0fe54019f09d3e8d2"
}

rule MalwareBazaar_CoinMiner_016_fa2a0934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa2a09342548fe01c57030f6d69dc38997fcd3547855701afeb6519f3e390c18"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:35:58"
  condition:
    hash.sha256(0, filesize) == "fa2a09342548fe01c57030f6d69dc38997fcd3547855701afeb6519f3e390c18"
}

rule MalwareBazaar_unknown_017_f2deee4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2deee4f7cb4770c9e909c5319ec1357cee341dd442ebf51c644d6bf16f6709f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-27 02:21:57"
  condition:
    hash.sha256(0, filesize) == "f2deee4f7cb4770c9e909c5319ec1357cee341dd442ebf51c644d6bf16f6709f"
}

rule MalwareBazaar_CoinMiner_018_ba852441
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba852441acba7f4e928215426a94f44f6f5b74dbf21b323087e007f9baf0645f"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:21:52"
  condition:
    hash.sha256(0, filesize) == "ba852441acba7f4e928215426a94f44f6f5b74dbf21b323087e007f9baf0645f"
}

rule MalwareBazaar_CoinMiner_019_40479b05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40479b05e94cf5a4895d68867d9fdaebe1e2d7f9d632b76cb57041ea1fe20c71"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 02:15:36"
  condition:
    hash.sha256(0, filesize) == "40479b05e94cf5a4895d68867d9fdaebe1e2d7f9d632b76cb57041ea1fe20c71"
}

rule MalwareBazaar_unknown_020_992c26a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "992c26a5cc1ca754400a33b9973acd1c24a26997c0a19d1e2a2feaa62586f074"
    family = "unknown"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-27 02:04:55"
  condition:
    hash.sha256(0, filesize) == "992c26a5cc1ca754400a33b9973acd1c24a26997c0a19d1e2a2feaa62586f074"
}

rule MalwareBazaar_Mirai_021_5dde1b0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dde1b0de96d85a8dd0b3582dd9d32f095d0164f2b6d73e462415046ed19af6a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-27 01:57:58"
  condition:
    hash.sha256(0, filesize) == "5dde1b0de96d85a8dd0b3582dd9d32f095d0164f2b6d73e462415046ed19af6a"
}

rule MalwareBazaar_CoinMiner_022_b626c431
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b626c4317ff6d4ca1ec04471421bef1d0261c59d77cb0bc0cf3c1e077d984865"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 01:49:26"
  condition:
    hash.sha256(0, filesize) == "b626c4317ff6d4ca1ec04471421bef1d0261c59d77cb0bc0cf3c1e077d984865"
}

rule MalwareBazaar_Mirai_023_b3f4e9f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3f4e9f001c0d227b00dad00914eddb52280dd07f92ee13e54039eae5eb32133"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-06-27 01:41:00"
  condition:
    hash.sha256(0, filesize) == "b3f4e9f001c0d227b00dad00914eddb52280dd07f92ee13e54039eae5eb32133"
}

rule MalwareBazaar_unknown_024_f04d5131
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf"
    family = "unknown"
    file_name = "Видеозапись(3).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:44"
  condition:
    hash.sha256(0, filesize) == "f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf"
}

rule MalwareBazaar_unknown_025_82621c55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82621c55f48c03093f5682ea1b3a6c5e5ac48a1c964643d7ce67fe41ccdba387"
    family = "unknown"
    file_name = "triadaShowcase.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:33"
  condition:
    hash.sha256(0, filesize) == "82621c55f48c03093f5682ea1b3a6c5e5ac48a1c964643d7ce67fe41ccdba387"
}

rule MalwareBazaar_unknown_026_906896b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc"
    family = "unknown"
    file_name = "Stealer.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:28"
  condition:
    hash.sha256(0, filesize) == "906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc"
}

rule MalwareBazaar_unknown_027_0bf4779a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bf4779a000a63a12e5d22ef884df612a5b9823ba69d008fa137312955eba65e"
    family = "unknown"
    file_name = "startuptest.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:20"
  condition:
    hash.sha256(0, filesize) == "0bf4779a000a63a12e5d22ef884df612a5b9823ba69d008fa137312955eba65e"
}

rule MalwareBazaar_unknown_028_bede3630
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e"
    family = "unknown"
    file_name = "SimpleMiner_XMR.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:13"
  condition:
    hash.sha256(0, filesize) == "bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e"
}

rule MalwareBazaar_unknown_029_fbfab254
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794"
    family = "unknown"
    file_name = "SheetCrypt.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:22:05"
  condition:
    hash.sha256(0, filesize) == "fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794"
}

rule MalwareBazaar_unknown_030_a5716058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74"
    family = "unknown"
    file_name = "PoletDidlo.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:56"
  condition:
    hash.sha256(0, filesize) == "a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74"
}

rule MalwareBazaar_unknown_031_926d3c5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b"
    family = "unknown"
    file_name = "MinvyRatClient.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:45"
  condition:
    hash.sha256(0, filesize) == "926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b"
}

rule MalwareBazaar_unknown_032_db317a9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db317a9cb1a5fe669f01022e31d426240f675c3834426b23b83bcf56a5ecaa5b"
    family = "unknown"
    file_name = "loader_1_2_9_3_Panel.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:35"
  condition:
    hash.sha256(0, filesize) == "db317a9cb1a5fe669f01022e31d426240f675c3834426b23b83bcf56a5ecaa5b"
}

rule MalwareBazaar_unknown_033_50d86324
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701"
    family = "unknown"
    file_name = "Limbo.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:29"
  condition:
    hash.sha256(0, filesize) == "50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701"
}

rule MalwareBazaar_unknown_034_23d668f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7"
    family = "unknown"
    file_name = "Eternal Hacker Panel Loader _ 1_5(fix).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:19"
  condition:
    hash.sha256(0, filesize) == "23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7"
}

rule MalwareBazaar_unknown_035_0b47e13b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b47e13b4cb4d8943f45a94f1489294f61e0715a69614bc88c195b01daae6d68"
    family = "unknown"
    file_name = "Doxgram_New_1 701 (Fix).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:09"
  condition:
    hash.sha256(0, filesize) == "0b47e13b4cb4d8943f45a94f1489294f61e0715a69614bc88c195b01daae6d68"
}

rule MalwareBazaar_unknown_036_86acd31a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0"
    family = "unknown"
    file_name = "djzrjdshks.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:21:04"
  condition:
    hash.sha256(0, filesize) == "86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0"
}

rule MalwareBazaar_unknown_037_01dcbe19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
    family = "unknown"
    file_name = "DeltaRBX(Fix53).apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:20:58"
  condition:
    hash.sha256(0, filesize) == "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
}

rule MalwareBazaar_unknown_038_590c3fd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f"
    family = "unknown"
    file_name = "apktool_1_0.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:20:48"
  condition:
    hash.sha256(0, filesize) == "590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f"
}

rule MalwareBazaar_unknown_039_11ef87f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
    family = "unknown"
    file_name = "AndUnlocker1_0.apk"
    file_type = "apk"
    first_seen = "2026-06-27 01:20:43"
  condition:
    hash.sha256(0, filesize) == "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
}

rule MalwareBazaar_unknown_040_28955cde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28955cde4d05589d984605220f120878154bc081f95ed5c982baf976dd83c4da"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-27 01:00:18"
  condition:
    hash.sha256(0, filesize) == "28955cde4d05589d984605220f120878154bc081f95ed5c982baf976dd83c4da"
}

rule MalwareBazaar_unknown_041_b18cf21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b18cf21b9e159b07778aad026f369c39bc24c4b221b9c9383497942cecbdc6d2"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-06-27 00:53:19"
  condition:
    hash.sha256(0, filesize) == "b18cf21b9e159b07778aad026f369c39bc24c4b221b9c9383497942cecbdc6d2"
}

rule MalwareBazaar_unknown_042_bca3e5ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca3e5ca3be21f841fb6f5e1bd8c0bac3850a68cdd517059783978f879b5e669"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-06-27 00:19:15"
  condition:
    hash.sha256(0, filesize) == "bca3e5ca3be21f841fb6f5e1bd8c0bac3850a68cdd517059783978f879b5e669"
}

rule MalwareBazaar_Mirai_043_de138420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de138420498fbfad575b7c47f0eb80b5196d3741e1344b2d11468ad945e2c7ec"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-27 00:09:06"
  condition:
    hash.sha256(0, filesize) == "de138420498fbfad575b7c47f0eb80b5196d3741e1344b2d11468ad945e2c7ec"
}

rule MalwareBazaar_unknown_044_8da466b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8da466b43acd48b67e37d1acb3944d966f45bef9658c835d983d2d2017ee7921"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 23:54:32"
  condition:
    hash.sha256(0, filesize) == "8da466b43acd48b67e37d1acb3944d966f45bef9658c835d983d2d2017ee7921"
}

rule MalwareBazaar_RustyStealer_045_576f3ff7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "576f3ff7e34e66f6298efbb5b9ccda4d2c27adeb9040ba9c85012c9f555f2d4f"
    family = "RustyStealer"
    file_name = "SecuriteInfo.com.Trojan.GenericKD.80634618.26841.10932"
    file_type = "exe"
    first_seen = "2026-06-26 23:48:23"
  condition:
    hash.sha256(0, filesize) == "576f3ff7e34e66f6298efbb5b9ccda4d2c27adeb9040ba9c85012c9f555f2d4f"
}

rule MalwareBazaar_RustyStealer_046_795dc624
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "795dc62407f9db38cf3aa0f70313c14776e2c8d656b5c6ca859bc0b346a204f9"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 22:49:13"
  condition:
    hash.sha256(0, filesize) == "795dc62407f9db38cf3aa0f70313c14776e2c8d656b5c6ca859bc0b346a204f9"
}

rule MalwareBazaar_Mirai_047_5b834b5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b834b5dd162fe166bd4bf2d4b41515e4b7a902566b39905c9d8cc1f89a742b8"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-26 22:37:11"
  condition:
    hash.sha256(0, filesize) == "5b834b5dd162fe166bd4bf2d4b41515e4b7a902566b39905c9d8cc1f89a742b8"
}

rule MalwareBazaar_unknown_048_2e86f0c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e86f0c9eac76638eec0a2d7c85ab569d2a012e94f44b7a6a54d0061e6834f22"
    family = "unknown"
    file_name = "prefetch_9103.bat"
    file_type = "unknown"
    first_seen = "2026-06-26 22:35:03"
  condition:
    hash.sha256(0, filesize) == "2e86f0c9eac76638eec0a2d7c85ab569d2a012e94f44b7a6a54d0061e6834f22"
}

rule MalwareBazaar_unknown_049_90a4100a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90a4100a7cd32dc4581cc636b6c06ce6caa2ff632e4319b7ce9027aab100a021"
    family = "unknown"
    file_name = "cacherelay93.dat"
    file_type = "unknown"
    first_seen = "2026-06-26 22:31:59"
  condition:
    hash.sha256(0, filesize) == "90a4100a7cd32dc4581cc636b6c06ce6caa2ff632e4319b7ce9027aab100a021"
}

rule MalwareBazaar_Gafgyt_050_1cdd7666
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cdd76661e2b39c39e2e6e52210c5f3bdc14ac0d62857583e4f4cae423ccf960"
    family = "Gafgyt"
    file_name = "x-3.2-.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:11:13"
  condition:
    hash.sha256(0, filesize) == "1cdd76661e2b39c39e2e6e52210c5f3bdc14ac0d62857583e4f4cae423ccf960"
}

rule MalwareBazaar_Gafgyt_051_8016af3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8016af3ff04c12e7c43a36aa11dce4fdd6fedc171b2e069bf625ab144f44063f"
    family = "Gafgyt"
    file_name = "a-r.m-4.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:11:11"
  condition:
    hash.sha256(0, filesize) == "8016af3ff04c12e7c43a36aa11dce4fdd6fedc171b2e069bf625ab144f44063f"
}

rule MalwareBazaar_Gafgyt_052_588da751
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "588da75109cfc5a82d79b7433218e0a891e7e987d0ab30549a348dcacc029b5a"
    family = "Gafgyt"
    file_name = "x-8.6-.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:09"
  condition:
    hash.sha256(0, filesize) == "588da75109cfc5a82d79b7433218e0a891e7e987d0ab30549a348dcacc029b5a"
}

rule MalwareBazaar_Gafgyt_053_ceade2e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ceade2e6f3cc94173e8f6a7b065f359328dfcde8dd3931beeb26822627cd343a"
    family = "Gafgyt"
    file_name = "s-h.4-.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:07"
  condition:
    hash.sha256(0, filesize) == "ceade2e6f3cc94173e8f6a7b065f359328dfcde8dd3931beeb26822627cd343a"
}

rule MalwareBazaar_Gafgyt_054_9dd42a8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dd42a8f746ee23cca69f4b1471117906c3a2868cf4e8a247b0cb39869146f21"
    family = "Gafgyt"
    file_name = "m-p.s-l.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:06"
  condition:
    hash.sha256(0, filesize) == "9dd42a8f746ee23cca69f4b1471117906c3a2868cf4e8a247b0cb39869146f21"
}

rule MalwareBazaar_Gafgyt_055_f443b4c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f443b4c302cc5f9b0b97bd8636c93a12eb21674cfbac2711e8f23b02664d149a"
    family = "Gafgyt"
    file_name = "a-r.m-5.Sakura"
    file_type = "elf"
    first_seen = "2026-06-26 22:10:05"
  condition:
    hash.sha256(0, filesize) == "f443b4c302cc5f9b0b97bd8636c93a12eb21674cfbac2711e8f23b02664d149a"
}

rule MalwareBazaar_unknown_056_7fd2a7e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fd2a7e4824e8865bfc506cd3895719ff68d082910b619917fd09941ab96542a"
    family = "unknown"
    file_name = "Check.wsf"
    file_type = "wsf"
    first_seen = "2026-06-26 22:06:28"
  condition:
    hash.sha256(0, filesize) == "7fd2a7e4824e8865bfc506cd3895719ff68d082910b619917fd09941ab96542a"
}

rule MalwareBazaar_unknown_057_aba53ac9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba53ac926aec982a32be2012d84e931a4499d8bbc5c5c652fe3928c1132c134"
    family = "unknown"
    file_name = "files.cab"
    file_type = "cab"
    first_seen = "2026-06-26 22:06:11"
  condition:
    hash.sha256(0, filesize) == "aba53ac926aec982a32be2012d84e931a4499d8bbc5c5c652fe3928c1132c134"
}

rule MalwareBazaar_CoinMiner_058_722cd9ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "722cd9ed22abf4871c76f928fde01ee5b649905765afdce51f6e56bad1d757ea"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:55:45"
  condition:
    hash.sha256(0, filesize) == "722cd9ed22abf4871c76f928fde01ee5b649905765afdce51f6e56bad1d757ea"
}

rule MalwareBazaar_unknown_059_be31cb86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be31cb864127a72378b5eb989a68f4ef52b2f09430170fd1d4d090f272d2235e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:53:56"
  condition:
    hash.sha256(0, filesize) == "be31cb864127a72378b5eb989a68f4ef52b2f09430170fd1d4d090f272d2235e"
}

rule MalwareBazaar_unknown_060_dba68027
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dba680270005c06d212e4a5f5d632f363f563c9d0c00bafc7c1a43ec2de17f48"
    family = "unknown"
    file_name = "DVSKZy.vbs"
    file_type = "vbs"
    first_seen = "2026-06-26 21:47:49"
  condition:
    hash.sha256(0, filesize) == "dba680270005c06d212e4a5f5d632f363f563c9d0c00bafc7c1a43ec2de17f48"
}

rule MalwareBazaar_unknown_061_5a478e33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a478e3305d575ebd2e29ec4bc8c5981c7e5abdaa717cd3a694b2637323516c3"
    family = "unknown"
    file_name = "hFObmbDTio.js"
    file_type = "js"
    first_seen = "2026-06-26 21:47:33"
  condition:
    hash.sha256(0, filesize) == "5a478e3305d575ebd2e29ec4bc8c5981c7e5abdaa717cd3a694b2637323516c3"
}

rule MalwareBazaar_unknown_062_903eb1ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "903eb1ce068f0d66a2215086b5d1aff18c8472833b74dad47bc5f388aaf21ca3"
    family = "unknown"
    file_name = "bPQHHcxgbPUbB.js"
    file_type = "js"
    first_seen = "2026-06-26 21:47:10"
  condition:
    hash.sha256(0, filesize) == "903eb1ce068f0d66a2215086b5d1aff18c8472833b74dad47bc5f388aaf21ca3"
}

rule MalwareBazaar_unknown_063_8e730cdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187"
    family = "unknown"
    file_name = "8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187"
    file_type = "elf"
    first_seen = "2026-06-26 21:46:02"
  condition:
    hash.sha256(0, filesize) == "8e730cdde5708b2704ac0c67d78b36fd2fcf62d195a1c056f6ee87ca655d5187"
}

rule MalwareBazaar_unknown_064_b48ff07c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48ff07c855be9ab7b513c70dadfb4d0380f78477ade7b5e424933bc82cf9664"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:16:18"
  condition:
    hash.sha256(0, filesize) == "b48ff07c855be9ab7b513c70dadfb4d0380f78477ade7b5e424933bc82cf9664"
}

rule MalwareBazaar_unknown_065_62ae6518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62ae6518076f30d48eebc7a111f2cf7df2d0f29f8a7e82d9dea57141b18fa24c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:10:45"
  condition:
    hash.sha256(0, filesize) == "62ae6518076f30d48eebc7a111f2cf7df2d0f29f8a7e82d9dea57141b18fa24c"
}

rule MalwareBazaar_unknown_066_c0975581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c097558130cf957989c38f44e1a542412c4964d380fdba85197d83d5a83a8c56"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 21:10:12"
  condition:
    hash.sha256(0, filesize) == "c097558130cf957989c38f44e1a542412c4964d380fdba85197d83d5a83a8c56"
}

rule MalwareBazaar_RustyStealer_067_39fec39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39fec39c77cc6e2ba2c37b15485d7b7e6ec51f7aea047865adc414f52422529e"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 20:52:32"
  condition:
    hash.sha256(0, filesize) == "39fec39c77cc6e2ba2c37b15485d7b7e6ec51f7aea047865adc414f52422529e"
}

rule MalwareBazaar_RustyStealer_068_e00cd20d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e00cd20d10209b8f2744523ebeb5932bdbf969dfee9ceee9aa659c0b10e3369f"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 20:52:15"
  condition:
    hash.sha256(0, filesize) == "e00cd20d10209b8f2744523ebeb5932bdbf969dfee9ceee9aa659c0b10e3369f"
}

rule MalwareBazaar_Mirai_069_2f96d422
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f96d4220d7c716ef6b0763052f8f8f4ffa296ffb8be68dbed5ea7c02887a8a5"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-26 20:31:01"
  condition:
    hash.sha256(0, filesize) == "2f96d4220d7c716ef6b0763052f8f8f4ffa296ffb8be68dbed5ea7c02887a8a5"
}

rule MalwareBazaar_Mirai_070_a150c4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a150c4ff04cd3731328486fc03598eb1f366fffc6a31f66e2b27a560769e54ce"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-06-26 20:30:03"
  condition:
    hash.sha256(0, filesize) == "a150c4ff04cd3731328486fc03598eb1f366fffc6a31f66e2b27a560769e54ce"
}

rule MalwareBazaar_Mirai_071_213825dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "213825dd74de93e765db54061e185ca92e3715775adfe2a604dc5000e31385ce"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-26 20:29:40"
  condition:
    hash.sha256(0, filesize) == "213825dd74de93e765db54061e185ca92e3715775adfe2a604dc5000e31385ce"
}

rule MalwareBazaar_Mirai_072_d2102df6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2102df636e277ae48b10aa3b957b555316ac94ddd27131c840f737d5411fedc"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-26 20:29:05"
  condition:
    hash.sha256(0, filesize) == "d2102df636e277ae48b10aa3b957b555316ac94ddd27131c840f737d5411fedc"
}

rule MalwareBazaar_Mirai_073_9d48fad7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d48fad78597d426f827c79d8c5487eef94537bdc101eedf9ae21f0e038f4edc"
    family = "Mirai"
    file_name = "barm7"
    file_type = "elf"
    first_seen = "2026-06-26 20:28:07"
  condition:
    hash.sha256(0, filesize) == "9d48fad78597d426f827c79d8c5487eef94537bdc101eedf9ae21f0e038f4edc"
}

rule MalwareBazaar_WannaCry_074_d435698c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f"
    family = "WannaCry"
    file_name = "d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f.dll"
    file_type = "dll"
    first_seen = "2026-06-26 20:28:02"
  condition:
    hash.sha256(0, filesize) == "d435698c0c6075d687fff90803c54b24fb36c95be86ffedb9befc62f0277439f"
}

rule MalwareBazaar_unknown_075_8d8cb1fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d8cb1fc6861afc1afe5facdc700272f013abd1b97c3076a309175a730917bb0"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-26 20:09:04"
  condition:
    hash.sha256(0, filesize) == "8d8cb1fc6861afc1afe5facdc700272f013abd1b97c3076a309175a730917bb0"
}

rule MalwareBazaar_Mirai_076_f271ef8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f271ef8ef53476e81b33f00aaec737e14edb942a8447e79565bb468e88ce04b5"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-26 20:04:38"
  condition:
    hash.sha256(0, filesize) == "f271ef8ef53476e81b33f00aaec737e14edb942a8447e79565bb468e88ce04b5"
}

rule MalwareBazaar_Mirai_077_dbf7bd71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf7bd71c9f72fc15797cbee3843127bb58008861cbf199181fc8d434a557e41"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-26 20:04:11"
  condition:
    hash.sha256(0, filesize) == "dbf7bd71c9f72fc15797cbee3843127bb58008861cbf199181fc8d434a557e41"
}

rule MalwareBazaar_unknown_078_7e3432ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e3432eeefe91570948db274d03fe6e0e73afd31592f5ce7244ba000e9d816ce"
    family = "unknown"
    file_name = "Request For Quotation. #IMESA.vbs"
    file_type = "vbs"
    first_seen = "2026-06-26 20:02:24"
  condition:
    hash.sha256(0, filesize) == "7e3432eeefe91570948db274d03fe6e0e73afd31592f5ce7244ba000e9d816ce"
}

rule MalwareBazaar_Amadey_079_7b7cc6dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b7cc6ddaaf7883d131dcf43677381da5707ca6d534b5b2aaae4ec9033a69ec6"
    family = "Amadey"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-26 20:01:31"
  condition:
    hash.sha256(0, filesize) == "7b7cc6ddaaf7883d131dcf43677381da5707ca6d534b5b2aaae4ec9033a69ec6"
}

rule MalwareBazaar_Mirai_080_c60d7f88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c60d7f885f481f6e8194f01551640da1e45e493c90edebeecfa0deb7a89b838a"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-26 19:59:31"
  condition:
    hash.sha256(0, filesize) == "c60d7f885f481f6e8194f01551640da1e45e493c90edebeecfa0deb7a89b838a"
}

rule MalwareBazaar_Mirai_081_18feb219
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18feb21998dca47116dafc1a73d1873514c23f4d120c8f98282d690c2c061c5f"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-26 19:58:57"
  condition:
    hash.sha256(0, filesize) == "18feb21998dca47116dafc1a73d1873514c23f4d120c8f98282d690c2c061c5f"
}

rule MalwareBazaar_Mirai_082_08b40c95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08b40c951747b139fafb060bde6c9eebcce49d0502496367edc192679d0ec790"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-26 19:45:54"
  condition:
    hash.sha256(0, filesize) == "08b40c951747b139fafb060bde6c9eebcce49d0502496367edc192679d0ec790"
}

rule MalwareBazaar_Mirai_083_f5c35c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c35c91c3890f1f1d3886dfcb6f878d2be57ecc4485542e4a5c92188488452f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-26 19:44:59"
  condition:
    hash.sha256(0, filesize) == "f5c35c91c3890f1f1d3886dfcb6f878d2be57ecc4485542e4a5c92188488452f"
}

rule MalwareBazaar_Mirai_084_7dc47862
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7dc478626946985d859ed3ff34ad2804fcf456fcba03edf43668a97dd091bf8a"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-06-26 19:40:00"
  condition:
    hash.sha256(0, filesize) == "7dc478626946985d859ed3ff34ad2804fcf456fcba03edf43668a97dd091bf8a"
}

rule MalwareBazaar_Mirai_085_1b0027fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b0027fc3d2a78fcfb4d236e5bb44370a3bd6ea107276c483fbef0daa1687c2b"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-06-26 19:39:00"
  condition:
    hash.sha256(0, filesize) == "1b0027fc3d2a78fcfb4d236e5bb44370a3bd6ea107276c483fbef0daa1687c2b"
}

rule MalwareBazaar_unknown_086_92420aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92420aeb6fcb2cbd3f8b4b645f08c9fd7173fb258439f5de6b91dc45dd72d209"
    family = "unknown"
    file_name = "a-software85659014.msi"
    file_type = "msi"
    first_seen = "2026-06-26 19:25:38"
  condition:
    hash.sha256(0, filesize) == "92420aeb6fcb2cbd3f8b4b645f08c9fd7173fb258439f5de6b91dc45dd72d209"
}

rule MalwareBazaar_unknown_087_5210829b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5210829b2e77f77fb73d91eabdb98cadad7bbff09d7a38e8c224be275d57027f"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-26 19:22:36"
  condition:
    hash.sha256(0, filesize) == "5210829b2e77f77fb73d91eabdb98cadad7bbff09d7a38e8c224be275d57027f"
}

rule MalwareBazaar_unknown_088_78b674dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78b674dc41c0396a6a0fb9777155259d46509e4370ebcab97a4807f0ddf2d539"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-26 19:22:03"
  condition:
    hash.sha256(0, filesize) == "78b674dc41c0396a6a0fb9777155259d46509e4370ebcab97a4807f0ddf2d539"
}

rule MalwareBazaar_unknown_089_8af73d55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3"
    family = "unknown"
    file_name = "8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3"
    file_type = "elf"
    first_seen = "2026-06-26 19:08:46"
  condition:
    hash.sha256(0, filesize) == "8af73d551cab2ccbb5843aab342f9094fcd76dc3aec22b97532c1d75cab0bca3"
}

rule MalwareBazaar_Mirai_090_a1913214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1913214f517254c854ebc0ca8aaac737d89a633fed786c83d2b9f6bb8b7f398"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-26 18:49:20"
  condition:
    hash.sha256(0, filesize) == "a1913214f517254c854ebc0ca8aaac737d89a633fed786c83d2b9f6bb8b7f398"
}

rule MalwareBazaar_unknown_091_1b45f9d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b45f9d89cf03c56afa6ec5cce472e4b36680d792a47f728ee30ef993cf16648"
    family = "unknown"
    file_name = "check_bot_m"
    file_type = "sh"
    first_seen = "2026-06-26 18:47:10"
  condition:
    hash.sha256(0, filesize) == "1b45f9d89cf03c56afa6ec5cce472e4b36680d792a47f728ee30ef993cf16648"
}

rule MalwareBazaar_Mirai_092_a0a88574
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0a88574ece61c4b43691f3136d01a691436f875482bc3989af0d782847508ab"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-26 18:33:41"
  condition:
    hash.sha256(0, filesize) == "a0a88574ece61c4b43691f3136d01a691436f875482bc3989af0d782847508ab"
}

rule MalwareBazaar_Mirai_093_f000c9c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f000c9c9af23d705e397a04afea2cb9be350b4d756f0d392ddff5b63755c6bc8"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-06-26 18:32:32"
  condition:
    hash.sha256(0, filesize) == "f000c9c9af23d705e397a04afea2cb9be350b4d756f0d392ddff5b63755c6bc8"
}

rule MalwareBazaar_unknown_094_15df91e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15df91e37347dcb779f9d62f9a5655fc05a6834037dca4ff13fcc8dbe92f3453"
    family = "unknown"
    file_name = "sample.ps1"
    file_type = "ps1"
    first_seen = "2026-06-26 18:28:17"
  condition:
    hash.sha256(0, filesize) == "15df91e37347dcb779f9d62f9a5655fc05a6834037dca4ff13fcc8dbe92f3453"
}

rule MalwareBazaar_unknown_095_f251d75c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f251d75cbea7ce997ba95ced1af1b852180a7e3c276e8984b0ba5c6234b7390d"
    family = "unknown"
    file_name = "David_Jones_2025_Tax_Documents.pdf.js"
    file_type = "js"
    first_seen = "2026-06-26 18:21:20"
  condition:
    hash.sha256(0, filesize) == "f251d75cbea7ce997ba95ced1af1b852180a7e3c276e8984b0ba5c6234b7390d"
}

rule MalwareBazaar_Mirai_096_5b1cd0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b1cd0bd500ca70ae871d015ea1c11b0720056a9da86b023a06024ccd6265543"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-26 18:15:59"
  condition:
    hash.sha256(0, filesize) == "5b1cd0bd500ca70ae871d015ea1c11b0720056a9da86b023a06024ccd6265543"
}

rule MalwareBazaar_Mirai_097_6b5feef2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b5feef2f1ca3e77a5b1f8e066ebe820e829793d3c4b8c68525265bfe6fc888c"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-26 18:15:11"
  condition:
    hash.sha256(0, filesize) == "6b5feef2f1ca3e77a5b1f8e066ebe820e829793d3c4b8c68525265bfe6fc888c"
}

rule MalwareBazaar_unknown_098_f801da45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f801da45bc7d36c3a81b7a23ec4ed85dea9e95b82cf2a75effb0194ea5d05b52"
    family = "unknown"
    file_name = "nettt.bat"
    file_type = "bat"
    first_seen = "2026-06-26 18:14:58"
  condition:
    hash.sha256(0, filesize) == "f801da45bc7d36c3a81b7a23ec4ed85dea9e95b82cf2a75effb0194ea5d05b52"
}

rule MalwareBazaar_unknown_099_3c54bcae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c54bcae35db1c091af07cb1fee2040430b26b1c7f2d28a3b176e211ba43ea02"
    family = "unknown"
    file_name = "runnerr.vbs"
    file_type = "vbs"
    first_seen = "2026-06-26 18:14:28"
  condition:
    hash.sha256(0, filesize) == "3c54bcae35db1c091af07cb1fee2040430b26b1c7f2d28a3b176e211ba43ea02"
}

rule MalwareBazaar_ConnectWise_100_8369bca0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8369bca0547312a9ba1fe95848db1387a1191c8d91e91cee137c94d9ae888644"
    family = "ConnectWise"
    file_name = "~temp.msi"
    file_type = "msi"
    first_seen = "2026-06-26 18:01:49"
  condition:
    hash.sha256(0, filesize) == "8369bca0547312a9ba1fe95848db1387a1191c8d91e91cee137c94d9ae888644"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

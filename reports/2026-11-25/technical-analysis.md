# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-25

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 658 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 658 |
| Unique family labels | 26 |
| Unique file types | 15 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| EasyShell | 28 |
| unknown | 27 |
| Prometei | 9 |
| Mirai | 6 |
| CoinMiner | 5 |
| ValleyRAT | 3 |
| Formbook | 2 |
| njrat | 2 |
| GuLoader | 1 |
| Grandoreiro | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 48 |
| exe | 21 |
| macho | 12 |
| js | 5 |
| apk | 3 |
| ps1 | 2 |
| jse | 1 |
| hta | 1 |
| vbs | 1 |
| docx | 1 |

## Per-Sample Analysis

### Sample 1: `3083388c43fbfd73`

| Field | Value |
|---|---|
| SHA-256 | `3083388c43fbfd73492e4def0088496951ce7c03c7581652fb473f69f67f75f9` |
| Family label | `unknown` |
| File name | `shipping documents.exe` |
| File type | `exe` |
| First seen | `2026-11-25 08:45:58` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbcd052210a78a605fd685d250b8fa7f` |
| SHA-1 | `e0687cc5411a1f4710f177aa5289812f96195b2f` |
| SHA-256 | `3083388c43fbfd73492e4def0088496951ce7c03c7581652fb473f69f67f75f9` |
| SHA3-384 | `72ea74d564b004d7f051f3c1f6e2fc928fcf70b67d8f4b85838139f3d9cc456c8f4ef41af68e96b793ac680f959363dc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12EF4F1642239CF07E8B71BF459B1E2B413F16E996931D2168FE23CDBB836B005A45763` |
| SSDEEP | `12288:hJ8qwmuXackB2+omfLMTgd+oj3pGIA3YuX705aPBcJt/EcOeS/:hJ8qwmVckMSMg1j5RaYGRZcHEo2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_3083388c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3083388c43fbfd73492e4def0088496951ce7c03c7581652fb473f69f67f75f9"
    family = "unknown"
    file_name = "shipping documents.exe"
    file_type = "exe"
    first_seen = "2026-11-25 08:45:58"
  condition:
    hash.sha256(0, filesize) == "3083388c43fbfd73492e4def0088496951ce7c03c7581652fb473f69f67f75f9"
}
```

### Sample 2: `9f7107a581cf0f4c`

| Field | Value |
|---|---|
| SHA-256 | `9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225` |
| Family label | `unknown` |
| File name | `9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225` |
| File type | `elf` |
| First seen | `2026-11-25 08:44:04` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fd9af70e0e13642927a854f213dcdb3` |
| SHA-1 | `49dee005cbd778f7e9413220614b510261b9fc69` |
| SHA-256 | `9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225` |
| SHA3-384 | `d4ce8586fe1bbd4888e36ee5798b76687d7d2d462890f8ff3357515b2d04100442634f753770071450cc585118357c15` |
| TLSH | `T17AA4237EBAE3213FF8259970770F758AD010A0E89A6F0A7B931C6A138B3D4525D75871` |
| SSDEEP | `12288:qooQepOXnbyu+aDL9nS19GEMFz3D9p4FRVeTm7H8Vaar:zo7peVVnSizT9pqHoVaar` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_9f7107a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225"
    family = "unknown"
    file_name = "9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225"
    file_type = "elf"
    first_seen = "2026-11-25 08:44:04"
  condition:
    hash.sha256(0, filesize) == "9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225"
}
```

### Sample 3: `a711f6e1c4669158`

| Field | Value |
|---|---|
| SHA-256 | `a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835` |
| Family label | `Prometei` |
| File name | `a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835` |
| File type | `elf` |
| First seen | `2026-11-25 08:23:40` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `286f91be8f00ce776f26ede71c523bf8` |
| SHA-1 | `924261e1c680977ca7a6395cb0727f436f3b14cc` |
| SHA-256 | `a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835` |
| SHA3-384 | `764f6633a5756939e374c9ed73312ee9f708babbc06f9cf176484bb1d52432d91f2e1ba27a5fe6bd7a2bee1648ebe2e5` |
| TLSH | `T1BDA4237EBAE3213FF8259970770F75CAD010A0E89A6F0A7B931C6A138B3D4525D75872` |
| SSDEEP | `12288:qooQepOXnbyu+aDL9nS19GEMFz3D9p4FRVeTm7H8Vaax:zo7peVVnSizT9pqHoVaax` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_003_a711f6e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835"
    family = "Prometei"
    file_name = "a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835"
    file_type = "elf"
    first_seen = "2026-11-25 08:23:40"
  condition:
    hash.sha256(0, filesize) == "a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835"
}
```

### Sample 4: `3c4eba6a71f4ef4e`

| Field | Value |
|---|---|
| SHA-256 | `3c4eba6a71f4ef4ee2f2d76bbbc3fbb575c35a73c6e60d2ddf9ca85862e20d57` |
| Family label | `unknown` |
| File name | `Teklif talep formu_TT-26-125924_25 11 26_07 08 17.JSE` |
| File type | `jse` |
| First seen | `2026-11-25 08:18:35` |
| Reporter | `lowmal3` |
| Tags | `jse` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `754672ff9d1b1e55817f47cc3f234d69` |
| SHA-1 | `c913c13a08b511d6b7ba177a2792db90d828a039` |
| SHA-256 | `3c4eba6a71f4ef4ee2f2d76bbbc3fbb575c35a73c6e60d2ddf9ca85862e20d57` |
| SHA3-384 | `fc0580265ddd1bb2a6eb30dd76d12785a68b20f97bb1b8b911759596c32ff3817fc126b65e16038005ff7a8dd5b33a91` |
| TLSH | `T1667134CC6C85B02496B3F33D8B6B8209E7A295632E49951578BDE2811FF143542BDFDC` |
| SSDEEP | `48:1DG5j9n2Dtb/oIJ9qGe9GmWdRIq/XGVzdY3xp:5G5jh0XRSEpGVzdY3xp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jse`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_3c4eba6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c4eba6a71f4ef4ee2f2d76bbbc3fbb575c35a73c6e60d2ddf9ca85862e20d57"
    family = "unknown"
    file_name = "Teklif talep formu_TT-26-125924_25 11 26_07 08 17.JSE"
    file_type = "jse"
    first_seen = "2026-11-25 08:18:35"
  condition:
    hash.sha256(0, filesize) == "3c4eba6a71f4ef4ee2f2d76bbbc3fbb575c35a73c6e60d2ddf9ca85862e20d57"
}
```

### Sample 5: `df074b32c21f3519`

| Field | Value |
|---|---|
| SHA-256 | `df074b32c21f3519e2e8af8ca245b5acd9dedf7408dfb9c6714309d854910afd` |
| Family label | `unknown` |
| File name | `ALMA TEKLİF İSTEĞİ.hta` |
| File type | `hta` |
| First seen | `2026-11-25 08:18:14` |
| Reporter | `lowmal3` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18ad684244d948b86edf99cc29f4860e` |
| SHA-1 | `911cbb43e056f0614e42020501e721b82065f9d5` |
| SHA-256 | `df074b32c21f3519e2e8af8ca245b5acd9dedf7408dfb9c6714309d854910afd` |
| SHA3-384 | `fbb488b56a260b94b5ccc07ea4307daeb09255ed37d2b849439e8cf0ef424894fd74879f0fd8564c5d3b00f6592bb09c` |
| TLSH | `T12EA20E045581A554977B6B37B726A8E4F7B70A6B00904A47B87CB884DFF2D0CDEE0CB6` |
| SSDEEP | `384:ilcBJZL/OHYluG0emWrzDVTchXmbyLdLi+YrkckXUmdAfc1d:ilch/OHYlugmWrXVT2XmbcdLi+YrEU3e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_df074b32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df074b32c21f3519e2e8af8ca245b5acd9dedf7408dfb9c6714309d854910afd"
    family = "unknown"
    file_name = "ALMA TEKLİF İSTEĞİ.hta"
    file_type = "hta"
    first_seen = "2026-11-25 08:18:14"
  condition:
    hash.sha256(0, filesize) == "df074b32c21f3519e2e8af8ca245b5acd9dedf7408dfb9c6714309d854910afd"
}
```

### Sample 6: `6f58f42bcfd03cc9`

| Field | Value |
|---|---|
| SHA-256 | `6f58f42bcfd03cc945ab9ecc2584acc5d60a88596a02812c5b198884705dd4bc` |
| Family label | `unknown` |
| File name | `Tax_Compliance_Checklist_AY2026-27_23Nov2026.exe` |
| File type | `exe` |
| First seen | `2026-11-25 08:13:07` |
| Reporter | `smica83` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8a27e19f3e7a44af1277a7a06708d22` |
| SHA-1 | `9de2781ce9f42db7b564509385f920f0cb3ad251` |
| SHA-256 | `6f58f42bcfd03cc945ab9ecc2584acc5d60a88596a02812c5b198884705dd4bc` |
| SHA3-384 | `5e1d748599cd63ed8398b877a6da4057b5a579c51ad72b82e80c18a9d4201b5c278fadcd4992c1f3fadb248a748935e6` |
| IMPHASH | `3cb078d56956a17a984cb9d3b39d1dcb` |
| TLSH | `T17E167D93880606E8721A172E673B332395F83D681728EDFB63A5431C3A719DCC77D5A6` |
| SSDEEP | `49152:F6i6Us6S3x0CIZZtSlCJ8JjuWIZN1voAaqkl2Xy5oMYcxrPpYxLV+wVczV80nKMJ:cif++Piwzk7Oc3JoWaV4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_6f58f42b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f58f42bcfd03cc945ab9ecc2584acc5d60a88596a02812c5b198884705dd4bc"
    family = "unknown"
    file_name = "Tax_Compliance_Checklist_AY2026-27_23Nov2026.exe"
    file_type = "exe"
    first_seen = "2026-11-25 08:13:07"
  condition:
    hash.sha256(0, filesize) == "6f58f42bcfd03cc945ab9ecc2584acc5d60a88596a02812c5b198884705dd4bc"
}
```

### Sample 7: `dc4e7316351a587b`

| Field | Value |
|---|---|
| SHA-256 | `dc4e7316351a587b808f4c563ab3e3b26440bd5cd7f4bf79575862469a37a080` |
| Family label | `GuLoader` |
| File name | `AWB#000901_25 November, 2026.vbs` |
| File type | `vbs` |
| First seen | `2026-11-25 08:11:50` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfd35a183ff5d36dc4f8471fcb5ce1a0` |
| SHA-1 | `2bc2574d4671abcbaddeeedbc68c521cecd6c5a2` |
| SHA-256 | `dc4e7316351a587b808f4c563ab3e3b26440bd5cd7f4bf79575862469a37a080` |
| SHA3-384 | `b45f67f8862e0d47fc98208a064169330b44978e7e1e6ce3349ce2d564330dbcfb5ad75d5597fd56ef72778c26362210` |
| TLSH | `T1AC035B30CD5929710C1F06E5D4B60DAACDB88065D6E3C8ACAF9EF69E081575CEB3CA35` |
| SSDEEP | `768:YpTbE4/RaHRoqHmXcLEC5LLsIwlfN237j:YtE4/RaxoqGcLifN2n` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_007_dc4e7316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc4e7316351a587b808f4c563ab3e3b26440bd5cd7f4bf79575862469a37a080"
    family = "GuLoader"
    file_name = "AWB#000901_25 November, 2026.vbs"
    file_type = "vbs"
    first_seen = "2026-11-25 08:11:50"
  condition:
    hash.sha256(0, filesize) == "dc4e7316351a587b808f4c563ab3e3b26440bd5cd7f4bf79575862469a37a080"
}
```

### Sample 8: `a14a2e6a16419d43`

| Field | Value |
|---|---|
| SHA-256 | `a14a2e6a16419d43449bfc842339db91d997880f11d2d19a37d8fdbea4690f37` |
| Family label | `unknown` |
| File name | `easyshell-l64-a14a2e6a16419d43.bin` |
| File type | `elf` |
| First seen | `2026-11-25 08:06:40` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9a4e3b7a3050ea11a4fadb1a1a37ebb` |
| SHA-1 | `423fd9ed3bafbaf65ab33b38074dd3172d2cade1` |
| SHA-256 | `a14a2e6a16419d43449bfc842339db91d997880f11d2d19a37d8fdbea4690f37` |
| SHA3-384 | `89ced69117e03372dc98ea9b68f5c1b6d8215758e0a388ee78ea387b684f3df1cc3874430a78c27c4596919a37167baa` |
| TLSH | `T113267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiXH8hIU6iKHh:OYjiiKgib9qRGcEulXcW+gh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_a14a2e6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14a2e6a16419d43449bfc842339db91d997880f11d2d19a37d8fdbea4690f37"
    family = "unknown"
    file_name = "easyshell-l64-a14a2e6a16419d43.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:06:40"
  condition:
    hash.sha256(0, filesize) == "a14a2e6a16419d43449bfc842339db91d997880f11d2d19a37d8fdbea4690f37"
}
```

### Sample 9: `6b8b73097e41aeaf`

| Field | Value |
|---|---|
| SHA-256 | `6b8b73097e41aeafe37790df90207201f8f761d74d9d1009e281c2baa959160c` |
| Family label | `unknown` |
| File name | `easyshell-l32-6b8b73097e41aeaf.bin` |
| File type | `elf` |
| First seen | `2026-11-25 08:06:23` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adbcdc0cd71be8eca52c9560fbbabf08` |
| SHA-1 | `54e8f2d9a47a0105a1cbb98c57862e4de60c18ce` |
| SHA-256 | `6b8b73097e41aeafe37790df90207201f8f761d74d9d1009e281c2baa959160c` |
| SHA3-384 | `b63544639c9976dff54fd29908eb96aaa55173fd422ff24fb760677107817d48fe2dff4849788798b91c72074e3380fa` |
| TLSH | `T1FF068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL12F3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm12db` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_6b8b7309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b8b73097e41aeafe37790df90207201f8f761d74d9d1009e281c2baa959160c"
    family = "unknown"
    file_name = "easyshell-l32-6b8b73097e41aeaf.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:06:23"
  condition:
    hash.sha256(0, filesize) == "6b8b73097e41aeafe37790df90207201f8f761d74d9d1009e281c2baa959160c"
}
```

### Sample 10: `c1e1845884d412ba`

| Field | Value |
|---|---|
| SHA-256 | `c1e1845884d412baa3f3a97b0d2cfbdea088582038ca4e1d42f0728261c5b9d8` |
| Family label | `unknown` |
| File name | `easyshell-l128-c1e1845884d412ba.bin` |
| File type | `elf` |
| First seen | `2026-11-25 08:06:12` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `633b075a21abba4f790411e22b5539f3` |
| SHA-1 | `d0696844ca01c6d3d311b73b2670cd4b67af2fec` |
| SHA-256 | `c1e1845884d412baa3f3a97b0d2cfbdea088582038ca4e1d42f0728261c5b9d8` |
| SHA3-384 | `56f6e7b4a21689ff66f7cc0cbe36bcbb8691e7b4d82fb6d0fa813dc0b8e605fef838e54d861c8352426d27830e20cb60` |
| TLSH | `T1E2067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Cs:FUkCxwUGnaPdX8PNAS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_c1e18458
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e1845884d412baa3f3a97b0d2cfbdea088582038ca4e1d42f0728261c5b9d8"
    family = "unknown"
    file_name = "easyshell-l128-c1e1845884d412ba.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:06:12"
  condition:
    hash.sha256(0, filesize) == "c1e1845884d412baa3f3a97b0d2cfbdea088582038ca4e1d42f0728261c5b9d8"
}
```

### Sample 11: `d86769fd981bacca`

| Field | Value |
|---|---|
| SHA-256 | `d86769fd981bacca5b8a1d35b8381dd3cb2c9b8e02efb3371b1e5bacd229dafd` |
| Family label | `unknown` |
| File name | `easyshell-darwin_arm64-d86769fd981bacca.bin` |
| File type | `macho` |
| First seen | `2026-11-25 08:06:03` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae4594bb62fe4a5f642a3457504a5a5c` |
| SHA-1 | `eecf969f3ee011780fadabadbd2d66b7fdf0615c` |
| SHA-256 | `d86769fd981bacca5b8a1d35b8381dd3cb2c9b8e02efb3371b1e5bacd229dafd` |
| SHA3-384 | `288d4cf703ac58ce89a01163546a159dd6b37cbdb2bd335c4fa3fbff0a82810acaf4108e6c181466e5410bd69d811051` |
| TLSH | `T15DF5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tgwsj5g5FIU6icBV8GQU5NZm+lzP:8SeI1gkkvTgwt5C+OGU5NZm+lzP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_d86769fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86769fd981bacca5b8a1d35b8381dd3cb2c9b8e02efb3371b1e5bacd229dafd"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-d86769fd981bacca.bin"
    file_type = "macho"
    first_seen = "2026-11-25 08:06:03"
  condition:
    hash.sha256(0, filesize) == "d86769fd981bacca5b8a1d35b8381dd3cb2c9b8e02efb3371b1e5bacd229dafd"
}
```

### Sample 12: `f88b52fabf1f8897`

| Field | Value |
|---|---|
| SHA-256 | `f88b52fabf1f88979791ecb456bac42d9f38c8fbfa4062d69300388ac443c851` |
| Family label | `unknown` |
| File name | `easyshell-darwin_amd64-f88b52fabf1f8897.bin` |
| File type | `macho` |
| First seen | `2026-11-25 08:05:54` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c3c1607e51f1807a7f4a3fa02a98e87` |
| SHA-1 | `8508cb3ad7fcd93982553dbd524159a338809853` |
| SHA-256 | `f88b52fabf1f88979791ecb456bac42d9f38c8fbfa4062d69300388ac443c851` |
| SHA3-384 | `c57953ea2c890910b960ad14f0b345a13910b3d6837835d4bfd1ff3cdea5f19d426814811810acdc81f3054bac1dbf50` |
| TLSH | `T170168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6VKhx+wgbZmBlzoX:kyLbLNomEr6VKjW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_f88b52fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f88b52fabf1f88979791ecb456bac42d9f38c8fbfa4062d69300388ac443c851"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-f88b52fabf1f8897.bin"
    file_type = "macho"
    first_seen = "2026-11-25 08:05:54"
  condition:
    hash.sha256(0, filesize) == "f88b52fabf1f88979791ecb456bac42d9f38c8fbfa4062d69300388ac443c851"
}
```

### Sample 13: `847580dca23dedeb`

| Field | Value |
|---|---|
| SHA-256 | `847580dca23dedeb3c8ed54d381ddf79ae50f04ba1283c79ac403c5b6b2c7ed2` |
| Family label | `unknown` |
| File name | `easyshell-a64-847580dca23dedeb.bin` |
| File type | `elf` |
| First seen | `2026-11-25 08:05:44` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73f0d330202e83233ba62d775fbdee13` |
| SHA-1 | `c757878074293ef63ca7e6ea3b40b106a1531609` |
| SHA-256 | `847580dca23dedeb3c8ed54d381ddf79ae50f04ba1283c79ac403c5b6b2c7ed2` |
| SHA3-384 | `ef39f944ab96b0f2c7fbcf8ccd52865046d2cb24137db615d16ca1325deff68ec7cfa24f284b06034cadf1db22f3e755` |
| TLSH | `T1B906B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WTGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WTLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_847580dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847580dca23dedeb3c8ed54d381ddf79ae50f04ba1283c79ac403c5b6b2c7ed2"
    family = "unknown"
    file_name = "easyshell-a64-847580dca23dedeb.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:05:44"
  condition:
    hash.sha256(0, filesize) == "847580dca23dedeb3c8ed54d381ddf79ae50f04ba1283c79ac403c5b6b2c7ed2"
}
```

### Sample 14: `ba8a39be04f3c5bc`

| Field | Value |
|---|---|
| SHA-256 | `ba8a39be04f3c5bccc8a8cefb92f876f7b167a52f28c8fad9200ce0e12fe1e1a` |
| Family label | `unknown` |
| File name | `easyshell-a32-ba8a39be04f3c5bc.bin` |
| File type | `elf` |
| First seen | `2026-11-25 08:05:36` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2750625e9312555de3ec2cdabab0c814` |
| SHA-1 | `2ca44182a127dddf1b2c884edb6c7f5d1dc6edbe` |
| SHA-256 | `ba8a39be04f3c5bccc8a8cefb92f876f7b167a52f28c8fad9200ce0e12fe1e1a` |
| SHA3-384 | `7825297bf4c4c25547ad46a178b179d388918a4c1066a0d737c029b782bdb562c8430fd716b6062ac2f66c666a127319` |
| TLSH | `T14BF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBB:FhvZpiEGUx+pVdqo2laB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_ba8a39be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba8a39be04f3c5bccc8a8cefb92f876f7b167a52f28c8fad9200ce0e12fe1e1a"
    family = "unknown"
    file_name = "easyshell-a32-ba8a39be04f3c5bc.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:05:36"
  condition:
    hash.sha256(0, filesize) == "ba8a39be04f3c5bccc8a8cefb92f876f7b167a52f28c8fad9200ce0e12fe1e1a"
}
```

### Sample 15: `b5f9a5a76df193b4`

| Field | Value |
|---|---|
| SHA-256 | `b5f9a5a76df193b4708397d8b0dd52b8004cc523d6ab921a4a56f013f7a5d532` |
| Family label | `unknown` |
| File name | `edl.apk` |
| File type | `apk` |
| First seen | `2026-11-25 07:59:13` |
| Reporter | `anonymous` |
| Tags | `apk, SHAPARAK, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d897b4bb7edeac4b0cd2bc6290d5aca4` |
| SHA-1 | `bd2f7d2cefd1997cb52c477b281eb31971d16a72` |
| SHA-256 | `b5f9a5a76df193b4708397d8b0dd52b8004cc523d6ab921a4a56f013f7a5d532` |
| SHA3-384 | `5df1563a6c03993a926781ea65c885099cda51f393b8241d8d63c5885e4b4da9bc4925531a9177ead356e83538348b5c` |
| TLSH | `T148562352FB636E9AC8F2D33110A60B3972374E0AD347974B6B74B3B8687B6D84B451C4` |
| SSDEEP | `98304:8OlssV0P+MyZ8M3IF9Ab5s1/cNkI10hNHrPBiZ98znUfQPTldseXaovsg59qVZFd:z2PE8sIUb5Q4kl/LJyKAnQao1CVXNL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_b5f9a5a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5f9a5a76df193b4708397d8b0dd52b8004cc523d6ab921a4a56f013f7a5d532"
    family = "unknown"
    file_name = "edl.apk"
    file_type = "apk"
    first_seen = "2026-11-25 07:59:13"
  condition:
    hash.sha256(0, filesize) == "b5f9a5a76df193b4708397d8b0dd52b8004cc523d6ab921a4a56f013f7a5d532"
}
```

### Sample 16: `66e35d480a91277c`

| Field | Value |
|---|---|
| SHA-256 | `66e35d480a91277ca537075c96e47fb2c30ecc529e75499d4a796008c930c656` |
| Family label | `unknown` |
| File name | `Comprobante de pago.js` |
| File type | `js` |
| First seen | `2026-11-25 07:59:04` |
| Reporter | `lowmal3` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5449fe244d21dc39139d9dc3789944ea` |
| SHA-1 | `b85fdcdf7bfe6c96f03d70f0ac5b9025eae4c24f` |
| SHA-256 | `66e35d480a91277ca537075c96e47fb2c30ecc529e75499d4a796008c930c656` |
| SHA3-384 | `dd569ee66864a7150e2335a9909b506f8fbd78de11f950a032773da6bf9092ee18fe8ad8e1b5f9ee94b79f2cc5ce68d0` |
| TLSH | `T14CA45A3A2958404BF0F38E56979B8762A197FBA2DBBA4E28C04C35DC47B31049D76FC5` |
| SSDEEP | `3072:regf+gsgBrv7EOUD92ZE0Ieupupq7tn3/ZTmzaaS+O0AhBjU2iZYC+iASgsnQtY/:QjRh8d9rw6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_66e35d48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66e35d480a91277ca537075c96e47fb2c30ecc529e75499d4a796008c930c656"
    family = "unknown"
    file_name = "Comprobante de pago.js"
    file_type = "js"
    first_seen = "2026-11-25 07:59:04"
  condition:
    hash.sha256(0, filesize) == "66e35d480a91277ca537075c96e47fb2c30ecc529e75499d4a796008c930c656"
}
```

### Sample 17: `91615ca703db2a8d`

| Field | Value |
|---|---|
| SHA-256 | `91615ca703db2a8daded79c2f8b474b46aa9d8e17ff9ca59107958b6f3cb0cd2` |
| Family label | `unknown` |
| File name | `app-V96.apk` |
| File type | `apk` |
| First seen | `2026-11-25 07:58:57` |
| Reporter | `anonymous` |
| Tags | `apk, SHAPARAK, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7aa98ee9cd39133b4268283395bebc1b` |
| SHA-1 | `1179b32a7356b1c76de9d22b90298e2455f371e7` |
| SHA-256 | `91615ca703db2a8daded79c2f8b474b46aa9d8e17ff9ca59107958b6f3cb0cd2` |
| SHA3-384 | `c5ccb39469f75c423d4d4d345fe3426559be63e00ec6cfcbf155ac254f6b373c1bdcfb399d9304bd7a579e6357243f28` |
| TLSH | `T1A9562342FB925D99CCE1C33050790B3A763A4D5AD347A74A6B39B3B42CBF7E81B81194` |
| SSDEEP | `98304:CO8PssVbayD9+My+6Z48S7i55M1DlzTiVvP2jCL0Oc42pe5CE4AC7ZPG2Mx:sPRB96zV5MDT432jCVc65YAC7ZPcx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_91615ca7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91615ca703db2a8daded79c2f8b474b46aa9d8e17ff9ca59107958b6f3cb0cd2"
    family = "unknown"
    file_name = "app-V96.apk"
    file_type = "apk"
    first_seen = "2026-11-25 07:58:57"
  condition:
    hash.sha256(0, filesize) == "91615ca703db2a8daded79c2f8b474b46aa9d8e17ff9ca59107958b6f3cb0cd2"
}
```

### Sample 18: `6677805bb1221b74`

| Field | Value |
|---|---|
| SHA-256 | `6677805bb1221b74e5d0a058af995aba96d3f9cef1b98a39c3b46dc21685f581` |
| Family label | `unknown` |
| File name | `app (2).apk` |
| File type | `apk` |
| First seen | `2026-11-25 07:58:45` |
| Reporter | `anonymous` |
| Tags | `apk, SHAPARAK, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74965bfec6c095980a1491999b385a2f` |
| SHA-1 | `4602f87c95f0a785e88ed004c97d67a6ec24336f` |
| SHA-256 | `6677805bb1221b74e5d0a058af995aba96d3f9cef1b98a39c3b46dc21685f581` |
| SHA3-384 | `7e225b1fcda79a98fcac13f88a8a67450d481ccfc582ee0f502f1ce3b1489360aa3c76af44756b899f0ddaec754453d3` |
| TLSH | `T155562306F69719CAC8F6C33150BA0F3A713B4D569307978B6735B3B828BB6E84B465D0` |
| SSDEEP | `98304:GOtrssVA+MyKK5dYKOcLcMLynAVanwmtYBUdkAUFot4cq:hrWdK5hcMLEAVjmWBHAUylq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_6677805b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6677805bb1221b74e5d0a058af995aba96d3f9cef1b98a39c3b46dc21685f581"
    family = "unknown"
    file_name = "app (2).apk"
    file_type = "apk"
    first_seen = "2026-11-25 07:58:45"
  condition:
    hash.sha256(0, filesize) == "6677805bb1221b74e5d0a058af995aba96d3f9cef1b98a39c3b46dc21685f581"
}
```

### Sample 19: `6242e88ac10b1693`

| Field | Value |
|---|---|
| SHA-256 | `6242e88ac10b16931c488ac083b430964d870593267d69dd4e1699f076613b90` |
| Family label | `unknown` |
| File name | `恒永达#CGDD#1026110131.scr` |
| File type | `exe` |
| First seen | `2026-11-25 07:58:37` |
| Reporter | `lowmal3` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7d6be1ff2d62454a7dacf7b21846be2` |
| SHA-1 | `8201ed0946f8a158b3eeea28d0cdbc6ac1ff6404` |
| SHA-256 | `6242e88ac10b16931c488ac083b430964d870593267d69dd4e1699f076613b90` |
| SHA3-384 | `753aaadbd3127235d740558fde1a7ae398de1b2cc78ebe18bc93d3bed6e1a81123020037dc96b0dcf18e9d40f81da3cc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12705F121227DCA1AD5F75BB449B0F2B017F5AE8D6632C306CFE6ADDB78667001A41393` |
| SSDEEP | `24576:GgeqwmU3eP1tTqvnCmrvYDJ1H764WLWr:Gpe1ACu0H7v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_6242e88a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6242e88ac10b16931c488ac083b430964d870593267d69dd4e1699f076613b90"
    family = "unknown"
    file_name = "恒永达#CGDD#1026110131.scr"
    file_type = "exe"
    first_seen = "2026-11-25 07:58:37"
  condition:
    hash.sha256(0, filesize) == "6242e88ac10b16931c488ac083b430964d870593267d69dd4e1699f076613b90"
}
```

### Sample 20: `b155615611b8eeec`

| Field | Value |
|---|---|
| SHA-256 | `b155615611b8eeecbd2ed132558e26ed00fbe0c3c95b9719651a63a5ff372a45` |
| Family label | `unknown` |
| File name | `Bank_Document_for_returned_transfer.docx` |
| File type | `docx` |
| First seen | `2026-11-25 07:58:15` |
| Reporter | `lowmal3` |
| Tags | `docx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ca370debbaa8ec0daf4bac3b7708e8c` |
| SHA-1 | `9dd8289485336446f32ecb30a09bc4a937332c6a` |
| SHA-256 | `b155615611b8eeecbd2ed132558e26ed00fbe0c3c95b9719651a63a5ff372a45` |
| SHA3-384 | `648055bd862a36db314165645d3dce36a13b664269181a98aa221cc729f2a0f8aa81072d790c9341050046ca4d7eff24` |
| TLSH | `T17B4623B0E30489CFE445FE2F868B2FDF1DC118F74A3806D494E851B9B5B6462626ADD3` |
| SSDEEP | `98304:P83b9OE6f3v6KrUMTZxb4H2hT2QdBbZ6BDRYKxuGTW4Oat4TL4TKnwu+VP/aophM:PooEdKwyDb8mK1RYyu0W4a0TKnwu+VP0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `docx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_b1556156
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b155615611b8eeecbd2ed132558e26ed00fbe0c3c95b9719651a63a5ff372a45"
    family = "unknown"
    file_name = "Bank_Document_for_returned_transfer.docx"
    file_type = "docx"
    first_seen = "2026-11-25 07:58:15"
  condition:
    hash.sha256(0, filesize) == "b155615611b8eeecbd2ed132558e26ed00fbe0c3c95b9719651a63a5ff372a45"
}
```

### Sample 21: `57a09a26ccdcc017`

| Field | Value |
|---|---|
| SHA-256 | `57a09a26ccdcc0170fb20747fd0d02b669af348909c09eac086a33576ba06060` |
| Family label | `unknown` |
| File name | `Nov_PO.xls` |
| File type | `xls` |
| First seen | `2026-11-25 07:57:28` |
| Reporter | `lowmal3` |
| Tags | `CVE-2017-0199, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ad90b2bb565c69e4531c07e667ed4ef` |
| SHA-1 | `08179bc1640b0ab2e911fbff8f75209f9625b708` |
| SHA-256 | `57a09a26ccdcc0170fb20747fd0d02b669af348909c09eac086a33576ba06060` |
| SHA3-384 | `6a3d032634e2412fb3f97c543c660c23cb1b50df7ae5207902634518d1eba8446403b416752ae8761f4b8a024f6c1521` |
| TLSH | `T1CFA42373F1A6DB1BDA6308318FC2A2C68B26FC6367A3DB473B45731D54B7710205A54A` |
| SSDEEP | `12288:WYvmtoT1Ges3a1hqUgi9zha0fJwDmPnZJ0VM242Mduh:3mtoRGDKnqJiRtZnb0CDPduh` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_57a09a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a09a26ccdcc0170fb20747fd0d02b669af348909c09eac086a33576ba06060"
    family = "unknown"
    file_name = "Nov_PO.xls"
    file_type = "xls"
    first_seen = "2026-11-25 07:57:28"
  condition:
    hash.sha256(0, filesize) == "57a09a26ccdcc0170fb20747fd0d02b669af348909c09eac086a33576ba06060"
}
```

### Sample 22: `b6b8799983607099`

| Field | Value |
|---|---|
| SHA-256 | `b6b8799983607099eb1badfdd0a384dffcac054668bb24398f29de6276620c8a` |
| Family label | `Formbook` |
| File name | `PI-234-821-846-289-APD0515242.JS` |
| File type | `js` |
| First seen | `2026-11-25 07:56:25` |
| Reporter | `lowmal3` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f06ff0c8d611f4c6e9248e2688bc703` |
| SHA-1 | `9d4ac5131464782a65e1459f10eb93ba08b27cef` |
| SHA-256 | `b6b8799983607099eb1badfdd0a384dffcac054668bb24398f29de6276620c8a` |
| SHA3-384 | `9a1cab420e02b8c78efad88054c27e250f2038b4806e3cf375be73a09f8e46ae8e53d5369ae21e91bc63069f931fb60a` |
| TLSH | `T149164A801110EF93A87C2E69892E6BE61FBE53679B40EA3B276C4597674CF513EDC103` |
| SSDEEP | `98304:YJy3Kwwq5bQfcIh1wgDfpnnme8C6hiyf+A53mP3divgf/P8xx4I9l6R+nAR0:PKqufc4fBmxC6hiyfm/tax4INn` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_022_b6b87999
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6b8799983607099eb1badfdd0a384dffcac054668bb24398f29de6276620c8a"
    family = "Formbook"
    file_name = "PI-234-821-846-289-APD0515242.JS"
    file_type = "js"
    first_seen = "2026-11-25 07:56:25"
  condition:
    hash.sha256(0, filesize) == "b6b8799983607099eb1badfdd0a384dffcac054668bb24398f29de6276620c8a"
}
```

### Sample 23: `72b5b777ad4c96ac`

| Field | Value |
|---|---|
| SHA-256 | `72b5b777ad4c96ac8d11ff03a7c27a3530f4d49caa7a1d1acfcbe576c2e63c59` |
| Family label | `unknown` |
| File name | `FİYAT TEKLİFİ İSTEĞİ.wsf` |
| File type | `wsf` |
| First seen | `2026-11-25 07:55:57` |
| Reporter | `lowmal3` |
| Tags | `wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d640f4ff3815598bda48f15f778392a` |
| SHA-1 | `2055fecd2b249548e3a767bbb5b64e5a74c0e176` |
| SHA-256 | `72b5b777ad4c96ac8d11ff03a7c27a3530f4d49caa7a1d1acfcbe576c2e63c59` |
| SHA3-384 | `04d33e84b2d22e9660feeb8c40ac9ecdcb34c28ee936ad88a286b8e263cff7b51d98ea73b63935c8a27da30128cd1513` |
| TLSH | `T1327142886C85B02496B3F33D8B6B8208E7A295632E49951578ECE2811FF142543BEFDC` |
| SSDEEP | `48:0DG5j9n2Dtb/oIJ9qGe9GmWdRIq/XGVzdY3xo4:cG5jh0XRSEpGVzdY3xJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_72b5b777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b5b777ad4c96ac8d11ff03a7c27a3530f4d49caa7a1d1acfcbe576c2e63c59"
    family = "unknown"
    file_name = "FİYAT TEKLİFİ İSTEĞİ.wsf"
    file_type = "wsf"
    first_seen = "2026-11-25 07:55:57"
  condition:
    hash.sha256(0, filesize) == "72b5b777ad4c96ac8d11ff03a7c27a3530f4d49caa7a1d1acfcbe576c2e63c59"
}
```

### Sample 24: `a49f43d0ae373cb3`

| Field | Value |
|---|---|
| SHA-256 | `a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357` |
| Family label | `Mirai` |
| File name | `a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357.elf` |
| File type | `elf` |
| First seen | `2026-11-25 07:52:45` |
| Reporter | `KodaDr` |
| Tags | `Backdoor, elf, Linux, Mirai, ZQAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97669d76529bc5efd4fa6506de13fb71` |
| SHA-1 | `2cbeaed3a591219c0eca708b4cb9f4e249231b89` |
| SHA-256 | `a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357` |
| SHA3-384 | `2340e7304970c36be88e3351b90bb684f79be9ad7250a3f3e05bb0766d79b657d3849224fde432d4586f5abbb1e06734` |
| TLSH | `T150368E56B4BA446ED49AC8B0438FD2129D34B49801B2753F7A445AF43F6AE701FBFB12` |
| TELFHASH | `t176e2c7340db6b46233d2d866f343e47469321c2a99f435f035426ae6dcd86c5cc7a86e` |
| SSDEEP | `98304:tVj2n2Lfa3KEAXZXjO/5xYN35vYrjuTC+OTm:HfyYN3W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_a49f43d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357"
    family = "Mirai"
    file_name = "a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357.elf"
    file_type = "elf"
    first_seen = "2026-11-25 07:52:45"
  condition:
    hash.sha256(0, filesize) == "a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357"
}
```

### Sample 25: `e63c831112c3e3b5`

| Field | Value |
|---|---|
| SHA-256 | `e63c831112c3e3b5a516909493b18f6e82bc52f98b0fb759bf2ffae8b754e1ad` |
| Family label | `Grandoreiro` |
| File name | `2026_11__1216DocMNED-Aprob_CargJ75V71211.zip` |
| File type | `zip` |
| First seen | `2026-11-25 07:43:33` |
| Reporter | `abuse_ch` |
| Tags | `geo, Grandoreiro, MEX, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34c03897151d06208ee4125c1368cc62` |
| SHA-1 | `ee7e63e731f1194d91b3ab1f20a87346deeb4d29` |
| SHA-256 | `e63c831112c3e3b5a516909493b18f6e82bc52f98b0fb759bf2ffae8b754e1ad` |
| SHA3-384 | `603787c9c6fee4d3bc82081f3e15cb61d4fc0b98336efed13eaa2b378a90c2479acca3ba54d7d116a358ba4f8ca54b8c` |
| TLSH | `T18FA6332C1F37D7D2B3AA8821D806E5F99A18643BE7A66DFDA89011C23984D47D3343D7` |
| SSDEEP | `196608:J7K6KN+gR/QWz3wiXUsXR/3tYHssiSdaTJiYCMsOQo9:RKN53wQ1h/3iMbnViksOQg` |

#### Technical Assessment

- The sample is tracked as `Grandoreiro` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Grandoreiro_025_e63c8311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e63c831112c3e3b5a516909493b18f6e82bc52f98b0fb759bf2ffae8b754e1ad"
    family = "Grandoreiro"
    file_name = "2026_11__1216DocMNED-Aprob_CargJ75V71211.zip"
    file_type = "zip"
    first_seen = "2026-11-25 07:43:33"
  condition:
    hash.sha256(0, filesize) == "e63c831112c3e3b5a516909493b18f6e82bc52f98b0fb759bf2ffae8b754e1ad"
}
```

### Sample 26: `c0cef48735277d5f`

| Field | Value |
|---|---|
| SHA-256 | `c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758` |
| Family label | `Cartastrap` |
| File name | `c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758` |
| File type | `exe` |
| First seen | `2026-11-25 07:19:58` |
| Reporter | `Threatray` |
| Tags | `Cartastrap, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `323a9c9c2c14d2ee48250a8f231e6358` |
| SHA-1 | `f4ff767d60adb6454b95428b9e71a289ec19a68f` |
| SHA-256 | `c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758` |
| SHA3-384 | `f8a0c0ca642ff033e270179b49043b467303eb86b3c6c261de7b81b47b00f1cd2e5fdc7fdd726309241ed4898567c821` |
| IMPHASH | `1efd6eaf2d313dd1eed02e8cb74b3fd2` |
| TLSH | `T1ECD58E5A677901E9D077C178CA478613FBB2B8481335ABEB1790CB662F13AE15E3E710` |
| SSDEEP | `49152:mIQjoVElXpsifwfGh5xiVuhbwGuf4PezCT41uiEBQHM7OTSHTH2n0e0ysbns0iLu:0HXzKVuhbHs4WzlsoSHTH2n0e0yI` |

#### Technical Assessment

- The sample is tracked as `Cartastrap` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Cartastrap_026_c0cef487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758"
    family = "Cartastrap"
    file_name = "c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:58"
  condition:
    hash.sha256(0, filesize) == "c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758"
}
```

### Sample 27: `2a40fe2e27978d45`

| Field | Value |
|---|---|
| SHA-256 | `2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292` |
| Family label | `SosiskaStealer` |
| File name | `2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292` |
| File type | `exe` |
| First seen | `2026-11-25 07:19:58` |
| Reporter | `Threatray` |
| Tags | `exe, SosiskaStealer, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3c96c9cc9c1111391bfca491ce4cc3b` |
| SHA-1 | `b3a2e00687d6b0d290654070b6544e67580c5d2f` |
| SHA-256 | `2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292` |
| SHA3-384 | `6ab2c8f45ce02ace92665f2574dd6be48057fd1a33280dce07de98e81cd7c25fa06d7937e8c8f3f29f1795504c03bf7c` |
| IMPHASH | `48f60777a47a93efdb3fecdae8a3451c` |
| TLSH | `T14B26E05B72A900FCD4B7C1788A566A07E6B2781513359BDF02A0466A6F33EF11E7E334` |
| SSDEEP | `98304:6omxJT8JXXjvGWhBOkjSga82jB5qn9mrgKQZ7Pe+S:bmxMz2sSgn295gXBPe+S` |

#### Technical Assessment

- The sample is tracked as `SosiskaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SosiskaStealer_027_2a40fe2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292"
    family = "SosiskaStealer"
    file_name = "2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:58"
  condition:
    hash.sha256(0, filesize) == "2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292"
}
```

### Sample 28: `5e6265477f6bba6b`

| Field | Value |
|---|---|
| SHA-256 | `5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234` |
| Family label | `unknown` |
| File name | `5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234` |
| File type | `exe` |
| First seen | `2026-11-25 07:19:51` |
| Reporter | `Threatray` |
| Tags | `exe, MenaceRAT, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `908052e4632abac0281b19f17dfe1c30` |
| SHA-1 | `1b049e4c14fe96ab703d833c6783875eb30d8ce0` |
| SHA-256 | `5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234` |
| SHA3-384 | `de8fade263d87b554e655dd598eac1cfd6aca9cc15208e47c1fe58240c27c1f450d74e88c18567b732eb31206725afae` |
| IMPHASH | `1a4b4585c0b8c28a05e9e73e9c52f883` |
| TLSH | `T139654C07E26350ECC16FC1748656A772FA30B81D49347E6E1B99DF721F20E609B2EB64` |
| SSDEEP | `24576:yXIM5IDgvBMWxQHoefF0TWHNwx+hmAkETM9HYDMTI4ojlmZc7LkutW:yXIM5ID2MWxQIeKYhRdTLMTI4oj6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5e626547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234"
    family = "unknown"
    file_name = "5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234"
}
```

### Sample 29: `8275d2f4354c9a85`

| Field | Value |
|---|---|
| SHA-256 | `8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836` |
| Family label | `YattaRAT` |
| File name | `8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836` |
| File type | `exe` |
| First seen | `2026-11-25 07:19:51` |
| Reporter | `Threatray` |
| Tags | `exe, rat, YattaRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a8d32a20d18d6c2cdf53a17bed7c729` |
| SHA-1 | `194c9737d155ccc9438884ec92e2f9df74d48a40` |
| SHA-256 | `8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836` |
| SHA3-384 | `98db32e610786e284993ccfe53fe49fde15a4d9e51e280a1cb17bc4d642bb4dee6a197e759adb6043a74ddc8af425a15` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B194020073E98A54E5FF1FB979F22258873AF7E79D13EB8D5E84506E1832380A711762` |
| SSDEEP | `12288:CWWKBliLYSLtDqMeV89bROjl/1pJIRHqPuCA6H4pD0u9eR6Ay:TtSLx7eWBRwJIRR16zuV` |

#### Technical Assessment

- The sample is tracked as `YattaRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_YattaRAT_029_8275d2f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836"
    family = "YattaRAT"
    file_name = "8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836"
}
```

### Sample 30: `d14266bd4958e2c3`

| Field | Value |
|---|---|
| SHA-256 | `d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d` |
| Family label | `RustyStealer` |
| File name | `d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d` |
| File type | `exe` |
| First seen | `2026-11-25 07:19:51` |
| Reporter | `Threatray` |
| Tags | `exe, HexionBot, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cd0c1a2a51aaea7189838a123ab29f1` |
| SHA-1 | `d544a5f98ffbf9453a9575435f8434eed98ae548` |
| SHA-256 | `d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d` |
| SHA3-384 | `7a5558c690cf7683c0fb75a8e7aa31f4fcc109f4f35faec49bd92b6283a21258bfded0aa61212a9261b2b14a51308f2b` |
| IMPHASH | `cfa88569d6c76d80499865d73b6f27f8` |
| TLSH | `T1B9666C43E35581D9D0AFC478835AE337EB72B88D0A34B6AB5BD44B122F26F906B1D705` |
| SSDEEP | `49152:KWRVOb10tPUb6afgzyY7s+Sfii5isaWimpfLNfHVQvr/8Tlp2HYXTyxvgAN2tiVZ:KWiZeUrUsisaY9HVcEAWazAwQiAv6n+` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_030_d14266bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d"
    family = "RustyStealer"
    file_name = "d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d"
}
```

### Sample 31: `14e10e84d422cdcc`

| Field | Value |
|---|---|
| SHA-256 | `14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c` |
| Family label | `unknown` |
| File name | `14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c` |
| File type | `exe` |
| First seen | `2026-11-25 07:19:51` |
| Reporter | `Threatray` |
| Tags | `CrozaRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55d96bab2ea7dc27154247a2df599e70` |
| SHA-1 | `8c4c574468cf50d4e2f6b6805a9d0ea3e302b9bb` |
| SHA-256 | `14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c` |
| SHA3-384 | `36c00cd175cec733badad6720f7d940e38c424d3d805151c9631a3213ea51cb94a81b7aab66703e1fe33ddb8f57d8cd0` |
| IMPHASH | `bb7cf6c151cde792c9735b398ab8a4e9` |
| TLSH | `T18E95D02A5F9403BDE0A7C274DEA65952E772780A03B5AEFF03D044651F276E09F3A712` |
| SSDEEP | `49152:7uLPOoR9BoPPhP/f4Ecr+YAuicUdYs2JqXv:S9ElaA29Jq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_14e10e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c"
    family = "unknown"
    file_name = "14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c"
}
```

### Sample 32: `a419da2ed7c8cf4b`

| Field | Value |
|---|---|
| SHA-256 | `a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd` |
| Family label | `Snowlight` |
| File name | `a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd` |
| File type | `elf` |
| First seen | `2026-11-25 07:08:34` |
| Reporter | `BlackdomeIntel` |
| Tags | `blackdome, elf, honeypot, Snowlight, x86_64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87cb81f509f85b7c162c18c4b5c57343` |
| SHA-1 | `afc770965d8188e2f55cf2dde2f595efecb7557f` |
| SHA-256 | `a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd` |
| SHA3-384 | `f407bc85d9b6c4731243397db830d3152efe3bfd96cd11a6a589528a1dfe5d711794a46dbd6b5678062e129049bc968c` |
| TLSH | `T135123047A2D0CE3FC8E953384467122472B794BEDF629713064855B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `192:GqnWWHFZMWT1YmN4hrsnurfjTr8sbnsl:5WWF1YmC8Oe` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_032_a419da2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd"
    family = "Snowlight"
    file_name = "a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd"
    file_type = "elf"
    first_seen = "2026-11-25 07:08:34"
  condition:
    hash.sha256(0, filesize) == "a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd"
}
```

### Sample 33: `2153ca70b9166cbe`

| Field | Value |
|---|---|
| SHA-256 | `2153ca70b9166cbe4e62b13a9dc377412a75414658a8e01c809846e4db3dbaf1` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-2153ca70b9166cbe.bin` |
| File type | `elf` |
| First seen | `2026-11-25 07:06:42` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c93eb9dc237dbc370027117d68d015ff` |
| SHA-1 | `ff65fe5f89bd6145708f7331961dc019dc46ba7f` |
| SHA-256 | `2153ca70b9166cbe4e62b13a9dc377412a75414658a8e01c809846e4db3dbaf1` |
| SHA3-384 | `7fbbee0dc466495a845830b0c2afa03bc6da0cd2f90065cf1c0179e27edf719ecb1d6de508e60f43484edca3c295f394` |
| TLSH | `T15D267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxicH8hIU6iKHh:OYjiiKgib9qRGcEulccW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_033_2153ca70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2153ca70b9166cbe4e62b13a9dc377412a75414658a8e01c809846e4db3dbaf1"
    family = "EasyShell"
    file_name = "easyshell-l64-2153ca70b9166cbe.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:42"
  condition:
    hash.sha256(0, filesize) == "2153ca70b9166cbe4e62b13a9dc377412a75414658a8e01c809846e4db3dbaf1"
}
```

### Sample 34: `43a45d15febbdd5b`

| Field | Value |
|---|---|
| SHA-256 | `43a45d15febbdd5b7bdbda332916386f74e8f8bed10b4fe8cc36e309d393cef5` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-43a45d15febbdd5b.bin` |
| File type | `elf` |
| First seen | `2026-11-25 07:06:34` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97eb5ec61741ebfedbf5d30a334179d2` |
| SHA-1 | `db101717c22522edd6b2a347e7880896294b773a` |
| SHA-256 | `43a45d15febbdd5b7bdbda332916386f74e8f8bed10b4fe8cc36e309d393cef5` |
| SHA3-384 | `a3e9af7d67a26822e30a210b8f4b2b8ccc09b3de47942b1f171bdd698ca5de219be93ce48694c50c806a7d43065479d6` |
| TLSH | `T108068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1YF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Ydb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_034_43a45d15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43a45d15febbdd5b7bdbda332916386f74e8f8bed10b4fe8cc36e309d393cef5"
    family = "EasyShell"
    file_name = "easyshell-l32-43a45d15febbdd5b.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:34"
  condition:
    hash.sha256(0, filesize) == "43a45d15febbdd5b7bdbda332916386f74e8f8bed10b4fe8cc36e309d393cef5"
}
```

### Sample 35: `f9a1fcc6d375dfbd`

| Field | Value |
|---|---|
| SHA-256 | `f9a1fcc6d375dfbd2bd08ac507f27b970448bb86657404d4217e5f2f6da9c962` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-f9a1fcc6d375dfbd.bin` |
| File type | `elf` |
| First seen | `2026-11-25 07:06:26` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6896970d224c41c2ef067dd390fb4e3` |
| SHA-1 | `7d6f9076cb5046956548049e79401f584b4ffec2` |
| SHA-256 | `f9a1fcc6d375dfbd2bd08ac507f27b970448bb86657404d4217e5f2f6da9c962` |
| SHA3-384 | `74843cf129880309a215d6a538d0cac8c185dc15ca2e8714bb92be4790a03b7608c5aefbb6db4141715c45edfa93eecd` |
| TLSH | `T139067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1Co:FUkCxwUGnaPdX8PRAS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_035_f9a1fcc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9a1fcc6d375dfbd2bd08ac507f27b970448bb86657404d4217e5f2f6da9c962"
    family = "EasyShell"
    file_name = "easyshell-l128-f9a1fcc6d375dfbd.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:26"
  condition:
    hash.sha256(0, filesize) == "f9a1fcc6d375dfbd2bd08ac507f27b970448bb86657404d4217e5f2f6da9c962"
}
```

### Sample 36: `b125a41eff1cc8ad`

| Field | Value |
|---|---|
| SHA-256 | `b125a41eff1cc8ad6eef2c2d73e82e6ad082102b953891a11d6deeab62db79fa` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-b125a41eff1cc8ad.bin` |
| File type | `macho` |
| First seen | `2026-11-25 07:06:17` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df01a8bf20f2370c71116c09d6f59736` |
| SHA-1 | `3fd68cc796884f226cb372766469f0e5553b113e` |
| SHA-256 | `b125a41eff1cc8ad6eef2c2d73e82e6ad082102b953891a11d6deeab62db79fa` |
| SHA3-384 | `e193e2d1d8d5c565185470e8a3874f4abaa0f7f970143333a8afd8bfd9aace08dc341ff7eb76078eab2e187d475b9dd3` |
| TLSH | `T102F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgQsj5g5FIU6icBV8GQU5NZm+lzJ:8SeI1gkkvTgQt5C+OGU5NZm+lzJ` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_036_b125a41e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b125a41eff1cc8ad6eef2c2d73e82e6ad082102b953891a11d6deeab62db79fa"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-b125a41eff1cc8ad.bin"
    file_type = "macho"
    first_seen = "2026-11-25 07:06:17"
  condition:
    hash.sha256(0, filesize) == "b125a41eff1cc8ad6eef2c2d73e82e6ad082102b953891a11d6deeab62db79fa"
}
```

### Sample 37: `343dc9c33446edc3`

| Field | Value |
|---|---|
| SHA-256 | `343dc9c33446edc38b4c6552f25aa805fef45911f5760990cd76982afe0587fd` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-343dc9c33446edc3.bin` |
| File type | `macho` |
| First seen | `2026-11-25 07:06:09` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `154cbff4252a848cd1248af6ae6f0e21` |
| SHA-1 | `519d1341d3406ca4dc55387b5af0f3d17aabf759` |
| SHA-256 | `343dc9c33446edc38b4c6552f25aa805fef45911f5760990cd76982afe0587fd` |
| SHA3-384 | `e21506a07a130bbb8fc35fc99b8e14086295d06b14b765763a39918554f82765b33b1d57fa24b3559294726700f2e26a` |
| TLSH | `T1A9168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6rKhx+wgbZmBlz1X:kyLbLNomEr6rKjJ` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_037_343dc9c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "343dc9c33446edc38b4c6552f25aa805fef45911f5760990cd76982afe0587fd"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-343dc9c33446edc3.bin"
    file_type = "macho"
    first_seen = "2026-11-25 07:06:09"
  condition:
    hash.sha256(0, filesize) == "343dc9c33446edc38b4c6552f25aa805fef45911f5760990cd76982afe0587fd"
}
```

### Sample 38: `c524158b7358af9f`

| Field | Value |
|---|---|
| SHA-256 | `c524158b7358af9f6c1e396c8699082c9f51c82b1daf10eb4e7f1648b8da98bb` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-c524158b7358af9f.bin` |
| File type | `elf` |
| First seen | `2026-11-25 07:06:00` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52bf8722b7fb07d97800dc368aa2732b` |
| SHA-1 | `ed29ef42b3dc205793a8f3a1e1b346017c79d2ba` |
| SHA-256 | `c524158b7358af9f6c1e396c8699082c9f51c82b1daf10eb4e7f1648b8da98bb` |
| SHA3-384 | `f8bd299ab19b474a0c66f7cffb4673125f3f3a39816715f52116395249b41bc88d491bf71bcabe7e619cf1ebabd21d06` |
| TLSH | `T1E306B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WcGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WcLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_038_c524158b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c524158b7358af9f6c1e396c8699082c9f51c82b1daf10eb4e7f1648b8da98bb"
    family = "EasyShell"
    file_name = "easyshell-a64-c524158b7358af9f.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:00"
  condition:
    hash.sha256(0, filesize) == "c524158b7358af9f6c1e396c8699082c9f51c82b1daf10eb4e7f1648b8da98bb"
}
```

### Sample 39: `148ace31d1ed0087`

| Field | Value |
|---|---|
| SHA-256 | `148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-148ace31d1ed0087.bin` |
| File type | `elf` |
| First seen | `2026-11-25 07:05:52` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21e810bab4b3c0232d94c09252f5c6af` |
| SHA-1 | `bf8140f975e254d0d51dbd27b04462c83856ebb9` |
| SHA-256 | `148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59` |
| SHA3-384 | `22645b7f09144e028ba7b37f72aefdbd570719654b06780b4f02f516c9b950c538dc97cce2843c4b5a603d66648ccea8` |
| TLSH | `T1E7F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRB5:FhvZpiEGUx+pVdqs2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_039_148ace31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59"
    family = "EasyShell"
    file_name = "easyshell-a32-148ace31d1ed0087.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:05:52"
  condition:
    hash.sha256(0, filesize) == "148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59"
}
```

### Sample 40: `f1569455e60aa562`

| Field | Value |
|---|---|
| SHA-256 | `f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b` |
| Family label | `XWorm` |
| File name | `f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b.bin` |
| File type | `bat` |
| First seen | `2026-11-25 06:59:35` |
| Reporter | `Tuxxin` |
| Tags | `bat, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d393634fb281530342ee281c20ef060` |
| SHA-1 | `540caa585e37e86348f5c570f0db4c91f45340db` |
| SHA-256 | `f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b` |
| SHA3-384 | `ba45daa4ff2897cabd42ae1c360ab75609f2df7b792f9bf528dc66405bd78dc8527d72e25bca91eac814356cc936f057` |
| TLSH | `T166246C9E388CBDBD0C3029D799B2655473C3CB532F12EBCDE1E2A9616419B6D12C5CB8` |
| SSDEEP | `6144:ZL/P54taC6DFKuci7BWU8oZ07R24qPmBwm/CTu/f:RP5HD8oSfB5gu/f` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_040_f1569455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b"
    family = "XWorm"
    file_name = "f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b.bin"
    file_type = "bat"
    first_seen = "2026-11-25 06:59:35"
  condition:
    hash.sha256(0, filesize) == "f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b"
}
```

### Sample 41: `21965e964bc0ac5e`

| Field | Value |
|---|---|
| SHA-256 | `21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f` |
| Family label | `unknown` |
| File name | `21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f.bin` |
| File type | `ps1` |
| First seen | `2026-11-25 06:59:28` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94caffbabeb3324cd2cdf621a1127730` |
| SHA-1 | `f0e0529e38e7df78ec137137aa0c2fd0bd22e04f` |
| SHA-256 | `21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f` |
| SHA3-384 | `f43b17af65a7637ebeaed898d1bf753b82b97cd61b588cf2da5a71885ff3761bb1b12e8fdd5e014cdbaff82547edd15a` |
| TLSH | `T170325121A885AB2853C75C7B68F5EC08B7208067C13D2C40F6DCD1E4AFB557CCEA9AD9` |
| SSDEEP | `192:/K1lq9rD7EDt1gwgsL1dtWStThHfv4ErWIJmsQCUHqSjifliy9yvym3QOEHSVcve:/4VgwXXlFfBMs2YOcSVMq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_21965e96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f"
    family = "unknown"
    file_name = "21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f.bin"
    file_type = "ps1"
    first_seen = "2026-11-25 06:59:28"
  condition:
    hash.sha256(0, filesize) == "21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f"
}
```

### Sample 42: `0b8e463fa3c0aa23`

| Field | Value |
|---|---|
| SHA-256 | `0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1` |
| Family label | `OverlordRAT` |
| File name | `0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1.bin` |
| File type | `ps1` |
| First seen | `2026-11-25 06:58:16` |
| Reporter | `Tuxxin` |
| Tags | `OverlordRAT, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a64afe46bf561e39f6f1e862d5241d4e` |
| SHA-1 | `4f0241ea05bee0f2e858ba68afea34b1ba0168e6` |
| SHA-256 | `0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1` |
| SHA3-384 | `d68313d05e6260436694baf3cabd45c0285e0cb14369356fc60eaaf8ef2d06246acd2562747f86712ab96fb3fc44cd27` |
| TLSH | `T10AC141A97D13746142FBA77FBED32040FA6750B7460A1C04BE9CA1451FB01B8C7A6F56` |
| SSDEEP | `96:fzDQ66oTX0YHLU/ZSDeXwXURowXeT77IwnacXA:/Q66oTX0YrUxUeX66o6eT77Da2A` |

#### Technical Assessment

- The sample is tracked as `OverlordRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_OverlordRAT_042_0b8e463f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1"
    family = "OverlordRAT"
    file_name = "0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1.bin"
    file_type = "ps1"
    first_seen = "2026-11-25 06:58:16"
  condition:
    hash.sha256(0, filesize) == "0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1"
}
```

### Sample 43: `3b05f6a220ffea2f`

| Field | Value |
|---|---|
| SHA-256 | `3b05f6a220ffea2fb7fd412eb8ac58553c28c8c18f4ae7e24c035cf14a5bab95` |
| Family label | `CoinMiner` |
| File name | `ntm.x86_64` |
| File type | `elf` |
| First seen | `2026-11-25 06:47:15` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `810ddb896321786fb063e528d0ce4af7` |
| SHA-1 | `b8c87b34311ccff8b8b1e4435791c137bdc12616` |
| SHA-256 | `3b05f6a220ffea2fb7fd412eb8ac58553c28c8c18f4ae7e24c035cf14a5bab95` |
| SHA3-384 | `005fc1103b3c643c0dd9d369aaa4eaf98f1182f186e44fce466722af75fe3cec7b2d2f50cb24cb6fb231a07c18ab0884` |
| TLSH | `T1FA167D47B69358FDC1AAC434875BD963BA30781842257A7B32A4E7312B33F615B2DF21` |
| TELFHASH | `t18951cb70179538a4b3dbf7367346d6baac331e6142e571e8ea7760e5de217c10ea2023` |
| SSDEEP | `98304:JJr5K5KAfjw2Hmey8kYxiJRKcCz5I+eFksQnzMsuOVffY:jwU2e2KTOlfY` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_043_3b05f6a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b05f6a220ffea2fb7fd412eb8ac58553c28c8c18f4ae7e24c035cf14a5bab95"
    family = "CoinMiner"
    file_name = "ntm.x86_64"
    file_type = "elf"
    first_seen = "2026-11-25 06:47:15"
  condition:
    hash.sha256(0, filesize) == "3b05f6a220ffea2fb7fd412eb8ac58553c28c8c18f4ae7e24c035cf14a5bab95"
}
```

### Sample 44: `e484645745eb24ec`

| Field | Value |
|---|---|
| SHA-256 | `e484645745eb24ecd51c16c6e83264465fc450937e58461034e7b5aefb90be40` |
| Family label | `CoinMiner` |
| File name | `meow.sh` |
| File type | `sh` |
| First seen | `2026-11-25 06:46:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d33595645e3a7a6e3609bd4e632dc48` |
| SHA-1 | `30a423b6c971a11bd182539d4fb32e7b347d43bb` |
| SHA-256 | `e484645745eb24ecd51c16c6e83264465fc450937e58461034e7b5aefb90be40` |
| SHA3-384 | `5cf63042828479bb88dd78f8dba5554b234dfa77a376d0fa839d222fbadcd24ba6d18eebed078a07bcc089e9a3d0bb9b` |
| TLSH | `T149F08CE9019AF3070714AF2DB067C284A093F3C313F08CE4E38A9DA90A49F1631F4200` |
| SSDEEP | `6:hoKS30/30PU0xkdRjS3Fc3FpLF7axF+CQjS3SyG3SexRc55xS5H3l:iE/E3xa+qlax6+iyGiASRSll` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_044_e4846457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e484645745eb24ecd51c16c6e83264465fc450937e58461034e7b5aefb90be40"
    family = "CoinMiner"
    file_name = "meow.sh"
    file_type = "sh"
    first_seen = "2026-11-25 06:46:18"
  condition:
    hash.sha256(0, filesize) == "e484645745eb24ecd51c16c6e83264465fc450937e58461034e7b5aefb90be40"
}
```

### Sample 45: `0bc8eb550d606e25`

| Field | Value |
|---|---|
| SHA-256 | `0bc8eb550d606e253b7c07a009746013814bba300851a5193f1412032a3c2018` |
| Family label | `CoinMiner` |
| File name | `ntm.x86_64` |
| File type | `elf` |
| First seen | `2026-11-25 06:46:15` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f30b78f30c95b67f4dc80c651d3bc76` |
| SHA-1 | `74600a837ea09dd69aa80dced0a9fbe8f9b97edc` |
| SHA-256 | `0bc8eb550d606e253b7c07a009746013814bba300851a5193f1412032a3c2018` |
| SHA3-384 | `425afb19f825349074a9dfc26da5c93600a8443e5f23fe80b2e981b016f769c0aae915c0b190daeb59ef8a2130e71404` |
| TLSH | `T1BD753367817D38D0F1828F21BDBF5BE4F65B891578EA3EB1990438689111D361D2B8A3` |
| SSDEEP | `49152:7LyCTKVpwOaN38zZ0XuztADYKR5ZrUqTQPUgLgX:6CyqwKPCqQPLI` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_045_0bc8eb55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc8eb550d606e253b7c07a009746013814bba300851a5193f1412032a3c2018"
    family = "CoinMiner"
    file_name = "ntm.x86_64"
    file_type = "elf"
    first_seen = "2026-11-25 06:46:15"
  condition:
    hash.sha256(0, filesize) == "0bc8eb550d606e253b7c07a009746013814bba300851a5193f1412032a3c2018"
}
```

### Sample 46: `0e5617ec91fd3714`

| Field | Value |
|---|---|
| SHA-256 | `0e5617ec91fd371456c143e4bd4e348a53c19a6a0a72e78b5efd6f087b08d235` |
| Family label | `CoinMiner` |
| File name | `ntm.arm7` |
| File type | `elf` |
| First seen | `2026-11-25 06:46:11` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7354c09f78418fcb28d8384fe3043708` |
| SHA-1 | `d513e475ceb48241f57b73d256be43633d2fe8d3` |
| SHA-256 | `0e5617ec91fd371456c143e4bd4e348a53c19a6a0a72e78b5efd6f087b08d235` |
| SHA3-384 | `5e01efa8fef2ec3b27f16eeea8687df268bce2c6182ab4b4e280da3587c446028627ab2e06c3d26fb6cc40acb03d49f7` |
| TLSH | `T12E068C85F8519F52C5C0253AF65DA288371317BEE2DA7006AE3547346BEF89B0E3B706` |
| SSDEEP | `49152:kiC4R5jnH1lAGHq0xKQW0ElRU/Uc5Rcz8rGCF:kuH1lAGHtxbW0UshF` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_046_0e5617ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e5617ec91fd371456c143e4bd4e348a53c19a6a0a72e78b5efd6f087b08d235"
    family = "CoinMiner"
    file_name = "ntm.arm7"
    file_type = "elf"
    first_seen = "2026-11-25 06:46:11"
  condition:
    hash.sha256(0, filesize) == "0e5617ec91fd371456c143e4bd4e348a53c19a6a0a72e78b5efd6f087b08d235"
}
```

### Sample 47: `c33db4ab14a5d709`

| Field | Value |
|---|---|
| SHA-256 | `c33db4ab14a5d7091e7499fe196ad3faee3dbc3b3c13b507b572bb013bab8e9f` |
| Family label | `CoinMiner` |
| File name | `ntm.aarch64` |
| File type | `elf` |
| First seen | `2026-11-25 06:46:06` |
| Reporter | `abuse_ch` |
| Tags | `CoinMiner, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `542f4123cba08f8270bce3b1fdaa8ddc` |
| SHA-1 | `ff461b544627743ca6474c7a7727431ed22c8dc0` |
| SHA-256 | `c33db4ab14a5d7091e7499fe196ad3faee3dbc3b3c13b507b572bb013bab8e9f` |
| SHA3-384 | `79301af70d4fc4c39c128a7a3ad490a7763c5630494118aedebe09b39c637735ebe4ed1aa03c3c93eb3d4cf637a816f6` |
| TLSH | `T101067C98FC0F7C12F7EBF27CAE4AA7E2762735A4E226C07779614208D2C75D4C5A1921` |
| SSDEEP | `49152:yR5C35I+b9UUzLUEuERmDcRidtc5Acr8rwe3j4R:yR5W55JRHlAcRidtpsw4` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_047_c33db4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c33db4ab14a5d7091e7499fe196ad3faee3dbc3b3c13b507b572bb013bab8e9f"
    family = "CoinMiner"
    file_name = "ntm.aarch64"
    file_type = "elf"
    first_seen = "2026-11-25 06:46:06"
  condition:
    hash.sha256(0, filesize) == "c33db4ab14a5d7091e7499fe196ad3faee3dbc3b3c13b507b572bb013bab8e9f"
}
```

### Sample 48: `cedfa1105bf8d088`

| Field | Value |
|---|---|
| SHA-256 | `cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50` |
| Family label | `unknown` |
| File name | `cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50.exe` |
| File type | `exe` |
| First seen | `2026-11-25 06:43:17` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffd467e282375f1699b5f9c1292871a1` |
| SHA-1 | `a748738f5adddd110143a28c57826adde26ff04e` |
| SHA-256 | `cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50` |
| SHA3-384 | `bbc949027249d846164ceebbdd46f3e2ef8b89e550f3eb134688982146e7a61ffdcee797e25f65b0115209f59faf12dc` |
| IMPHASH | `b6ee6e32373740c15c109bd81c37fa29` |
| TLSH | `T1FDC53365BF1EE0FDE25943B96CC21A943BF9082F0BCC21856145DFEE69AD3ED24014E6` |
| SSDEEP | `49152:Tdqa9G6ZuCW2qNeokUlYar+4C/ohXP39dL+9kSCgJskBEWFyL/EdJ5ve:vZu+UzrD/tdL+QkrFKC5ve` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_cedfa110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50"
    family = "unknown"
    file_name = "cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50.exe"
    file_type = "exe"
    first_seen = "2026-11-25 06:43:17"
  condition:
    hash.sha256(0, filesize) == "cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50"
}
```

### Sample 49: `7674b5d1f9fb1051`

| Field | Value |
|---|---|
| SHA-256 | `7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9` |
| Family label | `RemusStealer` |
| File name | `7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9.exe` |
| File type | `exe` |
| First seen | `2026-11-25 06:43:12` |
| Reporter | `Tuxxin` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bdf5e56748dfb726fd4ed5608bfa6c9` |
| SHA-1 | `4cecbc3bad48f405b4c3ff91adeec533bac1603a` |
| SHA-256 | `7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9` |
| SHA3-384 | `eca075e9ab39472c1b408cbeb23a001119d4fa2a32d56beb03735c497cba2abfd37e522124fe7873dbf7684fa6a27b1f` |
| IMPHASH | `c23fc36245d47872e84461308224c119` |
| TLSH | `T143E3D063827AD081F13B4B3C9592B9B815D43D83362665F7D0ECF144B5B1AE8A34A7E3` |
| SSDEEP | `1536:NceMUowpH37doGkOhBDGh/4VMeTsoJ92MmqMVUkyZ7+haOp3qt/dDHpvhfR1koVl:NSwFdoG1lMe7i92PDvkCSOZQhG` |
| ICON-DHASH | `ccb239b9a23986d0` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_049_7674b5d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9"
    family = "RemusStealer"
    file_name = "7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9.exe"
    file_type = "exe"
    first_seen = "2026-11-25 06:43:12"
  condition:
    hash.sha256(0, filesize) == "7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9"
}
```

### Sample 50: `77436b4781c1bb83`

| Field | Value |
|---|---|
| SHA-256 | `77436b4781c1bb83d8f00a38512600deeb80faf37a4f73202c087aa4d804a778` |
| Family label | `AsyncRAT` |
| File name | `4D4380C8BF238CEB80ACB426F99CB360.exe` |
| File type | `exe` |
| First seen | `2026-11-25 06:25:10` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d4380c8bf238ceb80acb426f99cb360` |
| SHA-1 | `620159f81023ea3879725c5b3ab7314c3b62aea2` |
| SHA-256 | `77436b4781c1bb83d8f00a38512600deeb80faf37a4f73202c087aa4d804a778` |
| SHA3-384 | `78e3c8632487c39a5887463b7eb08d4457f79ff7159479980d19b9d9fc4a5b10ced5085e3184b2163444cccb496a4adb` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14B04079C726072EFC857D4729EA86D64FA5074BB831F5213A42716ADDE0D89BCF240F2` |
| SSDEEP | `3072:XEsOra/F/kRlsbUw64SsQ8zxWUrLja4tc/fUCnjFK/huIdToTnG4kZmL5+2EOI:UsrGIwwIp81Z4YHSjG4kZmL5+OI` |
| ICON-DHASH | `eccccccccec6cccc` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_050_77436b47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77436b4781c1bb83d8f00a38512600deeb80faf37a4f73202c087aa4d804a778"
    family = "AsyncRAT"
    file_name = "4D4380C8BF238CEB80ACB426F99CB360.exe"
    file_type = "exe"
    first_seen = "2026-11-25 06:25:10"
  condition:
    hash.sha256(0, filesize) == "77436b4781c1bb83d8f00a38512600deeb80faf37a4f73202c087aa4d804a778"
}
```

### Sample 51: `69f44c38f5ee8727`

| Field | Value |
|---|---|
| SHA-256 | `69f44c38f5ee8727d58697fabf8076f3cfb12a3c5c689afdae106062a9a898e1` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:21:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a468fd79eb2a1b2d5b695cf725959fdc` |
| SHA-1 | `caf1ee991538bf8e7ac4a32f9f553060eb161bff` |
| SHA-256 | `69f44c38f5ee8727d58697fabf8076f3cfb12a3c5c689afdae106062a9a898e1` |
| SHA3-384 | `aaeb280f10ca7a9e65105961dbf5452225ffc71806b4fa870cf56ff042b21f613d743aa31212f355ab89ea68498f6088` |
| TLSH | `T12F556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSU:SDjxB4m5n8XlaPWi+d+a4TjxQP4a` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_051_69f44c38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69f44c38f5ee8727d58697fabf8076f3cfb12a3c5c689afdae106062a9a898e1"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:21:03"
  condition:
    hash.sha256(0, filesize) == "69f44c38f5ee8727d58697fabf8076f3cfb12a3c5c689afdae106062a9a898e1"
}
```

### Sample 52: `8835d0fc727a8935`

| Field | Value |
|---|---|
| SHA-256 | `8835d0fc727a8935eeb3b34aabe688a3d1746ef3b564b9dcf8d0a42d02d82909` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:20:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ccaa84601e6c30d53768ca0060bd3ec` |
| SHA-1 | `51be57af8c12b4e757cfcf4585173eb173b67cac` |
| SHA-256 | `8835d0fc727a8935eeb3b34aabe688a3d1746ef3b564b9dcf8d0a42d02d82909` |
| SHA3-384 | `37d86f99f79035132321244a64dc939b246642133c77abcf92b5f8c39e4570504c9a84e2530c11239a73059e1d4b58aa` |
| TLSH | `T174556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSU:SDjxB4m5n8XlaPWi+d+a4TjxQP4a` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_052_8835d0fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8835d0fc727a8935eeb3b34aabe688a3d1746ef3b564b9dcf8d0a42d02d82909"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:20:04"
  condition:
    hash.sha256(0, filesize) == "8835d0fc727a8935eeb3b34aabe688a3d1746ef3b564b9dcf8d0a42d02d82909"
}
```

### Sample 53: `84d8e1333a3111a3`

| Field | Value |
|---|---|
| SHA-256 | `84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715` |
| Family label | `unknown` |
| File name | `84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715.bin` |
| File type | `macho` |
| First seen | `2026-11-25 06:14:41` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6a387f416aa862c5998080fed4d8471` |
| SHA-1 | `37a4f24a746e26bfb11c75a9009d642ea6e28293` |
| SHA-256 | `84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715` |
| SHA3-384 | `79a105e264966d0fab37d0a15845bf489c53483e07b2a75dffc56a16a03f60edfdb03b5033211d9ab5b3c4dc0b943e02` |
| TLSH | `T17FE26F43675C5929D05D83BE22FB1B936609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsC2wYjqclS06W1YbqclSl:GI2n5DbDycwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_84d8e133
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715"
    family = "unknown"
    file_name = "84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:14:41"
  condition:
    hash.sha256(0, filesize) == "84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715"
}
```

### Sample 54: `4367c5d2daff410a`

| Field | Value |
|---|---|
| SHA-256 | `4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897` |
| Family label | `unknown` |
| File name | `4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897.bin` |
| File type | `macho` |
| First seen | `2026-11-25 06:14:37` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ede0a951b40d6eb02d10d8b61d2577f7` |
| SHA-1 | `24511bd3bbc805569d1ddeadd92e369181530eea` |
| SHA-256 | `4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897` |
| SHA3-384 | `6afc4112717ca3dba2e03c5917ca2cf65f793a231adc793bd873f7e9901cc0c22e43937c1c4d2414a3c7e713a8fb4821` |
| TLSH | `T129F25F139B1C1A61C15C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRWCPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfbQlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_4367c5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897"
    family = "unknown"
    file_name = "4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:14:37"
  condition:
    hash.sha256(0, filesize) == "4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897"
}
```

### Sample 55: `2d99270095e3ded6`

| Field | Value |
|---|---|
| SHA-256 | `2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1` |
| Family label | `unknown` |
| File name | `2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1.elf` |
| File type | `elf` |
| First seen | `2026-11-25 06:14:31` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08b01b84aaeb02a596ff924411667115` |
| SHA-1 | `1c70bbb6a49045bdbfcfbd45b2ab2b3c60bb7420` |
| SHA-256 | `2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1` |
| SHA3-384 | `acbe8ac4df620c3426893fd58f1ae34c5a043b95c862c64de070fdcc89aca1a0a09e328595c48c7d461220cd4cc5e89d` |
| TLSH | `T1A6E14382BDD6CE3BCCA9627A1673C6203372C551AB439B07210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScswLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv9g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_2d992700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1"
    family = "unknown"
    file_name = "2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1.elf"
    file_type = "elf"
    first_seen = "2026-11-25 06:14:31"
  condition:
    hash.sha256(0, filesize) == "2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1"
}
```

### Sample 56: `716dfa041ac5f766`

| Field | Value |
|---|---|
| SHA-256 | `716dfa041ac5f766b13081f677d2fda3caaa6c8db33db1fc419b8a3b46cce1de` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:13:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a160a0c18e83a664f2db8d235444505d` |
| SHA-1 | `09f3106e0278b33055a69c104b9eac629b2fe92c` |
| SHA-256 | `716dfa041ac5f766b13081f677d2fda3caaa6c8db33db1fc419b8a3b46cce1de` |
| SHA3-384 | `5ec38707e44169275421e98704bf6c8c4ff0bf940ca1185c33c580e9f63a75c78244ac4e118783315c6c1ca863275255` |
| TLSH | `T156556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP4S` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_056_716dfa04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716dfa041ac5f766b13081f677d2fda3caaa6c8db33db1fc419b8a3b46cce1de"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:13:05"
  condition:
    hash.sha256(0, filesize) == "716dfa041ac5f766b13081f677d2fda3caaa6c8db33db1fc419b8a3b46cce1de"
}
```

### Sample 57: `d654a2fbda840709`

| Field | Value |
|---|---|
| SHA-256 | `d654a2fbda84070911a7e0c70d408ad8fde29fb36e87fd53ddeddcae3effdabe` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:12:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dac7bf7487db12e7a96dd61f55973fc` |
| SHA-1 | `2c7d9790870e41636cc5665ded2c6e947000b17b` |
| SHA-256 | `d654a2fbda84070911a7e0c70d408ad8fde29fb36e87fd53ddeddcae3effdabe` |
| SHA3-384 | `f8f97e87ed4ee5843751c8418ec9ee83ca3dadf866757d8ad45ab49aa03dfb17b50f8d01ada66aa83852549faa836978` |
| TLSH | `T1A3556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSd:SDjxB4m5n8XlaPWi+d+a4TjxQP4r` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_057_d654a2fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d654a2fbda84070911a7e0c70d408ad8fde29fb36e87fd53ddeddcae3effdabe"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:12:04"
  condition:
    hash.sha256(0, filesize) == "d654a2fbda84070911a7e0c70d408ad8fde29fb36e87fd53ddeddcae3effdabe"
}
```

### Sample 58: `34187b2d0498767d`

| Field | Value |
|---|---|
| SHA-256 | `34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266` |
| Family label | `PureLogsStealer` |
| File name | `md5001000057909.tmp` |
| File type | `exe` |
| First seen | `2026-11-25 06:10:17` |
| Reporter | `ni_fi_70` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac19b6418e88a9cbcef375f861d70a75` |
| SHA-1 | `6a1f5730173daea10c8c93674f7d2d1e67d6b6e4` |
| SHA-256 | `34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266` |
| SHA3-384 | `5f27e8eb5b57395958b847b9861b6c3a64f44fdffb448de6dbef22655b73c599e6ab701e60b28f5a6f38cb1dbe8f5cdb` |
| IMPHASH | `c49f3890f2dbe6e16286e5baa6ee27f5` |
| TLSH | `T17F85296C5654E77389872B113C11AB9593AFA34927840934E46DE6FFFF8160E8B009FE` |
| SSDEEP | `24576:SLapcBoLTHxF7dWdaNu0sWOl7x4WZfFD3pPWX1b8jSBZV:yaqUTH9+FWOlt4CdPq1wjI` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_058_34187b2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266"
    family = "PureLogsStealer"
    file_name = "md5001000057909.tmp"
    file_type = "exe"
    first_seen = "2026-11-25 06:10:17"
  condition:
    hash.sha256(0, filesize) == "34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266"
}
```

### Sample 59: `c2ea9d3ee5df6319`

| Field | Value |
|---|---|
| SHA-256 | `c2ea9d3ee5df6319491b779039943baebd37c0789af95ec3b1bb686be6076a04` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:10:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41090f0db34959eab3d85b4333812cf2` |
| SHA-1 | `7e65825508213247996a896a5041af3d103086e6` |
| SHA-256 | `c2ea9d3ee5df6319491b779039943baebd37c0789af95ec3b1bb686be6076a04` |
| SHA3-384 | `9a389c85934a865ebd7dc3175ca61b9ae665fd51c54a75093107ed9fa3ee6e2e0d1cf0b43ca032c50a4ab98146da5bbb` |
| TLSH | `T156556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSX:SDjxB4m5n8XlaPWi+d+a4TjxQP4h` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_059_c2ea9d3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ea9d3ee5df6319491b779039943baebd37c0789af95ec3b1bb686be6076a04"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:10:04"
  condition:
    hash.sha256(0, filesize) == "c2ea9d3ee5df6319491b779039943baebd37c0789af95ec3b1bb686be6076a04"
}
```

### Sample 60: `3d2338578fafe7b6`

| Field | Value |
|---|---|
| SHA-256 | `3d2338578fafe7b6ea546b394b1681537c49d63a08cc54df917dfafb1084685d` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-3d2338578fafe7b6.bin` |
| File type | `elf` |
| First seen | `2026-11-25 06:06:25` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1619a8401e52e0a5811f4bd9f0df1acf` |
| SHA-1 | `ab90c4f5218e1bbf24e8599387fdee1d4b6b7e5e` |
| SHA-256 | `3d2338578fafe7b6ea546b394b1681537c49d63a08cc54df917dfafb1084685d` |
| SHA3-384 | `8041ce7940727ad2b21d5533838f71532a2bb809d11ed7b7449425609c48f52eea18689808d0b6a7dd125dd9eb013d25` |
| TLSH | `T1B0267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxikH8hIU6iKHh:OYjiiKgib9qRGcEulkcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_060_3d233857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d2338578fafe7b6ea546b394b1681537c49d63a08cc54df917dfafb1084685d"
    family = "EasyShell"
    file_name = "easyshell-l64-3d2338578fafe7b6.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:25"
  condition:
    hash.sha256(0, filesize) == "3d2338578fafe7b6ea546b394b1681537c49d63a08cc54df917dfafb1084685d"
}
```

### Sample 61: `89b97517500fbae1`

| Field | Value |
|---|---|
| SHA-256 | `89b97517500fbae1c6ccd966540a0e466258230950dd39dc61297612ab4fabf1` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-89b97517500fbae1.bin` |
| File type | `elf` |
| First seen | `2026-11-25 06:06:15` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9de95d6c80ac49d7bb6220909566cd71` |
| SHA-1 | `c5155f2313cb98f2bf9b8e24923b0b5d934f7cbe` |
| SHA-256 | `89b97517500fbae1c6ccd966540a0e466258230950dd39dc61297612ab4fabf1` |
| SHA3-384 | `b4d19896c348fc4f72b942df89538de4206a2705e014514d504a2dce9577955a367f46fadc05d63ec1cb838759d225a0` |
| TLSH | `T1D1068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1QF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Qdb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_061_89b97517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89b97517500fbae1c6ccd966540a0e466258230950dd39dc61297612ab4fabf1"
    family = "EasyShell"
    file_name = "easyshell-l32-89b97517500fbae1.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:15"
  condition:
    hash.sha256(0, filesize) == "89b97517500fbae1c6ccd966540a0e466258230950dd39dc61297612ab4fabf1"
}
```

### Sample 62: `4c7e02045e1b0144`

| Field | Value |
|---|---|
| SHA-256 | `4c7e02045e1b0144c03fb01997008d6b05b16e2abd9edaaaaab12692340ad978` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-4c7e02045e1b0144.bin` |
| File type | `elf` |
| First seen | `2026-11-25 06:06:07` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e82909dac037895ff1e28026583d5bd3` |
| SHA-1 | `cc8183ea75532cd68dfc4d61e62e07fb082eb670` |
| SHA-256 | `4c7e02045e1b0144c03fb01997008d6b05b16e2abd9edaaaaab12692340ad978` |
| SHA3-384 | `47f6af974022a5f5a2954928394490f082caabe4671dca7d9fca8d8a424f569929b148a71dde9b684bfd7bd1ee8fc480` |
| TLSH | `T10D067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CQ:FUkCxwUGnaPdX8PpAS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_062_4c7e0204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c7e02045e1b0144c03fb01997008d6b05b16e2abd9edaaaaab12692340ad978"
    family = "EasyShell"
    file_name = "easyshell-l128-4c7e02045e1b0144.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:07"
  condition:
    hash.sha256(0, filesize) == "4c7e02045e1b0144c03fb01997008d6b05b16e2abd9edaaaaab12692340ad978"
}
```

### Sample 63: `ac24df074c04d400`

| Field | Value |
|---|---|
| SHA-256 | `ac24df074c04d40001db0e4fee58c1ea59525303d835d78bbe00762453626231` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:06:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `720ace9658d1c9e772caa98b236f3f11` |
| SHA-1 | `9262af5a43c7208f34701020bec3943242d75e62` |
| SHA-256 | `ac24df074c04d40001db0e4fee58c1ea59525303d835d78bbe00762453626231` |
| SHA3-384 | `0a205e0e0d31e0d17db7a17f40c048506fa11e53ec115fc6aeba9b1d6946fdc6d0b6326d7d4cbadb0570a0bc2f497006` |
| TLSH | `T1A4556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS1:SDjxB4m5n8XlaPWi+d+a4TjxQP47` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_063_ac24df07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac24df074c04d40001db0e4fee58c1ea59525303d835d78bbe00762453626231"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:05"
  condition:
    hash.sha256(0, filesize) == "ac24df074c04d40001db0e4fee58c1ea59525303d835d78bbe00762453626231"
}
```

### Sample 64: `26d7fb4417082be4`

| Field | Value |
|---|---|
| SHA-256 | `26d7fb4417082be45bfe2df84fe9f40bcb1173795468d4f2e20f2305eaa3ede4` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-26d7fb4417082be4.bin` |
| File type | `macho` |
| First seen | `2026-11-25 06:05:58` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86ebd5836271d0a5999fabc92f7529ca` |
| SHA-1 | `a5d931d1a4ceb07202e30fdf18a39fb627c842cc` |
| SHA-256 | `26d7fb4417082be45bfe2df84fe9f40bcb1173795468d4f2e20f2305eaa3ede4` |
| SHA3-384 | `68f5dee7e715bf4c46c85c60cd87ce7e1f3a5342d26e48ed53b9c51dcf8abff2289ab6d662e6c4c62aaeb3cffd98cf31` |
| TLSH | `T1F9F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1Tgfsj5g5FIU6icBV8GQU5NZm+lzd:8SeI1gkkvTgft5C+OGU5NZm+lzd` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_064_26d7fb44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26d7fb4417082be45bfe2df84fe9f40bcb1173795468d4f2e20f2305eaa3ede4"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-26d7fb4417082be4.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:05:58"
  condition:
    hash.sha256(0, filesize) == "26d7fb4417082be45bfe2df84fe9f40bcb1173795468d4f2e20f2305eaa3ede4"
}
```

### Sample 65: `9a3849a97ae51bbd`

| Field | Value |
|---|---|
| SHA-256 | `9a3849a97ae51bbd26952ffa98b4002de7eddfcce61a6e08ac9c6c766a2886a3` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-9a3849a97ae51bbd.bin` |
| File type | `macho` |
| First seen | `2026-11-25 06:05:49` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c29048d178ffec36005a0e0eb048ad03` |
| SHA-1 | `cceba2b9415663fb1d9f429a89031a23cfa114a9` |
| SHA-256 | `9a3849a97ae51bbd26952ffa98b4002de7eddfcce61a6e08ac9c6c766a2886a3` |
| SHA3-384 | `5e11523e894c0123399757293e97444cb0995253b579f0ca65e9bc92cc91cc34e91b08dc03893328cf301b229836d226` |
| TLSH | `T192168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6GKhx+wgbZmBlzwX:kyLbLNomEr6GKjm` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_065_9a3849a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a3849a97ae51bbd26952ffa98b4002de7eddfcce61a6e08ac9c6c766a2886a3"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-9a3849a97ae51bbd.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:05:49"
  condition:
    hash.sha256(0, filesize) == "9a3849a97ae51bbd26952ffa98b4002de7eddfcce61a6e08ac9c6c766a2886a3"
}
```

### Sample 66: `e4a723cc2824f9e5`

| Field | Value |
|---|---|
| SHA-256 | `e4a723cc2824f9e59e1f4be9e43c5d8e0116e2e5ef7ae47ee3037d77d1f456e1` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-e4a723cc2824f9e5.bin` |
| File type | `elf` |
| First seen | `2026-11-25 06:05:40` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f0d56e16b3f65bf0313379db7946099` |
| SHA-1 | `26c35a50daccf50a495996518345d00cf54169aa` |
| SHA-256 | `e4a723cc2824f9e59e1f4be9e43c5d8e0116e2e5ef7ae47ee3037d77d1f456e1` |
| SHA3-384 | `ace92d6e0f653af5d16527231dae4314c85bbdd45e929aef4b2356974052f72fd7478d31145fa7af19f1cf139fc3f18c` |
| TLSH | `T1F506B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WBGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WBLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_066_e4a723cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4a723cc2824f9e59e1f4be9e43c5d8e0116e2e5ef7ae47ee3037d77d1f456e1"
    family = "EasyShell"
    file_name = "easyshell-a64-e4a723cc2824f9e5.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:05:40"
  condition:
    hash.sha256(0, filesize) == "e4a723cc2824f9e59e1f4be9e43c5d8e0116e2e5ef7ae47ee3037d77d1f456e1"
}
```

### Sample 67: `9dea04bc898c1236`

| Field | Value |
|---|---|
| SHA-256 | `9dea04bc898c12369b7377981314bbda32c91c336c26e1b5124794d50fffa9d6` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-9dea04bc898c1236.bin` |
| File type | `elf` |
| First seen | `2026-11-25 06:05:32` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c325b650b1c2b7bd82fd92bf8d8faf00` |
| SHA-1 | `ff0ea63767428635b35554727f011bcef2087650` |
| SHA-256 | `9dea04bc898c12369b7377981314bbda32c91c336c26e1b5124794d50fffa9d6` |
| SHA3-384 | `78793b4d6bf542c8f0e7f2ca8d6a12e7394fbad77d5228c94354682b5db488fe3679b7f4e164d2129f88dde63263845a` |
| TLSH | `T1EEF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRB2:FhvZpiEGUx+pVdqV2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_067_9dea04bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dea04bc898c12369b7377981314bbda32c91c336c26e1b5124794d50fffa9d6"
    family = "EasyShell"
    file_name = "easyshell-a32-9dea04bc898c1236.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:05:32"
  condition:
    hash.sha256(0, filesize) == "9dea04bc898c12369b7377981314bbda32c91c336c26e1b5124794d50fffa9d6"
}
```

### Sample 68: `faea3cff49817239`

| Field | Value |
|---|---|
| SHA-256 | `faea3cff4981723910b6fdd3ec6f86fe141f587205d50a6b40d46cc3be862211` |
| Family label | `Mirai` |
| File name | `parm6` |
| File type | `elf` |
| First seen | `2026-11-25 06:05:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63f2a3d559cc7765c8f37c1aeab30eb7` |
| SHA-1 | `ed8a1677a9e016dc247651764853c6de80a6931f` |
| SHA-256 | `faea3cff4981723910b6fdd3ec6f86fe141f587205d50a6b40d46cc3be862211` |
| SHA3-384 | `069dad125fa92c30e914e1e7bdddd395b4534d90dce4ca95ff69a73707f33934944f5659c1254550be22389ba0da99a4` |
| TLSH | `T17C542A02EA428E53C4C10779BA9F82553333EB6493DB7302DA14AFB43F877AD0E6A555` |
| TELFHASH | `t1928133648a3c0599ee238c1598e957a3554bf52a22d5ff2aff26cccc044d42ef119c0f` |
| SSDEEP | `6144:qEN8gKLOnhClUpXi4UayOx3SsCeamstbUGecCHaLhlmoVA4HZleeeVL9x:qEN8gKLOhCepXnUatvam2DLhlmoVA4Ho` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_faea3cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faea3cff4981723910b6fdd3ec6f86fe141f587205d50a6b40d46cc3be862211"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-11-25 06:05:04"
  condition:
    hash.sha256(0, filesize) == "faea3cff4981723910b6fdd3ec6f86fe141f587205d50a6b40d46cc3be862211"
}
```

### Sample 69: `7b267670d293f475`

| Field | Value |
|---|---|
| SHA-256 | `7b267670d293f475c15ce9933b78d04fba3d07360591759f80c80ea0184a6473` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 06:02:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc6abe44d7f99f2d8d0088dd11bf1b3f` |
| SHA-1 | `ed9cc7c060306c950fbba37c8f12227ca1b27bac` |
| SHA-256 | `7b267670d293f475c15ce9933b78d04fba3d07360591759f80c80ea0184a6473` |
| SHA3-384 | `e58bdc15c5978410922fc357978ba09f976ce99fab39f12a702742e093cc52acd64f0ae9c2ddaabe11781bc7d3584dae` |
| TLSH | `T1B0556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSz:SDjxB4m5n8XlaPWi+d+a4TjxQP4V` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_069_7b267670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b267670d293f475c15ce9933b78d04fba3d07360591759f80c80ea0184a6473"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:02:04"
  condition:
    hash.sha256(0, filesize) == "7b267670d293f475c15ce9933b78d04fba3d07360591759f80c80ea0184a6473"
}
```

### Sample 70: `5dc385f71a8553af`

| Field | Value |
|---|---|
| SHA-256 | `5dc385f71a8553af1e111cfa2602500f15df13eb473427eba584599f15139d05` |
| Family label | `Mirai` |
| File name | `pppc` |
| File type | `elf` |
| First seen | `2026-11-25 06:00:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a39a57cd672f8e3446ce57bc5bd0633` |
| SHA-1 | `8da3ea8134f38a31512f1ff8141a9a9af0d4b06d` |
| SHA-256 | `5dc385f71a8553af1e111cfa2602500f15df13eb473427eba584599f15139d05` |
| SHA3-384 | `d2493cc008da7f05bb5f44c2b0b4e8138652f08f97025b965bf085df0d87cf62301318b060718a3b0612ca3cb8f6a440` |
| TLSH | `T1E7344C02731C0E43C1675EF026F717F0C3EBE96119A6A245F61EBE885272FB56849F89` |
| TELFHASH | `t1bc8121648a3c05d9ae238d1594e96ba3155bf52a22d5ff2aff26cccc044e42df119d0f` |
| SSDEEP | `6144:uZAk6HuT/xwFJmFkzKwl+ATqNPO5JCqC5434IIWYwdE:3uT+qkvl+AeNPO5JCqC5434IIWYwdE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_5dc385f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dc385f71a8553af1e111cfa2602500f15df13eb473427eba584599f15139d05"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-11-25 06:00:05"
  condition:
    hash.sha256(0, filesize) == "5dc385f71a8553af1e111cfa2602500f15df13eb473427eba584599f15139d05"
}
```

### Sample 71: `b05622a8ae11254a`

| Field | Value |
|---|---|
| SHA-256 | `b05622a8ae11254a0e2ebed7fb3b7dfbadce25d8752d2016636b26f74bfe4036` |
| Family label | `WARDENStealer` |
| File name | `apple.exe` |
| File type | `exe` |
| First seen | `2026-11-25 05:52:25` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d44ec58a59629a18f02ead78ab25f4c0` |
| SHA-1 | `3ad3e418d85bc68d051c2d7897f79ae12395c1f8` |
| SHA-256 | `b05622a8ae11254a0e2ebed7fb3b7dfbadce25d8752d2016636b26f74bfe4036` |
| SHA3-384 | `b2b622a00db2600b2194022a05eb08b0e34f7805f7608b9e108b959b5c0f11d2f708f14d25dba12d368246810dbf8c8b` |
| IMPHASH | `1a51aa43794c9e2d51ea15e34f28738b` |
| TLSH | `T1D4150117F79684EEC516C63485115632F6A37C532B60AFFF17981B2E1E3AAD08B39B10` |
| SSDEEP | `12288:8mvP7NANe2KGWYSVevfexfZ+Ds4WwaAOAWZNL0GN9Ejrn8/cegSIwJdBjs8u:zvP7ekIie3e2s4pQzL1EnmJ` |
| ICON-DHASH | `0004586150580200` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_071_b05622a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b05622a8ae11254a0e2ebed7fb3b7dfbadce25d8752d2016636b26f74bfe4036"
    family = "WARDENStealer"
    file_name = "apple.exe"
    file_type = "exe"
    first_seen = "2026-11-25 05:52:25"
  condition:
    hash.sha256(0, filesize) == "b05622a8ae11254a0e2ebed7fb3b7dfbadce25d8752d2016636b26f74bfe4036"
}
```

### Sample 72: `25cede1ceb17e1bd`

| Field | Value |
|---|---|
| SHA-256 | `25cede1ceb17e1bdb2a2ae0c285f191b6cccbf4ee9b62f13586258d1c2d1cae7` |
| Family label | `njrat` |
| File name | `1f0cf7c981b81f2a93081f755ff564c0.exe` |
| File type | `exe` |
| First seen | `2026-11-25 05:50:14` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f0cf7c981b81f2a93081f755ff564c0` |
| SHA-1 | `cca64def8dcefb11ce0046780cef544768bd952e` |
| SHA-256 | `25cede1ceb17e1bdb2a2ae0c285f191b6cccbf4ee9b62f13586258d1c2d1cae7` |
| SHA3-384 | `c394af8eac56351124c94fe4c23021745ad6609eb98d625a87f9451f7b09a8064c8526f2034ab05b43b41ae282119fe1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B1A2184DB7588618C3AE1A7809F3232487F1F68B8951DF4B1CDA50DA6F236D06642AFD` |
| SSDEEP | `384:vW6JwUSlWXMpv7MQTmKB4Xf5hsbNmH5aOWQ+dcs//34LAZSTb7Ng:+6JwUqWXsv7MQTmKQhOMZWQuHqx+` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_072_25cede1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25cede1ceb17e1bdb2a2ae0c285f191b6cccbf4ee9b62f13586258d1c2d1cae7"
    family = "njrat"
    file_name = "1f0cf7c981b81f2a93081f755ff564c0.exe"
    file_type = "exe"
    first_seen = "2026-11-25 05:50:14"
  condition:
    hash.sha256(0, filesize) == "25cede1ceb17e1bdb2a2ae0c285f191b6cccbf4ee9b62f13586258d1c2d1cae7"
}
```

### Sample 73: `164acbea4d0e5be3`

| Field | Value |
|---|---|
| SHA-256 | `164acbea4d0e5be341a566e76c95cde397150e04306055b0ae2662338057dbad` |
| Family label | `njrat` |
| File name | `B1C70C924159FB4972812B09BCAC92B8.exe` |
| File type | `exe` |
| First seen | `2026-11-25 05:50:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1c70c924159fb4972812b09bcac92b8` |
| SHA-1 | `891c97c3966b5b80877f2a8ee4dbb04ba7b7c010` |
| SHA-256 | `164acbea4d0e5be341a566e76c95cde397150e04306055b0ae2662338057dbad` |
| SHA3-384 | `5abdbb7235e0e90363fb85c0c865ffc024a1690a37aee03bfe06ffc0b65dde7df90a68f42c4c60112df78a5df12f78a7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1927302513A0D01A3E91B03B34DE3B3C3673C794BA2AA4E7CB6698737462236D1D496E0` |
| SSDEEP | `1536:6iyuvq6MRb/VmTnbgELK7dXbKYdXGuPvZn3gNFCM77u/jCh/Jxs84SgPoqeX:1Wb/QzbRkdLjdWuHZnQNMs7u/jon4SgS` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_073_164acbea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "164acbea4d0e5be341a566e76c95cde397150e04306055b0ae2662338057dbad"
    family = "njrat"
    file_name = "B1C70C924159FB4972812B09BCAC92B8.exe"
    file_type = "exe"
    first_seen = "2026-11-25 05:50:10"
  condition:
    hash.sha256(0, filesize) == "164acbea4d0e5be341a566e76c95cde397150e04306055b0ae2662338057dbad"
}
```

### Sample 74: `df1c696372f8fe3a`

| Field | Value |
|---|---|
| SHA-256 | `df1c696372f8fe3a879ae71d2133146a63cfdd3034152263757ae17f7fe587cc` |
| Family label | `Mirai` |
| File name | `parm5` |
| File type | `elf` |
| First seen | `2026-11-25 05:50:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `429aedc4d1a80e2fcd71773a84f52777` |
| SHA-1 | `f13a09e72c8caec25d5b34f9cacda3f5a854b8ad` |
| SHA-256 | `df1c696372f8fe3a879ae71d2133146a63cfdd3034152263757ae17f7fe587cc` |
| SHA3-384 | `8cebf06d1016a13586300a5f19b7461cfd1427c69f14f745e6c281477f7e7743e505beb0872a943e4deac4e1f405de41` |
| TLSH | `T1F7342C01B9514E53C5C32BB7F7DF42993736B76897DB3302EA14AEB42F4669E0D2A201` |
| TELFHASH | `t1c98122648a3c05d9ae238d1594e967a3155bf52a22d5ff2aff26cccc044e42df119d0f` |
| SSDEEP | `6144:HEcEMHR84fWq7n9kMhUIo3Rg1XO5CZqPZ+cs0548k+ME:HEV884eq79NSIsg1XO5CZqP8cs0548kW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_df1c6963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df1c696372f8fe3a879ae71d2133146a63cfdd3034152263757ae17f7fe587cc"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-11-25 05:50:04"
  condition:
    hash.sha256(0, filesize) == "df1c696372f8fe3a879ae71d2133146a63cfdd3034152263757ae17f7fe587cc"
}
```

### Sample 75: `6a649ff069e5be45`

| Field | Value |
|---|---|
| SHA-256 | `6a649ff069e5be459760ad418bb28cc875a75cd166cc18377c7cbc5dfc644fec` |
| Family label | `Mirai` |
| File name | `parm7` |
| File type | `elf` |
| First seen | `2026-11-25 05:48:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1e7cbe4125fe7de650366fc49a8835e` |
| SHA-1 | `d26a74093d9f915d1c86cc556b682dc884d4f174` |
| SHA-256 | `6a649ff069e5be459760ad418bb28cc875a75cd166cc18377c7cbc5dfc644fec` |
| SHA3-384 | `e66ae90347a30891bba66eb354562beeedb7c5f328759d22535fcedf91e9cd1a6fedf51ec33f4d24072610c16da91c03` |
| TLSH | `T18D442946FB404A13C4D61779FA9F42453333E7A8D3EB73069928AFB03B8775A0E62605` |
| TELFHASH | `t1d2410d758b2455266a61dc14cafe93a2241edb175344fe37df26c48c180544fe62bc4f` |
| SSDEEP | `6144:/0utnSmEvDtgSep9n5akPUE/goC+hpx1fFAMlHYonV/GV7AmT2cuqs:/0utnSmEvDtmp9n5avE/goC+hfBLd/0u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_6a649ff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a649ff069e5be459760ad418bb28cc875a75cd166cc18377c7cbc5dfc644fec"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-11-25 05:48:05"
  condition:
    hash.sha256(0, filesize) == "6a649ff069e5be459760ad418bb28cc875a75cd166cc18377c7cbc5dfc644fec"
}
```

### Sample 76: `f69e738accb80a2d`

| Field | Value |
|---|---|
| SHA-256 | `f69e738accb80a2d63a7ff32dd0c206402981750ea897536ca64396250760bc7` |
| Family label | `Mirai` |
| File name | `pmpsl` |
| File type | `elf` |
| First seen | `2026-11-25 05:42:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `333cbadb44a09f2c70f0e1f59a8e2b82` |
| SHA-1 | `b74260b5893e2abec81858875630123c6388cbfb` |
| SHA-256 | `f69e738accb80a2d63a7ff32dd0c206402981750ea897536ca64396250760bc7` |
| SHA3-384 | `e8d2f1d25f96b58867e428322f870858b9c0a0291d178ab90718fa6c5c27edbc27098eed281af6a9ec1ccff1c7c3cceb` |
| TLSH | `T140640A07BF510FF7D89BCE3702EB0B1125CDE41627A62B367238E968B94A58E15D3C64` |
| TELFHASH | `t1c98122648a3c05d9ae238d1594e967a3155bf52a22d5ff2aff26cccc044e42df119d0f` |
| SSDEEP | `6144:DvQNZSt1mLAfd0jCTb41+Ha4iNr+LOmkSOCCioleM3/6zcLHp:wSrmydqC41NRNKLOmkSOCCioleM3/6zS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f69e738a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f69e738accb80a2d63a7ff32dd0c206402981750ea897536ca64396250760bc7"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-11-25 05:42:04"
  condition:
    hash.sha256(0, filesize) == "f69e738accb80a2d63a7ff32dd0c206402981750ea897536ca64396250760bc7"
}
```

### Sample 77: `396b0309097455be`

| Field | Value |
|---|---|
| SHA-256 | `396b0309097455beb9b3c37425b295d9131278bbe7d0a36b0258bdfc1285c9f3` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-25 05:41:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `586b1878153ebdba8de69faffb9697ed` |
| SHA-1 | `ec76e6670bf187cd60fe3e02c521139d5e6bf5d7` |
| SHA-256 | `396b0309097455beb9b3c37425b295d9131278bbe7d0a36b0258bdfc1285c9f3` |
| SHA3-384 | `f13edba1a901a168e2e49abb266a5c53ebe1dd15a33705aa27d2b8976349494e838ab2bd6562c0fad3cac6fab08bc2fe` |
| TLSH | `T19B556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSo:SDjxB4m5n8XlaPWi+d+a4TjxQP4C` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_077_396b0309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "396b0309097455beb9b3c37425b295d9131278bbe7d0a36b0258bdfc1285c9f3"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 05:41:05"
  condition:
    hash.sha256(0, filesize) == "396b0309097455beb9b3c37425b295d9131278bbe7d0a36b0258bdfc1285c9f3"
}
```

### Sample 78: `92fc740036a655dc`

| Field | Value |
|---|---|
| SHA-256 | `92fc740036a655dc8154fb421e268e99a19ac86216d42b06faefe3401de86b27` |
| Family label | `Panchan` |
| File name | `sshd` |
| File type | `elf` |
| First seen | `2026-11-25 05:34:55` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot, Panchan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `258df828cb583c39dff1840d6c0f1537` |
| SHA-1 | `87016bace7d1e3e20898671ba0e9f25d5e030298` |
| SHA-256 | `92fc740036a655dc8154fb421e268e99a19ac86216d42b06faefe3401de86b27` |
| SHA3-384 | `ed87945c19e8dc4ab469fe34d9e9c662e708c2a1ad8c25d0cbeb74e29258117dd1676bf56fcec3543c8129de1eaae9d2` |
| TLSH | `T184A68CB3945324D8E1A989B4D11416527DBC3C8B5738A3C7BAC471F65BBABE48E38730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ2:cqYUQuVDt0TZER` |

#### Technical Assessment

- The sample is tracked as `Panchan` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Panchan_078_92fc7400
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92fc740036a655dc8154fb421e268e99a19ac86216d42b06faefe3401de86b27"
    family = "Panchan"
    file_name = "sshd"
    file_type = "elf"
    first_seen = "2026-11-25 05:34:55"
  condition:
    hash.sha256(0, filesize) == "92fc740036a655dc8154fb421e268e99a19ac86216d42b06faefe3401de86b27"
}
```

### Sample 79: `ed759c79fad1765c`

| Field | Value |
|---|---|
| SHA-256 | `ed759c79fad1765c38af744424dc5f763739f4cb82f7654f46d8c2badd611071` |
| Family label | `LunexStealer` |
| File name | `img_49811.NRIw62Nn.js.part` |
| File type | `js` |
| First seen | `2026-11-25 05:30:27` |
| Reporter | `ni_fi_70` |
| Tags | `js, LunexStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5f92261ff2a4961cf3daa6aff511ffa` |
| SHA-1 | `73876028ff8d0bd1e2e20892e3ff4b615fdb9e38` |
| SHA-256 | `ed759c79fad1765c38af744424dc5f763739f4cb82f7654f46d8c2badd611071` |
| SHA3-384 | `43205cae162223359182d9b4c035ab06e75aa84bacbe354b3fbc140b12a53e55ecd6c6c8a2877539fa712aefd078a657` |
| TLSH | `T1FAE70067A9CC07B743D38A95BE6E4296753E92383385A108D1FEC094315C9FC23BB5A7` |
| SSDEEP | `49152:HzgF259A0lvmLVFmhy8dJ9NGvrXIB3If+2gHaTOoMICFe2YayknNg0QDwcrEEXIe:OL` |

#### Technical Assessment

- The sample is tracked as `LunexStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LunexStealer_079_ed759c79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed759c79fad1765c38af744424dc5f763739f4cb82f7654f46d8c2badd611071"
    family = "LunexStealer"
    file_name = "img_49811.NRIw62Nn.js.part"
    file_type = "js"
    first_seen = "2026-11-25 05:30:27"
  condition:
    hash.sha256(0, filesize) == "ed759c79fad1765c38af744424dc5f763739f4cb82f7654f46d8c2badd611071"
}
```

### Sample 80: `6cf2378146c16033`

| Field | Value |
|---|---|
| SHA-256 | `6cf2378146c160333d0534920a53683b33d83b29cafe8d87887e19d9d832d3c7` |
| Family label | `Formbook` |
| File name | `md5001006330883.tmp` |
| File type | `js` |
| First seen | `2026-11-25 05:30:19` |
| Reporter | `ni_fi_70` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81bdb11c9e289dd1559a714669b68e7a` |
| SHA-1 | `c6871be7807a12c24127011342b3bfa74dbc48bf` |
| SHA-256 | `6cf2378146c160333d0534920a53683b33d83b29cafe8d87887e19d9d832d3c7` |
| SHA3-384 | `6517f5c13eea55809e937f1a068dae01b7ec85d9e772dd0cf0442c92ac610c1a922026cec5238bc62c48dd99d2d0683a` |
| TLSH | `T110F122C95D6560759A73B33E8F3BC60DE76A086B0502C216749C93C91FB439442E9EFE` |
| SSDEEP | `96:T/Xaeu2aldggZPL8iqY9VGM9NxMNPD2bGvsgmz7ziEBzc0Eqft9u5:ba9lT8H2R99FCEBQel98` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_080_6cf23781
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cf2378146c160333d0534920a53683b33d83b29cafe8d87887e19d9d832d3c7"
    family = "Formbook"
    file_name = "md5001006330883.tmp"
    file_type = "js"
    first_seen = "2026-11-25 05:30:19"
  condition:
    hash.sha256(0, filesize) == "6cf2378146c160333d0534920a53683b33d83b29cafe8d87887e19d9d832d3c7"
}
```

### Sample 81: `9499481dcee9eb0c`

| Field | Value |
|---|---|
| SHA-256 | `9499481dcee9eb0c20741c6c50b3d60a521e3200872de1e383c7230d1ca5327d` |
| Family label | `DarkCloud` |
| File name | `_00089` |
| File type | `js` |
| First seen | `2026-11-25 05:30:17` |
| Reporter | `ni_fi_70` |
| Tags | `DarkCloud, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3147b19a06563d926ca34feb5a4a0e6e` |
| SHA-1 | `775651c0aae35c00122949d49dd77c67de5c1233` |
| SHA-256 | `9499481dcee9eb0c20741c6c50b3d60a521e3200872de1e383c7230d1ca5327d` |
| SHA3-384 | `2f440f13d0d6503e38226167d2f64bf1e2f58e5bacf6c9becc649396040ac7b56155aeea1ffaa4ecfbb36339a4bafa37` |
| TLSH | `T136A412D15BCA99AF4178C971082E6F1E7BD4A782A8481E4F557EB1C71BBB7200706CCD` |
| SSDEEP | `12288:mvPXsmsCWKplLea1faF/PRarL/ssOLcw1rNuIyAZDF:mvP87C3eCfaFBC/FovNyCF` |

#### Technical Assessment

- The sample is tracked as `DarkCloud` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCloud_081_9499481d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9499481dcee9eb0c20741c6c50b3d60a521e3200872de1e383c7230d1ca5327d"
    family = "DarkCloud"
    file_name = "_00089"
    file_type = "js"
    first_seen = "2026-11-25 05:30:17"
  condition:
    hash.sha256(0, filesize) == "9499481dcee9eb0c20741c6c50b3d60a521e3200872de1e383c7230d1ca5327d"
}
```

### Sample 82: `387eddd8854615ce`

| Field | Value |
|---|---|
| SHA-256 | `387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c` |
| Family label | `WannaCry` |
| File name | `387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c` |
| File type | `exe` |
| First seen | `2026-11-25 05:15:13` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef93841039bf4ca290a70ac7cd07dd18` |
| SHA-1 | `4f77ee023eb0f805a3e3bc1c8cd8e4390b713665` |
| SHA-256 | `387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c` |
| SHA3-384 | `797d1a6945f9f66dd5aade49c268525225c06ba99e37a9ce64e48f0b4da33c047194792d08ed858165b5dbc6ea52764d` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1FE36235E326C91BCD107233594B38E27E7B37C5A22B99B0F4B54867A0E03795AF64B13` |
| SSDEEP | `24576:jbLgWbLgddQhfdmMSirYbcMNgef0QeQjG/D8kIqRYoAdNLKz6626:jnXnAQqMSPbcBVQej/1INR` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_082_387eddd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c"
    family = "WannaCry"
    file_name = "387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c"
    file_type = "exe"
    first_seen = "2026-11-25 05:15:13"
  condition:
    hash.sha256(0, filesize) == "387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c"
}
```

### Sample 83: `19fb8f7f65015f2a`

| Field | Value |
|---|---|
| SHA-256 | `19fb8f7f65015f2ac118fb49fe67359e73fb33f7b9920fd55961a7217034dcc9` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-19fb8f7f65015f2a.bin` |
| File type | `elf` |
| First seen | `2026-11-25 05:06:56` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `410bd1e03bc4e9600e122a9c021ac236` |
| SHA-1 | `a737e48d31b5c32e123ec1ff91e46854861ee776` |
| SHA-256 | `19fb8f7f65015f2ac118fb49fe67359e73fb33f7b9920fd55961a7217034dcc9` |
| SHA3-384 | `6ff256907460092354366af8b4110861645da55361c9b140114c61f1e8931069a0e3e6d4f3a59cdc4e1448ce506e9643` |
| TLSH | `T1D4267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxiNH8hIU6iKHh:OYjiiKgib9qRGcEulNcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_083_19fb8f7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fb8f7f65015f2ac118fb49fe67359e73fb33f7b9920fd55961a7217034dcc9"
    family = "EasyShell"
    file_name = "easyshell-l64-19fb8f7f65015f2a.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:06:56"
  condition:
    hash.sha256(0, filesize) == "19fb8f7f65015f2ac118fb49fe67359e73fb33f7b9920fd55961a7217034dcc9"
}
```

### Sample 84: `fb1f94db812a22bc`

| Field | Value |
|---|---|
| SHA-256 | `fb1f94db812a22bc4ccb6e5b9291e08d09c450f24088934d5fc49edf12bc4dc8` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-fb1f94db812a22bc.bin` |
| File type | `elf` |
| First seen | `2026-11-25 05:06:46` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bed0510e01d9d1a1930534090cf9d386` |
| SHA-1 | `2024c7c7a2ae8da6fa8b12c5e2012880c038c6a7` |
| SHA-256 | `fb1f94db812a22bc4ccb6e5b9291e08d09c450f24088934d5fc49edf12bc4dc8` |
| SHA3-384 | `f4dc44507af4574975a923183a43f846fde38511bb8e22c7fd347bc63ee05415ddec60383dd7abe4ac7decb57f986cd3` |
| TLSH | `T12C068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1AF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1Adb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_084_fb1f94db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb1f94db812a22bc4ccb6e5b9291e08d09c450f24088934d5fc49edf12bc4dc8"
    family = "EasyShell"
    file_name = "easyshell-l32-fb1f94db812a22bc.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:06:46"
  condition:
    hash.sha256(0, filesize) == "fb1f94db812a22bc4ccb6e5b9291e08d09c450f24088934d5fc49edf12bc4dc8"
}
```

### Sample 85: `bb7f9a6f535d69d8`

| Field | Value |
|---|---|
| SHA-256 | `bb7f9a6f535d69d8e4c1a41465f65341bd29253f71929046db6059d3de2529a2` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-bb7f9a6f535d69d8.bin` |
| File type | `elf` |
| First seen | `2026-11-25 05:06:37` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9bc23935d653f6fd18b322cabd9954e` |
| SHA-1 | `7f3fe863a7de15eca6b37bdc45844ece346e3ad9` |
| SHA-256 | `bb7f9a6f535d69d8e4c1a41465f65341bd29253f71929046db6059d3de2529a2` |
| SHA3-384 | `33667d47d71e82f4d3c6987c3767f73c4d6798357743b4fdffb5f972ab8c5367612ec5783773054bb78d6996b3357714` |
| TLSH | `T114067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CY:FUkCxwUGnaPdX8PBAS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_085_bb7f9a6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb7f9a6f535d69d8e4c1a41465f65341bd29253f71929046db6059d3de2529a2"
    family = "EasyShell"
    file_name = "easyshell-l128-bb7f9a6f535d69d8.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:06:37"
  condition:
    hash.sha256(0, filesize) == "bb7f9a6f535d69d8e4c1a41465f65341bd29253f71929046db6059d3de2529a2"
}
```

### Sample 86: `455aa926a1fd86b7`

| Field | Value |
|---|---|
| SHA-256 | `455aa926a1fd86b74b4bff9dc6f48c7e5a7d38e8061049714d82f0aabe29eecd` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-455aa926a1fd86b7.bin` |
| File type | `macho` |
| First seen | `2026-11-25 05:06:25` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `92e7afe9f658edb84ea554dab19e8555` |
| SHA-1 | `fd52e1386f1608e52b125eed30dfce08c0718efd` |
| SHA-256 | `455aa926a1fd86b74b4bff9dc6f48c7e5a7d38e8061049714d82f0aabe29eecd` |
| SHA3-384 | `a1a68d707a80bf4365950a37267d029a5e3344e55f7af96531167870967803ca51e36d2391c243ea58b5abdcae8aa299` |
| TLSH | `T1A7F5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgOsj5g5FIU6icBV8GQU5NZm+lzo:8SeI1gkkvTgOt5C+OGU5NZm+lzo` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_086_455aa926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "455aa926a1fd86b74b4bff9dc6f48c7e5a7d38e8061049714d82f0aabe29eecd"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-455aa926a1fd86b7.bin"
    file_type = "macho"
    first_seen = "2026-11-25 05:06:25"
  condition:
    hash.sha256(0, filesize) == "455aa926a1fd86b74b4bff9dc6f48c7e5a7d38e8061049714d82f0aabe29eecd"
}
```

### Sample 87: `84b60ee64966e9d8`

| Field | Value |
|---|---|
| SHA-256 | `84b60ee64966e9d84fa06c2e982f0ea14febda2b0a701797f86195887249d6ec` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-84b60ee64966e9d8.bin` |
| File type | `macho` |
| First seen | `2026-11-25 05:06:13` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8226f316644b3fec78182e6bfb9d730f` |
| SHA-1 | `31419aea8742121123404ace0260c1bb7b59e6ec` |
| SHA-256 | `84b60ee64966e9d84fa06c2e982f0ea14febda2b0a701797f86195887249d6ec` |
| SHA3-384 | `3a712d2832c729ed395a0526a3b167c17d5eae893feba2f48b5dbb4abe21f2b0106e9687439cb97ff2beeef96d43c55b` |
| TLSH | `T104168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6YKhx+wgbZmBlzlX:kyLbLNomEr6YKjJ` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_087_84b60ee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b60ee64966e9d84fa06c2e982f0ea14febda2b0a701797f86195887249d6ec"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-84b60ee64966e9d8.bin"
    file_type = "macho"
    first_seen = "2026-11-25 05:06:13"
  condition:
    hash.sha256(0, filesize) == "84b60ee64966e9d84fa06c2e982f0ea14febda2b0a701797f86195887249d6ec"
}
```

### Sample 88: `1237f050bc29a285`

| Field | Value |
|---|---|
| SHA-256 | `1237f050bc29a2854791d538f80eb6ec507aa8514886770e16439177c0730915` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-1237f050bc29a285.bin` |
| File type | `elf` |
| First seen | `2026-11-25 05:05:59` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aae172a8c3d9b10cc5371e592365794f` |
| SHA-1 | `e44d9850156f38efc5643639282296cec746c2f2` |
| SHA-256 | `1237f050bc29a2854791d538f80eb6ec507aa8514886770e16439177c0730915` |
| SHA3-384 | `00786be4879a86af7c89f9626efb41fe7932a6671a6e2d6cbfebec601790bda9798bd59e51c0b22c61bdc4fa03768e21` |
| TLSH | `T15E06B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WPGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WPLd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_088_1237f050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1237f050bc29a2854791d538f80eb6ec507aa8514886770e16439177c0730915"
    family = "EasyShell"
    file_name = "easyshell-a64-1237f050bc29a285.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:05:59"
  condition:
    hash.sha256(0, filesize) == "1237f050bc29a2854791d538f80eb6ec507aa8514886770e16439177c0730915"
}
```

### Sample 89: `e0763f53d2e88a93`

| Field | Value |
|---|---|
| SHA-256 | `e0763f53d2e88a932741b950029cd72d6fa6bd5d87bb8224baba6c9a0f64a289` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-e0763f53d2e88a93.bin` |
| File type | `elf` |
| First seen | `2026-11-25 05:05:46` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `562380a5f8bc0eab8b9f0e747f569b8b` |
| SHA-1 | `39d36cdf112a2c86d2cc9f1b3d2306befe4062c8` |
| SHA-256 | `e0763f53d2e88a932741b950029cd72d6fa6bd5d87bb8224baba6c9a0f64a289` |
| SHA3-384 | `4419fa938c2a24b7f99033c3fe02884cb5085327ebc7da571fbf849ecabc237e0e25e19445aab4b78fe1341fd48c875a` |
| TLSH | `T116F53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBS:FhvZpiEGUx+pVdqd2laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_089_e0763f53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0763f53d2e88a932741b950029cd72d6fa6bd5d87bb8224baba6c9a0f64a289"
    family = "EasyShell"
    file_name = "easyshell-a32-e0763f53d2e88a93.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:05:46"
  condition:
    hash.sha256(0, filesize) == "e0763f53d2e88a932741b950029cd72d6fa6bd5d87bb8224baba6c9a0f64a289"
}
```

### Sample 90: `cb60e6058bcb16a9`

| Field | Value |
|---|---|
| SHA-256 | `cb60e6058bcb16a99ee29ea32bb77a8773d6401404f66f5c7beabffda3e4dc35` |
| Family label | `AgentTesla` |
| File name | `Payment_receipt.exe` |
| File type | `exe` |
| First seen | `2026-11-25 04:37:23` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9f9eb2e7c449f1a3d350df956517e17` |
| SHA-1 | `29c0d5e77ce382c7ec791eaf77dd0278f32c4103` |
| SHA-256 | `cb60e6058bcb16a99ee29ea32bb77a8773d6401404f66f5c7beabffda3e4dc35` |
| SHA3-384 | `dd16495f766d03b599f9a7cfe2232f4fff74f55fd9c392bb261e1b62b3762d20157c140833a196b5de6d73e4d56d89f2` |
| IMPHASH | `9454a21d20b746646962ed2017d1adbe` |
| TLSH | `T11F75BD99E39901E8D907D2B4CB651633E77074760B7069DF1BAAEA052F33DE05E3A312` |
| SSDEEP | `24576:Nu++2O7eOZP732CEWmTAX7TASAihaieBYQB6eSs1FPbhm:Nd+1qw0TAX7TdhaieiV` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_090_cb60e605
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb60e6058bcb16a99ee29ea32bb77a8773d6401404f66f5c7beabffda3e4dc35"
    family = "AgentTesla"
    file_name = "Payment_receipt.exe"
    file_type = "exe"
    first_seen = "2026-11-25 04:37:23"
  condition:
    hash.sha256(0, filesize) == "cb60e6058bcb16a99ee29ea32bb77a8773d6401404f66f5c7beabffda3e4dc35"
}
```

### Sample 91: `b0afab781b3a3d3e`

| Field | Value |
|---|---|
| SHA-256 | `b0afab781b3a3d3e44372de5d3d09a5dfb60c605e5596cd9c86522be55afe06d` |
| Family label | `EasyShell` |
| File name | `easyshell-l64-b0afab781b3a3d3e.bin` |
| File type | `elf` |
| First seen | `2026-11-25 04:06:44` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8abbe8fbdf70c0ddbb54b243c51ee43a` |
| SHA-1 | `dd682b9e895d462acaec45ecf2bb617d78872700` |
| SHA-256 | `b0afab781b3a3d3e44372de5d3d09a5dfb60c605e5596cd9c86522be55afe06d` |
| SHA3-384 | `9afa3f01723fe4c41cee1ce3a6aab4ad6a295dfe910364fbe3e3965b1875d2d506a13860b216ddb5b047d01caa288d32` |
| TLSH | `T174267D03FAA144FDC9BDCC748A5FD633EA25B88DC121661737D89B002A26B70AF5D791` |
| SSDEEP | `49152:onN+3dn8szgfxiK2PkUinb/HyJGX4SqB8AXhGc/CbvFbmdBLasYxirH8hIU6iKHh:OYjiiKgib9qRGcEulrcW+gh` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_091_b0afab78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0afab781b3a3d3e44372de5d3d09a5dfb60c605e5596cd9c86522be55afe06d"
    family = "EasyShell"
    file_name = "easyshell-l64-b0afab781b3a3d3e.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:44"
  condition:
    hash.sha256(0, filesize) == "b0afab781b3a3d3e44372de5d3d09a5dfb60c605e5596cd9c86522be55afe06d"
}
```

### Sample 92: `464a69aac21410c6`

| Field | Value |
|---|---|
| SHA-256 | `464a69aac21410c620e8359d7b9ef2f2861af3f02066aa0289d4455225e51f84` |
| Family label | `EasyShell` |
| File name | `easyshell-l32-464a69aac21410c6.bin` |
| File type | `elf` |
| First seen | `2026-11-25 04:06:35` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2c78c1f3ed5b8834e306355b394f2e2` |
| SHA-1 | `ece2c240f6f2bad53d7e18d2ce40a0d7acdf6ee3` |
| SHA-256 | `464a69aac21410c620e8359d7b9ef2f2861af3f02066aa0289d4455225e51f84` |
| SHA3-384 | `0487d6eace2516d086f4ea3e5f1e5bfe1f3a794f2244a20e203f102b93abe7a2342463b6308e4584fc7e57cfebc25d7d` |
| TLSH | `T137068D06FD018679C1B721F0454FD235C9242A249623898BFF5E6D68B67F7E0AF6831B` |
| TELFHASH | `t18da310f31a9e49ed17a08907a60f1b15ee89d2374ae075f196effcd021a3d42ca71871` |
| SSDEEP | `98304:YAeH/JS39sxnErz+OHY8up3NBZDTcJvZLKWkL1rF3hhC:RmJS3ye+OHY8up3NBZDTcJvBKWm1rdb` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_092_464a69aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "464a69aac21410c620e8359d7b9ef2f2861af3f02066aa0289d4455225e51f84"
    family = "EasyShell"
    file_name = "easyshell-l32-464a69aac21410c6.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:35"
  condition:
    hash.sha256(0, filesize) == "464a69aac21410c620e8359d7b9ef2f2861af3f02066aa0289d4455225e51f84"
}
```

### Sample 93: `7d55bde560202932`

| Field | Value |
|---|---|
| SHA-256 | `7d55bde560202932f36b6b9ac97d13adac9220ff0433211700a7cf49f8b04c5b` |
| Family label | `EasyShell` |
| File name | `easyshell-l128-7d55bde560202932.bin` |
| File type | `elf` |
| First seen | `2026-11-25 04:06:26` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b296da501d57d304f650084b50bd5aef` |
| SHA-1 | `d30181d7ac242e2458815116f2fb9380832c1b24` |
| SHA-256 | `7d55bde560202932f36b6b9ac97d13adac9220ff0433211700a7cf49f8b04c5b` |
| SHA3-384 | `63cb95fac0b45b62d5a7a830bba9676c0e3370013dcc09b5d96032d2b017e080c5fae3b72dad7b2565162c721cf3f7e7` |
| TLSH | `T1D8067D03F65B999AC18723316C75E32AE73F9306122AE76DE61B3724EE573210D6D2C1` |
| TELFHASH | `t15a31e045683c4bfad8f25a519c2065a2c257d52d7921c704ff30ced65ebe048f526f8e` |
| SSDEEP | `24576:FUcbHNnCeQrwUGf+HCOI7+A176iDq7gCfiVvxTf8gpotpmOg37e/oUMh9fWht1CK:FUkCxwUGnaPdX8P/AS` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_093_7d55bde5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d55bde560202932f36b6b9ac97d13adac9220ff0433211700a7cf49f8b04c5b"
    family = "EasyShell"
    file_name = "easyshell-l128-7d55bde560202932.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:26"
  condition:
    hash.sha256(0, filesize) == "7d55bde560202932f36b6b9ac97d13adac9220ff0433211700a7cf49f8b04c5b"
}
```

### Sample 94: `5f9f7302a1dedf31`

| Field | Value |
|---|---|
| SHA-256 | `5f9f7302a1dedf31c3432739d9b83ef4080c069856a77f39a0d29668bdd51dc8` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_arm64-5f9f7302a1dedf31.bin` |
| File type | `macho` |
| First seen | `2026-11-25 04:06:18` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a85e30540cf62bbc36876c68e0038d3c` |
| SHA-1 | `b9fc6f515327a58fc6e16436c8b1acec40291f4c` |
| SHA-256 | `5f9f7302a1dedf31c3432739d9b83ef4080c069856a77f39a0d29668bdd51dc8` |
| SHA3-384 | `dd9325566f8355d70585adc81d7f2dec58dc2b712b95acee8d473a49bea41cb17ffa404b82b7b325e3890b1f96a17261` |
| TLSH | `T11EF5AE17F95D9C2BE6CEA5FC8C4E4775212BF9704121C2893C0A570DFE623A2099AB77` |
| SSDEEP | `49152:v0SeI1gk9ar9VH2mEY1TgZsj5g5FIU6icBV8GQU5NZm+lzy:8SeI1gkkvTgZt5C+OGU5NZm+lzy` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_094_5f9f7302
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f9f7302a1dedf31c3432739d9b83ef4080c069856a77f39a0d29668bdd51dc8"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-5f9f7302a1dedf31.bin"
    file_type = "macho"
    first_seen = "2026-11-25 04:06:18"
  condition:
    hash.sha256(0, filesize) == "5f9f7302a1dedf31c3432739d9b83ef4080c069856a77f39a0d29668bdd51dc8"
}
```

### Sample 95: `aa9350c82ede34a4`

| Field | Value |
|---|---|
| SHA-256 | `aa9350c82ede34a42c50949b507483d932732066b7f2f3ac472a92e618cd4d4e` |
| Family label | `EasyShell` |
| File name | `easyshell-darwin_amd64-aa9350c82ede34a4.bin` |
| File type | `macho` |
| First seen | `2026-11-25 04:06:10` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, macho, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a20224590fc64a47d928b2d2dbd9c668` |
| SHA-1 | `b30564f0d7e1c434ddee22e4fa145905ff082ed7` |
| SHA-256 | `aa9350c82ede34a42c50949b507483d932732066b7f2f3ac472a92e618cd4d4e` |
| SHA3-384 | `52b1da744332cc75b6ed3eb54d0d31794eaaca635a154e6818e9ae247ac1656f9ad505ac39c4dd5a34e10fed7c02d9e3` |
| TLSH | `T18B168D23B6A29494D186C0385BCFC7724A11FCB66625764B23E4BB216F76DE0774E30B` |
| SSDEEP | `98304:5yyLPMevrKOllH+Os0axlGrQNixO6XKhx+wgbZmBlzTX:kyLbLNomEr6XKjP` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_095_aa9350c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa9350c82ede34a42c50949b507483d932732066b7f2f3ac472a92e618cd4d4e"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-aa9350c82ede34a4.bin"
    file_type = "macho"
    first_seen = "2026-11-25 04:06:10"
  condition:
    hash.sha256(0, filesize) == "aa9350c82ede34a42c50949b507483d932732066b7f2f3ac472a92e618cd4d4e"
}
```

### Sample 96: `5598210272bf810f`

| Field | Value |
|---|---|
| SHA-256 | `5598210272bf810fa6da91fe58b11c74f806b7bd846734c7685d052e1f14345e` |
| Family label | `EasyShell` |
| File name | `easyshell-a64-5598210272bf810f.bin` |
| File type | `elf` |
| First seen | `2026-11-25 04:06:01` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9482b987a18796dcd63854afeca896a1` |
| SHA-1 | `37c253e177482efd9dfb59f5b8eb771bfa5a3be5` |
| SHA-256 | `5598210272bf810fa6da91fe58b11c74f806b7bd846734c7685d052e1f14345e` |
| SHA3-384 | `63989271f68606720002501e256775db59f098c98318bd50bfb092d03caee558ae4a41ec92410d2b9e774a5059cedb84` |
| TLSH | `T1AB06B027F64D6E36E7EEE07C8D8EC1E1B127B0AA1260C1873912550EF6856A04FF5F25` |
| SSDEEP | `49152:EWBWoO2jX1kNjO1712WEGYKIU6iKx4YzjJHz2b3:EWBWoO2OC712WELd+Kjzjlz2b3` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_096_55982102
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5598210272bf810fa6da91fe58b11c74f806b7bd846734c7685d052e1f14345e"
    family = "EasyShell"
    file_name = "easyshell-a64-5598210272bf810f.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:01"
  condition:
    hash.sha256(0, filesize) == "5598210272bf810fa6da91fe58b11c74f806b7bd846734c7685d052e1f14345e"
}
```

### Sample 97: `34d2785f3ece368e`

| Field | Value |
|---|---|
| SHA-256 | `34d2785f3ece368e99212b087f3b2549c1cd8e60f80b0701624b9a78bd290480` |
| Family label | `EasyShell` |
| File name | `easyshell-a32-34d2785f3ece368e.bin` |
| File type | `elf` |
| First seen | `2026-11-25 04:05:52` |
| Reporter | `Tuxxin` |
| Tags | `EasyShell, elf, RAT, Rust, SnoopyTriage` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f19948669589b64dbb519410232dfd00` |
| SHA-1 | `762bf46d2ddf7ccb1a71e0001ef038936cc68108` |
| SHA-256 | `34d2785f3ece368e99212b087f3b2549c1cd8e60f80b0701624b9a78bd290480` |
| SHA3-384 | `ecb235cb2ca92324866bba494ad1348766eb4da8277fc728d962f69733ccffe224ab3563afd3b6ea4fc0506cbe37d57f` |
| TLSH | `T15FF53A5BFC429A92C4C826F9F96D8288330353BCC3DA7106EA14CA3469DF99E4D7DB45` |
| TELFHASH | `t10fa00204219001940b60545242152d3f19bb211595002c0184209c461f052b63020433` |
| SSDEEP | `24576:Ce4tCbKqb/cpqTptZ9PldgIwqVal33Psxwy5XQNS6IaGd75LbyC/QByn0RDRcRBG:FhvZpiEGUx+pVdq52laB` |

#### Technical Assessment

- The sample is tracked as `EasyShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_EasyShell_097_34d2785f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d2785f3ece368e99212b087f3b2549c1cd8e60f80b0701624b9a78bd290480"
    family = "EasyShell"
    file_name = "easyshell-a32-34d2785f3ece368e.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:05:52"
  condition:
    hash.sha256(0, filesize) == "34d2785f3ece368e99212b087f3b2549c1cd8e60f80b0701624b9a78bd290480"
}
```

### Sample 98: `9ab5bb118bc94276`

| Field | Value |
|---|---|
| SHA-256 | `9ab5bb118bc94276e37d1ba709f3acf453e9accb3dfae8d527a1fff2c3f9d094` |
| Family label | `ValleyRAT` |
| File name | `11.23lvcha vpnawfr.exe` |
| File type | `exe` |
| First seen | `2026-11-25 03:58:21` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b2ae22a637b1a9b41814437a75c7af3` |
| SHA-1 | `4ab922b9c5fe21c0fa8403393ccd6382eeda027a` |
| SHA-256 | `9ab5bb118bc94276e37d1ba709f3acf453e9accb3dfae8d527a1fff2c3f9d094` |
| SHA3-384 | `388a6a9c394b1241d97ec8073b8beb5887728774917d349b68f9d96ec2e4d120f0d737e92239f57bac3b2b61c6012f5c` |
| IMPHASH | `4589b33620752985d6b49781e2a560d3` |
| TLSH | `T1F8383398B636014BCCEE74384DC51AA73174ECD98741AFAADB66FE590FA1C7C142A343` |
| SSDEEP | `3145728:Ceks3itXCiAJGZL+U7r8XfHHJlU1Zqny7QEx86xd1g:Ceks3itXCinZLzyhlUuyd+Wg` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_098_9ab5bb11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ab5bb118bc94276e37d1ba709f3acf453e9accb3dfae8d527a1fff2c3f9d094"
    family = "ValleyRAT"
    file_name = "11.23lvcha vpnawfr.exe"
    file_type = "exe"
    first_seen = "2026-11-25 03:58:21"
  condition:
    hash.sha256(0, filesize) == "9ab5bb118bc94276e37d1ba709f3acf453e9accb3dfae8d527a1fff2c3f9d094"
}
```

### Sample 99: `2074b31068d496d9`

| Field | Value |
|---|---|
| SHA-256 | `2074b31068d496d9fcf67c6ba314ce764b4d40e5b9144d0b8fb94c2d8ffbb5db` |
| Family label | `ValleyRAT` |
| File name | `物资采购清单1amd_jpg.exe` |
| File type | `exe` |
| First seen | `2026-11-25 03:54:03` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `507aa684441d08dffec37cd3df2a3b27` |
| SHA-1 | `abc002b09ede0e51bca20c31b4da160edaed0622` |
| SHA-256 | `2074b31068d496d9fcf67c6ba314ce764b4d40e5b9144d0b8fb94c2d8ffbb5db` |
| SHA3-384 | `9d0498e430a71612be699e80fa00ab37291b24df1debdd11a8e664c8a6b6cf43c67b464d0c33b18b8b70788c0e03da86` |
| IMPHASH | `3c7ce639101cbc830b184236bf7012c0` |
| TLSH | `T13C250111FED388B2D9521D3149A96BB266F9BD000BD4EDDF1B8836294F338C25935A3D` |
| SSDEEP | `24576:t6KWLJdpYLyhLaoHnDlbPN3/gkvwE6qU51jvnwhaoOT:m9N5rj1lLv6F1bnbDT` |
| ICON-DHASH | `8207ccd455692b96` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_099_2074b310
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2074b31068d496d9fcf67c6ba314ce764b4d40e5b9144d0b8fb94c2d8ffbb5db"
    family = "ValleyRAT"
    file_name = "物资采购清单1amd_jpg.exe"
    file_type = "exe"
    first_seen = "2026-11-25 03:54:03"
  condition:
    hash.sha256(0, filesize) == "2074b31068d496d9fcf67c6ba314ce764b4d40e5b9144d0b8fb94c2d8ffbb5db"
}
```

### Sample 100: `fe4054075a568a55`

| Field | Value |
|---|---|
| SHA-256 | `fe4054075a568a55beea3dfd1cf864beee4c27eabc2a30d6b022114317f08d31` |
| Family label | `ValleyRAT` |
| File name | `跨境王WhatsApp群发软件.exe` |
| File type | `exe` |
| First seen | `2026-11-25 03:53:16` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `458008807411e21a4b167ec5a6b294b2` |
| SHA-1 | `9a1400e371a70e7aba4f1654b56e67a85be577b5` |
| SHA-256 | `fe4054075a568a55beea3dfd1cf864beee4c27eabc2a30d6b022114317f08d31` |
| SHA3-384 | `0e4f47c881e27ac8c8b63f1d9bdd1df4dcb5800db7c76a7116152f199a4d50e6bacdbfad9e80a9e0140db21947f5e72e` |
| IMPHASH | `b1c5b1beabd90d9fdabd1df0779ea832` |
| TLSH | `T1E2C4AE09E7D409F8E0B7E538C9578902F77A7C4E03619A9F13A4566B2F273A0DE3A711` |
| SSDEEP | `12288:VCQjgAtAHM+vetZxF5EWry8AJGy0/X+tMLz5d3WQDlsRP4RaH:V5ZWs+OZVEWry8AFazO6lsgaH` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_100_fe405407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe4054075a568a55beea3dfd1cf864beee4c27eabc2a30d6b022114317f08d31"
    family = "ValleyRAT"
    file_name = "跨境王WhatsApp群发软件.exe"
    file_type = "exe"
    first_seen = "2026-11-25 03:53:16"
  condition:
    hash.sha256(0, filesize) == "fe4054075a568a55beea3dfd1cf864beee4c27eabc2a30d6b022114317f08d31"
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
 * Generated: 2026-11-25T08:49:25.308281+00:00
 */

rule MalwareBazaar_unknown_001_3083388c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3083388c43fbfd73492e4def0088496951ce7c03c7581652fb473f69f67f75f9"
    family = "unknown"
    file_name = "shipping documents.exe"
    file_type = "exe"
    first_seen = "2026-11-25 08:45:58"
  condition:
    hash.sha256(0, filesize) == "3083388c43fbfd73492e4def0088496951ce7c03c7581652fb473f69f67f75f9"
}

rule MalwareBazaar_unknown_002_9f7107a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225"
    family = "unknown"
    file_name = "9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225"
    file_type = "elf"
    first_seen = "2026-11-25 08:44:04"
  condition:
    hash.sha256(0, filesize) == "9f7107a581cf0f4cc001279c75fafa2caa48560e6bf18e336362dc4295c05225"
}

rule MalwareBazaar_Prometei_003_a711f6e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835"
    family = "Prometei"
    file_name = "a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835"
    file_type = "elf"
    first_seen = "2026-11-25 08:23:40"
  condition:
    hash.sha256(0, filesize) == "a711f6e1c4669158ec035db6361cd78693d4c385f6a9d3deeb4f5bf345a36835"
}

rule MalwareBazaar_unknown_004_3c4eba6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c4eba6a71f4ef4ee2f2d76bbbc3fbb575c35a73c6e60d2ddf9ca85862e20d57"
    family = "unknown"
    file_name = "Teklif talep formu_TT-26-125924_25 11 26_07 08 17.JSE"
    file_type = "jse"
    first_seen = "2026-11-25 08:18:35"
  condition:
    hash.sha256(0, filesize) == "3c4eba6a71f4ef4ee2f2d76bbbc3fbb575c35a73c6e60d2ddf9ca85862e20d57"
}

rule MalwareBazaar_unknown_005_df074b32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df074b32c21f3519e2e8af8ca245b5acd9dedf7408dfb9c6714309d854910afd"
    family = "unknown"
    file_name = "ALMA TEKLİF İSTEĞİ.hta"
    file_type = "hta"
    first_seen = "2026-11-25 08:18:14"
  condition:
    hash.sha256(0, filesize) == "df074b32c21f3519e2e8af8ca245b5acd9dedf7408dfb9c6714309d854910afd"
}

rule MalwareBazaar_unknown_006_6f58f42b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f58f42bcfd03cc945ab9ecc2584acc5d60a88596a02812c5b198884705dd4bc"
    family = "unknown"
    file_name = "Tax_Compliance_Checklist_AY2026-27_23Nov2026.exe"
    file_type = "exe"
    first_seen = "2026-11-25 08:13:07"
  condition:
    hash.sha256(0, filesize) == "6f58f42bcfd03cc945ab9ecc2584acc5d60a88596a02812c5b198884705dd4bc"
}

rule MalwareBazaar_GuLoader_007_dc4e7316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc4e7316351a587b808f4c563ab3e3b26440bd5cd7f4bf79575862469a37a080"
    family = "GuLoader"
    file_name = "AWB#000901_25 November, 2026.vbs"
    file_type = "vbs"
    first_seen = "2026-11-25 08:11:50"
  condition:
    hash.sha256(0, filesize) == "dc4e7316351a587b808f4c563ab3e3b26440bd5cd7f4bf79575862469a37a080"
}

rule MalwareBazaar_unknown_008_a14a2e6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14a2e6a16419d43449bfc842339db91d997880f11d2d19a37d8fdbea4690f37"
    family = "unknown"
    file_name = "easyshell-l64-a14a2e6a16419d43.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:06:40"
  condition:
    hash.sha256(0, filesize) == "a14a2e6a16419d43449bfc842339db91d997880f11d2d19a37d8fdbea4690f37"
}

rule MalwareBazaar_unknown_009_6b8b7309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b8b73097e41aeafe37790df90207201f8f761d74d9d1009e281c2baa959160c"
    family = "unknown"
    file_name = "easyshell-l32-6b8b73097e41aeaf.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:06:23"
  condition:
    hash.sha256(0, filesize) == "6b8b73097e41aeafe37790df90207201f8f761d74d9d1009e281c2baa959160c"
}

rule MalwareBazaar_unknown_010_c1e18458
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e1845884d412baa3f3a97b0d2cfbdea088582038ca4e1d42f0728261c5b9d8"
    family = "unknown"
    file_name = "easyshell-l128-c1e1845884d412ba.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:06:12"
  condition:
    hash.sha256(0, filesize) == "c1e1845884d412baa3f3a97b0d2cfbdea088582038ca4e1d42f0728261c5b9d8"
}

rule MalwareBazaar_unknown_011_d86769fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d86769fd981bacca5b8a1d35b8381dd3cb2c9b8e02efb3371b1e5bacd229dafd"
    family = "unknown"
    file_name = "easyshell-darwin_arm64-d86769fd981bacca.bin"
    file_type = "macho"
    first_seen = "2026-11-25 08:06:03"
  condition:
    hash.sha256(0, filesize) == "d86769fd981bacca5b8a1d35b8381dd3cb2c9b8e02efb3371b1e5bacd229dafd"
}

rule MalwareBazaar_unknown_012_f88b52fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f88b52fabf1f88979791ecb456bac42d9f38c8fbfa4062d69300388ac443c851"
    family = "unknown"
    file_name = "easyshell-darwin_amd64-f88b52fabf1f8897.bin"
    file_type = "macho"
    first_seen = "2026-11-25 08:05:54"
  condition:
    hash.sha256(0, filesize) == "f88b52fabf1f88979791ecb456bac42d9f38c8fbfa4062d69300388ac443c851"
}

rule MalwareBazaar_unknown_013_847580dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "847580dca23dedeb3c8ed54d381ddf79ae50f04ba1283c79ac403c5b6b2c7ed2"
    family = "unknown"
    file_name = "easyshell-a64-847580dca23dedeb.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:05:44"
  condition:
    hash.sha256(0, filesize) == "847580dca23dedeb3c8ed54d381ddf79ae50f04ba1283c79ac403c5b6b2c7ed2"
}

rule MalwareBazaar_unknown_014_ba8a39be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba8a39be04f3c5bccc8a8cefb92f876f7b167a52f28c8fad9200ce0e12fe1e1a"
    family = "unknown"
    file_name = "easyshell-a32-ba8a39be04f3c5bc.bin"
    file_type = "elf"
    first_seen = "2026-11-25 08:05:36"
  condition:
    hash.sha256(0, filesize) == "ba8a39be04f3c5bccc8a8cefb92f876f7b167a52f28c8fad9200ce0e12fe1e1a"
}

rule MalwareBazaar_unknown_015_b5f9a5a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5f9a5a76df193b4708397d8b0dd52b8004cc523d6ab921a4a56f013f7a5d532"
    family = "unknown"
    file_name = "edl.apk"
    file_type = "apk"
    first_seen = "2026-11-25 07:59:13"
  condition:
    hash.sha256(0, filesize) == "b5f9a5a76df193b4708397d8b0dd52b8004cc523d6ab921a4a56f013f7a5d532"
}

rule MalwareBazaar_unknown_016_66e35d48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66e35d480a91277ca537075c96e47fb2c30ecc529e75499d4a796008c930c656"
    family = "unknown"
    file_name = "Comprobante de pago.js"
    file_type = "js"
    first_seen = "2026-11-25 07:59:04"
  condition:
    hash.sha256(0, filesize) == "66e35d480a91277ca537075c96e47fb2c30ecc529e75499d4a796008c930c656"
}

rule MalwareBazaar_unknown_017_91615ca7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91615ca703db2a8daded79c2f8b474b46aa9d8e17ff9ca59107958b6f3cb0cd2"
    family = "unknown"
    file_name = "app-V96.apk"
    file_type = "apk"
    first_seen = "2026-11-25 07:58:57"
  condition:
    hash.sha256(0, filesize) == "91615ca703db2a8daded79c2f8b474b46aa9d8e17ff9ca59107958b6f3cb0cd2"
}

rule MalwareBazaar_unknown_018_6677805b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6677805bb1221b74e5d0a058af995aba96d3f9cef1b98a39c3b46dc21685f581"
    family = "unknown"
    file_name = "app (2).apk"
    file_type = "apk"
    first_seen = "2026-11-25 07:58:45"
  condition:
    hash.sha256(0, filesize) == "6677805bb1221b74e5d0a058af995aba96d3f9cef1b98a39c3b46dc21685f581"
}

rule MalwareBazaar_unknown_019_6242e88a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6242e88ac10b16931c488ac083b430964d870593267d69dd4e1699f076613b90"
    family = "unknown"
    file_name = "恒永达#CGDD#1026110131.scr"
    file_type = "exe"
    first_seen = "2026-11-25 07:58:37"
  condition:
    hash.sha256(0, filesize) == "6242e88ac10b16931c488ac083b430964d870593267d69dd4e1699f076613b90"
}

rule MalwareBazaar_unknown_020_b1556156
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b155615611b8eeecbd2ed132558e26ed00fbe0c3c95b9719651a63a5ff372a45"
    family = "unknown"
    file_name = "Bank_Document_for_returned_transfer.docx"
    file_type = "docx"
    first_seen = "2026-11-25 07:58:15"
  condition:
    hash.sha256(0, filesize) == "b155615611b8eeecbd2ed132558e26ed00fbe0c3c95b9719651a63a5ff372a45"
}

rule MalwareBazaar_unknown_021_57a09a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57a09a26ccdcc0170fb20747fd0d02b669af348909c09eac086a33576ba06060"
    family = "unknown"
    file_name = "Nov_PO.xls"
    file_type = "xls"
    first_seen = "2026-11-25 07:57:28"
  condition:
    hash.sha256(0, filesize) == "57a09a26ccdcc0170fb20747fd0d02b669af348909c09eac086a33576ba06060"
}

rule MalwareBazaar_Formbook_022_b6b87999
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6b8799983607099eb1badfdd0a384dffcac054668bb24398f29de6276620c8a"
    family = "Formbook"
    file_name = "PI-234-821-846-289-APD0515242.JS"
    file_type = "js"
    first_seen = "2026-11-25 07:56:25"
  condition:
    hash.sha256(0, filesize) == "b6b8799983607099eb1badfdd0a384dffcac054668bb24398f29de6276620c8a"
}

rule MalwareBazaar_unknown_023_72b5b777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b5b777ad4c96ac8d11ff03a7c27a3530f4d49caa7a1d1acfcbe576c2e63c59"
    family = "unknown"
    file_name = "FİYAT TEKLİFİ İSTEĞİ.wsf"
    file_type = "wsf"
    first_seen = "2026-11-25 07:55:57"
  condition:
    hash.sha256(0, filesize) == "72b5b777ad4c96ac8d11ff03a7c27a3530f4d49caa7a1d1acfcbe576c2e63c59"
}

rule MalwareBazaar_Mirai_024_a49f43d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357"
    family = "Mirai"
    file_name = "a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357.elf"
    file_type = "elf"
    first_seen = "2026-11-25 07:52:45"
  condition:
    hash.sha256(0, filesize) == "a49f43d0ae373cb35df2cb7a5542bc58234764dad15a628d28a5c67fc6834357"
}

rule MalwareBazaar_Grandoreiro_025_e63c8311
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e63c831112c3e3b5a516909493b18f6e82bc52f98b0fb759bf2ffae8b754e1ad"
    family = "Grandoreiro"
    file_name = "2026_11__1216DocMNED-Aprob_CargJ75V71211.zip"
    file_type = "zip"
    first_seen = "2026-11-25 07:43:33"
  condition:
    hash.sha256(0, filesize) == "e63c831112c3e3b5a516909493b18f6e82bc52f98b0fb759bf2ffae8b754e1ad"
}

rule MalwareBazaar_Cartastrap_026_c0cef487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758"
    family = "Cartastrap"
    file_name = "c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:58"
  condition:
    hash.sha256(0, filesize) == "c0cef48735277d5fa95ed943845c7a53a68b6d101b66fa5c1fd6cb5bf0e92758"
}

rule MalwareBazaar_SosiskaStealer_027_2a40fe2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292"
    family = "SosiskaStealer"
    file_name = "2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:58"
  condition:
    hash.sha256(0, filesize) == "2a40fe2e27978d45e96314ac2e368730bf99ff8a4ee801cb94fb143b45f89292"
}

rule MalwareBazaar_unknown_028_5e626547
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234"
    family = "unknown"
    file_name = "5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "5e6265477f6bba6b32f9020f85c0c122e08c5bd8668435dfdde052523e43b234"
}

rule MalwareBazaar_YattaRAT_029_8275d2f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836"
    family = "YattaRAT"
    file_name = "8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "8275d2f4354c9a85a9a76a3d854c2254caee30379931d442b4a808c7f6552836"
}

rule MalwareBazaar_RustyStealer_030_d14266bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d"
    family = "RustyStealer"
    file_name = "d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "d14266bd4958e2c31a0200085cb557413075af696a5ff4bb986108bdd18c963d"
}

rule MalwareBazaar_unknown_031_14e10e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c"
    family = "unknown"
    file_name = "14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c"
    file_type = "exe"
    first_seen = "2026-11-25 07:19:51"
  condition:
    hash.sha256(0, filesize) == "14e10e84d422cdcccdaf74b07bea30c62f605af5b849f320ad3abd4aeea0837c"
}

rule MalwareBazaar_Snowlight_032_a419da2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd"
    family = "Snowlight"
    file_name = "a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd"
    file_type = "elf"
    first_seen = "2026-11-25 07:08:34"
  condition:
    hash.sha256(0, filesize) == "a419da2ed7c8cf4bcfa048442bf04d7c6c55e6cb98d994873089e1cba7e7d6cd"
}

rule MalwareBazaar_EasyShell_033_2153ca70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2153ca70b9166cbe4e62b13a9dc377412a75414658a8e01c809846e4db3dbaf1"
    family = "EasyShell"
    file_name = "easyshell-l64-2153ca70b9166cbe.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:42"
  condition:
    hash.sha256(0, filesize) == "2153ca70b9166cbe4e62b13a9dc377412a75414658a8e01c809846e4db3dbaf1"
}

rule MalwareBazaar_EasyShell_034_43a45d15
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43a45d15febbdd5b7bdbda332916386f74e8f8bed10b4fe8cc36e309d393cef5"
    family = "EasyShell"
    file_name = "easyshell-l32-43a45d15febbdd5b.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:34"
  condition:
    hash.sha256(0, filesize) == "43a45d15febbdd5b7bdbda332916386f74e8f8bed10b4fe8cc36e309d393cef5"
}

rule MalwareBazaar_EasyShell_035_f9a1fcc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9a1fcc6d375dfbd2bd08ac507f27b970448bb86657404d4217e5f2f6da9c962"
    family = "EasyShell"
    file_name = "easyshell-l128-f9a1fcc6d375dfbd.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:26"
  condition:
    hash.sha256(0, filesize) == "f9a1fcc6d375dfbd2bd08ac507f27b970448bb86657404d4217e5f2f6da9c962"
}

rule MalwareBazaar_EasyShell_036_b125a41e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b125a41eff1cc8ad6eef2c2d73e82e6ad082102b953891a11d6deeab62db79fa"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-b125a41eff1cc8ad.bin"
    file_type = "macho"
    first_seen = "2026-11-25 07:06:17"
  condition:
    hash.sha256(0, filesize) == "b125a41eff1cc8ad6eef2c2d73e82e6ad082102b953891a11d6deeab62db79fa"
}

rule MalwareBazaar_EasyShell_037_343dc9c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "343dc9c33446edc38b4c6552f25aa805fef45911f5760990cd76982afe0587fd"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-343dc9c33446edc3.bin"
    file_type = "macho"
    first_seen = "2026-11-25 07:06:09"
  condition:
    hash.sha256(0, filesize) == "343dc9c33446edc38b4c6552f25aa805fef45911f5760990cd76982afe0587fd"
}

rule MalwareBazaar_EasyShell_038_c524158b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c524158b7358af9f6c1e396c8699082c9f51c82b1daf10eb4e7f1648b8da98bb"
    family = "EasyShell"
    file_name = "easyshell-a64-c524158b7358af9f.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:06:00"
  condition:
    hash.sha256(0, filesize) == "c524158b7358af9f6c1e396c8699082c9f51c82b1daf10eb4e7f1648b8da98bb"
}

rule MalwareBazaar_EasyShell_039_148ace31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59"
    family = "EasyShell"
    file_name = "easyshell-a32-148ace31d1ed0087.bin"
    file_type = "elf"
    first_seen = "2026-11-25 07:05:52"
  condition:
    hash.sha256(0, filesize) == "148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59"
}

rule MalwareBazaar_XWorm_040_f1569455
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b"
    family = "XWorm"
    file_name = "f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b.bin"
    file_type = "bat"
    first_seen = "2026-11-25 06:59:35"
  condition:
    hash.sha256(0, filesize) == "f1569455e60aa5629f3095c6755cc8a01c7c079ff260824e411fae2ee532206b"
}

rule MalwareBazaar_unknown_041_21965e96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f"
    family = "unknown"
    file_name = "21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f.bin"
    file_type = "ps1"
    first_seen = "2026-11-25 06:59:28"
  condition:
    hash.sha256(0, filesize) == "21965e964bc0ac5e1e4a15cd826bfdf30eeaf280d07dd4232b6e2762a993e85f"
}

rule MalwareBazaar_OverlordRAT_042_0b8e463f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1"
    family = "OverlordRAT"
    file_name = "0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1.bin"
    file_type = "ps1"
    first_seen = "2026-11-25 06:58:16"
  condition:
    hash.sha256(0, filesize) == "0b8e463fa3c0aa23056a2bc6b6deea4b29d378109aa2f33962808c6f1a36e5b1"
}

rule MalwareBazaar_CoinMiner_043_3b05f6a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b05f6a220ffea2fb7fd412eb8ac58553c28c8c18f4ae7e24c035cf14a5bab95"
    family = "CoinMiner"
    file_name = "ntm.x86_64"
    file_type = "elf"
    first_seen = "2026-11-25 06:47:15"
  condition:
    hash.sha256(0, filesize) == "3b05f6a220ffea2fb7fd412eb8ac58553c28c8c18f4ae7e24c035cf14a5bab95"
}

rule MalwareBazaar_CoinMiner_044_e4846457
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e484645745eb24ecd51c16c6e83264465fc450937e58461034e7b5aefb90be40"
    family = "CoinMiner"
    file_name = "meow.sh"
    file_type = "sh"
    first_seen = "2026-11-25 06:46:18"
  condition:
    hash.sha256(0, filesize) == "e484645745eb24ecd51c16c6e83264465fc450937e58461034e7b5aefb90be40"
}

rule MalwareBazaar_CoinMiner_045_0bc8eb55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc8eb550d606e253b7c07a009746013814bba300851a5193f1412032a3c2018"
    family = "CoinMiner"
    file_name = "ntm.x86_64"
    file_type = "elf"
    first_seen = "2026-11-25 06:46:15"
  condition:
    hash.sha256(0, filesize) == "0bc8eb550d606e253b7c07a009746013814bba300851a5193f1412032a3c2018"
}

rule MalwareBazaar_CoinMiner_046_0e5617ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e5617ec91fd371456c143e4bd4e348a53c19a6a0a72e78b5efd6f087b08d235"
    family = "CoinMiner"
    file_name = "ntm.arm7"
    file_type = "elf"
    first_seen = "2026-11-25 06:46:11"
  condition:
    hash.sha256(0, filesize) == "0e5617ec91fd371456c143e4bd4e348a53c19a6a0a72e78b5efd6f087b08d235"
}

rule MalwareBazaar_CoinMiner_047_c33db4ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c33db4ab14a5d7091e7499fe196ad3faee3dbc3b3c13b507b572bb013bab8e9f"
    family = "CoinMiner"
    file_name = "ntm.aarch64"
    file_type = "elf"
    first_seen = "2026-11-25 06:46:06"
  condition:
    hash.sha256(0, filesize) == "c33db4ab14a5d7091e7499fe196ad3faee3dbc3b3c13b507b572bb013bab8e9f"
}

rule MalwareBazaar_unknown_048_cedfa110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50"
    family = "unknown"
    file_name = "cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50.exe"
    file_type = "exe"
    first_seen = "2026-11-25 06:43:17"
  condition:
    hash.sha256(0, filesize) == "cedfa1105bf8d0884bc7ecd14f694393cc136ab53a6f402f08073cadbf966a50"
}

rule MalwareBazaar_RemusStealer_049_7674b5d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9"
    family = "RemusStealer"
    file_name = "7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9.exe"
    file_type = "exe"
    first_seen = "2026-11-25 06:43:12"
  condition:
    hash.sha256(0, filesize) == "7674b5d1f9fb10510e96be6e8ffbabba3624ee19a61c20a405b4b681faa919c9"
}

rule MalwareBazaar_AsyncRAT_050_77436b47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77436b4781c1bb83d8f00a38512600deeb80faf37a4f73202c087aa4d804a778"
    family = "AsyncRAT"
    file_name = "4D4380C8BF238CEB80ACB426F99CB360.exe"
    file_type = "exe"
    first_seen = "2026-11-25 06:25:10"
  condition:
    hash.sha256(0, filesize) == "77436b4781c1bb83d8f00a38512600deeb80faf37a4f73202c087aa4d804a778"
}

rule MalwareBazaar_Prometei_051_69f44c38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69f44c38f5ee8727d58697fabf8076f3cfb12a3c5c689afdae106062a9a898e1"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:21:03"
  condition:
    hash.sha256(0, filesize) == "69f44c38f5ee8727d58697fabf8076f3cfb12a3c5c689afdae106062a9a898e1"
}

rule MalwareBazaar_Prometei_052_8835d0fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8835d0fc727a8935eeb3b34aabe688a3d1746ef3b564b9dcf8d0a42d02d82909"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:20:04"
  condition:
    hash.sha256(0, filesize) == "8835d0fc727a8935eeb3b34aabe688a3d1746ef3b564b9dcf8d0a42d02d82909"
}

rule MalwareBazaar_unknown_053_84d8e133
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715"
    family = "unknown"
    file_name = "84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:14:41"
  condition:
    hash.sha256(0, filesize) == "84d8e1333a3111a3c505512821d861aef49aa29277953b4713c3a1beac013715"
}

rule MalwareBazaar_unknown_054_4367c5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897"
    family = "unknown"
    file_name = "4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:14:37"
  condition:
    hash.sha256(0, filesize) == "4367c5d2daff410a0df46a3083a7f292cbb6d9ec656b7c39ba3b352d25ecd897"
}

rule MalwareBazaar_unknown_055_2d992700
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1"
    family = "unknown"
    file_name = "2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1.elf"
    file_type = "elf"
    first_seen = "2026-11-25 06:14:31"
  condition:
    hash.sha256(0, filesize) == "2d99270095e3ded68441a4022432cdf85a5cfcb3db3771c2fc70c6b7fe9dd0a1"
}

rule MalwareBazaar_Prometei_056_716dfa04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716dfa041ac5f766b13081f677d2fda3caaa6c8db33db1fc419b8a3b46cce1de"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:13:05"
  condition:
    hash.sha256(0, filesize) == "716dfa041ac5f766b13081f677d2fda3caaa6c8db33db1fc419b8a3b46cce1de"
}

rule MalwareBazaar_Prometei_057_d654a2fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d654a2fbda84070911a7e0c70d408ad8fde29fb36e87fd53ddeddcae3effdabe"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:12:04"
  condition:
    hash.sha256(0, filesize) == "d654a2fbda84070911a7e0c70d408ad8fde29fb36e87fd53ddeddcae3effdabe"
}

rule MalwareBazaar_PureLogsStealer_058_34187b2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266"
    family = "PureLogsStealer"
    file_name = "md5001000057909.tmp"
    file_type = "exe"
    first_seen = "2026-11-25 06:10:17"
  condition:
    hash.sha256(0, filesize) == "34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266"
}

rule MalwareBazaar_Prometei_059_c2ea9d3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ea9d3ee5df6319491b779039943baebd37c0789af95ec3b1bb686be6076a04"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:10:04"
  condition:
    hash.sha256(0, filesize) == "c2ea9d3ee5df6319491b779039943baebd37c0789af95ec3b1bb686be6076a04"
}

rule MalwareBazaar_EasyShell_060_3d233857
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d2338578fafe7b6ea546b394b1681537c49d63a08cc54df917dfafb1084685d"
    family = "EasyShell"
    file_name = "easyshell-l64-3d2338578fafe7b6.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:25"
  condition:
    hash.sha256(0, filesize) == "3d2338578fafe7b6ea546b394b1681537c49d63a08cc54df917dfafb1084685d"
}

rule MalwareBazaar_EasyShell_061_89b97517
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89b97517500fbae1c6ccd966540a0e466258230950dd39dc61297612ab4fabf1"
    family = "EasyShell"
    file_name = "easyshell-l32-89b97517500fbae1.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:15"
  condition:
    hash.sha256(0, filesize) == "89b97517500fbae1c6ccd966540a0e466258230950dd39dc61297612ab4fabf1"
}

rule MalwareBazaar_EasyShell_062_4c7e0204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c7e02045e1b0144c03fb01997008d6b05b16e2abd9edaaaaab12692340ad978"
    family = "EasyShell"
    file_name = "easyshell-l128-4c7e02045e1b0144.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:07"
  condition:
    hash.sha256(0, filesize) == "4c7e02045e1b0144c03fb01997008d6b05b16e2abd9edaaaaab12692340ad978"
}

rule MalwareBazaar_Prometei_063_ac24df07
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac24df074c04d40001db0e4fee58c1ea59525303d835d78bbe00762453626231"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:06:05"
  condition:
    hash.sha256(0, filesize) == "ac24df074c04d40001db0e4fee58c1ea59525303d835d78bbe00762453626231"
}

rule MalwareBazaar_EasyShell_064_26d7fb44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26d7fb4417082be45bfe2df84fe9f40bcb1173795468d4f2e20f2305eaa3ede4"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-26d7fb4417082be4.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:05:58"
  condition:
    hash.sha256(0, filesize) == "26d7fb4417082be45bfe2df84fe9f40bcb1173795468d4f2e20f2305eaa3ede4"
}

rule MalwareBazaar_EasyShell_065_9a3849a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a3849a97ae51bbd26952ffa98b4002de7eddfcce61a6e08ac9c6c766a2886a3"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-9a3849a97ae51bbd.bin"
    file_type = "macho"
    first_seen = "2026-11-25 06:05:49"
  condition:
    hash.sha256(0, filesize) == "9a3849a97ae51bbd26952ffa98b4002de7eddfcce61a6e08ac9c6c766a2886a3"
}

rule MalwareBazaar_EasyShell_066_e4a723cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4a723cc2824f9e59e1f4be9e43c5d8e0116e2e5ef7ae47ee3037d77d1f456e1"
    family = "EasyShell"
    file_name = "easyshell-a64-e4a723cc2824f9e5.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:05:40"
  condition:
    hash.sha256(0, filesize) == "e4a723cc2824f9e59e1f4be9e43c5d8e0116e2e5ef7ae47ee3037d77d1f456e1"
}

rule MalwareBazaar_EasyShell_067_9dea04bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9dea04bc898c12369b7377981314bbda32c91c336c26e1b5124794d50fffa9d6"
    family = "EasyShell"
    file_name = "easyshell-a32-9dea04bc898c1236.bin"
    file_type = "elf"
    first_seen = "2026-11-25 06:05:32"
  condition:
    hash.sha256(0, filesize) == "9dea04bc898c12369b7377981314bbda32c91c336c26e1b5124794d50fffa9d6"
}

rule MalwareBazaar_Mirai_068_faea3cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faea3cff4981723910b6fdd3ec6f86fe141f587205d50a6b40d46cc3be862211"
    family = "Mirai"
    file_name = "parm6"
    file_type = "elf"
    first_seen = "2026-11-25 06:05:04"
  condition:
    hash.sha256(0, filesize) == "faea3cff4981723910b6fdd3ec6f86fe141f587205d50a6b40d46cc3be862211"
}

rule MalwareBazaar_Prometei_069_7b267670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b267670d293f475c15ce9933b78d04fba3d07360591759f80c80ea0184a6473"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 06:02:04"
  condition:
    hash.sha256(0, filesize) == "7b267670d293f475c15ce9933b78d04fba3d07360591759f80c80ea0184a6473"
}

rule MalwareBazaar_Mirai_070_5dc385f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dc385f71a8553af1e111cfa2602500f15df13eb473427eba584599f15139d05"
    family = "Mirai"
    file_name = "pppc"
    file_type = "elf"
    first_seen = "2026-11-25 06:00:05"
  condition:
    hash.sha256(0, filesize) == "5dc385f71a8553af1e111cfa2602500f15df13eb473427eba584599f15139d05"
}

rule MalwareBazaar_WARDENStealer_071_b05622a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b05622a8ae11254a0e2ebed7fb3b7dfbadce25d8752d2016636b26f74bfe4036"
    family = "WARDENStealer"
    file_name = "apple.exe"
    file_type = "exe"
    first_seen = "2026-11-25 05:52:25"
  condition:
    hash.sha256(0, filesize) == "b05622a8ae11254a0e2ebed7fb3b7dfbadce25d8752d2016636b26f74bfe4036"
}

rule MalwareBazaar_njrat_072_25cede1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25cede1ceb17e1bdb2a2ae0c285f191b6cccbf4ee9b62f13586258d1c2d1cae7"
    family = "njrat"
    file_name = "1f0cf7c981b81f2a93081f755ff564c0.exe"
    file_type = "exe"
    first_seen = "2026-11-25 05:50:14"
  condition:
    hash.sha256(0, filesize) == "25cede1ceb17e1bdb2a2ae0c285f191b6cccbf4ee9b62f13586258d1c2d1cae7"
}

rule MalwareBazaar_njrat_073_164acbea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "164acbea4d0e5be341a566e76c95cde397150e04306055b0ae2662338057dbad"
    family = "njrat"
    file_name = "B1C70C924159FB4972812B09BCAC92B8.exe"
    file_type = "exe"
    first_seen = "2026-11-25 05:50:10"
  condition:
    hash.sha256(0, filesize) == "164acbea4d0e5be341a566e76c95cde397150e04306055b0ae2662338057dbad"
}

rule MalwareBazaar_Mirai_074_df1c6963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df1c696372f8fe3a879ae71d2133146a63cfdd3034152263757ae17f7fe587cc"
    family = "Mirai"
    file_name = "parm5"
    file_type = "elf"
    first_seen = "2026-11-25 05:50:04"
  condition:
    hash.sha256(0, filesize) == "df1c696372f8fe3a879ae71d2133146a63cfdd3034152263757ae17f7fe587cc"
}

rule MalwareBazaar_Mirai_075_6a649ff0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a649ff069e5be459760ad418bb28cc875a75cd166cc18377c7cbc5dfc644fec"
    family = "Mirai"
    file_name = "parm7"
    file_type = "elf"
    first_seen = "2026-11-25 05:48:05"
  condition:
    hash.sha256(0, filesize) == "6a649ff069e5be459760ad418bb28cc875a75cd166cc18377c7cbc5dfc644fec"
}

rule MalwareBazaar_Mirai_076_f69e738a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f69e738accb80a2d63a7ff32dd0c206402981750ea897536ca64396250760bc7"
    family = "Mirai"
    file_name = "pmpsl"
    file_type = "elf"
    first_seen = "2026-11-25 05:42:04"
  condition:
    hash.sha256(0, filesize) == "f69e738accb80a2d63a7ff32dd0c206402981750ea897536ca64396250760bc7"
}

rule MalwareBazaar_Prometei_077_396b0309
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "396b0309097455beb9b3c37425b295d9131278bbe7d0a36b0258bdfc1285c9f3"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-25 05:41:05"
  condition:
    hash.sha256(0, filesize) == "396b0309097455beb9b3c37425b295d9131278bbe7d0a36b0258bdfc1285c9f3"
}

rule MalwareBazaar_Panchan_078_92fc7400
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92fc740036a655dc8154fb421e268e99a19ac86216d42b06faefe3401de86b27"
    family = "Panchan"
    file_name = "sshd"
    file_type = "elf"
    first_seen = "2026-11-25 05:34:55"
  condition:
    hash.sha256(0, filesize) == "92fc740036a655dc8154fb421e268e99a19ac86216d42b06faefe3401de86b27"
}

rule MalwareBazaar_LunexStealer_079_ed759c79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed759c79fad1765c38af744424dc5f763739f4cb82f7654f46d8c2badd611071"
    family = "LunexStealer"
    file_name = "img_49811.NRIw62Nn.js.part"
    file_type = "js"
    first_seen = "2026-11-25 05:30:27"
  condition:
    hash.sha256(0, filesize) == "ed759c79fad1765c38af744424dc5f763739f4cb82f7654f46d8c2badd611071"
}

rule MalwareBazaar_Formbook_080_6cf23781
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cf2378146c160333d0534920a53683b33d83b29cafe8d87887e19d9d832d3c7"
    family = "Formbook"
    file_name = "md5001006330883.tmp"
    file_type = "js"
    first_seen = "2026-11-25 05:30:19"
  condition:
    hash.sha256(0, filesize) == "6cf2378146c160333d0534920a53683b33d83b29cafe8d87887e19d9d832d3c7"
}

rule MalwareBazaar_DarkCloud_081_9499481d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9499481dcee9eb0c20741c6c50b3d60a521e3200872de1e383c7230d1ca5327d"
    family = "DarkCloud"
    file_name = "_00089"
    file_type = "js"
    first_seen = "2026-11-25 05:30:17"
  condition:
    hash.sha256(0, filesize) == "9499481dcee9eb0c20741c6c50b3d60a521e3200872de1e383c7230d1ca5327d"
}

rule MalwareBazaar_WannaCry_082_387eddd8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c"
    family = "WannaCry"
    file_name = "387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c"
    file_type = "exe"
    first_seen = "2026-11-25 05:15:13"
  condition:
    hash.sha256(0, filesize) == "387eddd8854615ce940dcc9439594de40524e45cb28891a3a8af10390b88274c"
}

rule MalwareBazaar_EasyShell_083_19fb8f7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19fb8f7f65015f2ac118fb49fe67359e73fb33f7b9920fd55961a7217034dcc9"
    family = "EasyShell"
    file_name = "easyshell-l64-19fb8f7f65015f2a.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:06:56"
  condition:
    hash.sha256(0, filesize) == "19fb8f7f65015f2ac118fb49fe67359e73fb33f7b9920fd55961a7217034dcc9"
}

rule MalwareBazaar_EasyShell_084_fb1f94db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb1f94db812a22bc4ccb6e5b9291e08d09c450f24088934d5fc49edf12bc4dc8"
    family = "EasyShell"
    file_name = "easyshell-l32-fb1f94db812a22bc.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:06:46"
  condition:
    hash.sha256(0, filesize) == "fb1f94db812a22bc4ccb6e5b9291e08d09c450f24088934d5fc49edf12bc4dc8"
}

rule MalwareBazaar_EasyShell_085_bb7f9a6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb7f9a6f535d69d8e4c1a41465f65341bd29253f71929046db6059d3de2529a2"
    family = "EasyShell"
    file_name = "easyshell-l128-bb7f9a6f535d69d8.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:06:37"
  condition:
    hash.sha256(0, filesize) == "bb7f9a6f535d69d8e4c1a41465f65341bd29253f71929046db6059d3de2529a2"
}

rule MalwareBazaar_EasyShell_086_455aa926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "455aa926a1fd86b74b4bff9dc6f48c7e5a7d38e8061049714d82f0aabe29eecd"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-455aa926a1fd86b7.bin"
    file_type = "macho"
    first_seen = "2026-11-25 05:06:25"
  condition:
    hash.sha256(0, filesize) == "455aa926a1fd86b74b4bff9dc6f48c7e5a7d38e8061049714d82f0aabe29eecd"
}

rule MalwareBazaar_EasyShell_087_84b60ee6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b60ee64966e9d84fa06c2e982f0ea14febda2b0a701797f86195887249d6ec"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-84b60ee64966e9d8.bin"
    file_type = "macho"
    first_seen = "2026-11-25 05:06:13"
  condition:
    hash.sha256(0, filesize) == "84b60ee64966e9d84fa06c2e982f0ea14febda2b0a701797f86195887249d6ec"
}

rule MalwareBazaar_EasyShell_088_1237f050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1237f050bc29a2854791d538f80eb6ec507aa8514886770e16439177c0730915"
    family = "EasyShell"
    file_name = "easyshell-a64-1237f050bc29a285.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:05:59"
  condition:
    hash.sha256(0, filesize) == "1237f050bc29a2854791d538f80eb6ec507aa8514886770e16439177c0730915"
}

rule MalwareBazaar_EasyShell_089_e0763f53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0763f53d2e88a932741b950029cd72d6fa6bd5d87bb8224baba6c9a0f64a289"
    family = "EasyShell"
    file_name = "easyshell-a32-e0763f53d2e88a93.bin"
    file_type = "elf"
    first_seen = "2026-11-25 05:05:46"
  condition:
    hash.sha256(0, filesize) == "e0763f53d2e88a932741b950029cd72d6fa6bd5d87bb8224baba6c9a0f64a289"
}

rule MalwareBazaar_AgentTesla_090_cb60e605
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb60e6058bcb16a99ee29ea32bb77a8773d6401404f66f5c7beabffda3e4dc35"
    family = "AgentTesla"
    file_name = "Payment_receipt.exe"
    file_type = "exe"
    first_seen = "2026-11-25 04:37:23"
  condition:
    hash.sha256(0, filesize) == "cb60e6058bcb16a99ee29ea32bb77a8773d6401404f66f5c7beabffda3e4dc35"
}

rule MalwareBazaar_EasyShell_091_b0afab78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0afab781b3a3d3e44372de5d3d09a5dfb60c605e5596cd9c86522be55afe06d"
    family = "EasyShell"
    file_name = "easyshell-l64-b0afab781b3a3d3e.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:44"
  condition:
    hash.sha256(0, filesize) == "b0afab781b3a3d3e44372de5d3d09a5dfb60c605e5596cd9c86522be55afe06d"
}

rule MalwareBazaar_EasyShell_092_464a69aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "464a69aac21410c620e8359d7b9ef2f2861af3f02066aa0289d4455225e51f84"
    family = "EasyShell"
    file_name = "easyshell-l32-464a69aac21410c6.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:35"
  condition:
    hash.sha256(0, filesize) == "464a69aac21410c620e8359d7b9ef2f2861af3f02066aa0289d4455225e51f84"
}

rule MalwareBazaar_EasyShell_093_7d55bde5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d55bde560202932f36b6b9ac97d13adac9220ff0433211700a7cf49f8b04c5b"
    family = "EasyShell"
    file_name = "easyshell-l128-7d55bde560202932.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:26"
  condition:
    hash.sha256(0, filesize) == "7d55bde560202932f36b6b9ac97d13adac9220ff0433211700a7cf49f8b04c5b"
}

rule MalwareBazaar_EasyShell_094_5f9f7302
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f9f7302a1dedf31c3432739d9b83ef4080c069856a77f39a0d29668bdd51dc8"
    family = "EasyShell"
    file_name = "easyshell-darwin_arm64-5f9f7302a1dedf31.bin"
    file_type = "macho"
    first_seen = "2026-11-25 04:06:18"
  condition:
    hash.sha256(0, filesize) == "5f9f7302a1dedf31c3432739d9b83ef4080c069856a77f39a0d29668bdd51dc8"
}

rule MalwareBazaar_EasyShell_095_aa9350c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa9350c82ede34a42c50949b507483d932732066b7f2f3ac472a92e618cd4d4e"
    family = "EasyShell"
    file_name = "easyshell-darwin_amd64-aa9350c82ede34a4.bin"
    file_type = "macho"
    first_seen = "2026-11-25 04:06:10"
  condition:
    hash.sha256(0, filesize) == "aa9350c82ede34a42c50949b507483d932732066b7f2f3ac472a92e618cd4d4e"
}

rule MalwareBazaar_EasyShell_096_55982102
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5598210272bf810fa6da91fe58b11c74f806b7bd846734c7685d052e1f14345e"
    family = "EasyShell"
    file_name = "easyshell-a64-5598210272bf810f.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:06:01"
  condition:
    hash.sha256(0, filesize) == "5598210272bf810fa6da91fe58b11c74f806b7bd846734c7685d052e1f14345e"
}

rule MalwareBazaar_EasyShell_097_34d2785f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d2785f3ece368e99212b087f3b2549c1cd8e60f80b0701624b9a78bd290480"
    family = "EasyShell"
    file_name = "easyshell-a32-34d2785f3ece368e.bin"
    file_type = "elf"
    first_seen = "2026-11-25 04:05:52"
  condition:
    hash.sha256(0, filesize) == "34d2785f3ece368e99212b087f3b2549c1cd8e60f80b0701624b9a78bd290480"
}

rule MalwareBazaar_ValleyRAT_098_9ab5bb11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ab5bb118bc94276e37d1ba709f3acf453e9accb3dfae8d527a1fff2c3f9d094"
    family = "ValleyRAT"
    file_name = "11.23lvcha vpnawfr.exe"
    file_type = "exe"
    first_seen = "2026-11-25 03:58:21"
  condition:
    hash.sha256(0, filesize) == "9ab5bb118bc94276e37d1ba709f3acf453e9accb3dfae8d527a1fff2c3f9d094"
}

rule MalwareBazaar_ValleyRAT_099_2074b310
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2074b31068d496d9fcf67c6ba314ce764b4d40e5b9144d0b8fb94c2d8ffbb5db"
    family = "ValleyRAT"
    file_name = "物资采购清单1amd_jpg.exe"
    file_type = "exe"
    first_seen = "2026-11-25 03:54:03"
  condition:
    hash.sha256(0, filesize) == "2074b31068d496d9fcf67c6ba314ce764b4d40e5b9144d0b8fb94c2d8ffbb5db"
}

rule MalwareBazaar_ValleyRAT_100_fe405407
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe4054075a568a55beea3dfd1cf864beee4c27eabc2a30d6b022114317f08d31"
    family = "ValleyRAT"
    file_name = "跨境王WhatsApp群发软件.exe"
    file_type = "exe"
    first_seen = "2026-11-25 03:53:16"
  condition:
    hash.sha256(0, filesize) == "fe4054075a568a55beea3dfd1cf864beee4c27eabc2a30d6b022114317f08d31"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

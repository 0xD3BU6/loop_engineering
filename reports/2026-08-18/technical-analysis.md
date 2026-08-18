# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-18

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 609 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 609 |
| Unique family labels | 11 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 53 |
| Mirai | 36 |
| Prometei | 2 |
| Vidar | 2 |
| AgentTesla | 1 |
| AsyncRAT | 1 |
| WannaCry | 1 |
| CoinMiner | 1 |
| RustyStealer | 1 |
| LummaStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 46 |
| elf | 38 |
| sh | 7 |
| unknown | 4 |
| js | 1 |
| jar | 1 |
| ps1 | 1 |
| iso | 1 |
| gz | 1 |

## Per-Sample Analysis

### Sample 1: `4256efa4f4e316b8`

| Field | Value |
|---|---|
| SHA-256 | `4256efa4f4e316b8394e42d2f2ea36bb533c5438e05c64f79f2e26a368d1c98c` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-18 01:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e0eaf4aa25fcbfbfc0fe05d006f24d4` |
| SHA-1 | `35f90fc57abdd818dd3ae2def80cfc8367610a38` |
| SHA-256 | `4256efa4f4e316b8394e42d2f2ea36bb533c5438e05c64f79f2e26a368d1c98c` |
| SHA3-384 | `dad034c0e4769271fb4f81cbfb3e5c33bd0470855b1652a73b698a0f8565ccfb776fffa599b47663cb7922831e415065` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T14CE63318AED016BEE9239138EEF18191DBFCB9651732C5EB17B84A21BE532D08C7D513` |
| SSDEEP | `393216:NZJn4xU8nGK2KI0as0XvoXMCHWUj/cuI3/PGTAI:NT4xU8nGK30wXMb8UH/O7` |
| ICON-DHASH | `71f0d8d8f8e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_4256efa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4256efa4f4e316b8394e42d2f2ea36bb533c5438e05c64f79f2e26a368d1c98c"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-18 01:52:09"
  condition:
    hash.sha256(0, filesize) == "4256efa4f4e316b8394e42d2f2ea36bb533c5438e05c64f79f2e26a368d1c98c"
}
```

### Sample 2: `97fe2dac2c95aae6`

| Field | Value |
|---|---|
| SHA-256 | `97fe2dac2c95aae6eb2033e51324dd8e0bebd043d114a07bb4f1c2b42eb6b023` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-18 01:49:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62f749025c058359243e0e32b23b0fd0` |
| SHA-1 | `c9411e11d00b88164866c867bed740f5ebc98478` |
| SHA-256 | `97fe2dac2c95aae6eb2033e51324dd8e0bebd043d114a07bb4f1c2b42eb6b023` |
| SHA3-384 | `81667cabe9ad767f18e7acd8f78c3e507e097b9349226c2d0d98befe4e5e9d12185e548db6bd5a9141acc211490d0fbd` |
| TLSH | `T15DC31B99FC90DE12C6D52675F95E428C332317B8D3DA7106CE209F34B7E796A0E3A942` |
| SSDEEP | `3072:NKJWOd2K6CeLWoMiSVuvUQ4g8OICVeP8Sz+OPpFNsXQf1Dl1:Nq/eLSuvUQ4g8O9VePbPpFaQ95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_97fe2dac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97fe2dac2c95aae6eb2033e51324dd8e0bebd043d114a07bb4f1c2b42eb6b023"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-18 01:49:34"
  condition:
    hash.sha256(0, filesize) == "97fe2dac2c95aae6eb2033e51324dd8e0bebd043d114a07bb4f1c2b42eb6b023"
}
```

### Sample 3: `c55bd2281fa67c02`

| Field | Value |
|---|---|
| SHA-256 | `c55bd2281fa67c02d2456f66e00e0fbda57bdeebc2ca3d86557ff8280a5ff05e` |
| Family label | `unknown` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-18 01:49:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d94b16254578b5c030941d206340888` |
| SHA-1 | `4f0dbe576cfb376ba98fcb90eed3ea4bbd24b86e` |
| SHA-256 | `c55bd2281fa67c02d2456f66e00e0fbda57bdeebc2ca3d86557ff8280a5ff05e` |
| SHA3-384 | `7d9a1e12511286eea2770425088f97febb41e1152ad15979d614e15dce19f849b40ffa02be764d6da9b1086a3e27bed0` |
| TLSH | `T17143F105100C74A1F6B67C3AF09DD741B80E5AB8E57EB7E31023DA6FC791C882E96D99` |
| SSDEEP | `1536:0PXRKrXbJPJMSlAj7QI9aSfhoYoRumxS/fs:WXRMd3lAj7QIoSNmgE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_c55bd228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c55bd2281fa67c02d2456f66e00e0fbda57bdeebc2ca3d86557ff8280a5ff05e"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-18 01:49:18"
  condition:
    hash.sha256(0, filesize) == "c55bd2281fa67c02d2456f66e00e0fbda57bdeebc2ca3d86557ff8280a5ff05e"
}
```

### Sample 4: `9659e581598ab314`

| Field | Value |
|---|---|
| SHA-256 | `9659e581598ab314e5a31301648cc43d16adfa098762c6c9dbd9ba2b6c1d773f` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-18 01:45:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43604380bdc5e510ed1a6c5af10ec5ec` |
| SHA-1 | `5d9b5de23df0afbffc3e8ef5bc6986717378932d` |
| SHA-256 | `9659e581598ab314e5a31301648cc43d16adfa098762c6c9dbd9ba2b6c1d773f` |
| SHA3-384 | `2d26cadc03a6d8c12541af2083fdc2fbff41c57c5a268162ff5064711c7e5c7479acfbabbf4706e47f42f0adf99a9484` |
| TLSH | `T1D2C319A9F880DE52C6D52676FB5E428C33231778C3DA7105CE109E35F7EB95A0E3A942` |
| SSDEEP | `3072:b2mXr1bQ2UFCq6NrcYEEUjPZsrOuvLyuqzOvLkNQFxNBLudf1Dl:bHhiDCrcYEEUjPZsaeLzuOvjN6d95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_9659e581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9659e581598ab314e5a31301648cc43d16adfa098762c6c9dbd9ba2b6c1d773f"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-18 01:45:54"
  condition:
    hash.sha256(0, filesize) == "9659e581598ab314e5a31301648cc43d16adfa098762c6c9dbd9ba2b6c1d773f"
}
```

### Sample 5: `983cfe9b42edc273`

| Field | Value |
|---|---|
| SHA-256 | `983cfe9b42edc2733c90abbfd39427afbe761e8136960e3267558b658fd8b477` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-18 01:45:40` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `776e3646ff95c2010ed276b12e1999e7` |
| SHA-1 | `96c42ccf2fe2862a20d0c39145ac1679229b9f6f` |
| SHA-256 | `983cfe9b42edc2733c90abbfd39427afbe761e8136960e3267558b658fd8b477` |
| SHA3-384 | `985fba997daa5e7f71f7fbf0170caf31f7146107500ae81885a73a72f352ce20e3690f81bee51b026e4ea1d64bb2ae93` |
| IMPHASH | `7f972135e4ef2afd8f6b7ede6e0f3f09` |
| TLSH | `T199B46BA3639627FCC1A6C3348016362CF6B13F9552288696925AF7210F37B886F7DF54` |
| SSDEEP | `6144:+JQv+/LvT4gyOeaTmTfyu/WuJy/cbuBPk1BmkWcvZ6G+3RBl1e2BlZv3fsuXfH:4QvELvT4Ce8m7IflIxvi3RBl1rJ/fvH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_983cfe9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "983cfe9b42edc2733c90abbfd39427afbe761e8136960e3267558b658fd8b477"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 01:45:40"
  condition:
    hash.sha256(0, filesize) == "983cfe9b42edc2733c90abbfd39427afbe761e8136960e3267558b658fd8b477"
}
```

### Sample 6: `fc47c4d1172496ff`

| Field | Value |
|---|---|
| SHA-256 | `fc47c4d1172496ff98213b490f7b01da57493e23dc84277d596c0ca19e60b180` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-18 01:45:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bfb6753f1ee2b14c5cd2b5e50aaabac` |
| SHA-1 | `94648284039eea4d8be548dec19ffeaf2397c875` |
| SHA-256 | `fc47c4d1172496ff98213b490f7b01da57493e23dc84277d596c0ca19e60b180` |
| SHA3-384 | `25ef5d4b7cd760646638a3d10f2fe4ba12c1a752c4af7433a43eae27e5df3d5c664f2e2c4c94b568871d15e07ba3c44e` |
| TLSH | `T1B743F1D2A4C6266FDD782235E8BFC5971A247B3CBB87F123E2246B5C22D490612F18D5` |
| SSDEEP | `1536:SzkFZ5LDfg1Inf3PdtzQET1mjO0DPtA7O+bEYpfR:QkFjLDfgYXdRRRmjhDV9WEk5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_fc47c4d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc47c4d1172496ff98213b490f7b01da57493e23dc84277d596c0ca19e60b180"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-18 01:45:29"
  condition:
    hash.sha256(0, filesize) == "fc47c4d1172496ff98213b490f7b01da57493e23dc84277d596c0ca19e60b180"
}
```

### Sample 7: `558517ccded57ad4`

| Field | Value |
|---|---|
| SHA-256 | `558517ccded57ad4f971621c1dfafb46461b7e1ab4d89305408703b34b38f265` |
| Family label | `AgentTesla` |
| File name | `New_Purchase_Order_[PO_02081].pdf.JS` |
| File type | `js` |
| First seen | `2026-08-18 01:21:44` |
| Reporter | `nat` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4839ba614198cc739075ffc329e914a6` |
| SHA-1 | `31956c0817279539b05f6f815806d5e4b4f9ec2d` |
| SHA-256 | `558517ccded57ad4f971621c1dfafb46461b7e1ab4d89305408703b34b38f265` |
| SHA3-384 | `fc84c80a8f2e3e35acb1b47d14a785e234afa2d17b7f9e1bf5c297618a74c51be7a70643bde06b35abcb75e608f825a5` |
| TLSH | `T1E30675C81357D1B2F7687B4C4A3599A1E1AEB1CB11C9EF18B8EDC3143B18AD713489E6` |
| SSDEEP | `98304:Yg/VX7V+QzEmYYJvI5nBMqDYhRTv1lHXcpgY/P4A4jCiXB8inKUb:3/D1AmYYCoeI9l3Cn4/jXXB1l` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_007_558517cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "558517ccded57ad4f971621c1dfafb46461b7e1ab4d89305408703b34b38f265"
    family = "AgentTesla"
    file_name = "New_Purchase_Order_[PO_02081].pdf.JS"
    file_type = "js"
    first_seen = "2026-08-18 01:21:44"
  condition:
    hash.sha256(0, filesize) == "558517ccded57ad4f971621c1dfafb46461b7e1ab4d89305408703b34b38f265"
}
```

### Sample 8: `daabf9021158e5dd`

| Field | Value |
|---|---|
| SHA-256 | `daabf9021158e5dd35e162c05bc25c6df677a919a8c125a1006871bce7c0d4e5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-18 01:07:51` |
| Reporter | `Bitsight` |
| Tags | `974b6b4ed30ddaa4b6f4ec27976e52d8, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4cfaa2e7775ada62a9a0c264502b0cf` |
| SHA-1 | `3e5ddd2530c38ed664a451014c465e97099be1b8` |
| SHA-256 | `daabf9021158e5dd35e162c05bc25c6df677a919a8c125a1006871bce7c0d4e5` |
| SHA3-384 | `0ca31c960bc59436662484d554aa694a259ce64ed0a77f943fbc1a1e974529d129c399dcb0180bb80fd5692caeaa18da` |
| IMPHASH | `de85a398477c39117ee5fd3f2278b959` |
| TLSH | `T1F4750147FFA106F4C1538D38627E2607E239380DD719DABBB79D05903F2639895B9B28` |
| SSDEEP | `49152:bMwJhSiAR28jHt6UarBVxBVilEiEiyGQ/C/RaGpwTD3dDw:T7PxfiyGEF5w` |
| ICON-DHASH | `0671e8d4d4c87196` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_daabf902
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daabf9021158e5dd35e162c05bc25c6df677a919a8c125a1006871bce7c0d4e5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 01:07:51"
  condition:
    hash.sha256(0, filesize) == "daabf9021158e5dd35e162c05bc25c6df677a919a8c125a1006871bce7c0d4e5"
}
```

### Sample 9: `866ac5e19171919e`

| Field | Value |
|---|---|
| SHA-256 | `866ac5e19171919e0861a591f746f7b8b746a59cb9aec48306539569d83373c2` |
| Family label | `AsyncRAT` |
| File name | `e-dekont_html.exe` |
| File type | `exe` |
| First seen | `2026-08-18 00:52:20` |
| Reporter | `threatcat_ch` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b4ec44ceae97db109fdb0ad5b23590c` |
| SHA-1 | `a320de3db70f40dc770a9fa16a3be6ce8dd2bbe6` |
| SHA-256 | `866ac5e19171919e0861a591f746f7b8b746a59cb9aec48306539569d83373c2` |
| SHA3-384 | `9693c3fef4337a6de95674892a92f626ab7981c992d066ed1314bce042dec22b0b136fec24f6e935903fcfff01bf66e9` |
| IMPHASH | `8c0ed5311e0eeba51b4c1a13e4263081` |
| TLSH | `T193358D18E38811ECE627C674CBA69232F775B4460761B9DB17DAD6152F73AE02F3A301` |
| SSDEEP | `24576:KhS1vsyzK2pP732C6RY5fVqr02esyuu5AKLfJCBfvxq:Kkvsq+e58rFeEyLkW` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_009_866ac5e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866ac5e19171919e0861a591f746f7b8b746a59cb9aec48306539569d83373c2"
    family = "AsyncRAT"
    file_name = "e-dekont_html.exe"
    file_type = "exe"
    first_seen = "2026-08-18 00:52:20"
  condition:
    hash.sha256(0, filesize) == "866ac5e19171919e0861a591f746f7b8b746a59cb9aec48306539569d83373c2"
}
```

### Sample 10: `d51c9cd1b1de63ae`

| Field | Value |
|---|---|
| SHA-256 | `d51c9cd1b1de63ae62ae781147cc17adc0f0450206884737c996b858a8b770ad` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-18 00:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87bec19928e47ceb5bf8844f9485bffe` |
| SHA-1 | `24468289ee1e7979f8162c52054eb07ffb225d6e` |
| SHA-256 | `d51c9cd1b1de63ae62ae781147cc17adc0f0450206884737c996b858a8b770ad` |
| SHA3-384 | `f665f1f3a712b1de50f3948335600cf8b3b055c6d51d492d1583c9df1858ccb692f558283a7de57624788c91a7ef7dc8` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T144E633D8A7C421EDE4A3403D7BB14595AB7478616332C9EB13BD82B62D635E08D3E363` |
| SSDEEP | `393216:/Tj08+TUHtZg3Ci8QuG10s6XMCHWUjMcuI3/PGTAI:7RSU0SiQG10fXMb8ZH/O7` |
| ICON-DHASH | `71f0f0e8e8e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_d51c9cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51c9cd1b1de63ae62ae781147cc17adc0f0450206884737c996b858a8b770ad"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-18 00:52:11"
  condition:
    hash.sha256(0, filesize) == "d51c9cd1b1de63ae62ae781147cc17adc0f0450206884737c996b858a8b770ad"
}
```

### Sample 11: `8995cc7fb82c8c42`

| Field | Value |
|---|---|
| SHA-256 | `8995cc7fb82c8c4223b3ccf74047ab7c2055c1551dfc04fe649257c47c9f624c` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-18 00:47:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `827bbb51382589ec833d9d76e711555d` |
| SHA-1 | `979f58c523cf5ab45fbb85429ab9a370d9466ef2` |
| SHA-256 | `8995cc7fb82c8c4223b3ccf74047ab7c2055c1551dfc04fe649257c47c9f624c` |
| SHA3-384 | `239eb0a215192bb3d385b7e00d96a16f76e72723fd3cd82d8d1ba6db90751d73a8de48bac84f20597a683189b54922aa` |
| TLSH | `T142C319A9F880DE52C6D52676FB5E428C33231778C3DA7105CE109E35F7EB95A0E3A942` |
| SSDEEP | `3072:b2mXr1bQ2UFCq6NrcYEEUjPZsrOuvLyuqzOvLkNQFxNBLuzf1Dl:bHhiDCrcYEEUjPZsaeLzuOvjN6z95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_8995cc7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8995cc7fb82c8c4223b3ccf74047ab7c2055c1551dfc04fe649257c47c9f624c"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-18 00:47:40"
  condition:
    hash.sha256(0, filesize) == "8995cc7fb82c8c4223b3ccf74047ab7c2055c1551dfc04fe649257c47c9f624c"
}
```

### Sample 12: `a9f85b311c3ea2c6`

| Field | Value |
|---|---|
| SHA-256 | `a9f85b311c3ea2c60e76b905844cfb6e37c6a0575e55dcc53eef4bd308acf72c` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-18 00:47:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4867e7c3fe85066cb850980b630fe779` |
| SHA-1 | `3a80894626bd820f537c03c0acaa92054c98bfed` |
| SHA-256 | `a9f85b311c3ea2c60e76b905844cfb6e37c6a0575e55dcc53eef4bd308acf72c` |
| SHA3-384 | `11ddf3b6096a70e83357ff3f49bf10a2dd1030dc79bad1d168eac1757151154a04295d691486883eb71a3ae152ee1437` |
| TLSH | `T1A44302D3A8D2397ECD385371E4BEC2971D20AB3CFA93B027F524AB5C21E594612B14D6` |
| SSDEEP | `1536:SzkFZ5LDfg1Inf3PdtzQET1mjO0DPtjpfi:QkFjLDfgYXdRRRmjhDVFK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_a9f85b31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9f85b311c3ea2c60e76b905844cfb6e37c6a0575e55dcc53eef4bd308acf72c"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-18 00:47:10"
  condition:
    hash.sha256(0, filesize) == "a9f85b311c3ea2c60e76b905844cfb6e37c6a0575e55dcc53eef4bd308acf72c"
}
```

### Sample 13: `561b9327e87addc6`

| Field | Value |
|---|---|
| SHA-256 | `561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467` |
| Family label | `Mirai` |
| File name | `561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467` |
| File type | `sh` |
| First seen | `2026-08-18 00:43:06` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3aa30e57e1960d842003b21aa3f0f9a0` |
| SHA-1 | `cf5d10e03415e981fc60942d76c0ba8ff1904ad4` |
| SHA-256 | `561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467` |
| SHA3-384 | `1758edba4189fabb4115a9dec956b4f86762f3a2ba4bb38046a6932ad407a2c7301b90459a1df5946146e50951454a60` |
| TLSH | `T10EF0C9EEF8768C397F088D7FB0A732E47040A45280D52D94338AF9F7855CC49FA1A222` |
| SSDEEP | `12:CRm/EKJKU/3pJ++96X+spqt6Xth+F1H8ZF:bBX/Zw+969gt6dW1H2F` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_561b9327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467"
    family = "Mirai"
    file_name = "561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467"
    file_type = "sh"
    first_seen = "2026-08-18 00:43:06"
  condition:
    hash.sha256(0, filesize) == "561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467"
}
```

### Sample 14: `416658765b860dc7`

| Field | Value |
|---|---|
| SHA-256 | `416658765b860dc70979dc970a5179d7b51163aa6b173ab002c3affe46608e19` |
| Family label | `Mirai` |
| File name | `1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:16:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `652586cf0e29c172e9e50618f451c61f` |
| SHA-1 | `24b8dd3c4570e00333d7dde30b24781a57784dc9` |
| SHA-256 | `416658765b860dc70979dc970a5179d7b51163aa6b173ab002c3affe46608e19` |
| SHA3-384 | `8cb3ce7bf4e11f0ea02623fbbf6a3c28646a18c962e3e6dc29963358e9adc820f130b65ff14234f00ddbbb70cbbc10c8` |
| TLSH | `T11104185F7710CF61C769C63009B3CB5666F526522AE18849F32CDE08AE6434DB86FED8` |
| TELFHASH | `t102319db08b7b65115ac5c7ec88ec775a591a8515470adf33fd2180bc50260ade22ad4f` |
| SSDEEP | `3072:YDgtLI+T2FoGVoJOtINqb76tnbMQrWrtocmdgei9xmzwcy1DdjN:1xnbXr4lMMc0coFN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_41665876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "416658765b860dc70979dc970a5179d7b51163aa6b173ab002c3affe46608e19"
    family = "Mirai"
    file_name = "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:37"
  condition:
    hash.sha256(0, filesize) == "416658765b860dc70979dc970a5179d7b51163aa6b173ab002c3affe46608e19"
}
```

### Sample 15: `54217f8171496a01`

| Field | Value |
|---|---|
| SHA-256 | `54217f8171496a010c07e8befa2207248bd70948c46467f3f8ddfe807b1b4115` |
| Family label | `Mirai` |
| File name | `09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:16:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bca30537b2220731ad59e45f96968e0e` |
| SHA-1 | `d0c8aeab924151bfa966bd4bd5739c55d9d1c934` |
| SHA-256 | `54217f8171496a010c07e8befa2207248bd70948c46467f3f8ddfe807b1b4115` |
| SHA3-384 | `d8e4397363369a9aebd6d945e971de87f0e38cd05af88782f741fcf30a97476b77c243a4ea662dc00c0cb98065977189` |
| TLSH | `T1D904194F7710DF61C369C93049B3CB5656E926622AD28849F31CDE08BE6534DA82FFE4` |
| TELFHASH | `t15531cdb48b7b65019a89c7ec89ecb74a591e85064746df33fe3180bc80260ade229d4f` |
| SSDEEP | `3072:JFsWXXhiN0dq8/v3vjmH+0b0WURwddy1DdjU9:LsAhiGd/v3bB2V0+doFU9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_54217f81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54217f8171496a010c07e8befa2207248bd70948c46467f3f8ddfe807b1b4115"
    family = "Mirai"
    file_name = "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:32"
  condition:
    hash.sha256(0, filesize) == "54217f8171496a010c07e8befa2207248bd70948c46467f3f8ddfe807b1b4115"
}
```

### Sample 16: `b785ba9b7b7e3fc5`

| Field | Value |
|---|---|
| SHA-256 | `b785ba9b7b7e3fc5da5595c92c54b6e0ab42a0c9e3b1310caff0ac4b509a304c` |
| Family label | `Mirai` |
| File name | `419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:16:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40fa58d0381ffc0d68b5f4a4048df05e` |
| SHA-1 | `126a41753a1b95329d1fd993a8389d484b928327` |
| SHA-256 | `b785ba9b7b7e3fc5da5595c92c54b6e0ab42a0c9e3b1310caff0ac4b509a304c` |
| SHA3-384 | `7c7a0ad74e30f328bc4580a8b605afbdb76a48ad1c68372fc2d73d78a20c84224c1d86128d68afdcdd0f9b310b07df5b` |
| TLSH | `T1CDC33BA9F890DE52C6C52676FB4E418C33231778D3DA7105CE149E34F7EB96A0E3A942` |
| SSDEEP | `3072:D6rwNzs5nQCaUql6hxcYEEUjnIsAOJvLPM9euv3sNTFxNhbudf1Dl:D6k5UiexcYEEUjnIsHVL0suv2tKd95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_b785ba9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b785ba9b7b7e3fc5da5595c92c54b6e0ab42a0c9e3b1310caff0ac4b509a304c"
    family = "Mirai"
    file_name = "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:27"
  condition:
    hash.sha256(0, filesize) == "b785ba9b7b7e3fc5da5595c92c54b6e0ab42a0c9e3b1310caff0ac4b509a304c"
}
```

### Sample 17: `2eb780b601900b2a`

| Field | Value |
|---|---|
| SHA-256 | `2eb780b601900b2aa2fc35715b1a5dcaecb0e561ff6e11509a326e80fea6ee09` |
| Family label | `Mirai` |
| File name | `5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:16:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `049e17a8a8e17d8148badff6464f3a94` |
| SHA-1 | `a7e6f9f3a8a8c70ccd3493345ccc3a4c50a445a8` |
| SHA-256 | `2eb780b601900b2aa2fc35715b1a5dcaecb0e561ff6e11509a326e80fea6ee09` |
| SHA3-384 | `e1a1e3ef4d87fbb57d54b1dbcfe2be4802d3859fe94bab82c33c85881427fff1ceeba3f27c17568a57f620dbcdf41ed3` |
| TLSH | `T112C33A0675A144FCC156C074C77FD927EA32785D13343ABE6B84BB71AE22E365B0AB42` |
| SSDEEP | `3072:ZV0iUqzo0ijGA1AhARn8fd0uskJqNdG4tB:ZVfijGun8fdPsdNdrB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_2eb780b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2eb780b601900b2aa2fc35715b1a5dcaecb0e561ff6e11509a326e80fea6ee09"
    family = "Mirai"
    file_name = "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:21"
  condition:
    hash.sha256(0, filesize) == "2eb780b601900b2aa2fc35715b1a5dcaecb0e561ff6e11509a326e80fea6ee09"
}
```

### Sample 18: `47da111e14337dfb`

| Field | Value |
|---|---|
| SHA-256 | `47da111e14337dfb56d04c6eeae455f9fd413a1bd34b6e7a6be4414a8a1d676c` |
| Family label | `Mirai` |
| File name | `c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:16:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5ddb7fb3b215047b11660fb753c8837` |
| SHA-1 | `44fead7906b513503e52d5d2f667988da33565d4` |
| SHA-256 | `47da111e14337dfb56d04c6eeae455f9fd413a1bd34b6e7a6be4414a8a1d676c` |
| SHA3-384 | `dd70ff22a696673dfcc5b0f66d72afa949592ccf7dba1707803664c40cf5c4480133071b2a5d28dbc2761af15bcf4d26` |
| TLSH | `T1BDE35A59FA5FC0F0D6D344F1062BEBAA963699222232F4F1FF563A71F8B1301598526C` |
| SSDEEP | `3072:lc4H0QJcjjRed1TsOxiPhavLAyWI43qf7v:lc4UQmjsvxAQ0yy6j` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_47da111e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47da111e14337dfb56d04c6eeae455f9fd413a1bd34b6e7a6be4414a8a1d676c"
    family = "Mirai"
    file_name = "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:14"
  condition:
    hash.sha256(0, filesize) == "47da111e14337dfb56d04c6eeae455f9fd413a1bd34b6e7a6be4414a8a1d676c"
}
```

### Sample 19: `ae7683748d03c5f1`

| Field | Value |
|---|---|
| SHA-256 | `ae7683748d03c5f143465f8a298c726787f968e744eb7aece3a04a5f13f213ca` |
| Family label | `Mirai` |
| File name | `c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:16:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c215fc7c304094b9eae1b072dc7bcdf4` |
| SHA-1 | `7ecb9201cb2755b46efb0ba72f4ce7236d13504c` |
| SHA-256 | `ae7683748d03c5f143465f8a298c726787f968e744eb7aece3a04a5f13f213ca` |
| SHA3-384 | `4bc51d64756d37be6cb797edcc25989576c667c076e493624959ac0ec27ca19ca7419ffd78e8ee43759df0c380e44e1b` |
| TLSH | `T15D044C49AE742AFBC06FCE300929934711DDA44FA2F6A7396678CD4C759F2085DF3894` |
| TELFHASH | `t102319db08b7b65115ac5c7ec88ec775a591a8515470adf33fd2180bc50260ade22ad4f` |
| SSDEEP | `3072:aELD7ifs1Q8rEikvXMKtj/SGpuCayT6C8TWIIXTw/RbL6k8sGx1DXN+4/:bD7iE1Q8rEikvXMKbSGpuCayT6C8TWCA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_ae768374
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae7683748d03c5f143465f8a298c726787f968e744eb7aece3a04a5f13f213ca"
    family = "Mirai"
    file_name = "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:08"
  condition:
    hash.sha256(0, filesize) == "ae7683748d03c5f143465f8a298c726787f968e744eb7aece3a04a5f13f213ca"
}
```

### Sample 20: `a5a65f7a602bf856`

| Field | Value |
|---|---|
| SHA-256 | `a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd` |
| Family label | `WannaCry` |
| File name | `a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd` |
| File type | `exe` |
| First seen | `2026-08-18 00:15:47` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf45ceccffbbdc3f91aed61a3bfca6f1` |
| SHA-1 | `36554c407b733b09fabd2c137d63448aa5b375fb` |
| SHA-256 | `a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd` |
| SHA3-384 | `94a5c6575f415a4861644afee6d06886477136598303c55284a04f2687f5c8cd2a480bcefe866efdbeec2739430e61e9` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T19736235A31AC90FCD11B6374A4B38E26D2B37C5A227D970F8B5487661D03790BF68B63` |
| SSDEEP | `24576:jbLgBbLguEQhfdmMSirYbcMNgef0QeQjG/D8kI:jnsnUQqMSPbcBVQej/` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_020_a5a65f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd"
    family = "WannaCry"
    file_name = "a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd"
    file_type = "exe"
    first_seen = "2026-08-18 00:15:47"
  condition:
    hash.sha256(0, filesize) == "a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd"
}
```

### Sample 21: `1c5dbb5fbeb83d5e`

| Field | Value |
|---|---|
| SHA-256 | `1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407` |
| Family label | `Mirai` |
| File name | `1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:15:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9bab85ff0d9332006dab4f182479a431` |
| SHA-1 | `2e20a00816d8eddca48166871697ad726c04e951` |
| SHA-256 | `1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407` |
| SHA3-384 | `1bd35f72329d365aa7efdd079beca0179e87fb7d098b1466be2963357e15baf574850f46438bd13e9238e53ef82d834e` |
| TLSH | `T1A383121941769AB2FDC4DCF41D2286C5FE239E39ECFC37861D9A2A8607F5C10518C726` |
| SSDEEP | `1536:hLY0FTNR1b47wynOs5WAj2DMVm8J9FH1/kIYJ6oRIFVvv8SL7+Z7JheQL:1DFTtadWAyKHJNK6z9j+Z7JF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_1c5dbb5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407"
    family = "Mirai"
    file_name = "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:42"
  condition:
    hash.sha256(0, filesize) == "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407"
}
```

### Sample 22: `09d1afc8ea294d1e`

| Field | Value |
|---|---|
| SHA-256 | `09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0` |
| Family label | `Mirai` |
| File name | `09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:15:37` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcd99cfe4b6bfac5dc4f8d3c10016424` |
| SHA-1 | `c68f2d5cbac2cadd27bd7187327852f7d55a112a` |
| SHA-256 | `09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0` |
| SHA3-384 | `944cc65f81557e2c3aae8d4d780188d668a7850d49550721df35fcf5b476d9e365faffb6c25b532ee81ca749a55d7e49` |
| TLSH | `T1F06301C5893A3AC2D07F88327ED92BF27B27467310279CC2D4186896CD373696E75C42` |
| SSDEEP | `1536:EdlZNk+wIFmFNKwCdHhd9gEjiYNFEAuzp6RZjdnbYEDLcFV1ce:sHG+wDKfdrjiYvEAIkpVDYFV19` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_09d1afc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0"
    family = "Mirai"
    file_name = "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:37"
  condition:
    hash.sha256(0, filesize) == "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0"
}
```

### Sample 23: `419b9978ed20ad6b`

| Field | Value |
|---|---|
| SHA-256 | `419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016` |
| Family label | `Mirai` |
| File name | `419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:15:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6068d32d9ac378708203fda54e3cf5f9` |
| SHA-1 | `d9de4b05cdeed7efba5e90e9d6ecc9e96b738031` |
| SHA-256 | `419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016` |
| SHA3-384 | `4c7f8b0b7bc8b913abcd849944549cd09f10c8cd9f484a250553b56af00e48be76af1e9aff57dbe8ae64bca4b6587bb8` |
| TLSH | `T15A43F27D85C8BDEAEB56707EE051071FBF4FCBB5D492B9610799076827EA04E202C087` |
| SSDEEP | `1536:7WVKw1/Gaw9dzL0t9aG8A4KKgvSvZ8ZFmf9:aK0GayH0jUnsSvCm1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_419b9978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016"
    family = "Mirai"
    file_name = "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:32"
  condition:
    hash.sha256(0, filesize) == "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016"
}
```

### Sample 24: `5684d4a9dee9642b`

| Field | Value |
|---|---|
| SHA-256 | `5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f` |
| Family label | `Mirai` |
| File name | `5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:15:28` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6994ec72057849be7943327ca29af3b` |
| SHA-1 | `1413c5403d3599965c1d8053864511e832acc88e` |
| SHA-256 | `5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f` |
| SHA3-384 | `2792a822abcae05f31893d290d6b14a508eb0535070d1d1259d219401a585ed08567234fe0f9b99a51d8bdb9a8da22d4` |
| TLSH | `T1FB5302E35789AA7DCFFF80F5512D5480797B902A8A4F4B2B205119BBEC6FF0C9644709` |
| SSDEEP | `1536:1AwlCVKj2IjCgEIRuDEg4pTG8lAgHYPp5ecClP:uVKqqCN5UGyYBIP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_5684d4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f"
    family = "Mirai"
    file_name = "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:28"
  condition:
    hash.sha256(0, filesize) == "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f"
}
```

### Sample 25: `c7b36cde3fafc0a9`

| Field | Value |
|---|---|
| SHA-256 | `c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc` |
| Family label | `Mirai` |
| File name | `c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:15:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `147e287618a92f18e89a9924ea0f3844` |
| SHA-1 | `49f02d680ecf4bbf0f0794cdd7bd7079915c78f8` |
| SHA-256 | `c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc` |
| SHA3-384 | `fa4ca1bcfd56b2bfc2dcee878977071bdeba26ada7d2a17efb3edb546067155c6642f97472b751f39e6528401fdc7eb8` |
| TLSH | `T1ED53F14A508BE714F2D643B07E6BDEC6505C840FF2A38280FE7591AA489F7353694BE7` |
| SSDEEP | `1536:ziT0b3uIV1q0xVjnK3hU/KEWxBsDEpD9pBfCTnouy8DMg:Pb3TlVjnK3O6BsDEpD9rOoutDMg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_c7b36cde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc"
    family = "Mirai"
    file_name = "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:24"
  condition:
    hash.sha256(0, filesize) == "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc"
}
```

### Sample 26: `c97ba03bd5dfb2c5`

| Field | Value |
|---|---|
| SHA-256 | `c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47` |
| Family label | `Mirai` |
| File name | `c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:15:20` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da12c7b047b8ff24bfa80a05225dba96` |
| SHA-1 | `9ef936348073a58b7a91b500126471790f1b91b3` |
| SHA-256 | `c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47` |
| SHA3-384 | `1fd1e8413498726d2fe562843b3ca943fc8c30fe96e783444ed357e0b80f87adc847c89662cbe8ef97c6f171fd208fa4` |
| TLSH | `T11283021755B21AB5C253C83669F78C117B6FBC9E7BC86B30565AD28A7E30869E70C00E` |
| SSDEEP | `1536:0NcOK281TcRIGx25gfY7/JO9CrI8v4HeJTQn21QnZ5fUb7GD0ce:0eOK28ZOIGx2KfY7/M9CrI8g+J82mrUn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_c97ba03b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47"
    family = "Mirai"
    file_name = "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:20"
  condition:
    hash.sha256(0, filesize) == "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47"
}
```

### Sample 27: `70df37a7ce68efcc`

| Field | Value |
|---|---|
| SHA-256 | `70df37a7ce68efccd01b2e2ebc992d01931d5b3e423f53f665632a08e4a6c180` |
| Family label | `Mirai` |
| File name | `89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:11:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4be7cd072de3ff2d71803e4b5fa2ecd` |
| SHA-1 | `7b0745788c4c0eef2d0c51d05d0b6f64cdbc859e` |
| SHA-256 | `70df37a7ce68efccd01b2e2ebc992d01931d5b3e423f53f665632a08e4a6c180` |
| SHA3-384 | `c27e084b488aa461e3503886932e5e4dcc5db36141d3467acf2dc9dfede1bc486141e994f0a4587f7d722d3090ccd559` |
| TLSH | `T10BC33BA9F890DE52C6C52676FB4E418C33231778D3DA7105CE149E34F7EB96A0E3A942` |
| SSDEEP | `3072:D6rwNzs5nQCaUql6hxcYEEUjnIsAOJvLPM9euv3sNTFxNhbuCf1Dl:D6k5UiexcYEEUjnIsHVL0suv2tKC95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_70df37a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70df37a7ce68efccd01b2e2ebc992d01931d5b3e423f53f665632a08e4a6c180"
    family = "Mirai"
    file_name = "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:11:38"
  condition:
    hash.sha256(0, filesize) == "70df37a7ce68efccd01b2e2ebc992d01931d5b3e423f53f665632a08e4a6c180"
}
```

### Sample 28: `112843a05bbafa5c`

| Field | Value |
|---|---|
| SHA-256 | `112843a05bbafa5c0c3c2325788ef4fb65bf4c4158f01220b7a173ab716643b3` |
| Family label | `Mirai` |
| File name | `99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c763e6f1eb062979220ed6e885a9e0e` |
| SHA-1 | `22f3adcf7a5980d2c3eb1ee82bf3c61c0560215e` |
| SHA-256 | `112843a05bbafa5c0c3c2325788ef4fb65bf4c4158f01220b7a173ab716643b3` |
| SHA3-384 | `a915f3a5f8fb252c2427105fded5d1c1b4d7be00aa06a8a8cb3757e803f61bc66d6f52e7dab05f6da434d36b9e121a96` |
| TLSH | `T1CC148F00FB181913C5931DB44B3B0776E379DD8318B9F109290EBB564733AFA9A87B96` |
| SSDEEP | `6144:KxY6cjSYMvY0OJU7BDuWAIAivNQdLsYz8GI:8oWY9U8zieVI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_112843a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "112843a05bbafa5c0c3c2325788ef4fb65bf4c4158f01220b7a173ab716643b3"
    family = "Mirai"
    file_name = "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:56"
  condition:
    hash.sha256(0, filesize) == "112843a05bbafa5c0c3c2325788ef4fb65bf4c4158f01220b7a173ab716643b3"
}
```

### Sample 29: `34bc6abdf70e197e`

| Field | Value |
|---|---|
| SHA-256 | `34bc6abdf70e197e048a2fb0a5b20d7f2ad4a726ca8a4aa58a88bee5757f7f3d` |
| Family label | `Mirai` |
| File name | `50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef5e33da9f58a52860f7be54ad30690e` |
| SHA-1 | `c965cd61d3a7affc4f27bc113189970fb9d9d34c` |
| SHA-256 | `34bc6abdf70e197e048a2fb0a5b20d7f2ad4a726ca8a4aa58a88bee5757f7f3d` |
| SHA3-384 | `4d9eac685ffc2a5f7d08a7be99216f0392a761d18c443a8f25dd8f0d36a958ebe54b5e9f491c7c478de8861127e9419a` |
| TLSH | `T1D8C33BA9F890DE52C6C52676FB4E418C33231778D3DA7105CE149E34F7EB96A0E3A942` |
| SSDEEP | `3072:D6rwNzs5nQCaUql6hxcYEEUjnIsAOJvLPM9euv3sNTFxNhbuzf1Dl:D6k5UiexcYEEUjnIsHVL0suv2tKz95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_34bc6abd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34bc6abdf70e197e048a2fb0a5b20d7f2ad4a726ca8a4aa58a88bee5757f7f3d"
    family = "Mirai"
    file_name = "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:51"
  condition:
    hash.sha256(0, filesize) == "34bc6abdf70e197e048a2fb0a5b20d7f2ad4a726ca8a4aa58a88bee5757f7f3d"
}
```

### Sample 30: `f14841867417bba5`

| Field | Value |
|---|---|
| SHA-256 | `f14841867417bba572fa268bdb08ee9e4a723ab0856667f52f7b532aeda43423` |
| Family label | `Mirai` |
| File name | `cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6d9dd9916bf4e111da7b05638100f35` |
| SHA-1 | `b8ceee00dbef29f735a5051f9ca9d2b9c4705083` |
| SHA-256 | `f14841867417bba572fa268bdb08ee9e4a723ab0856667f52f7b532aeda43423` |
| SHA3-384 | `aa37a6b19a0ca0c4f5e718b2d195c175856b629a255d53d740b214d2f105ff243f061df93c29008f9a1884160706e6f9` |
| TLSH | `T161C33C99FC90DE52C6C52675F95E028C332317B8D3DA7206CD249F34B7E796A0E3A942` |
| SSDEEP | `3072:lPk6d7z96x2OCe5HoMiG8MqUQ4g8O9CVenThIhzDlp0NsMQf1DlD:l5XLe5WMqUQ4g8OoVenTulp0ZQ95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_f1484186
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14841867417bba572fa268bdb08ee9e4a723ab0856667f52f7b532aeda43423"
    family = "Mirai"
    file_name = "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:47"
  condition:
    hash.sha256(0, filesize) == "f14841867417bba572fa268bdb08ee9e4a723ab0856667f52f7b532aeda43423"
}
```

### Sample 31: `89f464e363f25559`

| Field | Value |
|---|---|
| SHA-256 | `89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2` |
| Family label | `Mirai` |
| File name | `89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:38` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7385f4b6e7f29da2b6be87dc243b42c1` |
| SHA-1 | `9a9e2da2d9b9df6109b286b08c06b5cd50bce246` |
| SHA-256 | `89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2` |
| SHA3-384 | `e9e5eb2502e3b718d6d997ad58be74234353278108d11f188c59a44c9d5d36edb8b9cd309d51b468cd830e30b1585e63` |
| TLSH | `T13F43026E55CC7EECDB59747EE064030A7F8B8B95E092FCB206990BB823D909E106D0C7` |
| SSDEEP | `1536:7WVKw1/Gaw9dzL0t9aG8A4KKQKa8bWIFmfZ:aK0GayH0jUndmh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_89f464e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2"
    family = "Mirai"
    file_name = "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:38"
  condition:
    hash.sha256(0, filesize) == "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2"
}
```

### Sample 32: `99aa30034b0277f1`

| Field | Value |
|---|---|
| SHA-256 | `99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123` |
| Family label | `Mirai` |
| File name | `99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a198aa024df494df612cf826cc726b50` |
| SHA-1 | `a5e2c1675c1d3e81bdd6f319cb54cc164583864b` |
| SHA-256 | `99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123` |
| SHA3-384 | `bdadcd940832ad8647d5f862891cdb7fd84e8b9b33b210c674434582085c6cef159792e4e3d7aeafe39e8c6e7852f32b` |
| TLSH | `T1A8530110D2C08F2BFF78363C45A2CAF277D61AFA16F4C4D49BA446B8B50576FA950A84` |
| SSDEEP | `1536:9YBfhsVEKn6jJNMgvHsvw3+8f40io6HSvaF+CFUUgtjcz4c4u+qgw0rJ/:0sVEKnC3H62LfTiotaMkUUQc4u+qgwC/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_99aa3003
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123"
    family = "Mirai"
    file_name = "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:33"
  condition:
    hash.sha256(0, filesize) == "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123"
}
```

### Sample 33: `c3bf94e24ef78430`

| Field | Value |
|---|---|
| SHA-256 | `c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7` |
| Family label | `Mirai` |
| File name | `c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:28` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `caf2b4d62daae3ed3190f107f1e1966e` |
| SHA-1 | `78906d1368b9248d7b9821b8515de4b20329bacf` |
| SHA-256 | `c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7` |
| SHA3-384 | `58fef8c439dfaa1396a659e2b149c6dc9dd3db78c5a684aa88cfae44a9dcae79b1b39af6453b41d080a4e22e430a5c3c` |
| TLSH | `T1C9C37CC5B20C7EAED1836D3CC20A13176E1C9E50DC93451190B9FA47DAB72E71E269CB` |
| TELFHASH | `t1c5e0b1f1878fa205458dcbcd83c9779c1a0dd145004bef13fd62553c816091cb95998f` |
| SSDEEP | `3072:7/rWMAYhE8ZcWBJcPv9rS27klpaaBP5rCypvxrFs8QLLjyokIpo:Dr3Tbmv9rKcaBPR9vxr+8QXvkI2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_c3bf94e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7"
    family = "Mirai"
    file_name = "c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:28"
  condition:
    hash.sha256(0, filesize) == "c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7"
}
```

### Sample 34: `50f2e541c9ce5575`

| Field | Value |
|---|---|
| SHA-256 | `50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae` |
| Family label | `Mirai` |
| File name | `50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `668488c84752b08c98a1820cd1ee4ef7` |
| SHA-1 | `e26631ddc0629c4bdbdc1f19e4db2ac4da14e4ba` |
| SHA-256 | `50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae` |
| SHA3-384 | `4669240148df0571f57c402fa765c5fed0b664024f71e5f0d9da08efc7ed44c1c3afc391c4f5e28a70bb02c104e18ec7` |
| TLSH | `T15F4302BD9688BED9D35A3439E054030B7F8ECB96E0D3B87116594BF827EA09E141D4C7` |
| SSDEEP | `1536:7WVKw1/Gaw9dzL0t9aG8A4KK7+7YBwFmfz:aK0GayH0jUnWYqmL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_50f2e541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae"
    family = "Mirai"
    file_name = "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:25"
  condition:
    hash.sha256(0, filesize) == "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae"
}
```

### Sample 35: `cae329df409e789c`

| Field | Value |
|---|---|
| SHA-256 | `cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1` |
| Family label | `Mirai` |
| File name | `cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1.elf` |
| File type | `elf` |
| First seen | `2026-08-18 00:10:18` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8300ed9ecd4f7af30cda8cb93fd27f5` |
| SHA-1 | `bc2ab06d5ad4e20d21db9682c2d1091bbff9130a` |
| SHA-256 | `cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1` |
| SHA3-384 | `7643075f46eafba2339390f70e17d422bb92262eeb45cf1789d7cae79f0b86c49c82b4557a039746db1bdd4d481fe733` |
| TLSH | `T18543F1B0A39AA694CA346476B72C676AF34811F601DB2103D6614D77F4F4FD0A0A87EA` |
| SSDEEP | `1536:w6WBjb9y3nbust76bjIerMDSTbbV4YtCylvivG2Sso/fw:xmjb9y5BgjrMDKbFCylvsHG/o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_cae329df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1"
    family = "Mirai"
    file_name = "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:18"
  condition:
    hash.sha256(0, filesize) == "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1"
}
```

### Sample 36: `c1bbf296cafb65c2`

| Field | Value |
|---|---|
| SHA-256 | `c1bbf296cafb65c2ec94c313cb043889183bc79316be9f20344fd59c7da92421` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-18 00:02:50` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cc11dd00e8a82bf4cc2111992078611` |
| SHA-1 | `2af00978bb8836190e710fbd3ab201e7bd9c08a8` |
| SHA-256 | `c1bbf296cafb65c2ec94c313cb043889183bc79316be9f20344fd59c7da92421` |
| SHA3-384 | `c62820a5b4832a0246e274656a8f12eab68b1564adc9f8d834e018577d50838a525bef9331d6a91f56874f96b53d3eb9` |
| IMPHASH | `c44f935d14991cc22f7845a20b7ff7f2` |
| TLSH | `T12B1423445D82FD88D1FF00703C9E4275B9B92AFC9EF5A5E7350B75108CA4AD4A8E0EA3` |
| SSDEEP | `3072:Q4xVsYtbORgxbXAgKwjrdy6gs4TJi7P4X2JmdU4NiTxRS/0RR/96OmySzYQkUNrs:QXYtbOix7AgK6iYbc2JfkiTxRS/u1rm4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_c1bbf296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1bbf296cafb65c2ec94c313cb043889183bc79316be9f20344fd59c7da92421"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 00:02:50"
  condition:
    hash.sha256(0, filesize) == "c1bbf296cafb65c2ec94c313cb043889183bc79316be9f20344fd59c7da92421"
}
```

### Sample 37: `c177e67cb8d6aa08`

| Field | Value |
|---|---|
| SHA-256 | `c177e67cb8d6aa080cfb1493b15aea4aec8ed809c80054e12adb7b43ff6ba8a2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 23:54:53` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17037ada7152668022ac26c204c33075` |
| SHA-1 | `fdee60d6ee97c3714373136297e6d34ccac68e78` |
| SHA-256 | `c177e67cb8d6aa080cfb1493b15aea4aec8ed809c80054e12adb7b43ff6ba8a2` |
| SHA3-384 | `ae6561a01fbc8b2c58ced1f27e8bcdce83291ef3e3265558a209bc806aa0f327a428911c8bfc0e62c9bf60417886df6d` |
| IMPHASH | `366b3dd8ee9f9843ce1278514005b708` |
| TLSH | `T1CF5612433F00D602D95A2E718AB4C7F96720FE489A85938B34E6BE2FFDD96D34E15184` |
| SSDEEP | `98304:t+90liLbDpDtuvXBOck4CmfvB3oxlDxLf7FgT4d95W91YxnA2uK4:thliXDBtuvPCm3MvxSK95W9yxnApK4` |
| ICON-DHASH | `30f0cc968ecc6821` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_c177e67c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c177e67cb8d6aa080cfb1493b15aea4aec8ed809c80054e12adb7b43ff6ba8a2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 23:54:53"
  condition:
    hash.sha256(0, filesize) == "c177e67cb8d6aa080cfb1493b15aea4aec8ed809c80054e12adb7b43ff6ba8a2"
}
```

### Sample 38: `5fa3e214842722f8`

| Field | Value |
|---|---|
| SHA-256 | `5fa3e214842722f8dbc56499a74b3794701fd00a7c38396f9bd22c382ad73816` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-17 23:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5029426caf4a893927ba671d10442cc0` |
| SHA-1 | `616f1223a7db481ff618215ce418220a85e1743e` |
| SHA-256 | `5fa3e214842722f8dbc56499a74b3794701fd00a7c38396f9bd22c382ad73816` |
| SHA3-384 | `4a5466dc0bbf0e63ea8f37be7feef5ce557f35aa4deeb7355fd9641a4b0f27d78e3cfef84833ab2948a4dc731cdfff5b` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1E9E633445BD062EECE73623CEEE14371A67938690B75CAEF52B843159F171D0883E72A` |
| SSDEEP | `393216:oZhsiatOIv8sT0W3JXMCHWUj3cuI3/PGTAI:owtOIvrT0iXMb8MH/O7` |
| ICON-DHASH | `b271e8cccce8f0b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_5fa3e214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fa3e214842722f8dbc56499a74b3794701fd00a7c38396f9bd22c382ad73816"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 23:52:10"
  condition:
    hash.sha256(0, filesize) == "5fa3e214842722f8dbc56499a74b3794701fd00a7c38396f9bd22c382ad73816"
}
```

### Sample 39: `77702ddc1b003b03`

| Field | Value |
|---|---|
| SHA-256 | `77702ddc1b003b03bbd30b5cefb9c737f1ba11df7db07f848fb11aee0b1440fe` |
| Family label | `unknown` |
| File name | `NexusMods.exe` |
| File type | `exe` |
| First seen | `2026-08-17 22:54:40` |
| Reporter | `anonymous` |
| Tags | `exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6174ac8ed359acb1babe9c58917431fd` |
| SHA-256 | `77702ddc1b003b03bbd30b5cefb9c737f1ba11df7db07f848fb11aee0b1440fe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_77702ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77702ddc1b003b03bbd30b5cefb9c737f1ba11df7db07f848fb11aee0b1440fe"
    family = "unknown"
    file_name = "NexusMods.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:54:40"
  condition:
    hash.sha256(0, filesize) == "77702ddc1b003b03bbd30b5cefb9c737f1ba11df7db07f848fb11aee0b1440fe"
}
```

### Sample 40: `9b1cba255f9494df`

| Field | Value |
|---|---|
| SHA-256 | `9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9` |
| Family label | `Prometei` |
| File name | `9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9` |
| File type | `elf` |
| First seen | `2026-08-17 22:52:36` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3b4dd4011cf04ed777149dcd042f58c` |
| SHA-1 | `6819b4fbc701a3777586e5dad17c54d3185d35d7` |
| SHA-256 | `9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9` |
| SHA3-384 | `b1391d1f77527dd3ca114a3de0bd1cb4aed217193187f841770aa2899ff5c605dab1706bf1231eb8d8371e086a224aab` |
| TLSH | `T1D5A423B4F9219E9F6DD769F91B24831DE181C172689D4C2313AE94E34F3D632AF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsd1:Fs6pyCC/Ya2hpi6T6N43` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_040_9b1cba25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9"
    family = "Prometei"
    file_name = "9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9"
    file_type = "elf"
    first_seen = "2026-08-17 22:52:36"
  condition:
    hash.sha256(0, filesize) == "9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9"
}
```

### Sample 41: `31876a3a26a0f92a`

| Field | Value |
|---|---|
| SHA-256 | `31876a3a26a0f92a001dcae2b84174bb9f47af9208f7a92b6e160b1931899b01` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-17 22:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74144ce50b557709049a757091ea8b9f` |
| SHA-1 | `d8d0f68556d02eb0e99892e1bd1870c948604bf9` |
| SHA-256 | `31876a3a26a0f92a001dcae2b84174bb9f47af9208f7a92b6e160b1931899b01` |
| SHA3-384 | `c84bb83af0bd30167de270be5ee079272c817cae9aa89ab6969ecc668d611b290ca9939566bd89ee1a7eabd40600a313` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1B2E6334CA3E412EED5F3113CAB920558E775B832173DC5EF43B95161AE632E09C39A1B` |
| SSDEEP | `393216:lqr7DxNQDpUN0wK1XMCHWUj/cuI3/PGTAI:lqHDxNqUN0wcXMb8UH/O7` |
| ICON-DHASH | `30f0d4d8c8ecf030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_31876a3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31876a3a26a0f92a001dcae2b84174bb9f47af9208f7a92b6e160b1931899b01"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 22:52:10"
  condition:
    hash.sha256(0, filesize) == "31876a3a26a0f92a001dcae2b84174bb9f47af9208f7a92b6e160b1931899b01"
}
```

### Sample 42: `15658aa912696d8c`

| Field | Value |
|---|---|
| SHA-256 | `15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe` |
| Family label | `unknown` |
| File name | `15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe.bin` |
| File type | `exe` |
| First seen | `2026-08-17 22:40:06` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5e7e7604e186579f461050084151c61` |
| SHA-1 | `9e647365800ab23181132408e323b2f3e5b232a5` |
| SHA-256 | `15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe` |
| SHA3-384 | `e5f2f8d485f9ab45ffe6dd0520714605583530965d4815e106160d27e5009911d7c863b09787dbf35dc0cf4a6d094afc` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1ECA733076C9146E5C0A9AA309967A196BB35BC0C4F3233D76EA0B7782F727C45D7AF01` |
| SSDEEP | `786432:prSIdq0YS4GwkyBAnpPfDGuCLigQ+eHUb6pLOqmWPZ0CxE+nEi:Vs0CGfyCh7AQ/06/P6CxEwH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_15658aa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe"
    family = "unknown"
    file_name = "15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe.bin"
    file_type = "exe"
    first_seen = "2026-08-17 22:40:06"
  condition:
    hash.sha256(0, filesize) == "15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe"
}
```

### Sample 43: `9758059acd85ad5b`

| Field | Value |
|---|---|
| SHA-256 | `9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298` |
| Family label | `unknown` |
| File name | `9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298.exe` |
| File type | `exe` |
| First seen | `2026-08-17 22:25:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ef6ce79530182d4d4c293cb43899b90` |
| SHA-1 | `54cfc695ab59c04e040986bcca2a3f409a37db4f` |
| SHA-256 | `9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298` |
| SHA3-384 | `6cdee1e177dbdeab908aa67bdf81de749a617130bb41c9faca3edbe157e0a31d45dc0ea1a41f10bf450a3bcc8578ccd3` |
| IMPHASH | `24e8765fd838d429e6f908cdeb96c2d6` |
| TLSH | `T14ED523CAFDD20434E032C3B753A3606E71787BA447794C9B76C9AB102E526287CB7679` |
| SSDEEP | `49152:U5/fnX+BnSkbnF0teLSUCF83lefEQbAuG9lK1cXOF2sQLE325c+AoCnGs8fK:UhX+BS0F0tsSUt3lefE5tGD2sQLA25IR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_9758059a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298"
    family = "unknown"
    file_name = "9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:25:39"
  condition:
    hash.sha256(0, filesize) == "9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298"
}
```

### Sample 44: `5e08c1d1f34fda07`

| Field | Value |
|---|---|
| SHA-256 | `5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082` |
| Family label | `unknown` |
| File name | `5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082.exe` |
| File type | `exe` |
| First seen | `2026-08-17 22:25:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `580415ed81e71919c8ebe2a9d4368bda` |
| SHA-1 | `fb5cc1263f8cbf264afa9da8e7e989c0dfb46731` |
| SHA-256 | `5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082` |
| SHA3-384 | `ab432589a0ef1592925ddca6249af6518f6fd81d42ab9e01738a658b95f3e291fb7e7fc77461abf7ea79dd924e600667` |
| IMPHASH | `b8048b8957358587b4fda264349e8f60` |
| TLSH | `T187D5239A79F609B1D433C3B5CF82E46CB03EBB954A718E8BBACD2D044D121945C7A772` |
| SSDEEP | `49152:ULCAp+dVQHLnhw0IzzNqpQ3h8gUcZhtVliaXHPYYf2RQ825ByXuqebc3I2pgS29:ULCLVuiZD+IVliqhf2682AngT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_5e08c1d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082"
    family = "unknown"
    file_name = "5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:25:34"
  condition:
    hash.sha256(0, filesize) == "5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082"
}
```

### Sample 45: `5436f494f7a96e51`

| Field | Value |
|---|---|
| SHA-256 | `5436f494f7a96e5140529e5b628ed70d51b10e932a82c56abb0e8e826ba64c1c` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-17 22:17:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c67136aa483532f4a96e50acff1e6e2` |
| SHA-1 | `1c659313810fac3d40efde216f63eb5442cf9d4a` |
| SHA-256 | `5436f494f7a96e5140529e5b628ed70d51b10e932a82c56abb0e8e826ba64c1c` |
| SHA3-384 | `9993545128a181cdae6ef4034de9656ba6a6fa0babeac4d8f910ac2c26d787c451c406c0ffe521970e585e6f39b494f0` |
| TLSH | `T1BCC27D966A867C44BEC94B3E4CBD2B1D6DF5C3D1324942AC3D4A3C719C11FACD618B1A` |
| SSDEEP | `768:g8vCB+25j6es8R89FYpMSUpi+20qUpi+20YQX:g8l25JKd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_5436f494
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5436f494f7a96e5140529e5b628ed70d51b10e932a82c56abb0e8e826ba64c1c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-17 22:17:17"
  condition:
    hash.sha256(0, filesize) == "5436f494f7a96e5140529e5b628ed70d51b10e932a82c56abb0e8e826ba64c1c"
}
```

### Sample 46: `57369d7d7eb1ea95`

| Field | Value |
|---|---|
| SHA-256 | `57369d7d7eb1ea95aef9f374dd418af94c2b9e534e46a83257b57ac48ecb11a5` |
| Family label | `unknown` |
| File name | `9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6` |
| File type | `exe` |
| First seen | `2026-08-17 22:15:56` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c216ea7a3a3628736c7e66ec88d32570` |
| SHA-1 | `53c08c630d49b934f02d0b551b889a1cd7d078f5` |
| SHA-256 | `57369d7d7eb1ea95aef9f374dd418af94c2b9e534e46a83257b57ac48ecb11a5` |
| SHA3-384 | `a291fc6fa093db54449b514aa34e339717d4317b5fc190dc51acbc77c5e67980f45ccaa64b340604a57ea2dc61fe984f` |
| IMPHASH | `d9210cd966b2e5956644b71b6805e8d7` |
| TLSH | `T17974DF63F6B8F14EE88297324B57CB0287A53FA58842E09E79B4230F28756544F74F76` |
| SSDEEP | `6144:7+LQwhNI65MY5wH2l3D5YolYvRjf6yl/5JTFw1iKzHk2oGbksEb5iFeL:7MQwA65YHWDeXvRjf6YnyixGbk1o4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_57369d7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57369d7d7eb1ea95aef9f374dd418af94c2b9e534e46a83257b57ac48ecb11a5"
    family = "unknown"
    file_name = "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
    file_type = "exe"
    first_seen = "2026-08-17 22:15:56"
  condition:
    hash.sha256(0, filesize) == "57369d7d7eb1ea95aef9f374dd418af94c2b9e534e46a83257b57ac48ecb11a5"
}
```

### Sample 47: `5551851317fe09fb`

| Field | Value |
|---|---|
| SHA-256 | `5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34` |
| Family label | `Prometei` |
| File name | `5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34` |
| File type | `elf` |
| First seen | `2026-08-17 22:15:29` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16ce99cb1c29d60c68ab78156eab7e18` |
| SHA-1 | `37523dd0c6fe0900356427a87ec29ba0b20d3c88` |
| SHA-256 | `5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34` |
| SHA3-384 | `7e4b988837cd153b87f48c7e76466dc2f01fe28c4a27de1bbd878fb0bef54c63bc96cca4d346421a7b4e79dc9af02499` |
| TLSH | `T1D29423FA5A8EF3FB49127F7027A0980181A47470F99D775986CBFDDA0FA52679CC8108` |
| SSDEEP | `12288:4a6aYYIX2dWVxeJAaLYxAOfUhjXb44UfhlBeLn:V+2WejYxUxsU` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_047_55518513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34"
    family = "Prometei"
    file_name = "5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34"
    file_type = "elf"
    first_seen = "2026-08-17 22:15:29"
  condition:
    hash.sha256(0, filesize) == "5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34"
}
```

### Sample 48: `9103f68a42ba9227`

| Field | Value |
|---|---|
| SHA-256 | `9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6` |
| Family label | `unknown` |
| File name | `9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6` |
| File type | `exe` |
| First seen | `2026-08-17 22:14:45` |
| Reporter | `c2hunter` |
| Tags | `exe, upx, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f93e6b9e82803cdec12ddb6d68a2cd4` |
| SHA-1 | `970e2d3b9c0605bc83ec76c607e006579f4a7045` |
| SHA-256 | `9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6` |
| SHA3-384 | `1270af7461ce7583238bb99c4103ff282ab809c2fae77d7e676337f0f3538f113677b27f38caa7516c811eb2eb60fd4d` |
| IMPHASH | `f418afe0379776397753ae40798cc2e3` |
| TLSH | `T18E34F13628B82F04D4637335B1071F3196F59B1F3B7A129EEAFE47B5B1A4A0119630DA` |
| SSDEEP | `6144:VMooVQnnOBccnskYPmTpUxrr1XRA7WHxWoN+J0EafCUSYibN6WG7:OQnO/s1mTpG5bUo4bafVibvY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_9103f68a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
    family = "unknown"
    file_name = "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
    file_type = "exe"
    first_seen = "2026-08-17 22:14:45"
  condition:
    hash.sha256(0, filesize) == "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
}
```

### Sample 49: `e680982a6eb09369`

| Field | Value |
|---|---|
| SHA-256 | `e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0` |
| Family label | `unknown` |
| File name | `e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0.bin` |
| File type | `exe` |
| First seen | `2026-08-17 22:13:20` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dac9b8fb50eaeaf0453a9d6ae115570d` |
| SHA-1 | `5ed12f354b49f96f6d4dc89135e6b863b873a2cf` |
| SHA-256 | `e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0` |
| SHA3-384 | `1ed253333309d9ce9af8b5d441ad7d8f2bf0ba6888b903fd3b9df4590c6ca484a574c8a6ff0bd054e6e74c9295dcb26d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A2969E8BAD910A5DD08A853A8A7B6341773478785B7133DB2E60B2383EB5FD47D7A340` |
| SSDEEP | `98304:qyXtM6QvLVNUBLqlDA4cYdaodJHwMmciUx:qymBNiWEIJHwMmq` |
| ICON-DHASH | `2259b86861d3d42a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_e680982a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0"
    family = "unknown"
    file_name = "e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0.bin"
    file_type = "exe"
    first_seen = "2026-08-17 22:13:20"
  condition:
    hash.sha256(0, filesize) == "e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0"
}
```

### Sample 50: `34e57ad8876da0ff`

| Field | Value |
|---|---|
| SHA-256 | `34e57ad8876da0ffa60b3fc74386eb8d35f5a75c5f1ef870537e57eaa4f598ab` |
| Family label | `unknown` |
| File name | `FUXhack V3.1.2.exe` |
| File type | `exe` |
| First seen | `2026-08-17 22:12:54` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44e572b79d0ecd8b29e79a0e1ff15a99` |
| SHA-256 | `34e57ad8876da0ffa60b3fc74386eb8d35f5a75c5f1ef870537e57eaa4f598ab` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_34e57ad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e57ad8876da0ffa60b3fc74386eb8d35f5a75c5f1ef870537e57eaa4f598ab"
    family = "unknown"
    file_name = "FUXhack V3.1.2.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:12:54"
  condition:
    hash.sha256(0, filesize) == "34e57ad8876da0ffa60b3fc74386eb8d35f5a75c5f1ef870537e57eaa4f598ab"
}
```

### Sample 51: `018937753ffa1fdc`

| Field | Value |
|---|---|
| SHA-256 | `018937753ffa1fdc88796297948d82cff81b0b0beb1dae0335417b178eb581f2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 22:09:31` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX1.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c2668a8f6101dd6977e602171f5c9e3` |
| SHA-1 | `8f7d02fdec98ceff04f2156a93504086a5b224f8` |
| SHA-256 | `018937753ffa1fdc88796297948d82cff81b0b0beb1dae0335417b178eb581f2` |
| SHA3-384 | `b86c0efe333303de4c201593c427ffa40c0d5b44bb4e5e10fb32a8ed1a99cb4782d80b57ab1ec74e846eacb52e65edc2` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A4769E03FD9505A9C0AA9639C9B743527B38B8498B3137D72E50B7383EB6BC16E79740` |
| SSDEEP | `49152:QytrJs9Ae21l8ZiJKTUrkyMcn2/qGuXvy1c7l98/dj4RST1n5R45roPZp5Ry/Ni+:Qy+Aefy4fw3YdCroPf5/jQ+HFXkn9J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_01893775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "018937753ffa1fdc88796297948d82cff81b0b0beb1dae0335417b178eb581f2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 22:09:31"
  condition:
    hash.sha256(0, filesize) == "018937753ffa1fdc88796297948d82cff81b0b0beb1dae0335417b178eb581f2"
}
```

### Sample 52: `562620e1df663c85`

| Field | Value |
|---|---|
| SHA-256 | `562620e1df663c852e7323d07272d223d29e8558c95110faac06f7c6d26eec5b` |
| Family label | `unknown` |
| File name | `GTA6.exe` |
| File type | `exe` |
| First seen | `2026-08-17 22:00:39` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `891cde05a29c5d9adbe71ae598a32703` |
| SHA-256 | `562620e1df663c852e7323d07272d223d29e8558c95110faac06f7c6d26eec5b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_562620e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "562620e1df663c852e7323d07272d223d29e8558c95110faac06f7c6d26eec5b"
    family = "unknown"
    file_name = "GTA6.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:00:39"
  condition:
    hash.sha256(0, filesize) == "562620e1df663c852e7323d07272d223d29e8558c95110faac06f7c6d26eec5b"
}
```

### Sample 53: `4abbb9cb37b34ec4`

| Field | Value |
|---|---|
| SHA-256 | `4abbb9cb37b34ec498078496f17a7821b8271ae2e01f63e773a1feac994cd0f4` |
| Family label | `unknown` |
| File name | `QuickFetch.exe` |
| File type | `exe` |
| First seen | `2026-08-17 21:52:15` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc5d7aa1fe8e77ea708b00ad094a8b96` |
| SHA-1 | `51b914308e60389fde5493a580a4869c229544e2` |
| SHA-256 | `4abbb9cb37b34ec498078496f17a7821b8271ae2e01f63e773a1feac994cd0f4` |
| SHA3-384 | `791c0b09589ee8356c4c3c15f37623344fcab7ff82069f25f51acbe1ee5759579e8a285a2e02a27562c68a1d5b3a2089` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1EDB55A0B7CA145E9C0AAAB3689775265BB31BC0C4B3533D72E90B6742FB23C15D7AB44` |
| SSDEEP | `24576:SoopQ0oM08IElG7ZfPytOCngGkigcxRykT6rTtR3pkHLb4LxbO5CaaTBele5y92B:SooyTMQMG7BykHTswXZkHLb4LxbcHJ6f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_4abbb9cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4abbb9cb37b34ec498078496f17a7821b8271ae2e01f63e773a1feac994cd0f4"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-17 21:52:15"
  condition:
    hash.sha256(0, filesize) == "4abbb9cb37b34ec498078496f17a7821b8271ae2e01f63e773a1feac994cd0f4"
}
```

### Sample 54: `e77c1d3fd059fe82`

| Field | Value |
|---|---|
| SHA-256 | `e77c1d3fd059fe8248e81fdfcbdc1f72c99bd208e4951203e43e16f803dabb1d` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-17 21:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e88adcb803dc99ce1e5b565a061e9937` |
| SHA-1 | `8fc7f5d80ef3745ac43f6e22ca27de7d61d0644c` |
| SHA-256 | `e77c1d3fd059fe8248e81fdfcbdc1f72c99bd208e4951203e43e16f803dabb1d` |
| SHA3-384 | `68030adea9f6c281da73a474bb7cf8fa0a2056f76acc61356b79ee095e824db49cf0533d8f9725acc286171102844dc5` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1BFE6331D99D111EFD6B3913D6DA208A4E938B876237AC9DB137403A5BD272E02C7D723` |
| SSDEEP | `393216:ecCiRdvvd3Y3Voq3bihcqoNsFba88PF0MAXMCHWUjIcuI3/PGTAI:xCkdHO3VoZcLyFu8qF0MAXMb89H/O7` |
| ICON-DHASH | `71f0e4d6e6e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_e77c1d3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e77c1d3fd059fe8248e81fdfcbdc1f72c99bd208e4951203e43e16f803dabb1d"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 21:52:10"
  condition:
    hash.sha256(0, filesize) == "e77c1d3fd059fe8248e81fdfcbdc1f72c99bd208e4951203e43e16f803dabb1d"
}
```

### Sample 55: `ac3af462408f14e5`

| Field | Value |
|---|---|
| SHA-256 | `ac3af462408f14e5f953129158a65c9a75f2109d69bdd447aacd6998b488c9d5` |
| Family label | `unknown` |
| File name | `Launcher.exe` |
| File type | `exe` |
| First seen | `2026-08-17 21:39:06` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4c58110e0378154907357f9d2dd859a` |
| SHA-256 | `ac3af462408f14e5f953129158a65c9a75f2109d69bdd447aacd6998b488c9d5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_ac3af462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac3af462408f14e5f953129158a65c9a75f2109d69bdd447aacd6998b488c9d5"
    family = "unknown"
    file_name = "Launcher.exe"
    file_type = "exe"
    first_seen = "2026-08-17 21:39:06"
  condition:
    hash.sha256(0, filesize) == "ac3af462408f14e5f953129158a65c9a75f2109d69bdd447aacd6998b488c9d5"
}
```

### Sample 56: `051f2d8dd668f5c0`

| Field | Value |
|---|---|
| SHA-256 | `051f2d8dd668f5c0a4d4cbeba44db53b970daae37f9408a02de6563f287cbee6` |
| Family label | `unknown` |
| File name | `y` |
| File type | `unknown` |
| First seen | `2026-08-17 21:34:18` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5ab838a4e1dae90874dff31fbcc34e8` |
| SHA-256 | `051f2d8dd668f5c0a4d4cbeba44db53b970daae37f9408a02de6563f287cbee6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_051f2d8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "051f2d8dd668f5c0a4d4cbeba44db53b970daae37f9408a02de6563f287cbee6"
    family = "unknown"
    file_name = "y"
    file_type = "unknown"
    first_seen = "2026-08-17 21:34:18"
  condition:
    hash.sha256(0, filesize) == "051f2d8dd668f5c0a4d4cbeba44db53b970daae37f9408a02de6563f287cbee6"
}
```

### Sample 57: `89dacc86bc936a33`

| Field | Value |
|---|---|
| SHA-256 | `89dacc86bc936a33d32fc6070e8b0923f247d8dc89f21b331ecba9bb2ae9b01a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 21:33:17` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d002785e313e02506581408ea5d52af` |
| SHA-1 | `a4bfa303e8878d30db7291435ffbe8b96b4b7932` |
| SHA-256 | `89dacc86bc936a33d32fc6070e8b0923f247d8dc89f21b331ecba9bb2ae9b01a` |
| SHA3-384 | `8b06591ca651512071d90554065d49636a5841aa691829a1cb72dead9a259cbc483ecb6dff721b3ef6001a5798dc3077` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1F7F59D07BD8591B5C5EAE2318AB60251B6307C984B3137C72F51B7B82F727D06E3AB94` |
| SSDEEP | `49152:Fu2Jcd/As6hNuq5NI+8hvk39I6ioh2ztCvZg5ybwj14msD1ONjHhb/1yyebSr72p:U+hNh5Z8hv89iPVV1hpbeotop` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_89dacc86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89dacc86bc936a33d32fc6070e8b0923f247d8dc89f21b331ecba9bb2ae9b01a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 21:33:17"
  condition:
    hash.sha256(0, filesize) == "89dacc86bc936a33d32fc6070e8b0923f247d8dc89f21b331ecba9bb2ae9b01a"
}
```

### Sample 58: `53b349aac82e1fc1`

| Field | Value |
|---|---|
| SHA-256 | `53b349aac82e1fc104db81027c957a38c1abac76f6dd20c8536ba267ef4b0727` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-17 21:22:42` |
| Reporter | `anonymous` |
| Tags | `exe, SalatStealer, stealer, XMRIG` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `528fd5e9877c7a6433a14a6594e3cfa5` |
| SHA-256 | `53b349aac82e1fc104db81027c957a38c1abac76f6dd20c8536ba267ef4b0727` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_53b349aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53b349aac82e1fc104db81027c957a38c1abac76f6dd20c8536ba267ef4b0727"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 21:22:42"
  condition:
    hash.sha256(0, filesize) == "53b349aac82e1fc104db81027c957a38c1abac76f6dd20c8536ba267ef4b0727"
}
```

### Sample 59: `dd16a399bfd025a7`

| Field | Value |
|---|---|
| SHA-256 | `dd16a399bfd025a70ab801188be21e98b09eb53b02777478ad144d34f7643282` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-17 21:20:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bd67025a1aa17079be0981d3cf5cc44` |
| SHA-1 | `8ce55dbbce4205314cfaaf590f1fde8bdffd0890` |
| SHA-256 | `dd16a399bfd025a70ab801188be21e98b09eb53b02777478ad144d34f7643282` |
| SHA3-384 | `cd38ec3ad5dd7cb0b76287c675751b3813346605ef7c7d479f91c9472ec66968b6100e7f1279eb677942ee03bd337347` |
| TLSH | `T14D237D652A817C14AA98C4371D7E2F0CB9AD43E6320452ED7FCF3CF68C5A69DA11871D` |
| SSDEEP | `768:OXOGVvU9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ALxcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_dd16a399
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd16a399bfd025a70ab801188be21e98b09eb53b02777478ad144d34f7643282"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-17 21:20:37"
  condition:
    hash.sha256(0, filesize) == "dd16a399bfd025a70ab801188be21e98b09eb53b02777478ad144d34f7643282"
}
```

### Sample 60: `b407def7668e61b9`

| Field | Value |
|---|---|
| SHA-256 | `b407def7668e61b9a917aeecdfc408fa3b91c7a9656551debede768fc2406bf5` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-17 21:17:55` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `734f1854f6638cea92cf9474cfb58ecb` |
| SHA-1 | `d7eddf2333c1cf28ba57bdafe072173ee1e0111f` |
| SHA-256 | `b407def7668e61b9a917aeecdfc408fa3b91c7a9656551debede768fc2406bf5` |
| SHA3-384 | `acbc3a0cdcfc50eafb92f34ba17e477880baf1d389979c8539fcedb4e79d56ff2225bb1b56f159ec680f103d71dd0172` |
| TLSH | `T104C27D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:Q8vCB+25j6es8Ry9FYpMSUpi+20qUpi+20YQX:Q8l25JUd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_b407def7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b407def7668e61b9a917aeecdfc408fa3b91c7a9656551debede768fc2406bf5"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-17 21:17:55"
  condition:
    hash.sha256(0, filesize) == "b407def7668e61b9a917aeecdfc408fa3b91c7a9656551debede768fc2406bf5"
}
```

### Sample 61: `bab753aa194389c1`

| Field | Value |
|---|---|
| SHA-256 | `bab753aa194389c1877e5d21e6bcd2a1cfe291388363239561ca6f6172473dee` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 21:12:39` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56e23ae8475784e31f85f887b2b9993f` |
| SHA-1 | `e12b715bcfb654c6a0aeb12acf9c12f7a12ba46e` |
| SHA-256 | `bab753aa194389c1877e5d21e6bcd2a1cfe291388363239561ca6f6172473dee` |
| SHA3-384 | `6a9a7d7717c461a69cea1ae77cdd856a0a4e4daf8ce3d5b1e885e51cc2246822fc5c7e400058ee57c1e72a6ac055892f` |
| TLSH | `T1DFC582207EE1D01257C0B93885D11FA08942C925A0F35FABE9AF3F7DBB2A51D0A5CD76` |
| SSDEEP | `49152:jc1NkB+2HDYp/r2LbQgG+b6Hn8R+HcwBOlyzApfG6j+vfXx3ec:Y1Sk2kpT2VGBH8gcwBopfG66vf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_bab753aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bab753aa194389c1877e5d21e6bcd2a1cfe291388363239561ca6f6172473dee"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 21:12:39"
  condition:
    hash.sha256(0, filesize) == "bab753aa194389c1877e5d21e6bcd2a1cfe291388363239561ca6f6172473dee"
}
```

### Sample 62: `722e61b1ce656fc0`

| Field | Value |
|---|---|
| SHA-256 | `722e61b1ce656fc024981dfefd4ff161af3df5e4ed556b3c75da3d9be84a0c79` |
| Family label | `unknown` |
| File name | `Radium.jar` |
| File type | `jar` |
| First seen | `2026-08-17 21:08:34` |
| Reporter | `anonymous` |
| Tags | `jar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d3ccfe8950a95d903c37487fb66d4a8` |
| SHA-256 | `722e61b1ce656fc024981dfefd4ff161af3df5e4ed556b3c75da3d9be84a0c79` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_722e61b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "722e61b1ce656fc024981dfefd4ff161af3df5e4ed556b3c75da3d9be84a0c79"
    family = "unknown"
    file_name = "Radium.jar"
    file_type = "jar"
    first_seen = "2026-08-17 21:08:34"
  condition:
    hash.sha256(0, filesize) == "722e61b1ce656fc024981dfefd4ff161af3df5e4ed556b3c75da3d9be84a0c79"
}
```

### Sample 63: `c064c921e50349f9`

| Field | Value |
|---|---|
| SHA-256 | `c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21` |
| Family label | `unknown` |
| File name | `c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21` |
| File type | `unknown` |
| First seen | `2026-08-17 21:00:20` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `219a1a30e0215be8e05548313d56d73b` |
| SHA-256 | `c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_c064c921
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21"
    family = "unknown"
    file_name = "c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21"
    file_type = "unknown"
    first_seen = "2026-08-17 21:00:20"
  condition:
    hash.sha256(0, filesize) == "c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21"
}
```

### Sample 64: `5e37d8222f4ecac4`

| Field | Value |
|---|---|
| SHA-256 | `5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f` |
| Family label | `unknown` |
| File name | `5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f` |
| File type | `unknown` |
| First seen | `2026-08-17 21:00:16` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4452e2a9664b0b5744ed13736c1de7be` |
| SHA-256 | `5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_5e37d822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f"
    family = "unknown"
    file_name = "5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f"
    file_type = "unknown"
    first_seen = "2026-08-17 21:00:16"
  condition:
    hash.sha256(0, filesize) == "5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f"
}
```

### Sample 65: `448fc8f1dea0e9cc`

| Field | Value |
|---|---|
| SHA-256 | `448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b` |
| Family label | `unknown` |
| File name | `448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b` |
| File type | `unknown` |
| First seen | `2026-08-17 21:00:12` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd06904a9163ec933fa0285e77d7ed81` |
| SHA-256 | `448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_448fc8f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b"
    family = "unknown"
    file_name = "448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b"
    file_type = "unknown"
    first_seen = "2026-08-17 21:00:12"
  condition:
    hash.sha256(0, filesize) == "448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b"
}
```

### Sample 66: `363806adf53215b5`

| Field | Value |
|---|---|
| SHA-256 | `363806adf53215b567099b55da5a05c25b74b7744c18c5c395ccd1fc842d8985` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 20:59:58` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX6.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a891567bf03c0f2615f619c37ed938a` |
| SHA-1 | `1ad8c7ec9c80f95ad7015904ed540e9a7a0289f1` |
| SHA-256 | `363806adf53215b567099b55da5a05c25b74b7744c18c5c395ccd1fc842d8985` |
| SHA3-384 | `c7ce1c708774b51d6e9d2850ecf8b43c1e474046e3ae8a0c59651b7e84165c2b3ecac5eaf5b023d279425bc5c1651678` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T1B3763803EC5925E9C1AD923189B79252BB717C881B3223D71B90F6383E76BD4BDB9350` |
| SSDEEP | `49152:sJr1V8RW1KsRCKA9wA8b2uTExwiMavwRI3l1+5GVcjcJw85b9AOSl1cyj2U9UM8I:sJZCQPfXEIGVpA74xGawv6Ezi6` |
| ICON-DHASH | `8e33d4d4d4d433cc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_363806ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363806adf53215b567099b55da5a05c25b74b7744c18c5c395ccd1fc842d8985"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:59:58"
  condition:
    hash.sha256(0, filesize) == "363806adf53215b567099b55da5a05c25b74b7744c18c5c395ccd1fc842d8985"
}
```

### Sample 67: `3a1625ef4a1b4639`

| Field | Value |
|---|---|
| SHA-256 | `3a1625ef4a1b46393e6ddd71e04de8f4c546ba56616da3aef682d8399c86dce5` |
| Family label | `unknown` |
| File name | `resight-v1.7.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:59:49` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1be4715d532326997715078ffe99d686` |
| SHA-256 | `3a1625ef4a1b46393e6ddd71e04de8f4c546ba56616da3aef682d8399c86dce5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_3a1625ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a1625ef4a1b46393e6ddd71e04de8f4c546ba56616da3aef682d8399c86dce5"
    family = "unknown"
    file_name = "resight-v1.7.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:59:49"
  condition:
    hash.sha256(0, filesize) == "3a1625ef4a1b46393e6ddd71e04de8f4c546ba56616da3aef682d8399c86dce5"
}
```

### Sample 68: `7af7eeec1e562a81`

| Field | Value |
|---|---|
| SHA-256 | `7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3` |
| Family label | `unknown` |
| File name | `7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:55:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `935d8566d81dae181921087c14e02cd1` |
| SHA-1 | `b03c43b18d245b4970a7bb7a67937fcc996709b6` |
| SHA-256 | `7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3` |
| SHA3-384 | `35cc460669942343a5ece7b0fd30560e846c6a19b5da5247595e342e355a930390ca5c5b226062c719132ccec5882c34` |
| IMPHASH | `cc678ea372003a91fefb68ce6b422039` |
| TLSH | `T111D523CAB9B268B0D837C7E39F51E56DB16877908BB1CD07B5CE59048EA39842D39370` |
| SSDEEP | `49152:lnOYoLSFwqKXsDQqyUA19IszBm2o8wh55LdSIWbEFgIgFT75WCr:tOYMxqKciI2MJ3SEahL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_7af7eeec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3"
    family = "unknown"
    file_name = "7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:55:21"
  condition:
    hash.sha256(0, filesize) == "7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3"
}
```

### Sample 69: `a1e1b4f32118b471`

| Field | Value |
|---|---|
| SHA-256 | `a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9` |
| Family label | `Vidar` |
| File name | `a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9.bin` |
| File type | `exe` |
| First seen | `2026-08-17 20:52:53` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0a326051a75456bf463f5e672f08065` |
| SHA-1 | `7a7c4654ddd0101ff89aa726f8a8ac0c132b34d8` |
| SHA-256 | `a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9` |
| SHA3-384 | `106af8616088ef80c59a1a8576dc8cd94290ae14e1439a0ff59f8db612421e857ea713431ce71729c6da11633ca3417a` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C086AE17AED505A9C09A9639CAB787527B34B84C8B3127E72F50B7382F76BC06E75700` |
| SSDEEP | `98304:fq2wkOFEQ/Kq8LM8cYd6uQ8ftSH723eOz:fq2UFEPh9OweOz` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_069_a1e1b4f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9"
    family = "Vidar"
    file_name = "a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9.bin"
    file_type = "exe"
    first_seen = "2026-08-17 20:52:53"
  condition:
    hash.sha256(0, filesize) == "a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9"
}
```

### Sample 70: `892e3dee69fbd324`

| Field | Value |
|---|---|
| SHA-256 | `892e3dee69fbd32403412137c34b784707f1e7062938501ee34dca9f8695c61a` |
| Family label | `unknown` |
| File name | `composer.php` |
| File type | `exe` |
| First seen | `2026-08-17 20:52:10` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b01212edd5887aef1e1667dd86166154` |
| SHA-1 | `17ad409f0b79a145d5fc13daac01d494b1f5dcbe` |
| SHA-256 | `892e3dee69fbd32403412137c34b784707f1e7062938501ee34dca9f8695c61a` |
| SHA3-384 | `de120be73d4d06632891c516dd4260f3dd0c6a6dad6286cca5eb41c9a58810350a2600086f48b2e89305e4124cab18b8` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1B0E633C959C153FAE9B3513CFAE28251FA35B8B56774C2DF4A9483A63D230E14C79223` |
| SSDEEP | `393216:ixYdhyRJxIH0//TXMCHWUjocuI3/PGTAI:ixOwzxy0/rXMb8dH/O7` |
| ICON-DHASH | `f0f0dcc686c4f0f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_892e3dee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "892e3dee69fbd32403412137c34b784707f1e7062938501ee34dca9f8695c61a"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 20:52:10"
  condition:
    hash.sha256(0, filesize) == "892e3dee69fbd32403412137c34b784707f1e7062938501ee34dca9f8695c61a"
}
```

### Sample 71: `bffb15ba54944615`

| Field | Value |
|---|---|
| SHA-256 | `bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3` |
| Family label | `CoinMiner` |
| File name | `bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:50:27` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `511d62e9daac7e2ef91f37e14a11c33e` |
| SHA-1 | `c32aece364188d1c2d6890b4095e03f0190aff94` |
| SHA-256 | `bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3` |
| SHA3-384 | `0dcdb8b97e7f8bda1f2136f5119dade445416713169d64dbae5f609b1aef0664faab7a88398df992e43c36c4e55673d9` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1E23633C6AED21132C427D7B99742703DB23F7F954A657C0B79EC6A058C4AA2D683E3C1` |
| SSDEEP | `98304:nlsbfRnT+84XWK0x7cxCKnVuKg/Kbt6nA/kt2Ej8mJMyYoSo:2FT+jXWK0lkCKsZChnC` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_071_bffb15ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3"
    family = "CoinMiner"
    file_name = "bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:50:27"
  condition:
    hash.sha256(0, filesize) == "bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3"
}
```

### Sample 72: `11cc5709971c8135`

| Field | Value |
|---|---|
| SHA-256 | `11cc5709971c8135bed1e0f1a1ad80e1e918165ce742c308e9cd8abdef958b81` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-17 20:49:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d6135e818503e8509017ce74380dba6` |
| SHA-1 | `2d7564af66edd0fb2771f2318f5a4f4afa95f65b` |
| SHA-256 | `11cc5709971c8135bed1e0f1a1ad80e1e918165ce742c308e9cd8abdef958b81` |
| SHA3-384 | `7285f9ef85a6ae1b918eaa78f96656068dcf5d6fe7fbf8f54d0666fd869d1226382e344a11891a86578c3e8f40a61c17` |
| TLSH | `T142236C6516857C14AE99C4375C7F2F0CB9AD43E6314492EE7FCA3CF28C4A6ADA20861D` |
| SSDEEP | `768:kp9NyXsZztC+9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:oHusZWcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_11cc5709
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11cc5709971c8135bed1e0f1a1ad80e1e918165ce742c308e9cd8abdef958b81"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-17 20:49:27"
  condition:
    hash.sha256(0, filesize) == "11cc5709971c8135bed1e0f1a1ad80e1e918165ce742c308e9cd8abdef958b81"
}
```

### Sample 73: `192b59dc537d73dd`

| Field | Value |
|---|---|
| SHA-256 | `192b59dc537d73dd45f4c0a84b8dffaa664661b4523ca13fed01b5f40a6d5bc8` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 20:45:57` |
| Reporter | `Bitsight` |
| Tags | `B, BB4.file, dropped-by-GCleaner, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `950601458d12fc1d47878e6bc0779db1` |
| SHA-1 | `f4c1152cdf2aa5488834cf2c8aba0817ee6453ec` |
| SHA-256 | `192b59dc537d73dd45f4c0a84b8dffaa664661b4523ca13fed01b5f40a6d5bc8` |
| SHA3-384 | `f7664d69151dc5d3409992e0ee20edb0cff14b1491b3c64d97ff40ed309e4bd6f28026e5faaaeab327b238a0db720299` |
| IMPHASH | `736029744d6e019a39ea152cdcd00c12` |
| TLSH | `T156564B55BA6B94ACD197C47483468A639E2130DF0B36BAFF418485383F6ABF11B3D724` |
| SSDEEP | `49152:20iEPoOCAqwy12sMy5j9XQ2thQy/Z0ymc4ggu6a0WaBUFqxPvMNsg6/bHLDM/DHk:C7/7xxtx0JFxUscR5vmEqkbeWolgOQ6` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_073_192b59dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "192b59dc537d73dd45f4c0a84b8dffaa664661b4523ca13fed01b5f40a6d5bc8"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:45:57"
  condition:
    hash.sha256(0, filesize) == "192b59dc537d73dd45f4c0a84b8dffaa664661b4523ca13fed01b5f40a6d5bc8"
}
```

### Sample 74: `d460c2d998e4e390`

| Field | Value |
|---|---|
| SHA-256 | `d460c2d998e4e390635d79e7233ad268379131555bd9b87bce16a813b041b844` |
| Family label | `unknown` |
| File name | `NexomiaUI_v8.35.321.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:45:33` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f352e7d43425c5e75747cf9fa9cf65a1` |
| SHA-256 | `d460c2d998e4e390635d79e7233ad268379131555bd9b87bce16a813b041b844` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_d460c2d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d460c2d998e4e390635d79e7233ad268379131555bd9b87bce16a813b041b844"
    family = "unknown"
    file_name = "NexomiaUI_v8.35.321.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:45:33"
  condition:
    hash.sha256(0, filesize) == "d460c2d998e4e390635d79e7233ad268379131555bd9b87bce16a813b041b844"
}
```

### Sample 75: `36f4c72c0bfa37b5`

| Field | Value |
|---|---|
| SHA-256 | `36f4c72c0bfa37b52ca053b008e6d1020b8fdd0442cf0d1466a0affc1b521a15` |
| Family label | `unknown` |
| File name | `External_Release_Final_5374.ps1` |
| File type | `ps1` |
| First seen | `2026-08-17 20:39:32` |
| Reporter | `iamaachum` |
| Tags | `CountLoader, dropped-by-RemusStealer, ps1, titanwall-vg` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62161e345b9327722ad89ce811263ed3` |
| SHA-1 | `e5b6db66960c93748d40300ff05511994c19241c` |
| SHA-256 | `36f4c72c0bfa37b52ca053b008e6d1020b8fdd0442cf0d1466a0affc1b521a15` |
| SHA3-384 | `fd4c7f77adde9f79fc32cf581417a718cffaf185d501d34d6bdb9f5387b903dbaed1f32eadd512cb91fe10b329841557` |
| TLSH | `T16B2431C33341E9B8E2DD0BB2BC070515A1F8C926F99E5948B7F1ADC77B5AA841534F81` |
| SSDEEP | `6144:AknDcOG1+VeHEBSlE+nPRmsnNJX9Cq/+LpVp:lcu/erVm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_36f4c72c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36f4c72c0bfa37b52ca053b008e6d1020b8fdd0442cf0d1466a0affc1b521a15"
    family = "unknown"
    file_name = "External_Release_Final_5374.ps1"
    file_type = "ps1"
    first_seen = "2026-08-17 20:39:32"
  condition:
    hash.sha256(0, filesize) == "36f4c72c0bfa37b52ca053b008e6d1020b8fdd0442cf0d1466a0affc1b521a15"
}
```

### Sample 76: `891292d66392d8da`

| Field | Value |
|---|---|
| SHA-256 | `891292d66392d8da0e92cf38abcb108a69e33fb1714f7920448301b1aa5094d5` |
| Family label | `unknown` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:37:08` |
| Reporter | `iamaachum` |
| Tags | `ChromElevator, exe, signed, up4pc-com, whale-complex-site` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30718ddbe8c67b2562ef12db2a3cd852` |
| SHA-1 | `31728f1824d288d413ba6e881fe4e9603bb72493` |
| SHA-256 | `891292d66392d8da0e92cf38abcb108a69e33fb1714f7920448301b1aa5094d5` |
| SHA3-384 | `6809678113a52acc562725c2ddecc140ef7fbc7c638bf760d8334eb0bb8890ef7f14715066f9dbad94014de5f3c9dd3c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E3C633283DEA5019F273EF686BD4B4E7ED2FBB633B07486A1155034A0722981CED257D` |
| SSDEEP | `196608:REG12fx/Ox35OQJPpzutYtzptxSL+s3Zi8PG/FnoFwr/+hvUwJXkF804QTX38JQk:tX3wQdZlXxkrM8O/Fo4+hvUYXka1QTXo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_891292d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "891292d66392d8da0e92cf38abcb108a69e33fb1714f7920448301b1aa5094d5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:37:08"
  condition:
    hash.sha256(0, filesize) == "891292d66392d8da0e92cf38abcb108a69e33fb1714f7920448301b1aa5094d5"
}
```

### Sample 77: `727c152c2f20469a`

| Field | Value |
|---|---|
| SHA-256 | `727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1` |
| Family label | `LummaStealer` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:36:21` |
| Reporter | `iamaachum` |
| Tags | `exe, LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f19b6fbd4498b5c832645209da3ad7b` |
| SHA-1 | `e9918fe1a8038adf77b6e167ac7835699f1289ab` |
| SHA-256 | `727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1` |
| SHA3-384 | `57a0055259788a16ed04ed5546a98bfb7b3e86a0843790ac7170c669a90a90d4129061a29db419f2a6e4e9686a8a79e5` |
| IMPHASH | `4f2f006e2ecf7172ad368f8289dc96c1` |
| TLSH | `T124369C81FE9B85F5D9026A315097A26F633859094F36CF87EA44B739FD376E20836348` |
| SSDEEP | `49152:YluxH6CoDTYlBJXOTkKjVCaxKq3E1UZk6va3qXj7LvWGTS+aJsmUqoYmdFW3lFxL:UUd2VN01cva3qXLvWGp9mUqLMAfxL` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_077_727c152c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1"
    family = "LummaStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:36:21"
  condition:
    hash.sha256(0, filesize) == "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1"
}
```

### Sample 78: `1863c944ff0f5f06`

| Field | Value |
|---|---|
| SHA-256 | `1863c944ff0f5f06cafe0f98d6a6f54084ac266936c0dbc16a9d13ab03dda421` |
| Family label | `SnappyClient` |
| File name | `Setup.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:35:46` |
| Reporter | `iamaachum` |
| Tags | `exe, HijackLoader, SnappyClient, Vidar, YodaTeam` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37ba10d0ebd22287e120815f5241e1da` |
| SHA-1 | `5dca5c9264fd863aa8ccd0ef0d4ac944ea9d1561` |
| SHA-256 | `1863c944ff0f5f06cafe0f98d6a6f54084ac266936c0dbc16a9d13ab03dda421` |
| SHA3-384 | `afd329cc0d1aa9edd01f55be9200fcd210e50bf460e3967909915eba998b537555dd605baa49c0ee0149a918400031a7` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T13DC633623BC9F4FAE50886798F55DB3FA23AD9269390AC0345147F017EE18B1710B5FA` |
| SSDEEP | `196608:+piWYUfSDvL+ViYnwfTA80GlAt5aanoVDK/52r3LRlVhGrL0Kyd9kW/ErIWhzElZ:+p19fSDvC6fT/a2IOq/0KyR/zWdElmZ8` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_078_1863c944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1863c944ff0f5f06cafe0f98d6a6f54084ac266936c0dbc16a9d13ab03dda421"
    family = "SnappyClient"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:35:46"
  condition:
    hash.sha256(0, filesize) == "1863c944ff0f5f06cafe0f98d6a6f54084ac266936c0dbc16a9d13ab03dda421"
}
```

### Sample 79: `59d277908b548113`

| Field | Value |
|---|---|
| SHA-256 | `59d277908b548113ad40dd23406fb7ca5b004372602585c43422bd2d2608e783` |
| Family label | `unknown` |
| File name | `InstallerV5164x64.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:33:23` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f893a1cc3aa4e2255300b228f47a4ee5` |
| SHA-1 | `1c2f453d0cf57c72d0414c8e41f42f43b69e7e74` |
| SHA-256 | `59d277908b548113ad40dd23406fb7ca5b004372602585c43422bd2d2608e783` |
| SHA3-384 | `373bd7584528ad86e240500c600cf377187afe2905cbf136d95488d3c332486f38cbb17f86601c241150f070e1221532` |
| IMPHASH | `a56f115ee5ef2625bd949acaeec66b76` |
| TLSH | `T12DF633EA9D3CC88EEF511D7070B2468A8FB09C54BD045A5910B61D4A0BFF66F333AD5A` |
| SSDEEP | `393216:tIg33YMRHGRKIG952cPVINyKZdTeTLm9hi0lZiYkgeqd0rP9Ydp7x9:tIgHY1RKxf2cPeGiQIRxd0z` |
| ICON-DHASH | `cccccccccccccccc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_59d27790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d277908b548113ad40dd23406fb7ca5b004372602585c43422bd2d2608e783"
    family = "unknown"
    file_name = "InstallerV5164x64.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:33:23"
  condition:
    hash.sha256(0, filesize) == "59d277908b548113ad40dd23406fb7ca5b004372602585c43422bd2d2608e783"
}
```

### Sample 80: `fad6377eb2c2ccee`

| Field | Value |
|---|---|
| SHA-256 | `fad6377eb2c2ccee6bd87097bbe2947d81dca67f54117b09df436720469f67c3` |
| Family label | `unknown` |
| File name | `Installer.iso` |
| File type | `iso` |
| First seen | `2026-08-17 20:32:55` |
| Reporter | `iamaachum` |
| Tags | `CNBackdoor, iso` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30105669c08609e7f046e180e86c869a` |
| SHA-1 | `1d21c3729dc846cd0e4afd66074732d5b0060d5c` |
| SHA-256 | `fad6377eb2c2ccee6bd87097bbe2947d81dca67f54117b09df436720469f67c3` |
| SHA3-384 | `3e6a47a5f5a5cfe11c7833e86b1a3cfe31416cf6f14b8fd67309dc4911e20ab65d19e4e807218139370e647281ad816a` |
| TLSH | `T11AF633EA9D3CC88EDF511D7070B246898FB09C54BD04565920BA1D4A0BFF66F333AE5A` |
| SSDEEP | `393216:mIg33YMRHGRKIG952cPVINyKZdTeTLm9hi0lZiYkgeqd0rP9Ydp7x9:mIgHY1RKxf2cPeGiQIRxd0z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_fad6377e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fad6377eb2c2ccee6bd87097bbe2947d81dca67f54117b09df436720469f67c3"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-17 20:32:55"
  condition:
    hash.sha256(0, filesize) == "fad6377eb2c2ccee6bd87097bbe2947d81dca67f54117b09df436720469f67c3"
}
```

### Sample 81: `c12fd900f3294462`

| Field | Value |
|---|---|
| SHA-256 | `c12fd900f32944623823f5087ef3eb146586a9339c0262333ac9c9bc08c06e84` |
| Family label | `unknown` |
| File name | `FLStudio2025_v165_Win.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:31:40` |
| Reporter | `iamaachum` |
| Tags | `exe, Stealc, svhost-update-service-casa` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b1a2fd81f358d0eb51c40272e34acea` |
| SHA-1 | `07197e01a3f53a0c58eb9f59b96ea805ef7448f0` |
| SHA-256 | `c12fd900f32944623823f5087ef3eb146586a9339c0262333ac9c9bc08c06e84` |
| SHA3-384 | `665031b9aa57c1fe9052dd5a120def193ea8eaa688c1a3f65e13f12ff9f609b151661dc09ebe3b60803b634a7803ec17` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B055236C9E99C981C4E2033A3E55D37924386ED9E422EB06CFEDBCEB7934B1954E0345` |
| SSDEEP | `24576:me6VaTp72e5S2Zok3JIViZrMFsT80pe7vaqnDPjdJ2dtBaHJDIQoyaDv4l:FHTB5S2b3L9oZ0pGjDPKtBaHVIQXck` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_c12fd900
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c12fd900f32944623823f5087ef3eb146586a9339c0262333ac9c9bc08c06e84"
    family = "unknown"
    file_name = "FLStudio2025_v165_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:31:40"
  condition:
    hash.sha256(0, filesize) == "c12fd900f32944623823f5087ef3eb146586a9339c0262333ac9c9bc08c06e84"
}
```

### Sample 82: `7b33480aaa55a511`

| Field | Value |
|---|---|
| SHA-256 | `7b33480aaa55a5113056c9ae1d5d72cd9a2b105f9fd3302c07f095e5f2effee9` |
| Family label | `Vidar` |
| File name | `Download_Movie_Maker_2.6_For_Windows_7.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:29:55` |
| Reporter | `iamaachum` |
| Tags | `exe, Vidar, windowsof-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b96b0af5f6afd91af8d09d6850133d3` |
| SHA-1 | `dce4af6be0c2a6d070143975e5e645d0fce75215` |
| SHA-256 | `7b33480aaa55a5113056c9ae1d5d72cd9a2b105f9fd3302c07f095e5f2effee9` |
| SHA3-384 | `3495c225cb3f56b2d83ef9823f0cc223299fc087e922fc34a265dfa315884aa34bdf0119600620e390fd41fb7b85fac6` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T16786AE17ADD505A9C0AA9A39C5B783437734BC498B3137D72E50AB783EB2BC0AE75740` |
| SSDEEP | `98304:0aNwO2umlndiYtO/Uu17F1Yd0cAgwIpmhNxrhxW:0aN2uHYtmeAEOs` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_082_7b33480a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b33480aaa55a5113056c9ae1d5d72cd9a2b105f9fd3302c07f095e5f2effee9"
    family = "Vidar"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:29:55"
  condition:
    hash.sha256(0, filesize) == "7b33480aaa55a5113056c9ae1d5d72cd9a2b105f9fd3302c07f095e5f2effee9"
}
```

### Sample 83: `7b92e3f3669e1192`

| Field | Value |
|---|---|
| SHA-256 | `7b92e3f3669e11928a5f57e81cd37ebf1feabd31d66f8cc59b41953c9acf2a94` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:28:41` |
| Reporter | `iamaachum` |
| Tags | `45-115-27-4, AsgardProtector, exe, SunWukong, VorishkaStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4dc7e7d29c24d3a40a6e3308ff5d73b7` |
| SHA-1 | `b1f619350a50e5019ea5ce33d2fa02f7945d5fc8` |
| SHA-256 | `7b92e3f3669e11928a5f57e81cd37ebf1feabd31d66f8cc59b41953c9acf2a94` |
| SHA3-384 | `34d73cab29be43369d3ec12e9821a8e58bafd65573a257fd022d61ae1acf6f848a0c9ad828bcab94f6e4d2751dfaa88d` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T126B533017AE948F6E97D1778C8F1879756307CA28F3A5ABF1058858E5F23BC8843573A` |
| SSDEEP | `49152:sVBDs9ycFGagDwtOMDs14otNwom3BlolIcl1oi9vwFD:OcFeDoOMDq4QhZoiy` |
| ICON-DHASH | `8ee9b9c8ce84e41b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_7b92e3f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b92e3f3669e11928a5f57e81cd37ebf1feabd31d66f8cc59b41953c9acf2a94"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:28:41"
  condition:
    hash.sha256(0, filesize) == "7b92e3f3669e11928a5f57e81cd37ebf1feabd31d66f8cc59b41953c9acf2a94"
}
```

### Sample 84: `3dc384b44e2e6c37`

| Field | Value |
|---|---|
| SHA-256 | `3dc384b44e2e6c37ba4529b86740771f9f942bc0b01a9830110cb4f86739c131` |
| Family label | `Mirai` |
| File name | `iran.armv7l` |
| File type | `elf` |
| First seen | `2026-08-17 20:16:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9dc7b28f988998c9ab86567aff03d6f` |
| SHA-1 | `9307de4d4b362d5e9bd3e1618b930c0c67be58cc` |
| SHA-256 | `3dc384b44e2e6c37ba4529b86740771f9f942bc0b01a9830110cb4f86739c131` |
| SHA3-384 | `eb67e35fd8e639bff179e51b412de811595b06d45a1f461e7a4ca560549b951cd78982a3d082236c9d1a7a7164d4785e` |
| TLSH | `T10FE30749ED42AB00D5D636FAFE4E428973535B6CE3FE71129E245B2127CA92B0F7B101` |
| TELFHASH | `t1f6212004df984eaca7f480b9d1a8ba2b76dd3155391024678a7d9c8f9d136c3f428c0f` |
| SSDEEP | `3072:6nZpD+/4jw0P4GmyvC/frevbzQpgMCa5bo0nIQc0r9vI2mmCULXJWcbz0:6nZpD+/4jw0PpfvCazzQvCalfnIQc0r2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_3dc384b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc384b44e2e6c37ba4529b86740771f9f942bc0b01a9830110cb4f86739c131"
    family = "Mirai"
    file_name = "iran.armv7l"
    file_type = "elf"
    first_seen = "2026-08-17 20:16:31"
  condition:
    hash.sha256(0, filesize) == "3dc384b44e2e6c37ba4529b86740771f9f942bc0b01a9830110cb4f86739c131"
}
```

### Sample 85: `372d9ffd6a52d650`

| Field | Value |
|---|---|
| SHA-256 | `372d9ffd6a52d6503025ee4cc1393b8a3d754513b32e6dafd818b3db907ec2a5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 20:13:10` |
| Reporter | `Bitsight` |
| Tags | `6efb1e0ab361cda1dd534e37e543789c, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f381e62f89dbd5cd013f4c0da92dfa7` |
| SHA-1 | `4f14c47719dccc226fef88fe847494ddff94140c` |
| SHA-256 | `372d9ffd6a52d6503025ee4cc1393b8a3d754513b32e6dafd818b3db907ec2a5` |
| SHA3-384 | `bd08c22d8cb13689a82dc28becb3b1f9d067d24c49209f6e955d947616e245a93d0a291f2db285dc41a0710bcaabd526` |
| TLSH | `T11223FA47B9C371FCD613C534C6A35EB1B938B4A41A32EE7FA3C0C6361851A905A26F39` |
| SSDEEP | `768:CRcrEq7pqdb7oUih297wVfK7KR/Ws0npaX43VQXtQsVPH0vIIz:CQEig7g8Gi2RhCpaXoCHuIIz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_372d9ffd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372d9ffd6a52d6503025ee4cc1393b8a3d754513b32e6dafd818b3db907ec2a5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:13:10"
  condition:
    hash.sha256(0, filesize) == "372d9ffd6a52d6503025ee4cc1393b8a3d754513b32e6dafd818b3db907ec2a5"
}
```

### Sample 86: `797bcd9813c2c4f1`

| Field | Value |
|---|---|
| SHA-256 | `797bcd9813c2c4f11e3abde7b4806e0d81531eaeb68dfa98d3482b7c9174a61d` |
| Family label | `unknown` |
| File name | `?????.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:11:44` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8de8e52ff1867b0650b287570d762403` |
| SHA-1 | `f4f81171d56404c432da515d4faf8fe13505c01c` |
| SHA-256 | `797bcd9813c2c4f11e3abde7b4806e0d81531eaeb68dfa98d3482b7c9174a61d` |
| SHA3-384 | `02e0465396ca9d2ef5e1267e9ecd2a31910ee90ac152a9dfcf85f204442c8269a7742ea68e323a8d83a4eb7394474d83` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1FEB57A07BCA544A9C4AA933A89B70691B675FC188F3633DB3E50F6782F317D15A38B50` |
| SSDEEP | `24576:iA77iTxnFe6JMq/LKC0JPEdyZTqPiWaOpgQArqzB2TCnJ8GFqyerDUxR:PWTxn9MoLKCwE5PiWualdC0r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_797bcd98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "797bcd9813c2c4f11e3abde7b4806e0d81531eaeb68dfa98d3482b7c9174a61d"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:11:44"
  condition:
    hash.sha256(0, filesize) == "797bcd9813c2c4f11e3abde7b4806e0d81531eaeb68dfa98d3482b7c9174a61d"
}
```

### Sample 87: `98268f4b9de6c8c1`

| Field | Value |
|---|---|
| SHA-256 | `98268f4b9de6c8c17f83de8504302676c91710c6f801a73c94e2c43ef58b6100` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-17 20:10:38` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdecede121b48d0b6384f3b293a04840` |
| SHA-1 | `c96d8f8239bfb226798160c8c8e54353d3861ee9` |
| SHA-256 | `98268f4b9de6c8c17f83de8504302676c91710c6f801a73c94e2c43ef58b6100` |
| SHA3-384 | `3fa8c574dea39fe64a235b31de166324e7388d44700c6417d0070a9cb23d943dfecdde7d4ef205af5bd761a437b6a409` |
| IMPHASH | `9da7080b9b697496fd4f41997e8bd436` |
| TLSH | `T1252501512BE61CB9F8EEE6347AB142635833FCB057F491DF168C81681A329D419F0B2E` |
| SSDEEP | `24576:/QlZR+W3zeSuR6ZdhzTdKPHoWORFw3OSnnb:YXR+UM6V0oWOI/` |
| ICON-DHASH | `28969696969696e8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_98268f4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98268f4b9de6c8c17f83de8504302676c91710c6f801a73c94e2c43ef58b6100"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:10:38"
  condition:
    hash.sha256(0, filesize) == "98268f4b9de6c8c17f83de8504302676c91710c6f801a73c94e2c43ef58b6100"
}
```

### Sample 88: `6af6b0c8252dccb2`

| Field | Value |
|---|---|
| SHA-256 | `6af6b0c8252dccb24c82b81a75afbaf7ca8697298423bf0506783e69044b0ebd` |
| Family label | `unknown` |
| File name | `ws-Setup-Complete.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:10:23` |
| Reporter | `iamaachum` |
| Tags | `exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17f05bb4c0120489db0f52427c5460e7` |
| SHA-1 | `1344cd5a45fbeee064c97311831519c7b41ed669` |
| SHA-256 | `6af6b0c8252dccb24c82b81a75afbaf7ca8697298423bf0506783e69044b0ebd` |
| SHA3-384 | `40648cb150f3bea102757f1473d8683841c1433c83595aedf175f5fb886c032a1fac4433188e603942181fd9144a21bb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F816AD077D9140E5C8AAA731C97782627B61BC0C8B7933DB2E90AA782F723D25D75F44` |
| SSDEEP | `49152:ojvSoBbZbntyNT/a+a4cpWPtqVa6VUCKRpRzh+gdwkLpA9DDHUDfJ:oTTKaw3lqwEFK39hNdtAG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_6af6b0c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6af6b0c8252dccb24c82b81a75afbaf7ca8697298423bf0506783e69044b0ebd"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:10:23"
  condition:
    hash.sha256(0, filesize) == "6af6b0c8252dccb24c82b81a75afbaf7ca8697298423bf0506783e69044b0ebd"
}
```

### Sample 89: `0ccc999c0f8f96df`

| Field | Value |
|---|---|
| SHA-256 | `0ccc999c0f8f96df44bcfb6657392964dca46bcd8208cfe6b919f30e79b3c664` |
| Family label | `unknown` |
| File name | `cat.sh` |
| File type | `sh` |
| First seen | `2026-08-17 20:08:54` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `980e97f39c0e13227254d55a298df0d0` |
| SHA-1 | `79d089b27654e491ebcd0b7c6d1241e70e18fe0f` |
| SHA-256 | `0ccc999c0f8f96df44bcfb6657392964dca46bcd8208cfe6b919f30e79b3c664` |
| SHA3-384 | `c40f775c734f4a990a75fc82cf9ec6690749a51203f7f972bf5143575188315eabc70cf55a707ceabb6ed992dde4e1bc` |
| TLSH | `T11231548930B4D111E2C4EF21B0E946D65276FE8572B46ABBF4433E39B099D40301DA3D` |
| SSDEEP | `12:Upekfape0dt6hJpIpgNaKOOJpJ6TppODOqJpOpDDUJpyflpUMGJpBK1ppBk1ZJpY:QfacVFOeDuhwKrknKW2t2MtaECj0D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_0ccc999c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ccc999c0f8f96df44bcfb6657392964dca46bcd8208cfe6b919f30e79b3c664"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-08-17 20:08:54"
  condition:
    hash.sha256(0, filesize) == "0ccc999c0f8f96df44bcfb6657392964dca46bcd8208cfe6b919f30e79b3c664"
}
```

### Sample 90: `eacf32279b327b9e`

| Field | Value |
|---|---|
| SHA-256 | `eacf32279b327b9e7c4fe83404b2216abbe89801cf94e4b34828596e09f0f322` |
| Family label | `Mirai` |
| File name | `daredevil.powerpc` |
| File type | `elf` |
| First seen | `2026-08-17 20:07:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2fe9775138104bbd46caf55954d9f25` |
| SHA-1 | `baf8edf37f2d61dca12c744d92ed378c776fed63` |
| SHA-256 | `eacf32279b327b9e7c4fe83404b2216abbe89801cf94e4b34828596e09f0f322` |
| SHA3-384 | `c9a880881fa1bfcab24737a23b8025bbaa0ac1fffd6b2cb7fcc4dad8588176064fca7f521e8b8a943382dfe5f5d33617` |
| TLSH | `T1F5D32A05730C054BE2A32EF03A3F67E193DFDA9131E4E644295FAB8A9171D321586EDE` |
| SSDEEP | `1536:GvzP9eA15P5z9rxi28kNKgJtFXcKIXSBNOj2bmqsvAo/n2c/24eG0HqM9x:6zPIA1Bl1xJKEuFSXOjEoBQv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_eacf3227
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eacf32279b327b9e7c4fe83404b2216abbe89801cf94e4b34828596e09f0f322"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:44"
  condition:
    hash.sha256(0, filesize) == "eacf32279b327b9e7c4fe83404b2216abbe89801cf94e4b34828596e09f0f322"
}
```

### Sample 91: `69cf31dad20613d8`

| Field | Value |
|---|---|
| SHA-256 | `69cf31dad20613d82840a5530ab726c009dc00606bb79200172c24c76ccf61ba` |
| Family label | `Mirai` |
| File name | `daredevil.armv5l` |
| File type | `elf` |
| First seen | `2026-08-17 20:07:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbf300e3feb188d9030808853851549f` |
| SHA-1 | `5ab5b6f0e50c761e1dd6396a77668fd115c9c74a` |
| SHA-256 | `69cf31dad20613d82840a5530ab726c009dc00606bb79200172c24c76ccf61ba` |
| SHA3-384 | `abe8cb673322de6d4e62e906dabb5bc770447450a916031e5da765e6c761b6a2492dd6e6ae428a1e13e73e1b16b8895f` |
| TLSH | `T1A5D30A59FC818B13C6E161B7FB4E428D372A47A8D3EA71039D196F25379B8970E3B142` |
| TELFHASH | `t16a2165604e0c49be67d104b8d1cc863f319e35b51e223c94c6dd5b9fc093ce1b82a476` |
| SSDEEP | `1536:Q1NWKokfQcbgWQHEdYCvF4g2w363m4VP3mTkj0z63zWExy1LY5JAlCAwywGxxMz7:4ycbgWNNN4gKm4lmoj0zOzpuLMxK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_69cf31da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69cf31dad20613d82840a5530ab726c009dc00606bb79200172c24c76ccf61ba"
    family = "Mirai"
    file_name = "daredevil.armv5l"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:42"
  condition:
    hash.sha256(0, filesize) == "69cf31dad20613d82840a5530ab726c009dc00606bb79200172c24c76ccf61ba"
}
```

### Sample 92: `ede1ddcbccbad585`

| Field | Value |
|---|---|
| SHA-256 | `ede1ddcbccbad58538aa6b11febc140b6edc87a955deaccf479dfd9d9fd04b85` |
| Family label | `Mirai` |
| File name | `daredevil.armv6l` |
| File type | `elf` |
| First seen | `2026-08-17 20:07:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17e5e82d677ddcf8cf5bed62a13a44c8` |
| SHA-1 | `da934b76bd33a16cbbdeb7892360f6cbe941bd58` |
| SHA-256 | `ede1ddcbccbad58538aa6b11febc140b6edc87a955deaccf479dfd9d9fd04b85` |
| SHA3-384 | `192f337237d74c80a568346fe1c0ad36d41550d77a7b55eb0816482bee15983a6db4dc09225ee29f3c83146f31c55d18` |
| TLSH | `T1BEE30A96B8818B11D5C151BAFE0E124E33131B7CE3EE72139D146B697B8ACBB0E3B515` |
| TELFHASH | `t1ddd02e40db604dccead780e811eb323d26ac3a03321518aba00c1d8b8374085a06c60a` |
| SSDEEP | `3072:4GsBk5xCOZT3TEOXHi6QtbkadAaPn8xgXlGz2:bsuXTVXH+tQahUyXlGz2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_ede1ddcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ede1ddcbccbad58538aa6b11febc140b6edc87a955deaccf479dfd9d9fd04b85"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:39"
  condition:
    hash.sha256(0, filesize) == "ede1ddcbccbad58538aa6b11febc140b6edc87a955deaccf479dfd9d9fd04b85"
}
```

### Sample 93: `0afa465224ae07e0`

| Field | Value |
|---|---|
| SHA-256 | `0afa465224ae07e025b5bea1ba5b29618c3309754a9d471ac85958600ac66b5f` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-17 20:07:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3158380a9338e21e9db3dea68671dd59` |
| SHA-1 | `c7d6feeec4b98845f40d2e241a69f44f2b697135` |
| SHA-256 | `0afa465224ae07e025b5bea1ba5b29618c3309754a9d471ac85958600ac66b5f` |
| SHA3-384 | `e83f052945d689117d50fc2933c2535f14a827a8a28e4c0f9e28ea5daace31ad13e5b2c0c00f08eb334318945aa46777` |
| TLSH | `T1BFD4D70B6E228F7DF674873147F74A249BAD23D627E1D581D1ADC1142F2028E592FBAC` |
| TELFHASH | `t1cdb11499287817f4a7545d8c46ecfe36cca228ef2a561c33de51e89ed71ba835e10c1c` |
| SSDEEP | `6144:tPIIFTTVVpEELtS74jxDUaQmDH8gWVqyyuyPhrQYJwhKr07VnZAEPJl+bRaXNInj:pIwnfxS7Rm+iaXOxUh9rqnE4ww` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_0afa4652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0afa465224ae07e025b5bea1ba5b29618c3309754a9d471ac85958600ac66b5f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:28"
  condition:
    hash.sha256(0, filesize) == "0afa465224ae07e025b5bea1ba5b29618c3309754a9d471ac85958600ac66b5f"
}
```

### Sample 94: `3508dbe7b6b122c6`

| Field | Value |
|---|---|
| SHA-256 | `3508dbe7b6b122c61367de28788c6e3871351e3b9eb813162e08601cde83376a` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-17 20:07:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb889a61eeb40ccf41fa83e9114ff7a7` |
| SHA-1 | `5ac40be3380fb5892707da7ac562c430354096b9` |
| SHA-256 | `3508dbe7b6b122c61367de28788c6e3871351e3b9eb813162e08601cde83376a` |
| SHA3-384 | `2c82e49a827c9d7601dfe5ceb31d3eccc48ebc3e4e10e8866f4e24baa1483ceab156b723e90795cbb600d535b146ebab` |
| TLSH | `T1BC236D651A857C24AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9DD10871D` |
| SSDEEP | `768:qXRWNGxVP9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Wlx2cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_3508dbe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3508dbe7b6b122c61367de28788c6e3871351e3b9eb813162e08601cde83376a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-17 20:07:27"
  condition:
    hash.sha256(0, filesize) == "3508dbe7b6b122c61367de28788c6e3871351e3b9eb813162e08601cde83376a"
}
```

### Sample 95: `1bc9f7e61cfd65c7`

| Field | Value |
|---|---|
| SHA-256 | `1bc9f7e61cfd65c7e15eef8a6eac615aaa0ca68962ba7c2878ab0c4d4c254aa8` |
| Family label | `unknown` |
| File name | `Bootsexecs64.exe` |
| File type | `exe` |
| First seen | `2026-08-17 20:06:40` |
| Reporter | `anonymous` |
| Tags | `exe, Remus, RemusStealer, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc20fbf8826a6ea50b465804ffd8fd8b` |
| SHA-256 | `1bc9f7e61cfd65c7e15eef8a6eac615aaa0ca68962ba7c2878ab0c4d4c254aa8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_1bc9f7e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bc9f7e61cfd65c7e15eef8a6eac615aaa0ca68962ba7c2878ab0c4d4c254aa8"
    family = "unknown"
    file_name = "Bootsexecs64.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:06:40"
  condition:
    hash.sha256(0, filesize) == "1bc9f7e61cfd65c7e15eef8a6eac615aaa0ca68962ba7c2878ab0c4d4c254aa8"
}
```

### Sample 96: `e0d32119d4dbbfdb`

| Field | Value |
|---|---|
| SHA-256 | `e0d32119d4dbbfdb8dad9ae2f4c51d5d72fced89b0b290c25c810d94174bf604` |
| Family label | `unknown` |
| File name | `s.vbs` |
| File type | `gz` |
| First seen | `2026-08-17 20:06:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, DonutLoader, gz, KongTuke, wintrust3478-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a174a538a6abbb79433ac254e9d27281` |
| SHA-1 | `2807105a769b8c1874576b9c57db975cd7322f1b` |
| SHA-256 | `e0d32119d4dbbfdb8dad9ae2f4c51d5d72fced89b0b290c25c810d94174bf604` |
| SHA3-384 | `11a79ab7b00af7b16f5abefedbc6d34ba3066ad3ed3baa7a65f5d65f77ecc27ee9b6135ccd5f9466a0e0df070813d144` |
| TLSH | `T11F573382D4309A4B1D3FD02BD9B5A8876AFB9134A0E38F3DAD4172554DCB7E0B5EE409` |
| SSDEEP | `393216:/oMBEAnosoUULlCinvcCyiiRtq5oBZ9m5jMvxPD9jILmiw5aZTK/Om6kI:/oMBBFIZCinECORtqiBZ99xb9jILrmtI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `gz`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_e0d32119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d32119d4dbbfdb8dad9ae2f4c51d5d72fced89b0b290c25c810d94174bf604"
    family = "unknown"
    file_name = "s.vbs"
    file_type = "gz"
    first_seen = "2026-08-17 20:06:28"
  condition:
    hash.sha256(0, filesize) == "e0d32119d4dbbfdb8dad9ae2f4c51d5d72fced89b0b290c25c810d94174bf604"
}
```

### Sample 97: `f8b09ccd406b3614`

| Field | Value |
|---|---|
| SHA-256 | `f8b09ccd406b3614a49fea26c98b93826d1bc4a706e55c7f471f6a5c41975961` |
| Family label | `Mirai` |
| File name | `daredevil.mips` |
| File type | `elf` |
| First seen | `2026-08-17 20:06:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `431085f43913f49a95beaeb126aaf53f` |
| SHA-1 | `b1fcdda2f00ac6eb1bd8f7699ad4f3d26d45e56d` |
| SHA-256 | `f8b09ccd406b3614a49fea26c98b93826d1bc4a706e55c7f471f6a5c41975961` |
| SHA3-384 | `b39d56a14b514bbe80007e22ab3ae6c90cf78f0403a9099f00aec63d77e94fd4448dd31cff6921b82691d6876f934e3c` |
| TLSH | `T18604A85E6E22CF7DF27887344BB38E25A75D23D623E0D684D2ACC1105E6029E545FFA8` |
| TELFHASH | `t1154160180a7417f063396c8d099def7b96a330eb3f166d278e51e85eab69d834d10d0c` |
| SSDEEP | `1536:M4XvZQKteZ1ol1pPKwMqrf4Cgy9wO3lpPUu6eG/xVQZYX1EHTnxa70V9nGWl:jXxIZZrG4lDO1pMuMxVQIia70VIy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_f8b09ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b09ccd406b3614a49fea26c98b93826d1bc4a706e55c7f471f6a5c41975961"
    family = "Mirai"
    file_name = "daredevil.mips"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:28"
  condition:
    hash.sha256(0, filesize) == "f8b09ccd406b3614a49fea26c98b93826d1bc4a706e55c7f471f6a5c41975961"
}
```

### Sample 98: `7e0267bec46965ce`

| Field | Value |
|---|---|
| SHA-256 | `7e0267bec46965ce5a9bdb330a84338137d2b4cd56359679d8a5b093def1ec14` |
| Family label | `Mirai` |
| File name | `daredevil.armv4l` |
| File type | `elf` |
| First seen | `2026-08-17 20:06:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6ffcab160132e9a504ef825626f64ca` |
| SHA-1 | `d6c5ea6fd670153c315b4631968476673098c95e` |
| SHA-256 | `7e0267bec46965ce5a9bdb330a84338137d2b4cd56359679d8a5b093def1ec14` |
| SHA3-384 | `a32163494173b8f5549659260b647e6df812641031749b348c5c29f432c166e8b3863a152cec134fffb75c11cb7fc8c4` |
| TLSH | `T176D30A85BC818B13C6E161B7FB4E428D772B0768E3EA71039D196F25375B8570E3B142` |
| SSDEEP | `1536:IJdO7jHhp8RqEPcJEOO9mD2Ts9o4VzB12T+6GDAu5W0YXY4FkK8lfkwyw4xWqbcT:8Wp8RqR5qmD7o4XcK6GDx5QFOfPOPe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_7e0267be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e0267bec46965ce5a9bdb330a84338137d2b4cd56359679d8a5b093def1ec14"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:20"
  condition:
    hash.sha256(0, filesize) == "7e0267bec46965ce5a9bdb330a84338137d2b4cd56359679d8a5b093def1ec14"
}
```

### Sample 99: `49492a93cef8e4e9`

| Field | Value |
|---|---|
| SHA-256 | `49492a93cef8e4e9f707c2f705e1a5855c997f1b0c0177e3162b853d1d99eb1f` |
| Family label | `Mirai` |
| File name | `daredevil.armv7l` |
| File type | `elf` |
| First seen | `2026-08-17 20:06:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbe7810330a34aaa33903e09871fd4f1` |
| SHA-1 | `272dbf0700b1622629cef3485cc3431f66e50b94` |
| SHA-256 | `49492a93cef8e4e9f707c2f705e1a5855c997f1b0c0177e3162b853d1d99eb1f` |
| SHA3-384 | `d19c4fee939f4a9889ff7c2adb8a8fb67d20c4a1e0f23ab8a7153898de14b883a532757f1950bfad15ad3246fb150f13` |
| TLSH | `T1CF83189ABD809B01D5D626B6FE0E114E33134B7CE3FA72038E145B2E278AD6B0B77515` |
| TELFHASH | `t1e5d02b668e8042ccb6d28605d6a2b17d261432e9475124cb104d55cf007274cb015428` |
| SSDEEP | `1536:OQnIaIq9zisH5BJOZ9MC1N4prCPDRMaX4miuWGD3lDw1icKIaiT0BfY8x:qF+BJMKC1HPDRMaX4miqSNKIaiT0B/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_49492a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49492a93cef8e4e9f707c2f705e1a5855c997f1b0c0177e3162b853d1d99eb1f"
    family = "Mirai"
    file_name = "daredevil.armv7l"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:13"
  condition:
    hash.sha256(0, filesize) == "49492a93cef8e4e9f707c2f705e1a5855c997f1b0c0177e3162b853d1d99eb1f"
}
```

### Sample 100: `9a28bc11748337c0`

| Field | Value |
|---|---|
| SHA-256 | `9a28bc11748337c0f9be92b0317a7c1b68e853ad46734991aed95de5edea909d` |
| Family label | `Mirai` |
| File name | `daredevil.mipsel` |
| File type | `elf` |
| First seen | `2026-08-17 20:06:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bf7928c164e8d7ffe9188c297b46761` |
| SHA-1 | `b43787f272df31f153b948a9614a57f62c6167f3` |
| SHA-256 | `9a28bc11748337c0f9be92b0317a7c1b68e853ad46734991aed95de5edea909d` |
| SHA3-384 | `814b32ce8f0d665e9e2c66de20d16a775e2d7593e2d0c631b055d229f835431b366ad7fbd575b64a54b210f6c738f95e` |
| TLSH | `T1B504D80A9FA20EBBDCBFDD3306E9070539DC550722A53B753678D928F50A64B4AD3C68` |
| SSDEEP | `1536:EWBmGkbCtdMIjlOTLANitvujG9qMYGPAVodbCd737Jncl8MaX1jgYlTMhanIFWrs:O8AqZXGXoxLNXIrIksJwvaCVft` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_9a28bc11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a28bc11748337c0f9be92b0317a7c1b68e853ad46734991aed95de5edea909d"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:03"
  condition:
    hash.sha256(0, filesize) == "9a28bc11748337c0f9be92b0317a7c1b68e853ad46734991aed95de5edea909d"
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
 * Generated: 2026-08-18T01:53:33.551610+00:00
 */

rule MalwareBazaar_unknown_001_4256efa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4256efa4f4e316b8394e42d2f2ea36bb533c5438e05c64f79f2e26a368d1c98c"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-18 01:52:09"
  condition:
    hash.sha256(0, filesize) == "4256efa4f4e316b8394e42d2f2ea36bb533c5438e05c64f79f2e26a368d1c98c"
}

rule MalwareBazaar_Mirai_002_97fe2dac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97fe2dac2c95aae6eb2033e51324dd8e0bebd043d114a07bb4f1c2b42eb6b023"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-18 01:49:34"
  condition:
    hash.sha256(0, filesize) == "97fe2dac2c95aae6eb2033e51324dd8e0bebd043d114a07bb4f1c2b42eb6b023"
}

rule MalwareBazaar_unknown_003_c55bd228
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c55bd2281fa67c02d2456f66e00e0fbda57bdeebc2ca3d86557ff8280a5ff05e"
    family = "unknown"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-18 01:49:18"
  condition:
    hash.sha256(0, filesize) == "c55bd2281fa67c02d2456f66e00e0fbda57bdeebc2ca3d86557ff8280a5ff05e"
}

rule MalwareBazaar_Mirai_004_9659e581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9659e581598ab314e5a31301648cc43d16adfa098762c6c9dbd9ba2b6c1d773f"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-18 01:45:54"
  condition:
    hash.sha256(0, filesize) == "9659e581598ab314e5a31301648cc43d16adfa098762c6c9dbd9ba2b6c1d773f"
}

rule MalwareBazaar_unknown_005_983cfe9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "983cfe9b42edc2733c90abbfd39427afbe761e8136960e3267558b658fd8b477"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 01:45:40"
  condition:
    hash.sha256(0, filesize) == "983cfe9b42edc2733c90abbfd39427afbe761e8136960e3267558b658fd8b477"
}

rule MalwareBazaar_Mirai_006_fc47c4d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc47c4d1172496ff98213b490f7b01da57493e23dc84277d596c0ca19e60b180"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-18 01:45:29"
  condition:
    hash.sha256(0, filesize) == "fc47c4d1172496ff98213b490f7b01da57493e23dc84277d596c0ca19e60b180"
}

rule MalwareBazaar_AgentTesla_007_558517cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "558517ccded57ad4f971621c1dfafb46461b7e1ab4d89305408703b34b38f265"
    family = "AgentTesla"
    file_name = "New_Purchase_Order_[PO_02081].pdf.JS"
    file_type = "js"
    first_seen = "2026-08-18 01:21:44"
  condition:
    hash.sha256(0, filesize) == "558517ccded57ad4f971621c1dfafb46461b7e1ab4d89305408703b34b38f265"
}

rule MalwareBazaar_unknown_008_daabf902
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "daabf9021158e5dd35e162c05bc25c6df677a919a8c125a1006871bce7c0d4e5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 01:07:51"
  condition:
    hash.sha256(0, filesize) == "daabf9021158e5dd35e162c05bc25c6df677a919a8c125a1006871bce7c0d4e5"
}

rule MalwareBazaar_AsyncRAT_009_866ac5e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "866ac5e19171919e0861a591f746f7b8b746a59cb9aec48306539569d83373c2"
    family = "AsyncRAT"
    file_name = "e-dekont_html.exe"
    file_type = "exe"
    first_seen = "2026-08-18 00:52:20"
  condition:
    hash.sha256(0, filesize) == "866ac5e19171919e0861a591f746f7b8b746a59cb9aec48306539569d83373c2"
}

rule MalwareBazaar_unknown_010_d51c9cd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51c9cd1b1de63ae62ae781147cc17adc0f0450206884737c996b858a8b770ad"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-18 00:52:11"
  condition:
    hash.sha256(0, filesize) == "d51c9cd1b1de63ae62ae781147cc17adc0f0450206884737c996b858a8b770ad"
}

rule MalwareBazaar_Mirai_011_8995cc7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8995cc7fb82c8c4223b3ccf74047ab7c2055c1551dfc04fe649257c47c9f624c"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-18 00:47:40"
  condition:
    hash.sha256(0, filesize) == "8995cc7fb82c8c4223b3ccf74047ab7c2055c1551dfc04fe649257c47c9f624c"
}

rule MalwareBazaar_Mirai_012_a9f85b31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9f85b311c3ea2c60e76b905844cfb6e37c6a0575e55dcc53eef4bd308acf72c"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-18 00:47:10"
  condition:
    hash.sha256(0, filesize) == "a9f85b311c3ea2c60e76b905844cfb6e37c6a0575e55dcc53eef4bd308acf72c"
}

rule MalwareBazaar_Mirai_013_561b9327
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467"
    family = "Mirai"
    file_name = "561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467"
    file_type = "sh"
    first_seen = "2026-08-18 00:43:06"
  condition:
    hash.sha256(0, filesize) == "561b9327e87addc615ec1c93342af9227faf8bc904218ad513cf86b8ff26a467"
}

rule MalwareBazaar_Mirai_014_41665876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "416658765b860dc70979dc970a5179d7b51163aa6b173ab002c3affe46608e19"
    family = "Mirai"
    file_name = "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:37"
  condition:
    hash.sha256(0, filesize) == "416658765b860dc70979dc970a5179d7b51163aa6b173ab002c3affe46608e19"
}

rule MalwareBazaar_Mirai_015_54217f81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54217f8171496a010c07e8befa2207248bd70948c46467f3f8ddfe807b1b4115"
    family = "Mirai"
    file_name = "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:32"
  condition:
    hash.sha256(0, filesize) == "54217f8171496a010c07e8befa2207248bd70948c46467f3f8ddfe807b1b4115"
}

rule MalwareBazaar_Mirai_016_b785ba9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b785ba9b7b7e3fc5da5595c92c54b6e0ab42a0c9e3b1310caff0ac4b509a304c"
    family = "Mirai"
    file_name = "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:27"
  condition:
    hash.sha256(0, filesize) == "b785ba9b7b7e3fc5da5595c92c54b6e0ab42a0c9e3b1310caff0ac4b509a304c"
}

rule MalwareBazaar_Mirai_017_2eb780b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2eb780b601900b2aa2fc35715b1a5dcaecb0e561ff6e11509a326e80fea6ee09"
    family = "Mirai"
    file_name = "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:21"
  condition:
    hash.sha256(0, filesize) == "2eb780b601900b2aa2fc35715b1a5dcaecb0e561ff6e11509a326e80fea6ee09"
}

rule MalwareBazaar_Mirai_018_47da111e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47da111e14337dfb56d04c6eeae455f9fd413a1bd34b6e7a6be4414a8a1d676c"
    family = "Mirai"
    file_name = "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:14"
  condition:
    hash.sha256(0, filesize) == "47da111e14337dfb56d04c6eeae455f9fd413a1bd34b6e7a6be4414a8a1d676c"
}

rule MalwareBazaar_Mirai_019_ae768374
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae7683748d03c5f143465f8a298c726787f968e744eb7aece3a04a5f13f213ca"
    family = "Mirai"
    file_name = "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:16:08"
  condition:
    hash.sha256(0, filesize) == "ae7683748d03c5f143465f8a298c726787f968e744eb7aece3a04a5f13f213ca"
}

rule MalwareBazaar_WannaCry_020_a5a65f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd"
    family = "WannaCry"
    file_name = "a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd"
    file_type = "exe"
    first_seen = "2026-08-18 00:15:47"
  condition:
    hash.sha256(0, filesize) == "a5a65f7a602bf8569bf18345c0741e765e9b0c574f0371dd9b016ba28876c0cd"
}

rule MalwareBazaar_Mirai_021_1c5dbb5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407"
    family = "Mirai"
    file_name = "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:42"
  condition:
    hash.sha256(0, filesize) == "1c5dbb5fbeb83d5e7969b6db0456168c679e8f0a4f14ba51d8e852522a12b407"
}

rule MalwareBazaar_Mirai_022_09d1afc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0"
    family = "Mirai"
    file_name = "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:37"
  condition:
    hash.sha256(0, filesize) == "09d1afc8ea294d1e621bfadaa194bf4fe516fb8f7e422c1557ac29a603557ce0"
}

rule MalwareBazaar_Mirai_023_419b9978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016"
    family = "Mirai"
    file_name = "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:32"
  condition:
    hash.sha256(0, filesize) == "419b9978ed20ad6bf5f60c3b28fced738cb1a92b0ac00cb94a3476b4030ae016"
}

rule MalwareBazaar_Mirai_024_5684d4a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f"
    family = "Mirai"
    file_name = "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:28"
  condition:
    hash.sha256(0, filesize) == "5684d4a9dee9642baf9375fcbdfb268e5d2ba98195c535f46a206d065948601f"
}

rule MalwareBazaar_Mirai_025_c7b36cde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc"
    family = "Mirai"
    file_name = "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:24"
  condition:
    hash.sha256(0, filesize) == "c7b36cde3fafc0a94c42119b2e5526b7893c458fd8c8949671028e25a5ddc8fc"
}

rule MalwareBazaar_Mirai_026_c97ba03b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47"
    family = "Mirai"
    file_name = "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:15:20"
  condition:
    hash.sha256(0, filesize) == "c97ba03bd5dfb2c52bc5e33fb1e968f6c101e5902994a5a3cb0bc0fc865e4b47"
}

rule MalwareBazaar_Mirai_027_70df37a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70df37a7ce68efccd01b2e2ebc992d01931d5b3e423f53f665632a08e4a6c180"
    family = "Mirai"
    file_name = "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:11:38"
  condition:
    hash.sha256(0, filesize) == "70df37a7ce68efccd01b2e2ebc992d01931d5b3e423f53f665632a08e4a6c180"
}

rule MalwareBazaar_Mirai_028_112843a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "112843a05bbafa5c0c3c2325788ef4fb65bf4c4158f01220b7a173ab716643b3"
    family = "Mirai"
    file_name = "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:56"
  condition:
    hash.sha256(0, filesize) == "112843a05bbafa5c0c3c2325788ef4fb65bf4c4158f01220b7a173ab716643b3"
}

rule MalwareBazaar_Mirai_029_34bc6abd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34bc6abdf70e197e048a2fb0a5b20d7f2ad4a726ca8a4aa58a88bee5757f7f3d"
    family = "Mirai"
    file_name = "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:51"
  condition:
    hash.sha256(0, filesize) == "34bc6abdf70e197e048a2fb0a5b20d7f2ad4a726ca8a4aa58a88bee5757f7f3d"
}

rule MalwareBazaar_Mirai_030_f1484186
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f14841867417bba572fa268bdb08ee9e4a723ab0856667f52f7b532aeda43423"
    family = "Mirai"
    file_name = "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:47"
  condition:
    hash.sha256(0, filesize) == "f14841867417bba572fa268bdb08ee9e4a723ab0856667f52f7b532aeda43423"
}

rule MalwareBazaar_Mirai_031_89f464e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2"
    family = "Mirai"
    file_name = "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:38"
  condition:
    hash.sha256(0, filesize) == "89f464e363f25559b83e49fb969032ab135261df0564aad7793d78e4ea299ed2"
}

rule MalwareBazaar_Mirai_032_99aa3003
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123"
    family = "Mirai"
    file_name = "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:33"
  condition:
    hash.sha256(0, filesize) == "99aa30034b0277f1fd3d193bc1b43af401163c7645ff2499f7ee6e39ae166123"
}

rule MalwareBazaar_Mirai_033_c3bf94e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7"
    family = "Mirai"
    file_name = "c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:28"
  condition:
    hash.sha256(0, filesize) == "c3bf94e24ef78430e6ff3aca5d2dd8c62cdfebb2ae07dd69788420c1985104f7"
}

rule MalwareBazaar_Mirai_034_50f2e541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae"
    family = "Mirai"
    file_name = "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:25"
  condition:
    hash.sha256(0, filesize) == "50f2e541c9ce5575c85e43af4c3ce32536714d516a3c0a3eb4acfa0624fd3cae"
}

rule MalwareBazaar_Mirai_035_cae329df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1"
    family = "Mirai"
    file_name = "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1.elf"
    file_type = "elf"
    first_seen = "2026-08-18 00:10:18"
  condition:
    hash.sha256(0, filesize) == "cae329df409e789c9be7207de5156a19b8edeeaf3634edfe88726822de03a6a1"
}

rule MalwareBazaar_unknown_036_c1bbf296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1bbf296cafb65c2ec94c313cb043889183bc79316be9f20344fd59c7da92421"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-18 00:02:50"
  condition:
    hash.sha256(0, filesize) == "c1bbf296cafb65c2ec94c313cb043889183bc79316be9f20344fd59c7da92421"
}

rule MalwareBazaar_unknown_037_c177e67c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c177e67cb8d6aa080cfb1493b15aea4aec8ed809c80054e12adb7b43ff6ba8a2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 23:54:53"
  condition:
    hash.sha256(0, filesize) == "c177e67cb8d6aa080cfb1493b15aea4aec8ed809c80054e12adb7b43ff6ba8a2"
}

rule MalwareBazaar_unknown_038_5fa3e214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fa3e214842722f8dbc56499a74b3794701fd00a7c38396f9bd22c382ad73816"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 23:52:10"
  condition:
    hash.sha256(0, filesize) == "5fa3e214842722f8dbc56499a74b3794701fd00a7c38396f9bd22c382ad73816"
}

rule MalwareBazaar_unknown_039_77702ddc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77702ddc1b003b03bbd30b5cefb9c737f1ba11df7db07f848fb11aee0b1440fe"
    family = "unknown"
    file_name = "NexusMods.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:54:40"
  condition:
    hash.sha256(0, filesize) == "77702ddc1b003b03bbd30b5cefb9c737f1ba11df7db07f848fb11aee0b1440fe"
}

rule MalwareBazaar_Prometei_040_9b1cba25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9"
    family = "Prometei"
    file_name = "9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9"
    file_type = "elf"
    first_seen = "2026-08-17 22:52:36"
  condition:
    hash.sha256(0, filesize) == "9b1cba255f9494df63871d182cf7644fcd388c54d62a09921ed03452e4b115f9"
}

rule MalwareBazaar_unknown_041_31876a3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31876a3a26a0f92a001dcae2b84174bb9f47af9208f7a92b6e160b1931899b01"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 22:52:10"
  condition:
    hash.sha256(0, filesize) == "31876a3a26a0f92a001dcae2b84174bb9f47af9208f7a92b6e160b1931899b01"
}

rule MalwareBazaar_unknown_042_15658aa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe"
    family = "unknown"
    file_name = "15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe.bin"
    file_type = "exe"
    first_seen = "2026-08-17 22:40:06"
  condition:
    hash.sha256(0, filesize) == "15658aa912696d8cb7a721db43be332db24fe6b30e93495512fb17c24df55ebe"
}

rule MalwareBazaar_unknown_043_9758059a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298"
    family = "unknown"
    file_name = "9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:25:39"
  condition:
    hash.sha256(0, filesize) == "9758059acd85ad5b500777642f936fc88dbe54ec6d024f3ed802690c61e0e298"
}

rule MalwareBazaar_unknown_044_5e08c1d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082"
    family = "unknown"
    file_name = "5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:25:34"
  condition:
    hash.sha256(0, filesize) == "5e08c1d1f34fda070f4630e2d3f8cf15778cb5ac22acda0dff494ae09afd3082"
}

rule MalwareBazaar_unknown_045_5436f494
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5436f494f7a96e5140529e5b628ed70d51b10e932a82c56abb0e8e826ba64c1c"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-17 22:17:17"
  condition:
    hash.sha256(0, filesize) == "5436f494f7a96e5140529e5b628ed70d51b10e932a82c56abb0e8e826ba64c1c"
}

rule MalwareBazaar_unknown_046_57369d7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57369d7d7eb1ea95aef9f374dd418af94c2b9e534e46a83257b57ac48ecb11a5"
    family = "unknown"
    file_name = "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
    file_type = "exe"
    first_seen = "2026-08-17 22:15:56"
  condition:
    hash.sha256(0, filesize) == "57369d7d7eb1ea95aef9f374dd418af94c2b9e534e46a83257b57ac48ecb11a5"
}

rule MalwareBazaar_Prometei_047_55518513
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34"
    family = "Prometei"
    file_name = "5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34"
    file_type = "elf"
    first_seen = "2026-08-17 22:15:29"
  condition:
    hash.sha256(0, filesize) == "5551851317fe09fb0b15060fe5de15547d013e1d6deaf7c3ee288fc013476d34"
}

rule MalwareBazaar_unknown_048_9103f68a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
    family = "unknown"
    file_name = "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
    file_type = "exe"
    first_seen = "2026-08-17 22:14:45"
  condition:
    hash.sha256(0, filesize) == "9103f68a42ba9227f1d7e601e3c77945a396394492107dc79cfd9adc73db32f6"
}

rule MalwareBazaar_unknown_049_e680982a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0"
    family = "unknown"
    file_name = "e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0.bin"
    file_type = "exe"
    first_seen = "2026-08-17 22:13:20"
  condition:
    hash.sha256(0, filesize) == "e680982a6eb093692da658ed131a27541f218ae6287e967e996e261acc9d68d0"
}

rule MalwareBazaar_unknown_050_34e57ad8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e57ad8876da0ffa60b3fc74386eb8d35f5a75c5f1ef870537e57eaa4f598ab"
    family = "unknown"
    file_name = "FUXhack V3.1.2.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:12:54"
  condition:
    hash.sha256(0, filesize) == "34e57ad8876da0ffa60b3fc74386eb8d35f5a75c5f1ef870537e57eaa4f598ab"
}

rule MalwareBazaar_unknown_051_01893775
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "018937753ffa1fdc88796297948d82cff81b0b0beb1dae0335417b178eb581f2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 22:09:31"
  condition:
    hash.sha256(0, filesize) == "018937753ffa1fdc88796297948d82cff81b0b0beb1dae0335417b178eb581f2"
}

rule MalwareBazaar_unknown_052_562620e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "562620e1df663c852e7323d07272d223d29e8558c95110faac06f7c6d26eec5b"
    family = "unknown"
    file_name = "GTA6.exe"
    file_type = "exe"
    first_seen = "2026-08-17 22:00:39"
  condition:
    hash.sha256(0, filesize) == "562620e1df663c852e7323d07272d223d29e8558c95110faac06f7c6d26eec5b"
}

rule MalwareBazaar_unknown_053_4abbb9cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4abbb9cb37b34ec498078496f17a7821b8271ae2e01f63e773a1feac994cd0f4"
    family = "unknown"
    file_name = "QuickFetch.exe"
    file_type = "exe"
    first_seen = "2026-08-17 21:52:15"
  condition:
    hash.sha256(0, filesize) == "4abbb9cb37b34ec498078496f17a7821b8271ae2e01f63e773a1feac994cd0f4"
}

rule MalwareBazaar_unknown_054_e77c1d3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e77c1d3fd059fe8248e81fdfcbdc1f72c99bd208e4951203e43e16f803dabb1d"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 21:52:10"
  condition:
    hash.sha256(0, filesize) == "e77c1d3fd059fe8248e81fdfcbdc1f72c99bd208e4951203e43e16f803dabb1d"
}

rule MalwareBazaar_unknown_055_ac3af462
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac3af462408f14e5f953129158a65c9a75f2109d69bdd447aacd6998b488c9d5"
    family = "unknown"
    file_name = "Launcher.exe"
    file_type = "exe"
    first_seen = "2026-08-17 21:39:06"
  condition:
    hash.sha256(0, filesize) == "ac3af462408f14e5f953129158a65c9a75f2109d69bdd447aacd6998b488c9d5"
}

rule MalwareBazaar_unknown_056_051f2d8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "051f2d8dd668f5c0a4d4cbeba44db53b970daae37f9408a02de6563f287cbee6"
    family = "unknown"
    file_name = "y"
    file_type = "unknown"
    first_seen = "2026-08-17 21:34:18"
  condition:
    hash.sha256(0, filesize) == "051f2d8dd668f5c0a4d4cbeba44db53b970daae37f9408a02de6563f287cbee6"
}

rule MalwareBazaar_unknown_057_89dacc86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89dacc86bc936a33d32fc6070e8b0923f247d8dc89f21b331ecba9bb2ae9b01a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 21:33:17"
  condition:
    hash.sha256(0, filesize) == "89dacc86bc936a33d32fc6070e8b0923f247d8dc89f21b331ecba9bb2ae9b01a"
}

rule MalwareBazaar_unknown_058_53b349aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53b349aac82e1fc104db81027c957a38c1abac76f6dd20c8536ba267ef4b0727"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 21:22:42"
  condition:
    hash.sha256(0, filesize) == "53b349aac82e1fc104db81027c957a38c1abac76f6dd20c8536ba267ef4b0727"
}

rule MalwareBazaar_unknown_059_dd16a399
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd16a399bfd025a70ab801188be21e98b09eb53b02777478ad144d34f7643282"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-17 21:20:37"
  condition:
    hash.sha256(0, filesize) == "dd16a399bfd025a70ab801188be21e98b09eb53b02777478ad144d34f7643282"
}

rule MalwareBazaar_unknown_060_b407def7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b407def7668e61b9a917aeecdfc408fa3b91c7a9656551debede768fc2406bf5"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-17 21:17:55"
  condition:
    hash.sha256(0, filesize) == "b407def7668e61b9a917aeecdfc408fa3b91c7a9656551debede768fc2406bf5"
}

rule MalwareBazaar_unknown_061_bab753aa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bab753aa194389c1877e5d21e6bcd2a1cfe291388363239561ca6f6172473dee"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 21:12:39"
  condition:
    hash.sha256(0, filesize) == "bab753aa194389c1877e5d21e6bcd2a1cfe291388363239561ca6f6172473dee"
}

rule MalwareBazaar_unknown_062_722e61b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "722e61b1ce656fc024981dfefd4ff161af3df5e4ed556b3c75da3d9be84a0c79"
    family = "unknown"
    file_name = "Radium.jar"
    file_type = "jar"
    first_seen = "2026-08-17 21:08:34"
  condition:
    hash.sha256(0, filesize) == "722e61b1ce656fc024981dfefd4ff161af3df5e4ed556b3c75da3d9be84a0c79"
}

rule MalwareBazaar_unknown_063_c064c921
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21"
    family = "unknown"
    file_name = "c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21"
    file_type = "unknown"
    first_seen = "2026-08-17 21:00:20"
  condition:
    hash.sha256(0, filesize) == "c064c921e50349f93fac199f90d9ba25477ff333e5a119fd8e868056c0ba5d21"
}

rule MalwareBazaar_unknown_064_5e37d822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f"
    family = "unknown"
    file_name = "5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f"
    file_type = "unknown"
    first_seen = "2026-08-17 21:00:16"
  condition:
    hash.sha256(0, filesize) == "5e37d8222f4ecac4722be49de94694c513e509b17aa80c5adce875ffd6c3812f"
}

rule MalwareBazaar_unknown_065_448fc8f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b"
    family = "unknown"
    file_name = "448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b"
    file_type = "unknown"
    first_seen = "2026-08-17 21:00:12"
  condition:
    hash.sha256(0, filesize) == "448fc8f1dea0e9cc44a0443a3a0f9e137589dde90799b0c581545dd1b584bb4b"
}

rule MalwareBazaar_unknown_066_363806ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363806adf53215b567099b55da5a05c25b74b7744c18c5c395ccd1fc842d8985"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:59:58"
  condition:
    hash.sha256(0, filesize) == "363806adf53215b567099b55da5a05c25b74b7744c18c5c395ccd1fc842d8985"
}

rule MalwareBazaar_unknown_067_3a1625ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a1625ef4a1b46393e6ddd71e04de8f4c546ba56616da3aef682d8399c86dce5"
    family = "unknown"
    file_name = "resight-v1.7.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:59:49"
  condition:
    hash.sha256(0, filesize) == "3a1625ef4a1b46393e6ddd71e04de8f4c546ba56616da3aef682d8399c86dce5"
}

rule MalwareBazaar_unknown_068_7af7eeec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3"
    family = "unknown"
    file_name = "7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:55:21"
  condition:
    hash.sha256(0, filesize) == "7af7eeec1e562a8145abbf81dc1a58abbb9106276a20609bdb77529978ae1fb3"
}

rule MalwareBazaar_Vidar_069_a1e1b4f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9"
    family = "Vidar"
    file_name = "a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9.bin"
    file_type = "exe"
    first_seen = "2026-08-17 20:52:53"
  condition:
    hash.sha256(0, filesize) == "a1e1b4f32118b4712a0cd3ad27fede2d25c4a835c4b60c55d11ff76acbb9f7e9"
}

rule MalwareBazaar_unknown_070_892e3dee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "892e3dee69fbd32403412137c34b784707f1e7062938501ee34dca9f8695c61a"
    family = "unknown"
    file_name = "composer.php"
    file_type = "exe"
    first_seen = "2026-08-17 20:52:10"
  condition:
    hash.sha256(0, filesize) == "892e3dee69fbd32403412137c34b784707f1e7062938501ee34dca9f8695c61a"
}

rule MalwareBazaar_CoinMiner_071_bffb15ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3"
    family = "CoinMiner"
    file_name = "bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:50:27"
  condition:
    hash.sha256(0, filesize) == "bffb15ba549446153f35ba84416c339c6c88bd3e5559f9967f083e74ee7811c3"
}

rule MalwareBazaar_unknown_072_11cc5709
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11cc5709971c8135bed1e0f1a1ad80e1e918165ce742c308e9cd8abdef958b81"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-17 20:49:27"
  condition:
    hash.sha256(0, filesize) == "11cc5709971c8135bed1e0f1a1ad80e1e918165ce742c308e9cd8abdef958b81"
}

rule MalwareBazaar_RustyStealer_073_192b59dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "192b59dc537d73dd45f4c0a84b8dffaa664661b4523ca13fed01b5f40a6d5bc8"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:45:57"
  condition:
    hash.sha256(0, filesize) == "192b59dc537d73dd45f4c0a84b8dffaa664661b4523ca13fed01b5f40a6d5bc8"
}

rule MalwareBazaar_unknown_074_d460c2d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d460c2d998e4e390635d79e7233ad268379131555bd9b87bce16a813b041b844"
    family = "unknown"
    file_name = "NexomiaUI_v8.35.321.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:45:33"
  condition:
    hash.sha256(0, filesize) == "d460c2d998e4e390635d79e7233ad268379131555bd9b87bce16a813b041b844"
}

rule MalwareBazaar_unknown_075_36f4c72c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36f4c72c0bfa37b52ca053b008e6d1020b8fdd0442cf0d1466a0affc1b521a15"
    family = "unknown"
    file_name = "External_Release_Final_5374.ps1"
    file_type = "ps1"
    first_seen = "2026-08-17 20:39:32"
  condition:
    hash.sha256(0, filesize) == "36f4c72c0bfa37b52ca053b008e6d1020b8fdd0442cf0d1466a0affc1b521a15"
}

rule MalwareBazaar_unknown_076_891292d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "891292d66392d8da0e92cf38abcb108a69e33fb1714f7920448301b1aa5094d5"
    family = "unknown"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:37:08"
  condition:
    hash.sha256(0, filesize) == "891292d66392d8da0e92cf38abcb108a69e33fb1714f7920448301b1aa5094d5"
}

rule MalwareBazaar_LummaStealer_077_727c152c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1"
    family = "LummaStealer"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:36:21"
  condition:
    hash.sha256(0, filesize) == "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1"
}

rule MalwareBazaar_SnappyClient_078_1863c944
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1863c944ff0f5f06cafe0f98d6a6f54084ac266936c0dbc16a9d13ab03dda421"
    family = "SnappyClient"
    file_name = "Setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:35:46"
  condition:
    hash.sha256(0, filesize) == "1863c944ff0f5f06cafe0f98d6a6f54084ac266936c0dbc16a9d13ab03dda421"
}

rule MalwareBazaar_unknown_079_59d27790
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59d277908b548113ad40dd23406fb7ca5b004372602585c43422bd2d2608e783"
    family = "unknown"
    file_name = "InstallerV5164x64.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:33:23"
  condition:
    hash.sha256(0, filesize) == "59d277908b548113ad40dd23406fb7ca5b004372602585c43422bd2d2608e783"
}

rule MalwareBazaar_unknown_080_fad6377e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fad6377eb2c2ccee6bd87097bbe2947d81dca67f54117b09df436720469f67c3"
    family = "unknown"
    file_name = "Installer.iso"
    file_type = "iso"
    first_seen = "2026-08-17 20:32:55"
  condition:
    hash.sha256(0, filesize) == "fad6377eb2c2ccee6bd87097bbe2947d81dca67f54117b09df436720469f67c3"
}

rule MalwareBazaar_unknown_081_c12fd900
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c12fd900f32944623823f5087ef3eb146586a9339c0262333ac9c9bc08c06e84"
    family = "unknown"
    file_name = "FLStudio2025_v165_Win.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:31:40"
  condition:
    hash.sha256(0, filesize) == "c12fd900f32944623823f5087ef3eb146586a9339c0262333ac9c9bc08c06e84"
}

rule MalwareBazaar_Vidar_082_7b33480a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b33480aaa55a5113056c9ae1d5d72cd9a2b105f9fd3302c07f095e5f2effee9"
    family = "Vidar"
    file_name = "Download_Movie_Maker_2.6_For_Windows_7.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:29:55"
  condition:
    hash.sha256(0, filesize) == "7b33480aaa55a5113056c9ae1d5d72cd9a2b105f9fd3302c07f095e5f2effee9"
}

rule MalwareBazaar_unknown_083_7b92e3f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b92e3f3669e11928a5f57e81cd37ebf1feabd31d66f8cc59b41953c9acf2a94"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:28:41"
  condition:
    hash.sha256(0, filesize) == "7b92e3f3669e11928a5f57e81cd37ebf1feabd31d66f8cc59b41953c9acf2a94"
}

rule MalwareBazaar_Mirai_084_3dc384b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3dc384b44e2e6c37ba4529b86740771f9f942bc0b01a9830110cb4f86739c131"
    family = "Mirai"
    file_name = "iran.armv7l"
    file_type = "elf"
    first_seen = "2026-08-17 20:16:31"
  condition:
    hash.sha256(0, filesize) == "3dc384b44e2e6c37ba4529b86740771f9f942bc0b01a9830110cb4f86739c131"
}

rule MalwareBazaar_unknown_085_372d9ffd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "372d9ffd6a52d6503025ee4cc1393b8a3d754513b32e6dafd818b3db907ec2a5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:13:10"
  condition:
    hash.sha256(0, filesize) == "372d9ffd6a52d6503025ee4cc1393b8a3d754513b32e6dafd818b3db907ec2a5"
}

rule MalwareBazaar_unknown_086_797bcd98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "797bcd9813c2c4f11e3abde7b4806e0d81531eaeb68dfa98d3482b7c9174a61d"
    family = "unknown"
    file_name = "?????.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:11:44"
  condition:
    hash.sha256(0, filesize) == "797bcd9813c2c4f11e3abde7b4806e0d81531eaeb68dfa98d3482b7c9174a61d"
}

rule MalwareBazaar_unknown_087_98268f4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98268f4b9de6c8c17f83de8504302676c91710c6f801a73c94e2c43ef58b6100"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-17 20:10:38"
  condition:
    hash.sha256(0, filesize) == "98268f4b9de6c8c17f83de8504302676c91710c6f801a73c94e2c43ef58b6100"
}

rule MalwareBazaar_unknown_088_6af6b0c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6af6b0c8252dccb24c82b81a75afbaf7ca8697298423bf0506783e69044b0ebd"
    family = "unknown"
    file_name = "ws-Setup-Complete.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:10:23"
  condition:
    hash.sha256(0, filesize) == "6af6b0c8252dccb24c82b81a75afbaf7ca8697298423bf0506783e69044b0ebd"
}

rule MalwareBazaar_unknown_089_0ccc999c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ccc999c0f8f96df44bcfb6657392964dca46bcd8208cfe6b919f30e79b3c664"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-08-17 20:08:54"
  condition:
    hash.sha256(0, filesize) == "0ccc999c0f8f96df44bcfb6657392964dca46bcd8208cfe6b919f30e79b3c664"
}

rule MalwareBazaar_Mirai_090_eacf3227
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eacf32279b327b9e7c4fe83404b2216abbe89801cf94e4b34828596e09f0f322"
    family = "Mirai"
    file_name = "daredevil.powerpc"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:44"
  condition:
    hash.sha256(0, filesize) == "eacf32279b327b9e7c4fe83404b2216abbe89801cf94e4b34828596e09f0f322"
}

rule MalwareBazaar_Mirai_091_69cf31da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69cf31dad20613d82840a5530ab726c009dc00606bb79200172c24c76ccf61ba"
    family = "Mirai"
    file_name = "daredevil.armv5l"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:42"
  condition:
    hash.sha256(0, filesize) == "69cf31dad20613d82840a5530ab726c009dc00606bb79200172c24c76ccf61ba"
}

rule MalwareBazaar_Mirai_092_ede1ddcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ede1ddcbccbad58538aa6b11febc140b6edc87a955deaccf479dfd9d9fd04b85"
    family = "Mirai"
    file_name = "daredevil.armv6l"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:39"
  condition:
    hash.sha256(0, filesize) == "ede1ddcbccbad58538aa6b11febc140b6edc87a955deaccf479dfd9d9fd04b85"
}

rule MalwareBazaar_Mirai_093_0afa4652
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0afa465224ae07e025b5bea1ba5b29618c3309754a9d471ac85958600ac66b5f"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-17 20:07:28"
  condition:
    hash.sha256(0, filesize) == "0afa465224ae07e025b5bea1ba5b29618c3309754a9d471ac85958600ac66b5f"
}

rule MalwareBazaar_unknown_094_3508dbe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3508dbe7b6b122c61367de28788c6e3871351e3b9eb813162e08601cde83376a"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-17 20:07:27"
  condition:
    hash.sha256(0, filesize) == "3508dbe7b6b122c61367de28788c6e3871351e3b9eb813162e08601cde83376a"
}

rule MalwareBazaar_unknown_095_1bc9f7e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bc9f7e61cfd65c7e15eef8a6eac615aaa0ca68962ba7c2878ab0c4d4c254aa8"
    family = "unknown"
    file_name = "Bootsexecs64.exe"
    file_type = "exe"
    first_seen = "2026-08-17 20:06:40"
  condition:
    hash.sha256(0, filesize) == "1bc9f7e61cfd65c7e15eef8a6eac615aaa0ca68962ba7c2878ab0c4d4c254aa8"
}

rule MalwareBazaar_unknown_096_e0d32119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d32119d4dbbfdb8dad9ae2f4c51d5d72fced89b0b290c25c810d94174bf604"
    family = "unknown"
    file_name = "s.vbs"
    file_type = "gz"
    first_seen = "2026-08-17 20:06:28"
  condition:
    hash.sha256(0, filesize) == "e0d32119d4dbbfdb8dad9ae2f4c51d5d72fced89b0b290c25c810d94174bf604"
}

rule MalwareBazaar_Mirai_097_f8b09ccd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8b09ccd406b3614a49fea26c98b93826d1bc4a706e55c7f471f6a5c41975961"
    family = "Mirai"
    file_name = "daredevil.mips"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:28"
  condition:
    hash.sha256(0, filesize) == "f8b09ccd406b3614a49fea26c98b93826d1bc4a706e55c7f471f6a5c41975961"
}

rule MalwareBazaar_Mirai_098_7e0267be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e0267bec46965ce5a9bdb330a84338137d2b4cd56359679d8a5b093def1ec14"
    family = "Mirai"
    file_name = "daredevil.armv4l"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:20"
  condition:
    hash.sha256(0, filesize) == "7e0267bec46965ce5a9bdb330a84338137d2b4cd56359679d8a5b093def1ec14"
}

rule MalwareBazaar_Mirai_099_49492a93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49492a93cef8e4e9f707c2f705e1a5855c997f1b0c0177e3162b853d1d99eb1f"
    family = "Mirai"
    file_name = "daredevil.armv7l"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:13"
  condition:
    hash.sha256(0, filesize) == "49492a93cef8e4e9f707c2f705e1a5855c997f1b0c0177e3162b853d1d99eb1f"
}

rule MalwareBazaar_Mirai_100_9a28bc11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a28bc11748337c0f9be92b0317a7c1b68e853ad46734991aed95de5edea909d"
    family = "Mirai"
    file_name = "daredevil.mipsel"
    file_type = "elf"
    first_seen = "2026-08-17 20:06:03"
  condition:
    hash.sha256(0, filesize) == "9a28bc11748337c0f9be92b0317a7c1b68e853ad46734991aed95de5edea909d"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

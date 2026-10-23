# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-23

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 687 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 687 |
| Unique family labels | 12 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 47 |
| Mirai | 39 |
| Adware.OfferCore | 3 |
| RemcosRAT | 2 |
| Formbook | 2 |
| AokigaharaStealer | 1 |
| SalatStealer | 1 |
| VShell | 1 |
| AsyncRAT | 1 |
| Snowlight | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 47 |
| exe | 33 |
| macho | 14 |
| sh | 2 |
| js | 2 |
| msi | 1 |
| apk | 1 |

## Per-Sample Analysis

### Sample 1: `67b75dbf7e0fa300`

| Field | Value |
|---|---|
| SHA-256 | `67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64` |
| Family label | `unknown` |
| File name | `macho_67b75dbf7e0f.bin` |
| File type | `macho` |
| First seen | `2026-10-23 04:23:53` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f2f16c46540096f2a070c4a641f42b4` |
| SHA-1 | `612bc4b73ec7afc3bf487e87a110d25869ed5842` |
| SHA-256 | `67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64` |
| SHA3-384 | `60f699196ca45573a54a1e0864a7361affba904c30c06913d4a3ee62a7c3b983a51f9006ab55a5eddd166b031155118d` |
| TLSH | `T1CE85E0844FAEA157E98D41339D958F15857472C1CE48CEE9A302629BCE3939373272FB` |
| SSDEEP | `24576:H/Goqjfh6VK20BGdz5bhLr/8AJaiilvMouSVc9HaN9ZgAICaQ99mzLd86JayiLPt:HADgz5byvMoP29HhAXa4P84VK9pxAR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_67b75dbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64"
    family = "unknown"
    file_name = "macho_67b75dbf7e0f.bin"
    file_type = "macho"
    first_seen = "2026-10-23 04:23:53"
  condition:
    hash.sha256(0, filesize) == "67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64"
}
```

### Sample 2: `b71398a822927916`

| Field | Value |
|---|---|
| SHA-256 | `b71398a8229279163dd8ad582ac42dcc0e5bcc8146f461a9731965f535d6e127` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-23 04:23:19` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `517319688d268024518e8735e176f505` |
| SHA-1 | `6df07e0022184a540f0f21abdee5845ab412e715` |
| SHA-256 | `b71398a8229279163dd8ad582ac42dcc0e5bcc8146f461a9731965f535d6e127` |
| SHA3-384 | `cf649b763103fe1c6388a8b25a79dd61906c9f0caa96dbbfe2107a89745a43383d14559fc3f33e7b6f93a4fb5b958bc4` |
| TLSH | `T13514F8A6BD50EF7FC00E92305C73C6A056D23DB12EA2467E7264D75C2E3119A2F1B6E4` |
| SSDEEP | `3072:sQtg60q6eopquLpdXPV5eRdTKYIgOjayfBgGrTLqP4C3tbqCuED4Nt48ih:QFKoIQd/reRdTWgkDpMLH4Ntk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_b71398a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b71398a8229279163dd8ad582ac42dcc0e5bcc8146f461a9731965f535d6e127"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-23 04:23:19"
  condition:
    hash.sha256(0, filesize) == "b71398a8229279163dd8ad582ac42dcc0e5bcc8146f461a9731965f535d6e127"
}
```

### Sample 3: `2cd3f398007642bb`

| Field | Value |
|---|---|
| SHA-256 | `2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194` |
| Family label | `unknown` |
| File name | `lure_compact_fullchain.exe` |
| File type | `exe` |
| First seen | `2026-10-23 04:10:38` |
| Reporter | `PeterFellow` |
| Tags | `beenetprotect, exe, fake-torrent, LimeTorrents, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d8527e9ec16a153f10c4f8e32ef4866` |
| SHA-1 | `0b3b249bb8b0c35943cdc776e20f25bd3743fa20` |
| SHA-256 | `2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194` |
| SHA3-384 | `25dd1a9c414969a789a0a12728fc55af0193c73482cc3b599d1331fe506cece6915e783582ee2eec037bdcab9dde670f` |
| IMPHASH | `555aba33e471c8bf2b9fc3922635a660` |
| TLSH | `T1066533F012A760C3E55C11BDBB77416ACC61B51DBBB1ABBA83A0EE3DB980551379D20C` |
| SSDEEP | `24576:DpVcREkJpSvpMwaCHHISvEJpHHQHLP+TWJDuBvDpp04WY1N0JC/M5YZQ8+Y2:bcNpipMwauHgPe+TqD2F+4WE0JC/MeFY` |
| ICON-DHASH | `30b2b2f069f0d48a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_2cd3f398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
    family = "unknown"
    file_name = "lure_compact_fullchain.exe"
    file_type = "exe"
    first_seen = "2026-10-23 04:10:38"
  condition:
    hash.sha256(0, filesize) == "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
}
```

### Sample 4: `9933977b38adbe73`

| Field | Value |
|---|---|
| SHA-256 | `9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce` |
| Family label | `unknown` |
| File name | `stage2_stealer.exe` |
| File type | `exe` |
| First seen | `2026-10-23 04:10:25` |
| Reporter | `PeterFellow` |
| Tags | `beenetprotect, exe, fake-torrent, LimeTorrents, stage2, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0d70c2b63679d52f687da23e00c57ad` |
| SHA-1 | `8556e19e2c4f7c61746eab5f30bc6741bdb437e5` |
| SHA-256 | `9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce` |
| SHA3-384 | `954af76be243444917305c82951b0c6eb18dfba886895be1a2057d4ceeb5eddcb899b229514748aacc48b806beb47369` |
| IMPHASH | `34b951496b59aeb9913f6153c355bfba` |
| TLSH | `T195553BA175BD516EE0B6C7BBAA431845D577B408833B94EB07D5229A3F0B1E00E3F762` |
| SSDEEP | `24576:oIJkMNImSe8UplTqhGvQGdyVesxyL1SPdv:o2/SApVQTTyL1E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_9933977b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce"
    family = "unknown"
    file_name = "stage2_stealer.exe"
    file_type = "exe"
    first_seen = "2026-10-23 04:10:25"
  condition:
    hash.sha256(0, filesize) == "9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce"
}
```

### Sample 5: `1374af95ac03b089`

| Field | Value |
|---|---|
| SHA-256 | `1374af95ac03b0896be17444a0febe146378221e0994ea2991024599d593b43b` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-23 04:01:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa3b1ff21163dbb2cb3d17d8de46f239` |
| SHA-1 | `d7dbb1e98a0705b2e19d1206e257a0e2cb6344e4` |
| SHA-256 | `1374af95ac03b0896be17444a0febe146378221e0994ea2991024599d593b43b` |
| SHA3-384 | `cac317f00ee038939011d6172c1134dd4fe42d3d33f5777a8e7bf1783868c31b7b449560eb0fdd82da0f617c6dff1d59` |
| TLSH | `T192C36D03F9A254BDCD6ACD34836F9223DB38785D5262771B2BC5BB103E39A51AF0A705` |
| TELFHASH | `t1e351ac09bb9c1f579bbb5a121504681b388b20d2f9a76dc907dc9fc6347fbd13a91132` |
| SSDEEP | `3072:wuMgGeJrmcs8r0B1Y0Kd6khpxzXAFxuyn9VA:vHJY8AY0KYk9XK0SM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_1374af95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1374af95ac03b0896be17444a0febe146378221e0994ea2991024599d593b43b"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-23 04:01:42"
  condition:
    hash.sha256(0, filesize) == "1374af95ac03b0896be17444a0febe146378221e0994ea2991024599d593b43b"
}
```

### Sample 6: `5a93efa825493753`

| Field | Value |
|---|---|
| SHA-256 | `5a93efa8254937532bfbb7b583d826ec493263f12e9eaef6b22592a69416c285` |
| Family label | `unknown` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-10-23 03:59:13` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f8948aa333ef8ae1180fc5bdb92cabd` |
| SHA-1 | `a3e72a30819d4d80d60ad119973a6a884c6e0df3` |
| SHA-256 | `5a93efa8254937532bfbb7b583d826ec493263f12e9eaef6b22592a69416c285` |
| SHA3-384 | `880ea4a539c412a258f5dd46bbcc6a221cd010e72e7f4e3604c7dc5418b2886d1e9a46b3680d0e72ada01b1e1e6a95fa` |
| TLSH | `T1F5D35B408C1DED71D6CAF07C8D4D0A51A2363C781BA2C35A5D1391BEEA54A642FA3FA7` |
| SSDEEP | `3072:SuMghWSxjq0Hxkh105RdJwM/1W6dla0T817S:Nsutyr05RdJF/c4la0TA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_5a93efa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a93efa8254937532bfbb7b583d826ec493263f12e9eaef6b22592a69416c285"
    family = "unknown"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-10-23 03:59:13"
  condition:
    hash.sha256(0, filesize) == "5a93efa8254937532bfbb7b583d826ec493263f12e9eaef6b22592a69416c285"
}
```

### Sample 7: `0db860c62ce8c95a`

| Field | Value |
|---|---|
| SHA-256 | `0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8` |
| Family label | `unknown` |
| File name | `System Process.dll` |
| File type | `exe` |
| First seen | `2026-10-23 03:51:06` |
| Reporter | `PeterFellow` |
| Tags | `dll, dotnet, exe, fake-torrent, LimeTorrents, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e97bcda2e93e0f85a482d57f222d8bc` |
| SHA-1 | `7e499b9235862991e46d51db2ca960bb72cd0ad1` |
| SHA-256 | `0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8` |
| SHA3-384 | `e7e2ed87f6df16cd5f302a3bc50e74066eb1618e30df03e418570e7416c9a2728dc4d5fe6618d55704d4ba9f9d61a003` |
| TLSH | `T1DF8401236A4C85E1DA17393984F7CB461260BCFD46868D6E32ED3F1873B6B0E442F566` |
| SSDEEP | `6144:NURsmaLBNliOaFsPQsxPjt/N0mm1SqqLK4qcBcpxndjO0Ezn0x7U:wsmaL3cLsPQsHN07SZ/qmGEz0x7U` |
| ICON-DHASH | `b2b27079e8f8b286` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_0db860c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8"
    family = "unknown"
    file_name = "System Process.dll"
    file_type = "exe"
    first_seen = "2026-10-23 03:51:06"
  condition:
    hash.sha256(0, filesize) == "0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8"
}
```

### Sample 8: `9c21d2e504682723`

| Field | Value |
|---|---|
| SHA-256 | `9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8` |
| Family label | `unknown` |
| File name | `SystemProcess-bundle.exe` |
| File type | `exe` |
| First seen | `2026-10-23 03:50:52` |
| Reporter | `PeterFellow` |
| Tags | `dotnet, exe, fake-torrent, LimeTorrents, loader, padded` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec29ff7d0c0acee15b978e64c7ce2d78` |
| SHA-1 | `645cf1c691412acaa51402aa2e44f6e4135b897c` |
| SHA-256 | `9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8` |
| SHA3-384 | `93fa067a17a58c2f5033a7512c79b3bfb98c5e6a572470936b241de0b496074d25b387b60fb8c66cb496e40a849d320b` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T158888D1163E81A45E67B8678D77382A1E6B1BC535711C1CF0094FA4A2F73BC2BA36376` |
| SSDEEP | `786432:359T5nOUvDVZkv+V5OtsFltqHxbSs8cfrXp5m5r+h04Y2bmYE4w6:nT5npvB+v+z29SsFfjp5AyEY5w6` |
| ICON-DHASH | `b2b27079e8f8b286` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_9c21d2e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8"
    family = "unknown"
    file_name = "SystemProcess-bundle.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:50:52"
  condition:
    hash.sha256(0, filesize) == "9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8"
}
```

### Sample 9: `cd1b531e13ccd3b4`

| Field | Value |
|---|---|
| SHA-256 | `cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-23 03:47:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa79bf47b110b07db49457f188db2ca8` |
| SHA-1 | `9f43829de7270ec6f328cb3ebd0b65cf7a604a27` |
| SHA-256 | `cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be` |
| SHA3-384 | `7dc322847e6172a5982876c3ce12ac337a75e57f2ae4bbb62fc4267f8dfbee39a4b2e6cf8fe11194e2cdb86b02e9d6a8` |
| TLSH | `T169556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmu:OSCX9B9tGNnD+pb0qAYPWTM2wza6v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_cd1b531e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-23 03:47:51"
  condition:
    hash.sha256(0, filesize) == "cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be"
}
```

### Sample 10: `faf0bc67308eb8eb`

| Field | Value |
|---|---|
| SHA-256 | `faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-23 03:34:43` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4158a859a59fd44db2d21cc458adcd4` |
| SHA-1 | `6f4c8fd7603fefab432104968e5016cba66e9b04` |
| SHA-256 | `faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d` |
| SHA3-384 | `d64ca32166b97385cdc296e5e622951602977bb22b3f50030e434a06269cd25be4616070bc0ee65040579dbdb7b49662` |
| TLSH | `T1A6B307B6BE41DC41C4D869FAFA1E81CC3343177CD6DA7502AE029B3425DF9990E3AE91` |
| TELFHASH | `t18351e065fb981a7cb7d240e082bf502686e9319d032524968719fb2fae82dc3f43dc03` |
| SSDEEP | `3072:vqwuggVphVD5E1w28PloLsgn2QsehyjRNEw:IT3D5En8PGLsgXskAL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_faf0bc67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-23 03:34:43"
  condition:
    hash.sha256(0, filesize) == "faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d"
}
```

### Sample 11: `87f4c9758c73198c`

| Field | Value |
|---|---|
| SHA-256 | `87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1` |
| Family label | `unknown` |
| File name | `bot.mipsel` |
| File type | `elf` |
| First seen | `2026-10-23 03:34:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d201545575b396bf3fd188c5f2eeed70` |
| SHA-1 | `a80e493e530660e0653d49fdfda81b46108d4bed` |
| SHA-256 | `87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1` |
| SHA3-384 | `c737b80361668306840e499d5d6e1394ad761c69ae196c76de5c7f837629cb2523588e0f9a9ce68d35defb2838df5beb` |
| TLSH | `T12D14D64B7A04EEE7C02C4FB09ABDC71211D5A4C1A6A6A23F72B487DE7E353121E175D8` |
| SSDEEP | `3072:RQtgGdVCsuaG1GJDkf1ERo/pkDQmRrJ7ZJ++OsxrYIB/t9EAY:LGHCJa05f1co/pKRRr1ZJ9Osxrx7EA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_87f4c975
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1"
    family = "unknown"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-10-23 03:34:41"
  condition:
    hash.sha256(0, filesize) == "87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1"
}
```

### Sample 12: `82706984f1b92070`

| Field | Value |
|---|---|
| SHA-256 | `82706984f1b92070cf14109888f79d754aedbcff93f4322c9558d818da7f8a5a` |
| Family label | `unknown` |
| File name | `launcher.exe` |
| File type | `exe` |
| First seen | `2026-10-23 03:33:31` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7067453973511cde4cfa5c2cf86b4449` |
| SHA-1 | `5dbefd7bf57854c9bd15d887d71fe1a614626c5f` |
| SHA-256 | `82706984f1b92070cf14109888f79d754aedbcff93f4322c9558d818da7f8a5a` |
| SHA3-384 | `154c8e406c968f532ca97f8bb8c3491e149f63eabe5d7eb32e369c19ee11bd05b4e12802e5358d8d17ab664030ab214a` |
| IMPHASH | `c707f9a1770c34ae73906a3dbaa41dd6` |
| TLSH | `T1985723E2ADE5A3E4D3D34B44A2C7538A53D171AFC6CB8A1D22C65C032530D578A4AE7F` |
| SSDEEP | `393216:zhY8JIgTc5DMkNXS4hMA9/haxy7X7gT2oqIKZnFGbADatZYLeEn8Jp:q8JIgw55NXSyLHbEH9EnIbAD0ieE8Jp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_82706984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82706984f1b92070cf14109888f79d754aedbcff93f4322c9558d818da7f8a5a"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:33:31"
  condition:
    hash.sha256(0, filesize) == "82706984f1b92070cf14109888f79d754aedbcff93f4322c9558d818da7f8a5a"
}
```

### Sample 13: `64f8a2e463e90c05`

| Field | Value |
|---|---|
| SHA-256 | `64f8a2e463e90c05bfef709f4747224b39d0b69461a6fe646f1da9d4f509df9e` |
| Family label | `AokigaharaStealer` |
| File name | `glaicer.exe` |
| File type | `exe` |
| First seen | `2026-10-23 03:33:18` |
| Reporter | `AmadeyHunter` |
| Tags | `AokigaharaStealer, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a99e44e9284d40657818571464ea5b0` |
| SHA-1 | `6af54884b79e3677a956eb4e21b4a98319b6b895` |
| SHA-256 | `64f8a2e463e90c05bfef709f4747224b39d0b69461a6fe646f1da9d4f509df9e` |
| SHA3-384 | `bb69b381191609377fa61c2bb0332444232ad79d1d9e5eaab0e3ed383b0238488785d28aa63573f2c18f0b0628c11877` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T120E55B17BF9189B9C096E730CAB65552B6B5BC4C073233D72EA0B6342F723C45AB6B44` |
| SSDEEP | `49152:fB62IcqjPewhKXVB1sCVG06+KrsHQfsIlqlfe0yj:fkGlrKYHQUNxeB` |

#### Technical Assessment

- The sample is tracked as `AokigaharaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AokigaharaStealer_013_64f8a2e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64f8a2e463e90c05bfef709f4747224b39d0b69461a6fe646f1da9d4f509df9e"
    family = "AokigaharaStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:33:18"
  condition:
    hash.sha256(0, filesize) == "64f8a2e463e90c05bfef709f4747224b39d0b69461a6fe646f1da9d4f509df9e"
}
```

### Sample 14: `ba419690cd762058`

| Field | Value |
|---|---|
| SHA-256 | `ba419690cd762058a0037d11619c8a1fe5b6690c2f359addc91375c0712ed366` |
| Family label | `unknown` |
| File name | `ba419690cd762058.bin` |
| File type | `exe` |
| First seen | `2026-10-23 03:25:14` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20a403d93b109eb11ffb701439f748d6` |
| SHA-1 | `d0a9d6d4186843d9d780b32ddfbd70edb1f56a95` |
| SHA-256 | `ba419690cd762058a0037d11619c8a1fe5b6690c2f359addc91375c0712ed366` |
| SHA3-384 | `a01ebe3104d189d410553126995e7ce08b2a215e365185dd81d0ccdb6ca310184e00ca083b459a8f58182f3b818be082` |
| IMPHASH | `083d16235804af9682a658bb8ce08be4` |
| TLSH | `T120F63301BC50C070C99A15B05A75AF718A7DA9305F91A8FFB3C42F3B8FA15C16B39A5B` |
| SSDEEP | `393216:pEZ7lcON1sgnBWPON1sgnBWrcZ7lcON1sgnBWrcZ7lcON1sBc:WZ7lHPnBWCPnBWrcZ7lHPnBWrcZ7lHyc` |
| ICON-DHASH | `8a98c8e2e3e3e7ea` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_ba419690
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba419690cd762058a0037d11619c8a1fe5b6690c2f359addc91375c0712ed366"
    family = "unknown"
    file_name = "ba419690cd762058.bin"
    file_type = "exe"
    first_seen = "2026-10-23 03:25:14"
  condition:
    hash.sha256(0, filesize) == "ba419690cd762058a0037d11619c8a1fe5b6690c2f359addc91375c0712ed366"
}
```

### Sample 15: `9ba0ffb9e9cc6c00`

| Field | Value |
|---|---|
| SHA-256 | `9ba0ffb9e9cc6c0001239d647f5e5a5a7f22d162798c8312fc65e31cf55ce7ca` |
| Family label | `Adware.OfferCore` |
| File name | `9ba0ffb9e9cc6c00.bin` |
| File type | `exe` |
| First seen | `2026-10-23 03:25:01` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecb20bf55b95b24664cb83d9a15b9c97` |
| SHA-1 | `2f96166fb355b92e4358bee0dd191b46501b1a70` |
| SHA-256 | `9ba0ffb9e9cc6c0001239d647f5e5a5a7f22d162798c8312fc65e31cf55ce7ca` |
| SHA3-384 | `2560e918d8bf766fc39899fcb106e21dde0bc931637085ae235b14e75a630621a6eca6e06ea6ab65a15f588f52273c6c` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T14DA5D03FB28B653EE06E5A367A72E210583B7A6165138C5696F4C88CCF254701E3F787` |
| SSDEEP | `24576:lXNrSLScusMmOvjjhzvLVAOgLgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXc64a:muI2hREHcTeynRkfg7ve+AhrWzOUq` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_015_9ba0ffb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ba0ffb9e9cc6c0001239d647f5e5a5a7f22d162798c8312fc65e31cf55ce7ca"
    family = "Adware.OfferCore"
    file_name = "9ba0ffb9e9cc6c00.bin"
    file_type = "exe"
    first_seen = "2026-10-23 03:25:01"
  condition:
    hash.sha256(0, filesize) == "9ba0ffb9e9cc6c0001239d647f5e5a5a7f22d162798c8312fc65e31cf55ce7ca"
}
```

### Sample 16: `677b6c7d9a094c40`

| Field | Value |
|---|---|
| SHA-256 | `677b6c7d9a094c40c57ec2c77a07bbb9f992eb9850c24c6f4fc037152aeb8f31` |
| Family label | `SalatStealer` |
| File name | `Xeno-v1.3.60.exe` |
| File type | `exe` |
| First seen | `2026-10-23 03:22:16` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Salat, SalatStealer, Stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb099db86f0fe8e7f8109d911e96a9e8` |
| SHA-1 | `2e5dcd4166092a097acb5053e35c1c2e9086f0f2` |
| SHA-256 | `677b6c7d9a094c40c57ec2c77a07bbb9f992eb9850c24c6f4fc037152aeb8f31` |
| SHA3-384 | `bf41b2dbf7f7e4497206ba3ebd57320cd211a576a5463dba03153cc1a3f93641caf54d0ed0263a28d72da786d4136e56` |
| IMPHASH | `e715424ebef62edcf8229c713419932e` |
| TLSH | `T15A183350DCC931FDC46DE0F4CD61B206A0B5F80F8B54AB23216D699E7E775A14EAAB03` |
| SSDEEP | `1572864:jpfSYwFAuCRYi5lywxCTAuuppxPHxqRkrk1q3xanc2Gn4b4O:jpzwWFly3TPuHBURko1OanbGnk` |
| ICON-DHASH | `00e0c0d10c00a002` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_016_677b6c7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "677b6c7d9a094c40c57ec2c77a07bbb9f992eb9850c24c6f4fc037152aeb8f31"
    family = "SalatStealer"
    file_name = "Xeno-v1.3.60.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:22:16"
  condition:
    hash.sha256(0, filesize) == "677b6c7d9a094c40c57ec2c77a07bbb9f992eb9850c24c6f4fc037152aeb8f31"
}
```

### Sample 17: `0c0940c543d28b13`

| Field | Value |
|---|---|
| SHA-256 | `0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-23 03:19:53` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ad5e5ae162f001e82ad4732ddb84912` |
| SHA-1 | `21afec2976e42c73fd147a9dd465790251b69341` |
| SHA-256 | `0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902` |
| SHA3-384 | `06aa137f2f480e696138df927c4c0c2d1e1f034859b085d40ffe6541f971293009e052ffe16717cd87208c67616e727a` |
| IMPHASH | `9b69591fa5fe6c02d6be22e4d6d26c83` |
| TLSH | `T15F357AB1B7871FB4FC2D8731B64D7504CD622433FAD118AA42AC168ACE31E8DAAF5715` |
| SSDEEP | `24576:0Pv2vo2ewppqKm3kowPYKNzOz6Iez07E9ALAOW6:0Pew2nqGMWMEG7` |
| ICON-DHASH | `48349272b1115826` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_0c0940c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:19:53"
  condition:
    hash.sha256(0, filesize) == "0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902"
}
```

### Sample 18: `d63bcebff095babf`

| Field | Value |
|---|---|
| SHA-256 | `d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6` |
| Family label | `Mirai` |
| File name | `d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6` |
| File type | `elf` |
| First seen | `2026-10-23 03:17:24` |
| Reporter | `thinngo` |
| Tags | `elf, honeypot, Mirai, ppc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09b36e7f560b8a3c7cd9bb64c350ecb5` |
| SHA-1 | `ccce7b9cfaa465afb3941db5ea76a0bd7ce4862c` |
| SHA-256 | `d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6` |
| SHA3-384 | `0f62a4d9a5b4d4c045842a6eabe95654ae0d0f9a24a5f0e5e8c1d4c10ce80d264cf07b050646f6343b51ffbab6ddbe95` |
| TLSH | `T182F46C42FF1C4522C9570EF0193F43D5F7217A4341F5A22A370E5B672622E3AAAD778A` |
| TELFHASH | `t11b017b314721aa125ba1de88a8eea763612cc65b8b0dfd77c831844c30050fdd937c4f` |
| SSDEEP | `12288:6WVizJGDIzdbKcOyJVjBeyyjkjRefWyfK/jPjwxkNQepdrCC2PTObs+QICWZrn:6HMDIzdbKcOiefK2Wr3UuBmsNXZr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_d63bcebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6"
    family = "Mirai"
    file_name = "d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:24"
  condition:
    hash.sha256(0, filesize) == "d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6"
}
```

### Sample 19: `d41653b6ed41c562`

| Field | Value |
|---|---|
| SHA-256 | `d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa` |
| Family label | `Mirai` |
| File name | `d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa` |
| File type | `elf` |
| First seen | `2026-10-23 03:17:20` |
| Reporter | `thinngo` |
| Tags | `arm, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ad2edade7992a9360d2b653d3b8d737` |
| SHA-1 | `e4829e3e0254d187345a568add0e009684de4c59` |
| SHA-256 | `d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa` |
| SHA3-384 | `90d44e1ddf5d735810714c9fa2e796b781a05fd7dc917e9622c930ac49dee6d4242068684cd4817a99c76ba38b2fc7c3` |
| TLSH | `T1C8D44946F8808F62C5D12576F75F8268732347B9C3EBB20699184B343BD796F4B3A681` |
| TELFHASH | `t15b017b314720aa125b61de88a8eea723612cc65b8b0dfd77c431844c30050fdd937c4f` |
| SSDEEP | `12288:SYFPw2JzjpzmwxJz/EkGzAwhG33ktuMKkAt/68prPxB0VbV+ETG8r:SYjzjpz8kQxh4ktGvubV/TG8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_d41653b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa"
    family = "Mirai"
    file_name = "d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:20"
  condition:
    hash.sha256(0, filesize) == "d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa"
}
```

### Sample 20: `b6aec7e19e75aa2c`

| Field | Value |
|---|---|
| SHA-256 | `b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e` |
| Family label | `Mirai` |
| File name | `b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e` |
| File type | `elf` |
| First seen | `2026-10-23 03:17:16` |
| Reporter | `thinngo` |
| Tags | `elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6aeaf8d1ff832e32817185279e9c06c` |
| SHA-1 | `9e5dde52fe1a8f6bf6e7c1efb7c5abb0b05499b6` |
| SHA-256 | `b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e` |
| SHA3-384 | `5798b6016187a1da2171d8e77ad5b2fc66c90ae7ee9b8b8ea035be04a7133e9ba73a46e8199708de56d157aa6e3d7ac5` |
| TLSH | `T13CF46C623B11DFA5D354C67005F3C7654AE524A21BE24086B27CC7287A52A2E6D2FFFC` |
| TELFHASH | `t15b017b314720aa125b61de88a8eea723612cc65b8b0dfd77c431844c30050fdd937c4f` |
| SSDEEP | `12288:9v94ZviWW9Y4wQ5ywsP2dMevsEqdD2sp4U8pNJ0zlB6brx/7oSD:t94ZviWWmFQMrPQsEiD2sp2igl7oG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_b6aec7e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e"
    family = "Mirai"
    file_name = "b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:16"
  condition:
    hash.sha256(0, filesize) == "b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e"
}
```

### Sample 21: `5f4b862ec05beb9d`

| Field | Value |
|---|---|
| SHA-256 | `5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0` |
| Family label | `Mirai` |
| File name | `5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0` |
| File type | `elf` |
| First seen | `2026-10-23 03:17:12` |
| Reporter | `thinngo` |
| Tags | `elf, honeypot, Mirai, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43bd2d70cc6037ade6b3f91e83d992c9` |
| SHA-1 | `c08aeec075bbc21b3195c415967be08e28978a3e` |
| SHA-256 | `5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0` |
| SHA3-384 | `26266ac52775239324b139c46b9fc5d39979bae6cbaa40800735d0e7cba430ece060c9b19ee61cc0b9d15be09b922868` |
| TLSH | `T131258D46F2B334FDC067C030879BD762A936F46541222E7B21C4DA392E96E741B19FB6` |
| TELFHASH | `t1b20147314720a9125a61de88a8eea763622cc65b8b0df977d431844c20050fde937c4f` |
| SSDEEP | `24576:AsqEyhjY4c/6501Ps6g5qQe7K4Ikepe6L:1cSPs6iqQuKXD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_5f4b862e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0"
    family = "Mirai"
    file_name = "5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:12"
  condition:
    hash.sha256(0, filesize) == "5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0"
}
```

### Sample 22: `4b49891a0209264e`

| Field | Value |
|---|---|
| SHA-256 | `4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6` |
| Family label | `Mirai` |
| File name | `4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6` |
| File type | `elf` |
| First seen | `2026-10-23 03:17:09` |
| Reporter | `thinngo` |
| Tags | `elf, honeypot, Mirai, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `18f3b7b87f5d1244c2beeef69e9b48c8` |
| SHA-1 | `c9c62449005740177125cc82c56e7d1705b650a8` |
| SHA-256 | `4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6` |
| SHA3-384 | `bcbe16b91118ba97cb85cb94f78371a48d8bfc4a191575e3cce5ba6ea62181223cf170d2e24551f8c3107df15c6a223c` |
| TLSH | `T183058D9DE783D6F2F25341B1124ECBF20534A11AF463F6F2EB442A5678B27522E1632D` |
| TELFHASH | `t1da0168314721aa125a51de84aceea723652dc65b8b5dfd73d831844c30080fdda3bc8f` |
| SSDEEP | `24576:8tSohwOgrhubhB3UCZyDV9Wx6uD5YPbzMp:ahwvrhubhBj8zD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_4b49891a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6"
    family = "Mirai"
    file_name = "4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:09"
  condition:
    hash.sha256(0, filesize) == "4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6"
}
```

### Sample 23: `4feed588acc1396e`

| Field | Value |
|---|---|
| SHA-256 | `4feed588acc1396e2deeb1fc04f145cfca464ba7617dc3c1c9fe7dcc545d2d1d` |
| Family label | `VShell` |
| File name | `.sysd` |
| File type | `elf` |
| First seen | `2026-10-23 02:41:03` |
| Reporter | `boredchilada2` |
| Tags | `elf, Golang, Linux, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1576867492a38c99beac3c34fad6b8ea` |
| SHA-1 | `61d8f255e9a4cdf1c9df30e4b648cd0bd86b614c` |
| SHA-256 | `4feed588acc1396e2deeb1fc04f145cfca464ba7617dc3c1c9fe7dcc545d2d1d` |
| SHA3-384 | `988872198751bb6a933adf7d9c36fd84ed5cf0866b99a1a585f96ef21f1536f84465e6c912b73828cf5603dbfd883a7d` |
| TLSH | `T111860847F89181E9C0EED134C6669262BA707C895B3023E73B50F7B42B36BD46E7A354` |
| TELFHASH | `t1f8226b7149bc78b4b6aada10b352b5b8593719a172f934b41523e890ffc5f806ce2837` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Qtps6v6SMU1frb/ThvO90d7HjmAFd4A64nsfJkE71ZXJa7HSI8Sr3hgoHWcn4bMB:oM4NC1n4H6MNLL0wNKBjEBre15ZO` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_023_4feed588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4feed588acc1396e2deeb1fc04f145cfca464ba7617dc3c1c9fe7dcc545d2d1d"
    family = "VShell"
    file_name = ".sysd"
    file_type = "elf"
    first_seen = "2026-10-23 02:41:03"
  condition:
    hash.sha256(0, filesize) == "4feed588acc1396e2deeb1fc04f145cfca464ba7617dc3c1c9fe7dcc545d2d1d"
}
```

### Sample 24: `ce23335488686504`

| Field | Value |
|---|---|
| SHA-256 | `ce23335488686504739da1a00270b71a444ab4165b341fda116ff08d705bf914` |
| Family label | `Mirai` |
| File name | `linux_arm` |
| File type | `elf` |
| First seen | `2026-10-23 02:40:53` |
| Reporter | `boredchilada2` |
| Tags | `elf, Linux, Mirai, SNOWLIGHT, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64fb05d327801ce1c300cd9bdd55d905` |
| SHA-1 | `3bbea7e7e20289830118cfbedaec33f342ba95a4` |
| SHA-256 | `ce23335488686504739da1a00270b71a444ab4165b341fda116ff08d705bf914` |
| SHA3-384 | `ad2b5a828a8a350d4fc150c6ee7ce04d04ef553355f359354989c7d24b2b42c2f7e17e2f3c84a6ada75de50ea50f5378` |
| TLSH | `T13BF13356BAEBCD73CCAD233907678714337588D2AB42AB13611C08752D835ECAD76BE1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8Dt8WC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7k4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_ce233354
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce23335488686504739da1a00270b71a444ab4165b341fda116ff08d705bf914"
    family = "Mirai"
    file_name = "linux_arm"
    file_type = "elf"
    first_seen = "2026-10-23 02:40:53"
  condition:
    hash.sha256(0, filesize) == "ce23335488686504739da1a00270b71a444ab4165b341fda116ff08d705bf914"
}
```

### Sample 25: `407fb53e62d4ed0e`

| Field | Value |
|---|---|
| SHA-256 | `407fb53e62d4ed0e2d043b60f0916ff77ef2b8fba3dc0f6594218a4877edb5aa` |
| Family label | `Mirai` |
| File name | `linux_arm64` |
| File type | `elf` |
| First seen | `2026-10-23 02:40:45` |
| Reporter | `boredchilada2` |
| Tags | `elf, Linux, Mirai, SNOWLIGHT, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a970a7d046d188d8d529aec9d1300eb` |
| SHA-1 | `35d877c8c16051db743595e971b76997fecf8ead` |
| SHA-256 | `407fb53e62d4ed0e2d043b60f0916ff77ef2b8fba3dc0f6594218a4877edb5aa` |
| SHA3-384 | `7c0b9f15451968d965b51d3e622ea51bd88e00ee08b6a582ee1d7fdd33b0fabbeac3e51fddcf8bbde7735c6a6eefaa86` |
| TLSH | `T1B5221E27F3D4DDFFC8AA5335499303713223C83ADB828383691C56593F9A29D1D65B44` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOGx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeY+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_407fb53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "407fb53e62d4ed0e2d043b60f0916ff77ef2b8fba3dc0f6594218a4877edb5aa"
    family = "Mirai"
    file_name = "linux_arm64"
    file_type = "elf"
    first_seen = "2026-10-23 02:40:45"
  condition:
    hash.sha256(0, filesize) == "407fb53e62d4ed0e2d043b60f0916ff77ef2b8fba3dc0f6594218a4877edb5aa"
}
```

### Sample 26: `5fbd46e376797b75`

| Field | Value |
|---|---|
| SHA-256 | `5fbd46e376797b75f5455775d0e62dcfdb30e81375c45fb20e0c31593a37da1b` |
| Family label | `Mirai` |
| File name | `linux_i386` |
| File type | `elf` |
| First seen | `2026-10-23 02:40:36` |
| Reporter | `boredchilada2` |
| Tags | `elf, Linux, Mirai, SNOWLIGHT, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e1f834dbc82a803c93915f229b6110e` |
| SHA-1 | `c7a806a3740ef53f426aee8db77f7e680ba95f82` |
| SHA-256 | `5fbd46e376797b75f5455775d0e62dcfdb30e81375c45fb20e0c31593a37da1b` |
| SHA3-384 | `8322a16d7cc47d6745ffe9d9f8ebd71a3e5416e302c9306f452d92c7806ffd3c18609e109bc3d4c183c57bbc945c1a19` |
| TLSH | `T1D9E16207E2D5CE72D8CD133846931749213AC86EAB83AF03650C1999EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccF+146Iwz7cSym4S2ofahbpZiQ:fsue7cJJjFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_5fbd46e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fbd46e376797b75f5455775d0e62dcfdb30e81375c45fb20e0c31593a37da1b"
    family = "Mirai"
    file_name = "linux_i386"
    file_type = "elf"
    first_seen = "2026-10-23 02:40:36"
  condition:
    hash.sha256(0, filesize) == "5fbd46e376797b75f5455775d0e62dcfdb30e81375c45fb20e0c31593a37da1b"
}
```

### Sample 27: `187c25e0604530f5`

| Field | Value |
|---|---|
| SHA-256 | `187c25e0604530f5f6a8ee79b0798f89ef0a132dbe69b55b6afb1f2583f84b2b` |
| Family label | `Mirai` |
| File name | `linux_amd64` |
| File type | `elf` |
| First seen | `2026-10-23 02:39:59` |
| Reporter | `boredchilada2` |
| Tags | `elf, Linux, Mirai, SNOWLIGHT, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45e080995eb2fe8ed67743035c4adc41` |
| SHA-1 | `b16572a7859e54f89434d34b69eb7584ee10ac51` |
| SHA-256 | `187c25e0604530f5f6a8ee79b0798f89ef0a132dbe69b55b6afb1f2583f84b2b` |
| SHA3-384 | `d269bba46f99dda17a98cb262204a2ca1ed6981ceca79c3a3ebfb83d7767e25300c486646693d39350c1497342220f41` |
| TLSH | `T19D126147A2D1CE7FC8E813384467122472BBD47ADFA29713050C64B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf58lTTej6TNJ9VcNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WToTTfTpV0dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_187c25e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "187c25e0604530f5f6a8ee79b0798f89ef0a132dbe69b55b6afb1f2583f84b2b"
    family = "Mirai"
    file_name = "linux_amd64"
    file_type = "elf"
    first_seen = "2026-10-23 02:39:59"
  condition:
    hash.sha256(0, filesize) == "187c25e0604530f5f6a8ee79b0798f89ef0a132dbe69b55b6afb1f2583f84b2b"
}
```

### Sample 28: `5c54ede33db8a4af`

| Field | Value |
|---|---|
| SHA-256 | `5c54ede33db8a4af5c7574eb1cde60444ff3f6c3c742222139abaea3dc6bd6b3` |
| Family label | `unknown` |
| File name | `linux.sh` |
| File type | `sh` |
| First seen | `2026-10-23 02:39:51` |
| Reporter | `boredchilada2` |
| Tags | `Linux, sh, SNOWLIGHT, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fcdf97b273962fee1485e80923bb090` |
| SHA-1 | `d3a3550c53189e42a3a818a4c9e526a141f2b93e` |
| SHA-256 | `5c54ede33db8a4af5c7574eb1cde60444ff3f6c3c742222139abaea3dc6bd6b3` |
| SHA3-384 | `7373a1dfddfbf0927fd8f180c00a14425fcf7f39515028162bbf988ee407ba157d598775ef94d1933a74cb3acef476b7` |
| TLSH | `T1E231D03661D8FF7DB5049E6A19A5914858C260524EABF7C9F2D03612DD0992B71C0E35` |
| SSDEEP | `48:Y39LZ0Q+q2sHrCz7k/i76h7657RUa7QNZGyG:Y3FpCz7kK76h7657ma7QNZi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_5c54ede3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c54ede33db8a4af5c7574eb1cde60444ff3f6c3c742222139abaea3dc6bd6b3"
    family = "unknown"
    file_name = "linux.sh"
    file_type = "sh"
    first_seen = "2026-10-23 02:39:51"
  condition:
    hash.sha256(0, filesize) == "5c54ede33db8a4af5c7574eb1cde60444ff3f6c3c742222139abaea3dc6bd6b3"
}
```

### Sample 29: `8ce1805f5b1ca8c4`

| Field | Value |
|---|---|
| SHA-256 | `8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606` |
| Family label | `unknown` |
| File name | `vq-sp-lure-trimmed.exe` |
| File type | `exe` |
| First seen | `2026-10-23 02:31:14` |
| Reporter | `anonymous` |
| Tags | `exe, fake-torrent, iso, LimeTorrents, padded` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50676b460438904645e30674d438f6af` |
| SHA-1 | `9c519ed1980d4dc1e55d7b979cf5da0fa2a05358` |
| SHA-256 | `8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606` |
| SHA3-384 | `23e0a7b5c18dda5fe5dd314b7de785bf9640f268908791c6569186ffac593c0bed7f0398ec85d65645f4bedff3d45437` |
| IMPHASH | `555aba33e471c8bf2b9fc3922635a660` |
| TLSH | `T14AE3CF1350C5A0EBD52DB17DE63232A3C5743F1A8151863F92B2AE967C93201EFF925E` |
| SSDEEP | `3072:gDD1ieyNKDtaHYaEM1Y2k9Hc3/nl6LAHkzI1UfgEA6IIyRv:cD1iFKD4Ya7k96kAD` |
| ICON-DHASH | `30b2b2f069f0d48a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_8ce1805f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606"
    family = "unknown"
    file_name = "vq-sp-lure-trimmed.exe"
    file_type = "exe"
    first_seen = "2026-10-23 02:31:14"
  condition:
    hash.sha256(0, filesize) == "8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606"
}
```

### Sample 30: `4e11133df35ffece`

| Field | Value |
|---|---|
| SHA-256 | `4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e` |
| Family label | `RemcosRAT` |
| File name | `pesananpembeliankuartalterakhirtahun2026.JS.js` |
| File type | `js` |
| First seen | `2026-10-23 02:25:10` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4dd34720093c65cccf2ba1195bb518ca` |
| SHA-1 | `818c7d12585099dc01bbcfebc4d6987dce02763c` |
| SHA-256 | `4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e` |
| SHA3-384 | `da13cc74d77e6ece6fa38dd43239a43d3c5fecf54263430fd3fdfd25a546e6763111dab05539dd0598dde56a7faef02e` |
| TLSH | `T123564901DDC39662715FFB9B9B13C9634669002B2E014739ABF98BCB663B9073DDC189` |
| SSDEEP | `98304:yK2jZpZ6VE86P9xDsic8oaq75tbEPlxylrFtKb0uDfci3wRMsH0+z9m7weCYCGMo:PGN86l9Fc8ov75uvEi3weCdm7wnAMJMN` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_030_4e11133d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e"
    family = "RemcosRAT"
    file_name = "pesananpembeliankuartalterakhirtahun2026.JS.js"
    file_type = "js"
    first_seen = "2026-10-23 02:25:10"
  condition:
    hash.sha256(0, filesize) == "4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e"
}
```

### Sample 31: `c2d65bddfded3873`

| Field | Value |
|---|---|
| SHA-256 | `c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94` |
| Family label | `unknown` |
| File name | `c2d65bddfded3873.bin` |
| File type | `exe` |
| First seen | `2026-10-23 02:24:16` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73ac4851f2b9aa7fb67377f6eda10efb` |
| SHA-1 | `bec86f6793594b4ff003458e45db3ea2da3a7f5b` |
| SHA-256 | `c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94` |
| SHA3-384 | `4a73008f913dedc7c11a78a35ef2a7b2fba28679407ad781dcf08e85b36e3171c2e8b1d20ed14f130fd2b68b7e510340` |
| IMPHASH | `d436939e4edad1b901cb7ffa9ab98595` |
| TLSH | `T19A956C03F69580FCC55EC07887479632EA22BC8D092576EB2BD09B653E76F909F0DB19` |
| SSDEEP | `49152:6t1+B8HJUk5j3rwsWPVO2xiNWAXIU6isA60L:6bCI7MBxUC+sO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_c2d65bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94"
    family = "unknown"
    file_name = "c2d65bddfded3873.bin"
    file_type = "exe"
    first_seen = "2026-10-23 02:24:16"
  condition:
    hash.sha256(0, filesize) == "c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94"
}
```

### Sample 32: `5f7ca145520351f8`

| Field | Value |
|---|---|
| SHA-256 | `5f7ca145520351f85350d8a68b9188825cf0f9ef3868bbf32ec7fe703ca049ec` |
| Family label | `unknown` |
| File name | `5f7ca145520351f8.bin` |
| File type | `msi` |
| First seen | `2026-10-23 02:24:08` |
| Reporter | `Tuxxin` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63c26f83ee36715685c0dcaf57794283` |
| SHA-1 | `565ae581c7f208074d0d4f2b95db218a8c6c7edb` |
| SHA-256 | `5f7ca145520351f85350d8a68b9188825cf0f9ef3868bbf32ec7fe703ca049ec` |
| SHA3-384 | `f1dea578bd6c3a701cacb5ec241c2e6d234a6c9c3b1876cdd007d1615feb948b4525b332479a0ddfc4a938ee7b61dde7` |
| TLSH | `T1F6D34F2344F6C681EBACC2F0897DDAA4176A0EDC453D1A793388B1E42D371BD719626F` |
| SSDEEP | `384:W173OItkVj20u8aVuIfilQJTtWl38vN3IdXgtz5JK0truVvpJerV0RzdBJW7xkK3:wPtAi0d5pr3i36qmC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_5f7ca145
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f7ca145520351f85350d8a68b9188825cf0f9ef3868bbf32ec7fe703ca049ec"
    family = "unknown"
    file_name = "5f7ca145520351f8.bin"
    file_type = "msi"
    first_seen = "2026-10-23 02:24:08"
  condition:
    hash.sha256(0, filesize) == "5f7ca145520351f85350d8a68b9188825cf0f9ef3868bbf32ec7fe703ca049ec"
}
```

### Sample 33: `21af7d776011760b`

| Field | Value |
|---|---|
| SHA-256 | `21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43` |
| Family label | `Formbook` |
| File name | `21af7d776011760b.bin` |
| File type | `exe` |
| First seen | `2026-10-23 02:24:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `340655b9e4fb2776cb19e656d4ebc7a6` |
| SHA-1 | `343dfed03d4e1443f08204c2928f5e3c124c0341` |
| SHA-256 | `21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43` |
| SHA3-384 | `2d742ad0a030a5baa84411eb4a03291fdd290e17e2d4dc642874a96e2df815d12340882b4be454f501dd637fb98ddf41` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14FF402642398EB02E5B627F81471E3345BB6AE4EF631D31A8ED9ADDF3815B002C54793` |
| SSDEEP | `12288:xyCq5ua5RWJKfaEGMnxSEpVGfqgK7iuZpdDliA6cOOn89eIhDKDVSQfMxFpCevDG:xyT5YVwsMmuZpniHcdnfIVKDVSOKpC` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_033_21af7d77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43"
    family = "Formbook"
    file_name = "21af7d776011760b.bin"
    file_type = "exe"
    first_seen = "2026-10-23 02:24:00"
  condition:
    hash.sha256(0, filesize) == "21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43"
}
```

### Sample 34: `1a82e6aebae1050a`

| Field | Value |
|---|---|
| SHA-256 | `1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9` |
| Family label | `AsyncRAT` |
| File name | `1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9.exe` |
| File type | `exe` |
| First seen | `2026-10-23 01:47:23` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbf711d4a44e930c625f601007056d3f` |
| SHA-1 | `195f729943b7f5e4ce926b0b6889b3dcfb07ee09` |
| SHA-256 | `1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9` |
| SHA3-384 | `6b37fa14394b572bfd4546b4277bd2035f50d54e31cfac5091f7393347ac98e76b939567e1deb1d5150fa58612faebe4` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T137232C003BD8812BF2BE5F7898F26145467AF6633603E54E2CC451DB5713BC69A42AFE` |
| SSDEEP | `768:huwpFTAY3IQWUe9jqmo2qLeO5QfCBQPiNjPISzjbwgX3iVmjsVuIBDZCx:huwpFTA4/2tO5c/iKS3b3XSVrVuudCx` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_034_1a82e6ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9"
    family = "AsyncRAT"
    file_name = "1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9.exe"
    file_type = "exe"
    first_seen = "2026-10-23 01:47:23"
  condition:
    hash.sha256(0, filesize) == "1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9"
}
```

### Sample 35: `ba9810872fd8b1de`

| Field | Value |
|---|---|
| SHA-256 | `ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1` |
| Family label | `RemcosRAT` |
| File name | `20261023ISI.pdf.js` |
| File type | `js` |
| First seen | `2026-10-23 01:35:08` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13f284072b46281b93043e351025e4a5` |
| SHA-1 | `56e940390be4e6990abf2ac64e3ae2d8451bae87` |
| SHA-256 | `ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1` |
| SHA3-384 | `2541b25e98824c4d3e31b75668d74c2380e9c44768096e382489b49f8046243a100e7fe43292e5df4d60ad2940200786` |
| TLSH | `T193063470EAB3949D85D8C35EC66281D09A5E90525A1CAC39E46F722D18F3FCBC8452FF` |
| SSDEEP | `24576:6qzYfkKqJJYuZFxtOmyV8taQApecDJWR8sMYVwZClsZszuYnRZuCmMhkSI9Hx4iF:M` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_035_ba981087
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1"
    family = "RemcosRAT"
    file_name = "20261023ISI.pdf.js"
    file_type = "js"
    first_seen = "2026-10-23 01:35:08"
  condition:
    hash.sha256(0, filesize) == "ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1"
}
```

### Sample 36: `840754d6bf7c2f74`

| Field | Value |
|---|---|
| SHA-256 | `840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec` |
| Family label | `Mirai` |
| File name | `840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec` |
| File type | `elf` |
| First seen | `2026-10-23 01:33:02` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f82dff210adfb0628195904831ff1fb6` |
| SHA-1 | `ecb20cb26820ecee8db03996bc3d68d29ab686ee` |
| SHA-256 | `840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec` |
| SHA3-384 | `e271ac9fb82d994a55d28cdd0ca4eed4fb9e180dbc7c6125a3407314ae401e74b339b5d5bb1146853344be92a2bad25f` |
| TLSH | `T1CD357D237721CF69E355D67008F3CA514AE520A217E2509AB26CC7287E6072D2D6FFF9` |
| TELFHASH | `t19911cb344b60552a4781cd00dcde6363212cca6a9b0dfeb7e9704a0c22010fed93bc8f` |
| SSDEEP | `24576:Xu6iTb5FwgpJ3NpETjSLyA8C4zWGb1EyMOkR3UPwAxDi+a/SRix6qo:diH5FwgpJ3NpECGAF4zT1EwIAxa/SRii` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_840754d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec"
    family = "Mirai"
    file_name = "840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec"
    file_type = "elf"
    first_seen = "2026-10-23 01:33:02"
  condition:
    hash.sha256(0, filesize) == "840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec"
}
```

### Sample 37: `cd3553474afba344`

| Field | Value |
|---|---|
| SHA-256 | `cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f` |
| Family label | `Mirai` |
| File name | `cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f` |
| File type | `elf` |
| First seen | `2026-10-23 01:32:59` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c15d6376b32cc8dd68079dc9fd244f6d` |
| SHA-1 | `49d31918293370e2fd8d8cc69eaa55e1b1d04226` |
| SHA-256 | `cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f` |
| SHA3-384 | `171ce1180d7d1b3bde92d5720bff1f0c736a7d8d5a30470890d6c89d571804cb3964582f62e9d96cc98d83406fd5276f` |
| TLSH | `T1C5153B56F880DF62C5D1257AFA5F82A8331347B5C3EB720689199B343BD782F4B3A641` |
| TELFHASH | `t19911cb344b60552a4781cd00dcde6363212cca6a9b0dfeb7e9704a0c22010fed93bc8f` |
| SSDEEP | `24576:rLwDl2/SYwISmHcWPzrISuSCraBh91jTe:OYwIdMJaBh9s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_cd355347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f"
    family = "Mirai"
    file_name = "cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f"
    file_type = "elf"
    first_seen = "2026-10-23 01:32:59"
  condition:
    hash.sha256(0, filesize) == "cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f"
}
```

### Sample 38: `6c310c7b49c95c83`

| Field | Value |
|---|---|
| SHA-256 | `6c310c7b49c95c834bf31f53e68578ca0f684b43d5750af6e0092bd191770cac` |
| Family label | `Mirai` |
| File name | `mbupload-4me4pex1.bin` |
| File type | `elf` |
| First seen | `2026-10-23 01:30:21` |
| Reporter | `wristhulk` |
| Tags | `cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66f68750c89c55ad14234fa94347ef1c` |
| SHA-1 | `038fb59754f172ed8714df8eb5e92fe5ff0bb47a` |
| SHA-256 | `6c310c7b49c95c834bf31f53e68578ca0f684b43d5750af6e0092bd191770cac` |
| SHA3-384 | `11792efca31b7183e90fdf95b03877708a39e654982cffc8fb09ddfb1247f01b879ef91e9650dfe190d3a6b152112126` |
| TLSH | `T149458D1AB2B2B67CD007C03497DBC6A24531B0756A323D7B37C4DB352EA6DA46359B32` |
| TELFHASH | `t19611a8744b60552a4781ce00d8de6363212cca6a9a0dbeb7e9718a0c22010fed92bc8f` |
| SSDEEP | `24576:EsmP2rNyqKdp+dyx4bA7mNgYY1hghHFMlEcFJ7rz8bLBYW/RTlJx:SmNghwel57nWBj/RN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_6c310c7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c310c7b49c95c834bf31f53e68578ca0f684b43d5750af6e0092bd191770cac"
    family = "Mirai"
    file_name = "mbupload-4me4pex1.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:30:21"
  condition:
    hash.sha256(0, filesize) == "6c310c7b49c95c834bf31f53e68578ca0f684b43d5750af6e0092bd191770cac"
}
```

### Sample 39: `4b40fd9ccb2a4e33`

| Field | Value |
|---|---|
| SHA-256 | `4b40fd9ccb2a4e33ebc668f98bcf0c14e0b87c088e0bbc4869d33091f3288488` |
| Family label | `unknown` |
| File name | `4b40fd9ccb2a4e33.bin` |
| File type | `exe` |
| First seen | `2026-10-23 01:26:53` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9094f175289b85eed14e4d1d3f2d1f59` |
| SHA-1 | `c01d492552b636fb19f1123e44b820c82944c53b` |
| SHA-256 | `4b40fd9ccb2a4e33ebc668f98bcf0c14e0b87c088e0bbc4869d33091f3288488` |
| SHA3-384 | `a2794ddfaab33ea1c778bc3860b5bcef64ffcf98dc6bbc7e3d50fddb4c2b4cb6138aee8c36ac78d03dc2ea223421c977` |
| IMPHASH | `d436939e4edad1b901cb7ffa9ab98595` |
| TLSH | `T156956C03F69580FCC55EC07887479632EA22BC8D092576EB2BD09B653E76F909F0DB19` |
| SSDEEP | `49152:2t1+x8HJUk5j3rwsWPVO2xiNWAXIU6isA60L:2bqI7MBxUC+sO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_4b40fd9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b40fd9ccb2a4e33ebc668f98bcf0c14e0b87c088e0bbc4869d33091f3288488"
    family = "unknown"
    file_name = "4b40fd9ccb2a4e33.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:26:53"
  condition:
    hash.sha256(0, filesize) == "4b40fd9ccb2a4e33ebc668f98bcf0c14e0b87c088e0bbc4869d33091f3288488"
}
```

### Sample 40: `6eecc8a6959e2d9c`

| Field | Value |
|---|---|
| SHA-256 | `6eecc8a6959e2d9c2ad8ed338ef169e077fbd0372c38b41c55528dda0ca8e56b` |
| Family label | `Mirai` |
| File name | `6eecc8a6959e2d9c.bin` |
| File type | `elf` |
| First seen | `2026-10-23 01:26:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95d0cdea2c6c711feec6d1fd6b8a4b95` |
| SHA-1 | `d7fb75e82a1bf7ef03c00120a954294149ce1f55` |
| SHA-256 | `6eecc8a6959e2d9c2ad8ed338ef169e077fbd0372c38b41c55528dda0ca8e56b` |
| SHA3-384 | `7a337831f57030bf2bbfa9182ea42a17ff3010a8f13c36e7226cb0152e923d04e772e57c3760031bdecc0d0ada9a313b` |
| TLSH | `T1A1765B4AF5A358FDC09AC470875FC663AD31B85402317D7B3694AA342EB6E305B6EF21` |
| TELFHASH | `t1360243700ff424b4b2d3ca11b366f174c97314aa76e979b496627dc1dfa1e820c22c6b` |
| SSDEEP | `98304:nfMHTTea6U4Xr2H5mdW9myQFYTnjOV7Gixc0mZcFUS9ju9:nfzUu0zgVG0mvS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_6eecc8a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eecc8a6959e2d9c2ad8ed338ef169e077fbd0372c38b41c55528dda0ca8e56b"
    family = "Mirai"
    file_name = "6eecc8a6959e2d9c.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:26:44"
  condition:
    hash.sha256(0, filesize) == "6eecc8a6959e2d9c2ad8ed338ef169e077fbd0372c38b41c55528dda0ca8e56b"
}
```

### Sample 41: `c6abdc7bdb43b73b`

| Field | Value |
|---|---|
| SHA-256 | `c6abdc7bdb43b73bbabe29d21fce583770c5af965ba5c8d23c98bbb24b3b331a` |
| Family label | `Mirai` |
| File name | `c6abdc7bdb43b73b.bin` |
| File type | `elf` |
| First seen | `2026-10-23 01:26:33` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96e888025c9389d019018f6f83d7034a` |
| SHA-1 | `a73f2bd8daf34ddf9699f6fe3613a5436385f69e` |
| SHA-256 | `c6abdc7bdb43b73bbabe29d21fce583770c5af965ba5c8d23c98bbb24b3b331a` |
| SHA3-384 | `04efa87c0e681bd7375a28bbcea0626ee9b0a5b4c049312022dad530a766e2a9781250adf0a7f0c7e6ca1671b5cd6a36` |
| TLSH | `T1A3D3B54F7E229F6DF36C86344BB78B35A355239633E0C585D2ACDA005E6034E586FBA4` |
| TELFHASH | `t1cc214c188a3c12f497b62c9d67edff72e46170db46225e338d00e96d9a6dd415d00c2c` |
| SSDEEP | `1536:bk0w329OFWyYNLuWquWp9WQRFZ8BGom5lismK/nzLioSglrXTNOn7dvUjeWaAynz:Ix29AYNIF3ohKfMgdTNOnRvrnHT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_c6abdc7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6abdc7bdb43b73bbabe29d21fce583770c5af965ba5c8d23c98bbb24b3b331a"
    family = "Mirai"
    file_name = "c6abdc7bdb43b73b.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:26:33"
  condition:
    hash.sha256(0, filesize) == "c6abdc7bdb43b73bbabe29d21fce583770c5af965ba5c8d23c98bbb24b3b331a"
}
```

### Sample 42: `d5ef33c409b3d6f6`

| Field | Value |
|---|---|
| SHA-256 | `d5ef33c409b3d6f6cd6d27d44099edb504ca56e62e15948d5f868ea29385a708` |
| Family label | `unknown` |
| File name | `d5ef33c409b3d6f6.bin` |
| File type | `macho` |
| First seen | `2026-10-23 01:26:24` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8c43ea2252a7f75d319ac6baabe4045` |
| SHA-1 | `887e1fa929aff78ee69d2650f3b39d4cafad4d1d` |
| SHA-256 | `d5ef33c409b3d6f6cd6d27d44099edb504ca56e62e15948d5f868ea29385a708` |
| SHA3-384 | `a1df70dee83d7cd63bf390aa0dc5f760453a92b01d615d198aeb7e050b70016d2513cbd24c1be795ad4bf97f8da9a4f0` |
| TLSH | `T148F25F239B1C1A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB9D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMR6PlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfplilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d5ef33c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5ef33c409b3d6f6cd6d27d44099edb504ca56e62e15948d5f868ea29385a708"
    family = "unknown"
    file_name = "d5ef33c409b3d6f6.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:26:24"
  condition:
    hash.sha256(0, filesize) == "d5ef33c409b3d6f6cd6d27d44099edb504ca56e62e15948d5f868ea29385a708"
}
```

### Sample 43: `178e3df349f46728`

| Field | Value |
|---|---|
| SHA-256 | `178e3df349f467280b6dc13a1ed3e329a54ea2d5e9bf1555b2f2797c07dbc115` |
| Family label | `unknown` |
| File name | `178e3df349f46728.bin` |
| File type | `exe` |
| First seen | `2026-10-23 01:26:17` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `609a2c9817c47ee996d5725329783893` |
| SHA-1 | `9af6dca695d2fc3d4ef138f8e1af57327b9ca1f5` |
| SHA-256 | `178e3df349f467280b6dc13a1ed3e329a54ea2d5e9bf1555b2f2797c07dbc115` |
| SHA3-384 | `79310a9be26e4a8e95fde4d1150f7319598f021dbd04f1e30d49183408e59644f49b46ac06ba119afcb05deb2006639f` |
| IMPHASH | `d436939e4edad1b901cb7ffa9ab98595` |
| TLSH | `T15A956C03F69580FCC55EC07887479632EA22BC8D092576EB2BD09B653E76F909F0DB19` |
| SSDEEP | `49152:At1+u8HJUk5j3rwsWPVO2xiNWAXIU6isA60L:AbNI7MBxUC+sO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_178e3df3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "178e3df349f467280b6dc13a1ed3e329a54ea2d5e9bf1555b2f2797c07dbc115"
    family = "unknown"
    file_name = "178e3df349f46728.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:26:17"
  condition:
    hash.sha256(0, filesize) == "178e3df349f467280b6dc13a1ed3e329a54ea2d5e9bf1555b2f2797c07dbc115"
}
```

### Sample 44: `63c825cdc37d8fda`

| Field | Value |
|---|---|
| SHA-256 | `63c825cdc37d8fda0bc6f3c5edf820c9157582ac7641de9c991499c7576a71ef` |
| Family label | `Adware.OfferCore` |
| File name | `63c825cdc37d8fda.bin` |
| File type | `exe` |
| First seen | `2026-10-23 01:26:08` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `390f5ebd4a4af8c7b5cce249127b70ac` |
| SHA-1 | `5eb56a959d7019bb97167e6f15236e07a7b51466` |
| SHA-256 | `63c825cdc37d8fda0bc6f3c5edf820c9157582ac7641de9c991499c7576a71ef` |
| SHA3-384 | `07ab3da482cbd122cbe21d73ee2bae3705c0c6e65c4396bde5c0866cf050e05de4f0dca594306d0a330f2fc29ba63cbf` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T121A5D03FB28B653EE06E5A367AB2E210583B7A6165134C5696F4C88CCF250701E3F797` |
| SSDEEP | `49152:CuI2hGV/uZ/+QoV3E/+EGxbDaEzBAnVhRg:C5O8Q5o2/dGxbfzBAnVhRg` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_044_63c825cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c825cdc37d8fda0bc6f3c5edf820c9157582ac7641de9c991499c7576a71ef"
    family = "Adware.OfferCore"
    file_name = "63c825cdc37d8fda.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:26:08"
  condition:
    hash.sha256(0, filesize) == "63c825cdc37d8fda0bc6f3c5edf820c9157582ac7641de9c991499c7576a71ef"
}
```

### Sample 45: `102398d87e6fc027`

| Field | Value |
|---|---|
| SHA-256 | `102398d87e6fc027f91197033254b66504107a103b2d0508a7ca493a7e297f59` |
| Family label | `Mirai` |
| File name | `102398d87e6fc027.bin` |
| File type | `elf` |
| First seen | `2026-10-23 01:25:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af49028e83996c9e54210244fc73ef02` |
| SHA-1 | `1eb635968832946131e8c1a88f0628b7b2123016` |
| SHA-256 | `102398d87e6fc027f91197033254b66504107a103b2d0508a7ca493a7e297f59` |
| SHA3-384 | `92cc548a3f9adc625ff68a10e5a9311aab0a491d1490df134ca007dbf43be85d2bc075b21185e933952af03c3c32e24d` |
| TLSH | `T18FD3090ABF711EFBD4AFCE3305A94749399D550622B83B3A3674D81CB64A24F06E3C54` |
| SSDEEP | `1536:xwHCdYwBxxAF9b8FCjVPCEAoxDAQmZobkdHb8r3p5fMoO95aqyhAexpy5Y5Jtfil:xskWVPCEASXS6tVA2CTCNdG0rA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_102398d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "102398d87e6fc027f91197033254b66504107a103b2d0508a7ca493a7e297f59"
    family = "Mirai"
    file_name = "102398d87e6fc027.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:25:59"
  condition:
    hash.sha256(0, filesize) == "102398d87e6fc027f91197033254b66504107a103b2d0508a7ca493a7e297f59"
}
```

### Sample 46: `e2db18e2c09abd2a`

| Field | Value |
|---|---|
| SHA-256 | `e2db18e2c09abd2acf92d4869c5c3247e85e7ae09e9d5221125f01e1ed80137e` |
| Family label | `Adware.OfferCore` |
| File name | `e2db18e2c09abd2a.bin` |
| File type | `exe` |
| First seen | `2026-10-23 01:25:50` |
| Reporter | `Tuxxin` |
| Tags | `Adware.OfferCore, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ca782635b6573e5f1c08262497ced87` |
| SHA-1 | `4f9ac85089f50b505a6a29aa38eb504942c52054` |
| SHA-256 | `e2db18e2c09abd2acf92d4869c5c3247e85e7ae09e9d5221125f01e1ed80137e` |
| SHA3-384 | `6ba746312da1d9c7bc88306cf89608112184162b276fb843cd823b3c249db576a03850a12a234382b022d6ae6644dcee` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T168A5D03FB28B653EE06E5A397A72E210583B7A6165138C5696F4C88CCF254701E3F787` |
| SSDEEP | `24576:4XNrSLScusMmOvjjhzvLj51x6jMgkcXjPeynRkIegf+Sve+9Cx+gBbfWzOUxSXcn:XuI2hzxRHcTeynRkfg7ve+AhrWzOUh` |
| ICON-DHASH | `b36494a8cca2cc4d` |

#### Technical Assessment

- The sample is tracked as `Adware.OfferCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Adware_OfferCore_046_e2db18e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2db18e2c09abd2acf92d4869c5c3247e85e7ae09e9d5221125f01e1ed80137e"
    family = "Adware.OfferCore"
    file_name = "e2db18e2c09abd2a.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:25:50"
  condition:
    hash.sha256(0, filesize) == "e2db18e2c09abd2acf92d4869c5c3247e85e7ae09e9d5221125f01e1ed80137e"
}
```

### Sample 47: `c3bca04a525efbce`

| Field | Value |
|---|---|
| SHA-256 | `c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103` |
| Family label | `unknown` |
| File name | `macho_c3bca04a525e.bin` |
| File type | `macho` |
| First seen | `2026-10-23 01:17:15` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `442e493b59fe5369535df81c2d7b19e1` |
| SHA-1 | `8ed353544ad3e559bcd455fb5233bcebc2362e07` |
| SHA-256 | `c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103` |
| SHA3-384 | `e80a2d53960ab369b7c36f84c7ca6dddc955b1234a87e26830b010fd56788b3fda4d24cc73770737baa6831d6b7e0f2b` |
| TLSH | `T19285F1308657D27AE84721F28C101FF56CE0E54809986EFA53A7CB776C31A77B9632B1` |
| SSDEEP | `49152:V4RyFznTQowQyZTuQ9egfMrAZUmjcwACt:sg7Q9egfI6BH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_c3bca04a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103"
    family = "unknown"
    file_name = "macho_c3bca04a525e.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:17:15"
  condition:
    hash.sha256(0, filesize) == "c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103"
}
```

### Sample 48: `71fbe49d223d2728`

| Field | Value |
|---|---|
| SHA-256 | `71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d` |
| Family label | `unknown` |
| File name | `macho_71fbe49d223d.bin` |
| File type | `macho` |
| First seen | `2026-10-23 01:14:39` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5ac0b2653cebcb7e41e164e86ed81d3` |
| SHA-1 | `9bb29d818f819f328a381078dc2541ffbcf9cd96` |
| SHA-256 | `71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d` |
| SHA3-384 | `eff983db0288d4d3485afa711f72fecadecf506d9b99afa10e6312e9312edb8c4a921d0d96ef09a3fdf9e7b8aa47689c` |
| TLSH | `T1A795F2216632A2AAE4436273990C0FD11460A3E2193F6DF56A2DD7793C3D69B7E73331` |
| SSDEEP | `49152:EFy+zNB9eqCYIbhHelPqiH4Hx6pFBpeyPWhFlgmfE5dqfGfRbQ+Iy7:EF3n9+jHx6pD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_71fbe49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d"
    family = "unknown"
    file_name = "macho_71fbe49d223d.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:14:39"
  condition:
    hash.sha256(0, filesize) == "71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d"
}
```

### Sample 49: `54022fe4cfdaf500`

| Field | Value |
|---|---|
| SHA-256 | `54022fe4cfdaf50065aff8ba63fba9f3df77a483fec5c805047fc9a3f9f55245` |
| Family label | `unknown` |
| File name | `macho_54022fe4cfda.bin` |
| File type | `macho` |
| First seen | `2026-10-23 01:12:08` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbefc7c92b131d39785b90773c55a892` |
| SHA-1 | `d4305b646f6a7cea0fe7bbafeb7255d60f15fcf1` |
| SHA-256 | `54022fe4cfdaf50065aff8ba63fba9f3df77a483fec5c805047fc9a3f9f55245` |
| SHA3-384 | `42b78456c22ff9451d55e33b29d60ab17d2f5b4a7b6eb9cdf5d19dbe9fca6566b1f4d60a714e6e6b60d0e70dc3c7e1dd` |
| TLSH | `T121A5F1515FAA5197D58A0073AC9F8F6984B030A0CF44CEE95701A2DACE3A7D377631BB` |
| SSDEEP | `49152:JyzSTwxVjVqg6d3mDRtWCuprdLNnCRamCQged3+HbZUo:JRwxupxLNnCEx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_54022fe4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54022fe4cfdaf50065aff8ba63fba9f3df77a483fec5c805047fc9a3f9f55245"
    family = "unknown"
    file_name = "macho_54022fe4cfda.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:12:08"
  condition:
    hash.sha256(0, filesize) == "54022fe4cfdaf50065aff8ba63fba9f3df77a483fec5c805047fc9a3f9f55245"
}
```

### Sample 50: `ab253de6924568c6`

| Field | Value |
|---|---|
| SHA-256 | `ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26` |
| Family label | `unknown` |
| File name | `macho_ab253de69245.bin` |
| File type | `macho` |
| First seen | `2026-10-23 01:09:34` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6a57e74c3e9a713b989e2f996c6a9d9` |
| SHA-1 | `0918a07b9606e608adfb3507798235130cc70afa` |
| SHA-256 | `ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26` |
| SHA3-384 | `626948bd3bd8252d49ebadafe818c1400460efac23eb775ee9754d7e0d2a41ca39641d054411e9260695d55ee11e05e3` |
| TLSH | `T1DB95F2A21E3A5256D8C17473FC101FF618B06B966E4CEAE8627D93172D38293F16325F` |
| SSDEEP | `24576:B6dRZrx+WHGch4x6fw+rWuhWxU4nx4O8I3sOlKVavcEd6:BINWuhWKe5I` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_ab253de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26"
    family = "unknown"
    file_name = "macho_ab253de69245.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:09:34"
  condition:
    hash.sha256(0, filesize) == "ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26"
}
```

### Sample 51: `ec3eab84f83fc055`

| Field | Value |
|---|---|
| SHA-256 | `ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b` |
| Family label | `unknown` |
| File name | `ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b` |
| File type | `sh` |
| First seen | `2026-10-23 01:00:04` |
| Reporter | `viniciusouza` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a1749b4ee457774192cf506056c496f` |
| SHA-1 | `fc932dfcfafead53ad2e33e664ff46943ad75ae4` |
| SHA-256 | `ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b` |
| SHA3-384 | `a78e1648f789b1e2c32246a181b29faf364e95d0d2ae5b6e5f5f01b09484dbc3000d2aa7644fe0fb1f35a201459b19e7` |
| TLSH | `T135F0A7E5EDA05832F489446EB07CCC197983883E509D691858A3EC7245ACC0C7819F32` |
| SSDEEP | `6:hJAcUTAca7cNKvo8J+6SPPlfWXwLQ7fWXwLQ6KLlnLTLW+GFk7voc8phwDFXv:28J+6qlfj6fjqnLykcPh0v` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_ec3eab84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b"
    family = "unknown"
    file_name = "ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b"
    file_type = "sh"
    first_seen = "2026-10-23 01:00:04"
  condition:
    hash.sha256(0, filesize) == "ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b"
}
```

### Sample 52: `5bbc0e96d7bb507f`

| Field | Value |
|---|---|
| SHA-256 | `5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd` |
| Family label | `Mirai` |
| File name | `5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd` |
| File type | `elf` |
| First seen | `2026-10-23 00:46:06` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b64251da7979bd73db439009fa222de3` |
| SHA-1 | `413c026d8719fc449a26eb3ef9ef03463e7d21a8` |
| SHA-256 | `5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd` |
| SHA3-384 | `5503549d1e447060a610ee231ce738e1fadff00168bc20d55cedec71af508df4f15bada5f7109fa57c0f882e579ca3e5` |
| TLSH | `T10C44E78EFB023DBBD948EE72086E418841DD517927DEC63725B4C588FB8F61E9D53888` |
| TELFHASH | `t1ce2123348b30512a4693cd64dcde4312201dc6169709ee33e930c68c402a0fde32bc9f` |
| SSDEEP | `3072:SbcnVZUzOcolOB0cs2JXp6nClPcMmQD+s8GJRwauGx/3+ET:3ROBp4C6MVD+s8GJRwaTx/uET` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_5bbc0e96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd"
    family = "Mirai"
    file_name = "5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd"
    file_type = "elf"
    first_seen = "2026-10-23 00:46:06"
  condition:
    hash.sha256(0, filesize) == "5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd"
}
```

### Sample 53: `3934bb8fe8757867`

| Field | Value |
|---|---|
| SHA-256 | `3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c` |
| Family label | `Mirai` |
| File name | `3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c` |
| File type | `elf` |
| First seen | `2026-10-23 00:46:04` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02d5a762d4bf791e585f2df1de9f3dee` |
| SHA-1 | `bd94d455ec542485d6c534b100b9281558770f8c` |
| SHA-256 | `3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c` |
| SHA3-384 | `248dabb28454ac2fc4f7d92efdf11801644149d5f6cdc725c0c4373b77abaa7c92133220e978d24618035d8cc513f223` |
| TLSH | `T1BC343ADAFB097D67C750C3338E7B4BBDA339B1591A41A2635E2C216C9D03EA5EC83485` |
| TELFHASH | `t1d8f09e01ec79862d59c75eb4dc9c07689502a913405257209f28dbd1c83f458f31de6f` |
| SSDEEP | `3072:RCS+EjxaOe0YbT2aPdbZclGsGpVy28+3ngqpN9TRuDnTA:RCS+E1a30YbT2ahZclg44ndnt+n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_3934bb8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c"
    family = "Mirai"
    file_name = "3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c"
    file_type = "elf"
    first_seen = "2026-10-23 00:46:04"
  condition:
    hash.sha256(0, filesize) == "3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c"
}
```

### Sample 54: `c38eaf2b436cefd1`

| Field | Value |
|---|---|
| SHA-256 | `c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595` |
| Family label | `Mirai` |
| File name | `c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595` |
| File type | `elf` |
| First seen | `2026-10-23 00:46:01` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3da9e177085a6a75203b2e472b27bef` |
| SHA-1 | `6b5edb4ddecdc8371026dfbf0ef7347520ebf762` |
| SHA-256 | `c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595` |
| SHA3-384 | `d025cd99fd0ca0c98f0e33a454d13b7d8077edaa4c532ba214542fbb198da426f0e0fed0be3b0f2731476cacd2319979` |
| TLSH | `T141243AC9FA19057ECB915277AF77039C33398BD453C9E606D938923A3BC1B68EA23151` |
| TELFHASH | `t11be0ab01e97a461959d31db4dc4c0609a413e60380619b306f28dbd2c83e428f319e57` |
| SSDEEP | `3072:PPe/2GyZfUo3q7Oc5Ke2v9ms2LEHNbX+FL+LPcRiq4WR:PLGy+o3qKvksQ+LPA4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_c38eaf2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595"
    family = "Mirai"
    file_name = "c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595"
    file_type = "elf"
    first_seen = "2026-10-23 00:46:01"
  condition:
    hash.sha256(0, filesize) == "c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595"
}
```

### Sample 55: `629184be428a5bfe`

| Field | Value |
|---|---|
| SHA-256 | `629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277` |
| Family label | `Mirai` |
| File name | `629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277` |
| File type | `elf` |
| First seen | `2026-10-23 00:45:58` |
| Reporter | `c2hunter` |
| Tags | `elf, Gafgyt, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `55b15bf47721d78e788f1215fdf56d1f` |
| SHA-1 | `d4726c73705179da787727f1c14345a97858388d` |
| SHA-256 | `629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277` |
| SHA3-384 | `8d4c98a29f921ae9ada5dc7a9cc6411960a205e137768ee06075e1fcf615bc9427b2c0beecb786553d1b975b59f17077` |
| TLSH | `T1DC243B69FF52997EC217C2360EFB47BC5734B0F41734A20B3A6832392D16590DE57A2A` |
| TELFHASH | `t1d8f09e01ec79862d59c75eb4dc9c07689502a913405257209f28dbd1c83f458f31de6f` |
| SSDEEP | `3072:XsrWqT+ZA8uol82UisG9oYXj8vUDGr/AKNkYvIhNjQTh:Xs6++ZA8Jl82Fooq8O/32YvI3Qt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_629184be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277"
    family = "Mirai"
    file_name = "629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277"
    file_type = "elf"
    first_seen = "2026-10-23 00:45:58"
  condition:
    hash.sha256(0, filesize) == "629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277"
}
```

### Sample 56: `478d4d6936c7704f`

| Field | Value |
|---|---|
| SHA-256 | `478d4d6936c7704f3e9ef4caf15d922bcd5244eab747518d97bdffde4fdbbf92` |
| Family label | `unknown` |
| File name | `greth.dll` |
| File type | `exe` |
| First seen | `2026-10-23 00:34:54` |
| Reporter | `anonymous` |
| Tags | `exe, WARDENstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f3065aa84d6f7d6b74f67096fcb0a2d` |
| SHA-1 | `1730f5d7869aeb46a80d9f1bf9c31f852fb045ea` |
| SHA-256 | `478d4d6936c7704f3e9ef4caf15d922bcd5244eab747518d97bdffde4fdbbf92` |
| SHA3-384 | `52a0212659609ca0945c8958310d1c09793bccd1ab7c76c91ad92f7b0acacc22395cf542c6d12855d3809a17e0229e7a` |
| IMPHASH | `89a027a9a836c907c4e1402600938af0` |
| TLSH | `T1CD0501A1F99557A2D9398171865B9E469624B8230B112CFF03E0374C4F3BBD29B7FB21` |
| SSDEEP | `12288:wxFn/MHyCCItodJVs1Q9jdXdyL0B4zqXwIA97lldxmWPCMI8UiVdbszPe:w6BCItovVH9xtywNM7lTxjat8UIs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_478d4d69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "478d4d6936c7704f3e9ef4caf15d922bcd5244eab747518d97bdffde4fdbbf92"
    family = "unknown"
    file_name = "greth.dll"
    file_type = "exe"
    first_seen = "2026-10-23 00:34:54"
  condition:
    hash.sha256(0, filesize) == "478d4d6936c7704f3e9ef4caf15d922bcd5244eab747518d97bdffde4fdbbf92"
}
```

### Sample 57: `0836bbf73331c772`

| Field | Value |
|---|---|
| SHA-256 | `0836bbf73331c7727b236e42cea87a7096f58bcf4e3ba04f539f5669be0c8643` |
| Family label | `unknown` |
| File name | `yjhyt.exe` |
| File type | `exe` |
| First seen | `2026-10-23 00:34:28` |
| Reporter | `anonymous` |
| Tags | `exe, WARDENstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9cdc76fe000187eb09da494971bc664` |
| SHA-1 | `3b20df0597617e5213b9e41ff2370d38b466601e` |
| SHA-256 | `0836bbf73331c7727b236e42cea87a7096f58bcf4e3ba04f539f5669be0c8643` |
| SHA3-384 | `e3491b2aaef7b640e3062707eb81ae66bc57c90435e253108e11403388bcce518eb184557bb544077702790315b9e8a8` |
| IMPHASH | `cd6a662f3af41e277b4659fda4f64759` |
| TLSH | `T1FBC44A03F79282D8D42AC87587599133F6753C8D4A30B67B67946B251F36BA0EB3DB08` |
| SSDEEP | `12288:kkvkqhRmDjLqLLlicwJb0pRYuq4fbu6CcOctbUz7Uw24J:kjqkjmvwJcRYuq0bu6Zoo14` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_0836bbf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0836bbf73331c7727b236e42cea87a7096f58bcf4e3ba04f539f5669be0c8643"
    family = "unknown"
    file_name = "yjhyt.exe"
    file_type = "exe"
    first_seen = "2026-10-23 00:34:28"
  condition:
    hash.sha256(0, filesize) == "0836bbf73331c7727b236e42cea87a7096f58bcf4e3ba04f539f5669be0c8643"
}
```

### Sample 58: `bb220f8a648cfe81`

| Field | Value |
|---|---|
| SHA-256 | `bb220f8a648cfe810397ef0cb69e0c93c5913929828e0696e257d9f149064c7d` |
| Family label | `unknown` |
| File name | `gverbbv.exe` |
| File type | `exe` |
| First seen | `2026-10-23 00:34:13` |
| Reporter | `anonymous` |
| Tags | `exe, WARDENstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `045dbcaea6ae4383426fc1a1c307411d` |
| SHA-1 | `b687793736ecba9eafdbd3fbadd7227cc2499a37` |
| SHA-256 | `bb220f8a648cfe810397ef0cb69e0c93c5913929828e0696e257d9f149064c7d` |
| SHA3-384 | `0c2b42905b139866da5ac25380ec6d1395e865810170fb2f178185f9c62e947deffa271eac2d04dd7472af0820d61ad5` |
| IMPHASH | `c54767c7d3a9cfb1c75949579202faba` |
| TLSH | `T15825DF27B3960EF8F42A817D4A1105C0A661B8504BE366EB579C672E0F376DD4FFBA10` |
| SSDEEP | `24576:e1kw77eM1KPc/YOQ7ZOkfbaS4RmFMj1miOs:e1kw3KpwPzUi` |
| ICON-DHASH | `4416716969711644` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_bb220f8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb220f8a648cfe810397ef0cb69e0c93c5913929828e0696e257d9f149064c7d"
    family = "unknown"
    file_name = "gverbbv.exe"
    file_type = "exe"
    first_seen = "2026-10-23 00:34:13"
  condition:
    hash.sha256(0, filesize) == "bb220f8a648cfe810397ef0cb69e0c93c5913929828e0696e257d9f149064c7d"
}
```

### Sample 59: `6278c5d5f5ae25c7`

| Field | Value |
|---|---|
| SHA-256 | `6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602` |
| Family label | `unknown` |
| File name | `6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602.exe` |
| File type | `exe` |
| First seen | `2026-10-23 00:32:26` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fe0de8543922229d1c736a17458ce6b` |
| SHA-1 | `bdd17a0b6ad9c2f9c50ebc42e777cf7e49765df5` |
| SHA-256 | `6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602` |
| SHA3-384 | `bd0400fda7845f5cfe4a3089d58614133dc9382d243e9356492b885e7bc09f271af2eec0e12c00e0842977220bc82af9` |
| IMPHASH | `ff42fb4a46b8bc6d5144c3333b37cf5c` |
| TLSH | `T125A60968C79DD448E221A87CDA352A93CBF03D5C1217EF9794C13D172B77A9C932A9C8` |
| SSDEEP | `98304:QegXEVgFAnXnzHgzyfGU1KnicGbfozYWP:PyEV2KXnzAzyuU1KnicQfc` |
| ICON-DHASH | `95c5c65cd59699b6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_6278c5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602"
    family = "unknown"
    file_name = "6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602.exe"
    file_type = "exe"
    first_seen = "2026-10-23 00:32:26"
  condition:
    hash.sha256(0, filesize) == "6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602"
}
```

### Sample 60: `6a3a45ed8e0ae100`

| Field | Value |
|---|---|
| SHA-256 | `6a3a45ed8e0ae10013252651c2eeff306f6b31f9d4379a3e14db961a6ed85914` |
| Family label | `unknown` |
| File name | `6a3a45ed8e0ae100.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:24:38` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdd6d2abebe67bece442edc6eebbad2b` |
| SHA-1 | `17e3bada8ce233da36680392fdb2575b8568946b` |
| SHA-256 | `6a3a45ed8e0ae10013252651c2eeff306f6b31f9d4379a3e14db961a6ed85914` |
| SHA3-384 | `372bdaae7d7e2b0f261f345a0eb1727b836b6621c4edbb800456010cf191b460a6f6da716b15246542e2e12830336e70` |
| TLSH | `T15DE22D43AB4C9965C26D42301AF71BC6A615F6B09EE16B8B5750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUCVZqDDt0TOTLZ0BbFw2fHKk6XrMclSibFqAMcl:z4ZZXvv7VZMt0TO2bV//6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_6a3a45ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a3a45ed8e0ae10013252651c2eeff306f6b31f9d4379a3e14db961a6ed85914"
    family = "unknown"
    file_name = "6a3a45ed8e0ae100.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:24:38"
  condition:
    hash.sha256(0, filesize) == "6a3a45ed8e0ae10013252651c2eeff306f6b31f9d4379a3e14db961a6ed85914"
}
```

### Sample 61: `395f7031ffaf797e`

| Field | Value |
|---|---|
| SHA-256 | `395f7031ffaf797e82da79644d29df07e06d010a3dbf2eb930d3a3163ce9d01d` |
| Family label | `Mirai` |
| File name | `395f7031ffaf797e.bin` |
| File type | `elf` |
| First seen | `2026-10-23 00:24:30` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `255382758b5d18b0bc4a8098fbbfb3d3` |
| SHA-1 | `e065dabe1b0a8f75fa3aa6295ef2f95e0b233d48` |
| SHA-256 | `395f7031ffaf797e82da79644d29df07e06d010a3dbf2eb930d3a3163ce9d01d` |
| SHA3-384 | `06ba223a62ef9e9e712c4cce4550e145e2297bb199a9c70d4ae5ff6c3e4db4db96503a307c4b8f867d19dc38ff772e25` |
| TLSH | `T1E2937DC1D282D4F5E8690A74607AF3376633E9B9006CFEE3F764AF729425A50A14774C` |
| TELFHASH | `t19a31e6f965b61ce8abc06801f20d5761be5deb7b255072e308636834616ae43077bd38` |
| SSDEEP | `1536:9OtdJ6AultD7EK64Nppnma0LKhsZkrEyFhPEaKd2pycBYvXQi+7RY:9wvEltDgK64Npy2WgJFh8aG2YaYT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_395f7031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "395f7031ffaf797e82da79644d29df07e06d010a3dbf2eb930d3a3163ce9d01d"
    family = "Mirai"
    file_name = "395f7031ffaf797e.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:30"
  condition:
    hash.sha256(0, filesize) == "395f7031ffaf797e82da79644d29df07e06d010a3dbf2eb930d3a3163ce9d01d"
}
```

### Sample 62: `01e5360067eb7576`

| Field | Value |
|---|---|
| SHA-256 | `01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8` |
| Family label | `Mirai` |
| File name | `01e5360067eb7576.bin` |
| File type | `elf` |
| First seen | `2026-10-23 00:24:21` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11315b345a88d524ec4fcb724d9f5ea5` |
| SHA-1 | `aac5f13d94820b5831620a31d3f0b3a887a28856` |
| SHA-256 | `01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8` |
| SHA3-384 | `adbc605a260ba9385d11a6e676a9ca49d3a5670ab465243e206a28dc6e586c78b3cf6efabf014ff6e33d6937fa26e390` |
| TLSH | `T1DDB34CA6B410DC3EF51BE6B780570606B135A3F40E426B277627F923DE7A0781827E87` |
| SSDEEP | `3072:25JAZ1/46+bhjuuEpdHYtHF0NhhCb/ExMef:2K46ENJF0rhfxrf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_01e53600
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
    family = "Mirai"
    file_name = "01e5360067eb7576.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:21"
  condition:
    hash.sha256(0, filesize) == "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
}
```

### Sample 63: `c7bebd02f8db0410`

| Field | Value |
|---|---|
| SHA-256 | `c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983` |
| Family label | `unknown` |
| File name | `macho_c7bebd02f8db.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:24:15` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ea3f1445ba4e25307fda7d2503e9b39` |
| SHA-1 | `e68dcedc12169d620ed422ad6bee0cffaa89e42f` |
| SHA-256 | `c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983` |
| SHA3-384 | `70f60e16af48491b4793ee1da67dc888e3a496aa64e5fb8735466912e80ea5b7a81337745a13ab1466e062e193a84309` |
| TLSH | `T11D95F1502EF9532EE4943473EA1C5F519050B3B06E4CB5E5AE11CB47AD3A6C3BBA3326` |
| SSDEEP | `24576:cKaIfC9uI9HffA3Ci0Qruh9lcHqUoK3mzoqdFAsnuZaYpUk69KhYOn9FApqE2+:oUEDih6LlcK1oqdFAzxuD89FA4A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_c7bebd02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983"
    family = "unknown"
    file_name = "macho_c7bebd02f8db.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:24:15"
  condition:
    hash.sha256(0, filesize) == "c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983"
}
```

### Sample 64: `1a414a458c66e3c9`

| Field | Value |
|---|---|
| SHA-256 | `1a414a458c66e3c967737c7895e01412909bffe28919ecfbad859caddc6aaa38` |
| Family label | `Mirai` |
| File name | `1a414a458c66e3c9.bin` |
| File type | `elf` |
| First seen | `2026-10-23 00:24:12` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b2a7032d31dffca72d8134c28a454c7` |
| SHA-1 | `57ac6f6cf5114e42cc5c78315faddace97dc1574` |
| SHA-256 | `1a414a458c66e3c967737c7895e01412909bffe28919ecfbad859caddc6aaa38` |
| SHA3-384 | `e9596e97213dd257cc4b790c033b2c39cd2665366e73f8ba5cf91fe48120d20a39ea96891e78efd36cdde828b5a42ae3` |
| TLSH | `T1D8A39F22CCA49DDCE06A7D7120B5CAFA4723B580551B2DF73C96C2664047E98F1EABF4` |
| SSDEEP | `3072:TNZl5GI/zvjc6Ay+AX5I18/O0V1PlscMoCAVxjAFBn19:TNZl5Pc6AgXWTq1P6KLfM19` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_1a414a45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a414a458c66e3c967737c7895e01412909bffe28919ecfbad859caddc6aaa38"
    family = "Mirai"
    file_name = "1a414a458c66e3c9.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:12"
  condition:
    hash.sha256(0, filesize) == "1a414a458c66e3c967737c7895e01412909bffe28919ecfbad859caddc6aaa38"
}
```

### Sample 65: `aa0f3a504da0c4a1`

| Field | Value |
|---|---|
| SHA-256 | `aa0f3a504da0c4a16fb064f5bd2c23d1a977cbf05d6e1dea9f6efd57c3d32324` |
| Family label | `Mirai` |
| File name | `aa0f3a504da0c4a1.bin` |
| File type | `elf` |
| First seen | `2026-10-23 00:24:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08bc4ca16b24ae868a09577bbd08c2eb` |
| SHA-1 | `fb6cc4ba36f4706cd19182b827f80a5c2c349907` |
| SHA-256 | `aa0f3a504da0c4a16fb064f5bd2c23d1a977cbf05d6e1dea9f6efd57c3d32324` |
| SHA3-384 | `de8d521c8b922f8c957e6f217a47ba913f947728fc0022a2b9faf4af598e6350be4994331d649138c40e7ddb5de2544a` |
| TLSH | `T1F8B32B86BCC5C612C6E5A0F6FB1E91CD372643B8E3E672079D18AB29634F8570E3B151` |
| TELFHASH | `t1bd310f1aef540edc77f4034680db210765ae34fe1b5264a3adbeeb4f8a224d23036138` |
| SSDEEP | `1536:qDgiQ8pi61+pzUvqS7031RW0lCNx158uQvvH4N/0c69OVsK+vQKR2:qEVM+1U/4P3lq5RWvH4caEq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_aa0f3a50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa0f3a504da0c4a16fb064f5bd2c23d1a977cbf05d6e1dea9f6efd57c3d32324"
    family = "Mirai"
    file_name = "aa0f3a504da0c4a1.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:03"
  condition:
    hash.sha256(0, filesize) == "aa0f3a504da0c4a16fb064f5bd2c23d1a977cbf05d6e1dea9f6efd57c3d32324"
}
```

### Sample 66: `b6d03e3f9c178c77`

| Field | Value |
|---|---|
| SHA-256 | `b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299` |
| Family label | `Formbook` |
| File name | `b6d03e3f9c178c77.bin` |
| File type | `exe` |
| First seen | `2026-10-23 00:23:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ef11a7596e1ddcf5be57e0b52bacd11` |
| SHA-1 | `959700583d893a797c31a05a83338482ca9c2411` |
| SHA-256 | `b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299` |
| SHA3-384 | `4fc8f4f243c288dd22fd7f695dfe9253f17accf7820c7985e950720450807c1309fd6fd0a89bc3c9f687b5dc5648fb3e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T157F402642369F602E9B65FF51A71E334A336AE8DE531D30B8EEA6CDF38257016D44342` |
| SSDEEP | `12288:rDrO5uarElvJ0ig/mWyiaWwMMPqzy+gsXViF0hlDhX+J88oi:PrYqJ0/nQMgqzyPoVphNhX+C8o` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_066_b6d03e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299"
    family = "Formbook"
    file_name = "b6d03e3f9c178c77.bin"
    file_type = "exe"
    first_seen = "2026-10-23 00:23:54"
  condition:
    hash.sha256(0, filesize) == "b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299"
}
```

### Sample 67: `561095acf398b0ed`

| Field | Value |
|---|---|
| SHA-256 | `561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840` |
| Family label | `Snowlight` |
| File name | `561095acf398b0ed.bin` |
| File type | `elf` |
| First seen | `2026-10-23 00:23:46` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f7cd9c5372cc89ac4ab8a7bbf447adc` |
| SHA-1 | `253cce26bd8f6e39283a9f0d94f5bea914dfda54` |
| SHA-256 | `561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840` |
| SHA3-384 | `7b56b2d12cd7ab3f7a054a228ec45d8d70dffa5a769421d34042242d54a3fe931245474f521f65b10d246423d17c290b` |
| TLSH | `T157123047A2D0CE3FC8D957384467122472B794BEDF629723064815B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS63H5ML09V1J9G8Ymx+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHkZMWT1YmchrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_067_561095ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840"
    family = "Snowlight"
    file_name = "561095acf398b0ed.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:23:46"
  condition:
    hash.sha256(0, filesize) == "561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840"
}
```

### Sample 68: `3169f13963324e6b`

| Field | Value |
|---|---|
| SHA-256 | `3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71` |
| Family label | `unknown` |
| File name | `macho_3169f1396332.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:21:45` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09673b9717945cfdc5918941f4f4247c` |
| SHA-1 | `38ecfb39a0357bb83cc212f61f4de610817cf117` |
| SHA-256 | `3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71` |
| SHA3-384 | `23671159c03c8824523676416e624b0638b07b6a1dca3c599c7f0ccc1fa6710442fcb6df427454ec9b9d7fa1fed06604` |
| TLSH | `T1F995F1901A31056BE4412C3ABC250FD6C4B0B6925FCAB1E67320C64A6D7A5D3BEE37D7` |
| SSDEEP | `24576:A2KTw+gPbkXZFP6rhgQmwlfTqQRLvqdCYej8vY7lZkKwHDOqU1Udj1In6vb3GCGB:kdSRqzCiSlZ0Hg1Udj2n6T3GGmHEmB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_3169f139
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71"
    family = "unknown"
    file_name = "macho_3169f1396332.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:21:45"
  condition:
    hash.sha256(0, filesize) == "3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71"
}
```

### Sample 69: `27e4adf26375ac04`

| Field | Value |
|---|---|
| SHA-256 | `27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9` |
| Family label | `unknown` |
| File name | `macho_27e4adf26375.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:18:54` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `640ef3c3299afb6f0fa90ad0dea22dd9` |
| SHA-1 | `1172caf16e4f2a4d228ef570b1638fb54e8e65ae` |
| SHA-256 | `27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9` |
| SHA3-384 | `ea0c1cb840ea477818b8350d2bf9150d291b5635f212fbe81dee2531d1d9f88b36415ddc118657f6ccb3dcb3ece7b46e` |
| TLSH | `T12A85F1605A19466AE84471729CD04FFA20B0A6C9DE4CAAE8A331C747BD31753B17F36F` |
| SSDEEP | `24576:V2Ye3/AdK6lMT6QUeo2sSMddTpIBz0ItP2pYHht2cQcEk2wU2E8AP:goe9EdEBz0ItOqHW3wp4P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_27e4adf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9"
    family = "unknown"
    file_name = "macho_27e4adf26375.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:18:54"
  condition:
    hash.sha256(0, filesize) == "27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9"
}
```

### Sample 70: `946de91e0b3aaf6b`

| Field | Value |
|---|---|
| SHA-256 | `946de91e0b3aaf6bc466d9bf11df1b4ed74f24ef301dff697010ee15918f88f9` |
| Family label | `unknown` |
| File name | `macho_946de91e0b3a.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:16:20` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `512342c10968905393211edc85ef76b6` |
| SHA-1 | `4d7591761a928af732601dd60290376556abb02f` |
| SHA-256 | `946de91e0b3aaf6bc466d9bf11df1b4ed74f24ef301dff697010ee15918f88f9` |
| SHA3-384 | `43ad8a0dc8105f4585903e6bb0e6c6d88285c9356f5538fe90e79f139783d6d1e3c6024f9fb28980686165b5670125f4` |
| TLSH | `T19BB5E0209F5FA197E84600739D9B4F89857021A0CD49EEE96300F3A9DE367E37B12677` |
| SSDEEP | `49152:7jPrQIIbfBwsEZz4KYZWLkobIdjKWrdRnOZQcaBK+R3CEOrN:7YdbfIkZsWrXOZQN4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_946de91e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "946de91e0b3aaf6bc466d9bf11df1b4ed74f24ef301dff697010ee15918f88f9"
    family = "unknown"
    file_name = "macho_946de91e0b3a.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:16:20"
  condition:
    hash.sha256(0, filesize) == "946de91e0b3aaf6bc466d9bf11df1b4ed74f24ef301dff697010ee15918f88f9"
}
```

### Sample 71: `9081546dcd8528fa`

| Field | Value |
|---|---|
| SHA-256 | `9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839` |
| Family label | `unknown` |
| File name | `macho_9081546dcd85.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:13:39` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c02ba8c5af8bac7745df990c126c1f6c` |
| SHA-1 | `bbdab8e04feb711f6e16c6a4cf59c4db8e989df4` |
| SHA-256 | `9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839` |
| SHA3-384 | `36c85a5976e2889617a0e65cdeffbf15fdb54f2729434da8ae3e030f6d621b4b2b045da83090759315aa1bd8b358cf09` |
| TLSH | `T1C795F12027697229E7C320B28D148F5165A07FE15E48E5FB6A1197072F386F3B6B7363` |
| SSDEEP | `24576:IkUycq3y6dNr2Vp6GopmJC1au5Kh2XV5fCzxOFwwlq/hTQQzCSq0LIcTSCi8uHUN:Pd7E4pyL2XXKz1FzCSqYIcT7EDNaV1z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_9081546d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839"
    family = "unknown"
    file_name = "macho_9081546dcd85.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:13:39"
  condition:
    hash.sha256(0, filesize) == "9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839"
}
```

### Sample 72: `6d2c7f1837bd52c9`

| Field | Value |
|---|---|
| SHA-256 | `6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5` |
| Family label | `unknown` |
| File name | `macho_6d2c7f1837bd.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:11:01` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c38bd39549d423946837547208024cb3` |
| SHA-1 | `152ec8de069fb718acdbecb3ff5312bb2e7d7b81` |
| SHA-256 | `6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5` |
| SHA3-384 | `be9103091b6961896b1863463a3fcda83c9ecb2ce19ba64b66b250f23352a4d20564b7b7769f50ef8364edeb6237fd56` |
| TLSH | `T1FE9501A41517327BE642243EAD342FD0656057A04BD9EEFE6A14D3392C32AF36677332` |
| SSDEEP | `49152:WkiAVFS/ukpiprUr4y6z4llg7SsHl5HqMAO9x0Te2qxn:4fllg7HHLHj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_6d2c7f18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5"
    family = "unknown"
    file_name = "macho_6d2c7f1837bd.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:11:01"
  condition:
    hash.sha256(0, filesize) == "6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5"
}
```

### Sample 73: `b2a38245d0cd7985`

| Field | Value |
|---|---|
| SHA-256 | `b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03` |
| Family label | `unknown` |
| File name | `macho_b2a38245d0cd.bin` |
| File type | `macho` |
| First seen | `2026-10-23 00:08:06` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6851e0e8e7015f609eda76eb144b77b9` |
| SHA-1 | `c1a9db2134aaa9f0b36b41b8a8308f1d60ec8049` |
| SHA-256 | `b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03` |
| SHA3-384 | `ec72f8ca4b0ad1893549e67bcf520951879abe6bb705b3e1964cbea1540052878e672fc485608d54f8bcea2896534715` |
| TLSH | `T12385F170567702ABDC6761B2CF285F5045E0AA8CDAE4ABF9612CF34B3D36643F163225` |
| SSDEEP | `24576:rvVxz7X+G89dThR3gltoxp6UwXcOVIpVVy1WCX0yolQTTfbB9MntRFgHhIFDUUg7:j/tISENQTLbBj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_b2a38245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03"
    family = "unknown"
    file_name = "macho_b2a38245d0cd.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:08:06"
  condition:
    hash.sha256(0, filesize) == "b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03"
}
```

### Sample 74: `d2c1df26f01a178a`

| Field | Value |
|---|---|
| SHA-256 | `d2c1df26f01a178a3450da75022bdaf24a2427e9367531758969eb61147b9726` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-10-22 23:48:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `165df4224c79a799e75b81cb22a5ac76` |
| SHA-1 | `a83b856ba661c0852083f62409d3d53fce193c4a` |
| SHA-256 | `d2c1df26f01a178a3450da75022bdaf24a2427e9367531758969eb61147b9726` |
| SHA3-384 | `629fe3de2efbfc9341f12ca6dfb5545e8a61054e0f7c53c0c73943cf6f6344e9d97d2dbecbd7bee8ae5727c2bbb96550` |
| TLSH | `T1BCE329C7F900DEFAF80AE33748530905B630BBE111925F372257796BED3A1991963E86` |
| SSDEEP | `3072:aId13l15/Tm6DExyugI6p+rMM/VPjbixL4pGyVaaSC:nvoMExyur6sMM4L9yVbSC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_d2c1df26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c1df26f01a178a3450da75022bdaf24a2427e9367531758969eb61147b9726"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-10-22 23:48:31"
  condition:
    hash.sha256(0, filesize) == "d2c1df26f01a178a3450da75022bdaf24a2427e9367531758969eb61147b9726"
}
```

### Sample 75: `10ff3c82edf92620`

| Field | Value |
|---|---|
| SHA-256 | `10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec` |
| Family label | `DCRat` |
| File name | `250df0e912b813ee97bf1408bda36823.exe` |
| File type | `exe` |
| First seen | `2026-10-22 23:40:10` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `250df0e912b813ee97bf1408bda36823` |
| SHA-1 | `e49f1840c24ae911caab350feb70345e7ace99e0` |
| SHA-256 | `10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec` |
| SHA3-384 | `25271b2bf35e7f6067e7185486daa21d1b0ab4833f886755615bb10a3431ee9cb19dfe16c4c9af748582e7841b69701f` |
| IMPHASH | `fcf1390e9ce472c7270447fc5c61a0c1` |
| TLSH | `T1E34549017E84CE12F0191633C6EF494487B4AC512AB6E72B7EB9376E55223937C1DACB` |
| SSDEEP | `24576:U2G/nvxW3Ww0tzIiNStY03xyY+F6hrR55KghwZKGEyIX:UbA30zIi4QY+kr5KghrZP` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_075_10ff3c82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec"
    family = "DCRat"
    file_name = "250df0e912b813ee97bf1408bda36823.exe"
    file_type = "exe"
    first_seen = "2026-10-22 23:40:10"
  condition:
    hash.sha256(0, filesize) == "10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec"
}
```

### Sample 76: `13a4f1bb7f3db7a9`

| Field | Value |
|---|---|
| SHA-256 | `13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144` |
| Family label | `Mirai` |
| File name | `eclipse.x86_64` |
| File type | `elf` |
| First seen | `2026-10-22 23:33:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb961ff158079a25173bc8b4bc3e851e` |
| SHA-1 | `b2f105bb8f5146dbcee5924453ca4b3815a72e2a` |
| SHA-256 | `13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144` |
| SHA3-384 | `03d9771f265665aec69ef779363f3554c143b2694f9d457488b010c38f1bdd0619e94af265107df709273006f6e06eeb` |
| TLSH | `T1BAD34B17B4C1C0FDC8DAC1784BEEA616ED72B5A81234B10F27D86A371E5EE215F1EA50` |
| TELFHASH | `t1a75187b13a593888b1f3f2367346d569dc7a0e3008e031dacd72bdf8da26b400d66867` |
| SSDEEP | `3072:5pFqmNJOnBw+FIH/jIQD1uX5L4FaK9xoy:525NU/1uJOd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_13a4f1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-10-22 23:33:25"
  condition:
    hash.sha256(0, filesize) == "13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144"
}
```

### Sample 77: `8d88cda5439279eb`

| Field | Value |
|---|---|
| SHA-256 | `8d88cda5439279eb70e789a8718f8f27a40d328bc674d6d5197731935dbd16a5` |
| Family label | `Mirai` |
| File name | `dissarm7` |
| File type | `elf` |
| First seen | `2026-10-22 23:27:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c3cb06dbfc8dc00794a26e4a483a3be` |
| SHA-1 | `b7f6fb0487d933c882cf9979f525ae214fcf7210` |
| SHA-256 | `8d88cda5439279eb70e789a8718f8f27a40d328bc674d6d5197731935dbd16a5` |
| SHA3-384 | `d1ca10250f7a879c4e4875011767a83a8d6d124b8c63fb1382a8a24a86b164e069ba09b69602f4e76465636ae7b6c460` |
| TLSH | `T14F14F725B8917710D0E773BAFF6E414833679778C7A97003CA341A216BFA92F4E72469` |
| TELFHASH | `t158b01240ec1d04c0f440421cc1e2e70715f4eb04030c41de49095f0f06a3459f449533` |
| SSDEEP | `3072:XNC0CqBVFANisG92Ti0S4NMeZpQIXteaeY6ph9bvxF15Z6oGrBsCZndUiW:M0XKNG2TBCeLd9eaeYIh9bvxthG1sCZA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_8d88cda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d88cda5439279eb70e789a8718f8f27a40d328bc674d6d5197731935dbd16a5"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-22 23:27:17"
  condition:
    hash.sha256(0, filesize) == "8d88cda5439279eb70e789a8718f8f27a40d328bc674d6d5197731935dbd16a5"
}
```

### Sample 78: `2cf96dfd5f99e9a7`

| Field | Value |
|---|---|
| SHA-256 | `2cf96dfd5f99e9a713385fe5afb63ff97acc88abca00676de7f200d42c70e4e1` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-10-22 23:24:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1cc2d8ac7062280a90e47c76f656b11` |
| SHA-1 | `dff87322b809f3286101d8fa98c2de910d734b79` |
| SHA-256 | `2cf96dfd5f99e9a713385fe5afb63ff97acc88abca00676de7f200d42c70e4e1` |
| SHA3-384 | `7805014170c04ce9cbaa5d09416a7831f618987ef7f58705f6ecf0a624e88b8ee41c5390e945bf1c350b2bfbe3002989` |
| TLSH | `T1BAD32A06B30C0A47D1632EF03A3F67E193AFDAC121E4F640255FAB8A95B1D365586ECD` |
| SSDEEP | `1536:gYud53jFe0PuAIqOYnbxfml6lh6YwM6EP2MYemddWvA1J0gN+1uiquPAw2R:grFOgZnbxHhKdMzmdB1vrR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_2cf96dfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf96dfd5f99e9a713385fe5afb63ff97acc88abca00676de7f200d42c70e4e1"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-22 23:24:16"
  condition:
    hash.sha256(0, filesize) == "2cf96dfd5f99e9a713385fe5afb63ff97acc88abca00676de7f200d42c70e4e1"
}
```

### Sample 79: `65988926d1a02d38`

| Field | Value |
|---|---|
| SHA-256 | `65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d` |
| Family label | `Mirai` |
| File name | `dissmips` |
| File type | `elf` |
| First seen | `2026-10-22 23:15:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8b511bca0ce7cd1849a56090b586763` |
| SHA-1 | `bbe54e932701d4417ddcfa963c0bd9ddafac961e` |
| SHA-256 | `65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d` |
| SHA3-384 | `fed84fbf09622b7ff2c67af9de4601b98d671d852650ded994c883e22a8d9d013635814de2e4c152f4c8351440a370f7` |
| TLSH | `T16944C62A6D719B7DF27AE33487B74A20A76C63D61BA1D582C17CC0105E7025E681FBBC` |
| TELFHASH | `t16a4162580a7817f0a3386c5d05ddfb76d6a730df7e166c238f11e86aab69a839d11c0c` |
| SSDEEP | `3072:b7jjGR3G+tmtkkmymVduMxEb3i+ARoKTIMlT8VY1glSGFjOSOMF:b7jji3BtmKdBkSQklpOUGFj4MF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_65988926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-22 23:15:18"
  condition:
    hash.sha256(0, filesize) == "65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d"
}
```

### Sample 80: `35e9f2443d7fa3c5`

| Field | Value |
|---|---|
| SHA-256 | `35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e` |
| Family label | `Mirai` |
| File name | `disssh4` |
| File type | `elf` |
| First seen | `2026-10-22 23:15:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fa141da100859af96e410246d82e2a0` |
| SHA-1 | `116ab0e1c020bc882507e9522f7b4b5dc09fb1a7` |
| SHA-256 | `35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e` |
| SHA3-384 | `68a78eccdb3ac72540eec30b1f3aab190e97f13444ac57bee6748db208a77cebafffed3bfde6863fb706e57290417eb5` |
| TLSH | `T153040731A8B13FA4D037F378D7B587382366D6600B0A5EBB8136806589B7E6DB94177C` |
| SSDEEP | `3072:8QNo6toDejhdSupVzYFw+xnFWnDRz/+2Cbe:8lDIdSupKPwnDkbe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_35e9f244
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-22 23:15:16"
  condition:
    hash.sha256(0, filesize) == "35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e"
}
```

### Sample 81: `74fd8f8e014d46d8`

| Field | Value |
|---|---|
| SHA-256 | `74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-22 22:58:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88435751bb3a54c626e8fd03efcd0674` |
| SHA-1 | `39395b09ab21f4ed4271e529b2757103aaaeaf56` |
| SHA-256 | `74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061` |
| SHA3-384 | `a0a06ea41cba1332784dfd36409f37f699ed77fa45d9479dd2217298950c17f042d5181b85ea4c6dcc58e029c65de6a4` |
| TLSH | `T1DFE48C687ACE7D42E287F33DCF8A8660333BFAA49712D2933511415CD5E6AADCEB0511` |
| SSDEEP | `12288:40iLihYsccwq8B3rHT1/KfVcsM61fW7D8mTHf6PgyEs5RXaO:ihsccwLf1/4VJM61sD/HmF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_74fd8f8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-22 22:58:20"
  condition:
    hash.sha256(0, filesize) == "74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061"
}
```

### Sample 82: `b9b00a11b0bdecee`

| Field | Value |
|---|---|
| SHA-256 | `b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98` |
| Family label | `Mirai` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-22 22:55:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b239dc25d7ad3a84dc42581cfe6fda3` |
| SHA-1 | `ff4c40a2b6d666fd47e01ab9219915a12441150f` |
| SHA-256 | `b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98` |
| SHA3-384 | `58bc653b9724916ed432466e65c166be39359d6638ab218141506a5f3a2d8f9f497bf68f82f622e77c9c6161881e6ee0` |
| TLSH | `T15714392578E161FCC4A7F338CBBE9221A774F60C0B24B84F437459529EBDE3D4A68529` |
| TELFHASH | `t1ab51cb742ca2395852d7d267b34fdae9ec7206110fe270a64f57ace2ce877cc1e82815` |
| SSDEEP | `3072:zs53dvizGua1/pbY7zi9t5DsCICMpP6i7WKhs:zkqSayhB9NOs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_b9b00a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-22 22:55:18"
  condition:
    hash.sha256(0, filesize) == "b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98"
}
```

### Sample 83: `b8529448ca17ba76`

| Field | Value |
|---|---|
| SHA-256 | `b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f` |
| Family label | `Mirai` |
| File name | `disspoor` |
| File type | `elf` |
| First seen | `2026-10-22 22:34:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee9c21ece378631ffadcc6fee609b5ea` |
| SHA-1 | `95fa64a2fe3e4e5ceb81e77afa9e28d2020f37dc` |
| SHA-256 | `b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f` |
| SHA3-384 | `47e321a6f44fa543c7798567072f37dd5459a28ea5a7d88bfab157a7965a4df3180450d0ac1da5b254219735a961e820` |
| TLSH | `T1B114381076292353E0777BB49B3F13D0A3FED6511BA4AA47413E548AC6B6E3E4881CED` |
| SSDEEP | `3072:XYp6e9o9YIHMllWqxArgoXIadKgd/bLCg+2:XYp6e9F+MlYqxArgoYadljLS2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_b8529448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-22 22:34:48"
  condition:
    hash.sha256(0, filesize) == "b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f"
}
```

### Sample 84: `0cbe035f5448441e`

| Field | Value |
|---|---|
| SHA-256 | `0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f` |
| Family label | `Mirai` |
| File name | `main_arm6` |
| File type | `elf` |
| First seen | `2026-10-22 22:29:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `494b69694eaa86f71c4bd453bccda681` |
| SHA-1 | `090e2f6eb566ae5a3c522e8540e34de8a166e27c` |
| SHA-256 | `0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f` |
| SHA3-384 | `e5d0eba49459238261155726cde45ec6c38427c69e49aa84496d75a75faf82f6f9604f7eeab8b8ed5932a55b89aa2e5b` |
| TLSH | `T13EE30B46F8819B12D5C111BAFE1E124E37131BBCE2DF72029D246F647B8A97B0E3B915` |
| TELFHASH | `t1ecd0a775afb8304c96e8415cc0ed0127a39572e6360951aa69a54e1205630db303110d` |
| SSDEEP | `3072:6heViUpUvsk2iXeZMALhaYHufSc1DZkLMM:8eViUpAYiXOMAtazVDZkLM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_0cbe035f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-10-22 22:29:15"
  condition:
    hash.sha256(0, filesize) == "0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f"
}
```

### Sample 85: `a9892231ad0534ba`

| Field | Value |
|---|---|
| SHA-256 | `a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf` |
| Family label | `RemusStealer` |
| File name | `ХLосitуХ64-v.7.911.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:28:26` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, Remus, RemusStealer, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e132bb34e0b737ff9f7acbd935c5aebb` |
| SHA-1 | `b48bc8f610d5834ccca3b7c6d9854b6ddf103efb` |
| SHA-256 | `a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf` |
| SHA3-384 | `13abc45eb5287a46cb33004e9c6ee274bd0cacc0fef28492635bf846409c7aed4c14d1fc1c72120ad1fe8c796ef74866` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14AD549067C418269E5A65B35C9AA95A2B571BC4C8B3373E71F80AB302F333C39D75B58` |
| SSDEEP | `24576:C2RnGOyC1esXQJSwXEhDT2Uz8OYt5Zv25BKBy8bLOVyOu4/8KVhgzDfyN4w/BFRD:CAnGxC1jwI/2hK5BKB4Vnjj8w/3R` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_085_a9892231
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf"
    family = "RemusStealer"
    file_name = "ХLосitуХ64-v.7.911.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:28:26"
  condition:
    hash.sha256(0, filesize) == "a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf"
}
```

### Sample 86: `a65c89eb77e80859`

| Field | Value |
|---|---|
| SHA-256 | `a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff` |
| Family label | `unknown` |
| File name | `a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:28:07` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20b7b3f0efc545ada0587d0831795970` |
| SHA-1 | `cb5f78e3c6615ce5256992e243ed039b11b0fc7d` |
| SHA-256 | `a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff` |
| SHA3-384 | `d44159de85cac3ca0e0982463ae6a37e52b333c53cf478f90a8f73f9f75510a342b224589edd7d181820ad6d6041b03e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T121A38D5432D9D659C5ACCFF14CE3C273433D3DED8A0196AAB5493B7A0C326CD6B22626` |
| SSDEEP | `1536:wzK0JKSvgiH3iSVNHg6ng8WZvj4hloBBXy/uX4:wG01gII6ng8WZvj4hloBBXy/P` |
| ICON-DHASH | `f0c8c89cb6a6ccf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_a65c89eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff"
    family = "unknown"
    file_name = "a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:28:07"
  condition:
    hash.sha256(0, filesize) == "a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff"
}
```

### Sample 87: `9b206fbfb1ffce27`

| Field | Value |
|---|---|
| SHA-256 | `9b206fbfb1ffce27c8b641989f690e701437e7e91fdbfdea808dff935c2529f3` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:24:35` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, Remus, RemusStealer, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2da63cb9b33dd3f8d9c21ef32e6f088` |
| SHA-1 | `0878427d0f8f806d8456402d916778d77b97889c` |
| SHA-256 | `9b206fbfb1ffce27c8b641989f690e701437e7e91fdbfdea808dff935c2529f3` |
| SHA3-384 | `ff9604f76ee585c28ab7a0b303730aede39ba608cad18e6334dd2bf665c55a8046d20505e3265310a431260aa3b44301` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1D02629237DD595A4C1AEDB7688A25516A220B84DCB3173D32E90F7702EB43D0AE7DF21` |
| SSDEEP | `49152:XToxLK+jIhbv8fdFhVdeDq8II42jcGUA2T472fswAEFkTK5qCc5OB3Y:Xe9TAf1wcPTf35kY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_9b206fbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b206fbfb1ffce27c8b641989f690e701437e7e91fdbfdea808dff935c2529f3"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:24:35"
  condition:
    hash.sha256(0, filesize) == "9b206fbfb1ffce27c8b641989f690e701437e7e91fdbfdea808dff935c2529f3"
}
```

### Sample 88: `c266ce7a2343af69`

| Field | Value |
|---|---|
| SHA-256 | `c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131` |
| Family label | `Mirai` |
| File name | `main_arm` |
| File type | `elf` |
| First seen | `2026-10-22 22:23:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd710471167bfa26210237e1548f7957` |
| SHA-1 | `81231359fea054cc7a83550eb71356b127de94be` |
| SHA-256 | `c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131` |
| SHA3-384 | `43c2d46000fa14a645ad2541444b45fd3ad52775bbdadbc5d0494c494357f4bcca6f3d35306752539ccf7054c0c9cd6b` |
| TLSH | `T174D31A45F8404F23C6D612BBFB5E428D3B2A17E8D3EE72039D256F20378655B0E76A46` |
| TELFHASH | `t17111dc5bdb2c5a6d7ff041448a6ef11ad5a1769c0b633d639e24b54be2465c2344c012` |
| SSDEEP | `1536:HKO6laaFTcTwbMR3Eta8vApih4V/68STQ5s55rY7rE4eqg7eGlP1wywu5h1TsHws:HKOsg0M8vt4UVis55EH1KLAzVb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_c266ce7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-10-22 22:23:23"
  condition:
    hash.sha256(0, filesize) == "c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131"
}
```

### Sample 89: `4c6328fa44c5ddb6`

| Field | Value |
|---|---|
| SHA-256 | `4c6328fa44c5ddb6ebe42728fa85f08cfacee13afdd44f1883a7be80e530b301` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:22:48` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `722ecc19be1220e1cdafdf0dfba9a67c` |
| SHA-1 | `02a6016c4217e4ed8000b9b7d6c0ce09bbfe29c9` |
| SHA-256 | `4c6328fa44c5ddb6ebe42728fa85f08cfacee13afdd44f1883a7be80e530b301` |
| SHA3-384 | `452dc9f4c6f84c6df603d5afb0e890241a7c97d1d5f0180693c37ea897265523ff59cff7bee3244b9f4a70955333f362` |
| IMPHASH | `bb9872b6c7e568c8ac0c170ba5920572` |
| TLSH | `T155457D17BF50BFFFD409D9B30043748589F1681116AE79BAFB4AA3A94C311A673AB311` |
| SSDEEP | `12288:zYH7mNgfo35cqLqLA447qCG4NJ3UAz0z7puBSgn+33lCN5Rahby0G1KmvcWmHqXj:zYaNg0usqDyS+SU+33s2bet37znq` |
| ICON-DHASH | `7fffe9edfdf9ffff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_4c6328fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6328fa44c5ddb6ebe42728fa85f08cfacee13afdd44f1883a7be80e530b301"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:22:48"
  condition:
    hash.sha256(0, filesize) == "4c6328fa44c5ddb6ebe42728fa85f08cfacee13afdd44f1883a7be80e530b301"
}
```

### Sample 90: `2f4d8f8e668dfa68`

| Field | Value |
|---|---|
| SHA-256 | `2f4d8f8e668dfa68f74167247b15ce87d4e0d3f1eff61d6712aeacce03d87af2` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:22:31` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ece9bb0f35c796df5ea6d3def49fc51c` |
| SHA-1 | `a274babb9395f9d79cbfc80dcdd8e3240a8332c4` |
| SHA-256 | `2f4d8f8e668dfa68f74167247b15ce87d4e0d3f1eff61d6712aeacce03d87af2` |
| SHA3-384 | `f98ab1f4818202c61b99b8d367bd57c9472f70f600b496ec2d31bc4a720a99829a660671371c8418d9ddb714e8a1a560` |
| IMPHASH | `1fbc448a6858b22e9cda24b565fe2566` |
| TLSH | `T1C5259D75A7926EF4F043843ED2805E05DB75A8632FEE0CA7423E47258C28AD4B7FB654` |
| SSDEEP | `12288:bhbbLEaQwi2baNgd/zIIonHpcc2WvgtoeoP2kyBoPbxJS7:bhblQwFrVoHpNItejxJE` |
| ICON-DHASH | `4c3369cccc69b24d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_2f4d8f8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f4d8f8e668dfa68f74167247b15ce87d4e0d3f1eff61d6712aeacce03d87af2"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:22:31"
  condition:
    hash.sha256(0, filesize) == "2f4d8f8e668dfa68f74167247b15ce87d4e0d3f1eff61d6712aeacce03d87af2"
}
```

### Sample 91: `92774f66be66de1c`

| Field | Value |
|---|---|
| SHA-256 | `92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:22:11` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0307823ab2979f4a16bf2c0a4f81900` |
| SHA-1 | `17b6451033e10aa08001849d90d54a15c7a463aa` |
| SHA-256 | `92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d` |
| SHA3-384 | `9c64189419e6eafc89676f5072b5962d8c9a7f99c3bbc22cb06206ab2d25bbe49fe9451a22770adcc0df483ea1922c3b` |
| IMPHASH | `e3f9b852d603b762b1132ada490507ae` |
| TLSH | `T1DB253A50AB332C7DF065CB3C444244538AB2355797DD52EB0E5C42FA6AB7182BAFF81A` |
| SSDEEP | `12288:remNA96QR9DYgJoxV59tDwCxeLa+qM6v2agGLGVJPj19j0NIpATMJ:JaFJoh9ZNWF6v2fWGvbzj0up2` |
| ICON-DHASH | `fff7f36969f1ffff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_92774f66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:22:11"
  condition:
    hash.sha256(0, filesize) == "92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d"
}
```

### Sample 92: `5409085ecec90189`

| Field | Value |
|---|---|
| SHA-256 | `5409085ecec901891f284ae11b3f1e53acc24483cec458ff5e32f5073caef8f3` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:21:50` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e5f07be585bd1d203b12e0fe59979a6` |
| SHA-1 | `1177e5e96acac7d06ef894ec9b19063477ba19bd` |
| SHA-256 | `5409085ecec901891f284ae11b3f1e53acc24483cec458ff5e32f5073caef8f3` |
| SHA3-384 | `0d38ac792e1dbc621a071a71a6d3cf2063adfdc7b09087178ec73f8043e3e6d360a3d6a698f66e869a3447904343d6a6` |
| IMPHASH | `8d5c0bf2ad0db511b9e9bbcd2a45000e` |
| TLSH | `T1BF257851A3C78EB9F715E034C55D043DA5A7387386E056AA325C0EEA1B326D34BF9A3C` |
| SSDEEP | `12288:FGFYaQTLB7FcXoat5WlNY69jT2dJs5OXyhZVwzh/wZ8W5+9:FtTG/8lNYQjT2dJc5a5S5s` |
| ICON-DHASH | `0c3161cccc61310c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_5409085e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5409085ecec901891f284ae11b3f1e53acc24483cec458ff5e32f5073caef8f3"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:21:50"
  condition:
    hash.sha256(0, filesize) == "5409085ecec901891f284ae11b3f1e53acc24483cec458ff5e32f5073caef8f3"
}
```

### Sample 93: `2eefa765980ba35c`

| Field | Value |
|---|---|
| SHA-256 | `2eefa765980ba35c50047822903895501061062d17cccc296edd2ae8df3e5099` |
| Family label | `unknown` |
| File name | `DvnX.exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:21:28` |
| Reporter | `AmadeyHunter` |
| Tags | `DvnX, exe, stealer, Warden, WARDENStealer, Yap, YapStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ac1869934ee3fa7882c4cbdb75a2f55` |
| SHA-1 | `ca53c9d48a0357482ec9bbbe2073da0d4bc79ac6` |
| SHA-256 | `2eefa765980ba35c50047822903895501061062d17cccc296edd2ae8df3e5099` |
| SHA3-384 | `b3f587f2af46aa168cad325840e41624a24e32f253abcdd0a562e14f756a891a28f48e166ea839d98630d0aa2240fe3b` |
| IMPHASH | `ed9fc02075c0fb67c253f2b8af148924` |
| TLSH | `T1C145E061F3953EF5F42A85F08971E1028A31BC151BD01AFBA28C17DB4D32AD1BBFA615` |
| SSDEEP | `24576:0VdORUV3AiN6MsohGLL7mgppQtaM2wrh6fOpCp:wAasbktx2Yk` |
| ICON-DHASH | `6816716969711628` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_2eefa765
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2eefa765980ba35c50047822903895501061062d17cccc296edd2ae8df3e5099"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:21:28"
  condition:
    hash.sha256(0, filesize) == "2eefa765980ba35c50047822903895501061062d17cccc296edd2ae8df3e5099"
}
```

### Sample 94: `42a052758f12f875`

| Field | Value |
|---|---|
| SHA-256 | `42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-10-22 22:20:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1608209a6c0ab495607f6e66e9e5b954` |
| SHA-1 | `5fbca3c0ade56aa4076014dbaa5d784ef24eec7b` |
| SHA-256 | `42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf` |
| SHA3-384 | `6cf67d60ad09b74dcc0e0392061e7e4458bea74be58cb4cb710ce64ed36b36c45aa1b99f30525aca9e801c5f6b3459fb` |
| TLSH | `T181B34973D8266F58C659D074B0B18F792F53A69092471FBE19B7C2B84083D8DF609BB8` |
| SSDEEP | `1536:BUc/zQzYQZc4nvQtfcCgedKoA94fbikEMhH+WWe9u52DTwS4:BVLQze64tkZeEoXihq+WH9u5yb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_42a05275
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-22 22:20:23"
  condition:
    hash.sha256(0, filesize) == "42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf"
}
```

### Sample 95: `516c06a9dfe14672`

| Field | Value |
|---|---|
| SHA-256 | `516c06a9dfe146725cd34cd702626f5e68c7f2beff5f44c91f04f816d60ba77f` |
| Family label | `unknown` |
| File name | `Sеt_Uр [UРD].exe` |
| File type | `exe` |
| First seen | `2026-10-22 22:18:49` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c45b9ceeba260a1d04ed25a979c23393` |
| SHA-1 | `d463bb4da41d820bc958462161155db7e4123dab` |
| SHA-256 | `516c06a9dfe146725cd34cd702626f5e68c7f2beff5f44c91f04f816d60ba77f` |
| SHA3-384 | `521eee240af8c935f314bde8e351c4de48d10b4b2618e891a495c14807fb0e70679fdf11049caecb40b1096ef69f2d84` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1A5465A237AD185A5C06EDB76C4B26556A620B88DCB3173D32E60FB742EA03C49E7DF11` |
| SSDEEP | `98304:jTXbCSEvA0kPww0VTwUBKmwZO1ASph43Qc:jnCSj0nbJNo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_516c06a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "516c06a9dfe146725cd34cd702626f5e68c7f2beff5f44c91f04f816d60ba77f"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:18:49"
  condition:
    hash.sha256(0, filesize) == "516c06a9dfe146725cd34cd702626f5e68c7f2beff5f44c91f04f816d60ba77f"
}
```

### Sample 96: `7e8b2f481f827c41`

| Field | Value |
|---|---|
| SHA-256 | `7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4` |
| Family label | `Mirai` |
| File name | `main_x86_64` |
| File type | `elf` |
| First seen | `2026-10-22 22:14:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f45f5d592b24600ae3f877f54e4edd1` |
| SHA-1 | `78bb85f25d514c590767d633a4a611c386bd318c` |
| SHA-256 | `7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4` |
| SHA3-384 | `89d423883a1ab3feb30ec978df7e157999306affaf3cff6e1becd3bc6e46e7015cc88e50093d7d020411e17370d7fe4a` |
| TLSH | `T1EED34B17B5C180FEC4DAC1744B9AF53AAD33B1AD1238B15B27C4AB232E89E315F1D954` |
| TELFHASH | `t15851d1b03a593c94a1fbfb76734be5d0ac721a2544e031d4de7764e2df473800d65862` |
| SSDEEP | `3072:9GKS9psjG0BFgLb3L/VVyR88xX0wSGs5ssTMpFGhu4J:9GKS9psjG0BFgLKFY9tJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_7e8b2f48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-10-22 22:14:22"
  condition:
    hash.sha256(0, filesize) == "7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4"
}
```

### Sample 97: `d849fb8000891cf3`

| Field | Value |
|---|---|
| SHA-256 | `d849fb8000891cf3cca1b755eac2eda328135ae73041cfcd6f7eb612f6b9ab20` |
| Family label | `unknown` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-22 22:14:19` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e6d456454019b25a0f9ad4a1ea5d407` |
| SHA-1 | `08df49e73f0f5584d5a96ebc038d27f612eab8c7` |
| SHA-256 | `d849fb8000891cf3cca1b755eac2eda328135ae73041cfcd6f7eb612f6b9ab20` |
| SHA3-384 | `3af98dcce7f414a4b42c760b9a18ce94c8d5b3f92ec4a091357dc843509ee33b992f92048cfa349d5c394b7b9fb10fd8` |
| TLSH | `T1EF141965F8A16722C5E7737AEB7E4288333A9378C7EA310385341A207BFA53E0D76455` |
| TELFHASH | `t10a114829954419cc3ad4e0f9d0ad5306161e31f53d651415e7f4ca1fdd13ad27112d1f` |
| SSDEEP | `3072:F96kTtlSDhb7B/QDFf8AXYuB+ngkNX/5C4peOfDDIgetE6g2:F97TkB/iFf8AXTEgav84wOf/Ig96t` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_d849fb80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d849fb8000891cf3cca1b755eac2eda328135ae73041cfcd6f7eb612f6b9ab20"
    family = "unknown"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-22 22:14:19"
  condition:
    hash.sha256(0, filesize) == "d849fb8000891cf3cca1b755eac2eda328135ae73041cfcd6f7eb612f6b9ab20"
}
```

### Sample 98: `a0f4f36aba15058c`

| Field | Value |
|---|---|
| SHA-256 | `a0f4f36aba15058cd3b01bb68c90574d1fb44c5408cd909727f9f60ebdd6fa73` |
| Family label | `unknown` |
| File name | `TikTok18_v1.6.1.apk` |
| File type | `apk` |
| First seen | `2026-10-22 22:05:47` |
| Reporter | `MaxMax66` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9afbe44b1dd33026850913db540c578` |
| SHA-1 | `ae663604e123748e8caf1820085496b6ab126e2c` |
| SHA-256 | `a0f4f36aba15058cd3b01bb68c90574d1fb44c5408cd909727f9f60ebdd6fa73` |
| SHA3-384 | `54ee2fc196ebb0f7953c27859501274e6bd9e3e9cccb2e0783476045dd4171c8074617612f853c1d1bc47bc19d4876b4` |
| TLSH | `T16DD63315FE2EEC37DDC3743DA6521250231574CC6270C3AE86298654AEDB7F8AB297C2` |
| SSDEEP | `393216:1ATanX4PjRn439i/qG++Xt0v3l8BqId9KMFs:1XQNi40d8cIdDs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_a0f4f36a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f4f36aba15058cd3b01bb68c90574d1fb44c5408cd909727f9f60ebdd6fa73"
    family = "unknown"
    file_name = "TikTok18_v1.6.1.apk"
    file_type = "apk"
    first_seen = "2026-10-22 22:05:47"
  condition:
    hash.sha256(0, filesize) == "a0f4f36aba15058cd3b01bb68c90574d1fb44c5408cd909727f9f60ebdd6fa73"
}
```

### Sample 99: `273b6cd05d03c82d`

| Field | Value |
|---|---|
| SHA-256 | `273b6cd05d03c82d836d6ad298bfae66a696ca857856b9f9bf5c77e8d1fee949` |
| Family label | `Mirai` |
| File name | `adb.arm7` |
| File type | `elf` |
| First seen | `2026-10-22 22:05:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a18334278d9b38518dc6b16262b9cfac` |
| SHA-1 | `4f7669a41ab741197a85607c700ab09fd93c7707` |
| SHA-256 | `273b6cd05d03c82d836d6ad298bfae66a696ca857856b9f9bf5c77e8d1fee949` |
| SHA3-384 | `bb54863849b16bd3af5f95a71d2b30d86395b2185d714be6af5968e2104d5dce5f0e1a0f739e0be7ddaf4ca32478b791` |
| TLSH | `T10E14F925B8916B11D0E373BAEBBE41443367AB78CBB97003C5305F6167FA5AE0E72425` |
| TELFHASH | `t158b01240ec1d04c0f440421cc1e2e70715f4eb04030c41de49095f0f06a3459f449533` |
| SSDEEP | `6144:G0XKNG2TBCeLd9eaeYIh9bvxthG1sCZndUiFz/:t4J59eaeYybvxrkZndU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_273b6cd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "273b6cd05d03c82d836d6ad298bfae66a696ca857856b9f9bf5c77e8d1fee949"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-22 22:05:20"
  condition:
    hash.sha256(0, filesize) == "273b6cd05d03c82d836d6ad298bfae66a696ca857856b9f9bf5c77e8d1fee949"
}
```

### Sample 100: `40b37052ecb9c653`

| Field | Value |
|---|---|
| SHA-256 | `40b37052ecb9c65331d7bd23730b95477311ecc468cfe980f2b1201ae3a3eeca` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-22 22:00:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef739ec7d42135b97304b51402fcb742` |
| SHA-1 | `d221cf40df05547cf77d35d42ffce85ddd165156` |
| SHA-256 | `40b37052ecb9c65331d7bd23730b95477311ecc468cfe980f2b1201ae3a3eeca` |
| SHA3-384 | `879e481deed4826e7e664a0272a512f323860983ea65feb0c8525d2bca911ad0891f673709711d7f9d797c7264a57ce4` |
| TLSH | `T1E8556BBBF2A770BCC167D030479BCBA2AC35B4B501212D7B61C4A9723D62DE11766B27` |
| TELFHASH | `t1b8d1be700bf635b562dbda20b323f4798d3218ba64f435f466227d88ef85e814c6e427` |
| SSDEEP | `24576:O72CX9B92yGNnDg7pbPsTwxAYPWTM2VyYO7WzYSkuYJmO:OSCX9B9tGNnD+pb0qAYPWTM2wza6f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_40b37052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b37052ecb9c65331d7bd23730b95477311ecc468cfe980f2b1201ae3a3eeca"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-22 22:00:03"
  condition:
    hash.sha256(0, filesize) == "40b37052ecb9c65331d7bd23730b95477311ecc468cfe980f2b1201ae3a3eeca"
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
 * Generated: 2026-10-23T05:01:35.247613+00:00
 */

rule MalwareBazaar_unknown_001_67b75dbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64"
    family = "unknown"
    file_name = "macho_67b75dbf7e0f.bin"
    file_type = "macho"
    first_seen = "2026-10-23 04:23:53"
  condition:
    hash.sha256(0, filesize) == "67b75dbf7e0fa3009c3726b03cafd47b8eea8b7bd937409de615015410b3aa64"
}

rule MalwareBazaar_unknown_002_b71398a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b71398a8229279163dd8ad582ac42dcc0e5bcc8146f461a9731965f535d6e127"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-23 04:23:19"
  condition:
    hash.sha256(0, filesize) == "b71398a8229279163dd8ad582ac42dcc0e5bcc8146f461a9731965f535d6e127"
}

rule MalwareBazaar_unknown_003_2cd3f398
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
    family = "unknown"
    file_name = "lure_compact_fullchain.exe"
    file_type = "exe"
    first_seen = "2026-10-23 04:10:38"
  condition:
    hash.sha256(0, filesize) == "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
}

rule MalwareBazaar_unknown_004_9933977b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce"
    family = "unknown"
    file_name = "stage2_stealer.exe"
    file_type = "exe"
    first_seen = "2026-10-23 04:10:25"
  condition:
    hash.sha256(0, filesize) == "9933977b38adbe73cc852ffca785c4111b7922de7e515801ec8411e9e25708ce"
}

rule MalwareBazaar_unknown_005_1374af95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1374af95ac03b0896be17444a0febe146378221e0994ea2991024599d593b43b"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-23 04:01:42"
  condition:
    hash.sha256(0, filesize) == "1374af95ac03b0896be17444a0febe146378221e0994ea2991024599d593b43b"
}

rule MalwareBazaar_unknown_006_5a93efa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a93efa8254937532bfbb7b583d826ec493263f12e9eaef6b22592a69416c285"
    family = "unknown"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-10-23 03:59:13"
  condition:
    hash.sha256(0, filesize) == "5a93efa8254937532bfbb7b583d826ec493263f12e9eaef6b22592a69416c285"
}

rule MalwareBazaar_unknown_007_0db860c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8"
    family = "unknown"
    file_name = "System Process.dll"
    file_type = "exe"
    first_seen = "2026-10-23 03:51:06"
  condition:
    hash.sha256(0, filesize) == "0db860c62ce8c95ae3018ef4ded4711bc212d9bd54d4da1063da18790dbecac8"
}

rule MalwareBazaar_unknown_008_9c21d2e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8"
    family = "unknown"
    file_name = "SystemProcess-bundle.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:50:52"
  condition:
    hash.sha256(0, filesize) == "9c21d2e50468272329df31911ae3737e7b74a2db5ce33f5e0beccd36582d89c8"
}

rule MalwareBazaar_Mirai_009_cd1b531e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-23 03:47:51"
  condition:
    hash.sha256(0, filesize) == "cd1b531e13ccd3b443a2f439d958d05b632937209acf44be358584c6e605c8be"
}

rule MalwareBazaar_unknown_010_faf0bc67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-23 03:34:43"
  condition:
    hash.sha256(0, filesize) == "faf0bc67308eb8eb4261e918c57e187eef458d87d6ba64a591b2e6672b771d9d"
}

rule MalwareBazaar_unknown_011_87f4c975
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1"
    family = "unknown"
    file_name = "bot.mipsel"
    file_type = "elf"
    first_seen = "2026-10-23 03:34:41"
  condition:
    hash.sha256(0, filesize) == "87f4c9758c73198c38289dcc3cdbe032b9ebc5d39115f2c2cb187d2396edc2c1"
}

rule MalwareBazaar_unknown_012_82706984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82706984f1b92070cf14109888f79d754aedbcff93f4322c9558d818da7f8a5a"
    family = "unknown"
    file_name = "launcher.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:33:31"
  condition:
    hash.sha256(0, filesize) == "82706984f1b92070cf14109888f79d754aedbcff93f4322c9558d818da7f8a5a"
}

rule MalwareBazaar_AokigaharaStealer_013_64f8a2e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64f8a2e463e90c05bfef709f4747224b39d0b69461a6fe646f1da9d4f509df9e"
    family = "AokigaharaStealer"
    file_name = "glaicer.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:33:18"
  condition:
    hash.sha256(0, filesize) == "64f8a2e463e90c05bfef709f4747224b39d0b69461a6fe646f1da9d4f509df9e"
}

rule MalwareBazaar_unknown_014_ba419690
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba419690cd762058a0037d11619c8a1fe5b6690c2f359addc91375c0712ed366"
    family = "unknown"
    file_name = "ba419690cd762058.bin"
    file_type = "exe"
    first_seen = "2026-10-23 03:25:14"
  condition:
    hash.sha256(0, filesize) == "ba419690cd762058a0037d11619c8a1fe5b6690c2f359addc91375c0712ed366"
}

rule MalwareBazaar_Adware_OfferCore_015_9ba0ffb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ba0ffb9e9cc6c0001239d647f5e5a5a7f22d162798c8312fc65e31cf55ce7ca"
    family = "Adware.OfferCore"
    file_name = "9ba0ffb9e9cc6c00.bin"
    file_type = "exe"
    first_seen = "2026-10-23 03:25:01"
  condition:
    hash.sha256(0, filesize) == "9ba0ffb9e9cc6c0001239d647f5e5a5a7f22d162798c8312fc65e31cf55ce7ca"
}

rule MalwareBazaar_SalatStealer_016_677b6c7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "677b6c7d9a094c40c57ec2c77a07bbb9f992eb9850c24c6f4fc037152aeb8f31"
    family = "SalatStealer"
    file_name = "Xeno-v1.3.60.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:22:16"
  condition:
    hash.sha256(0, filesize) == "677b6c7d9a094c40c57ec2c77a07bbb9f992eb9850c24c6f4fc037152aeb8f31"
}

rule MalwareBazaar_unknown_017_0c0940c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-23 03:19:53"
  condition:
    hash.sha256(0, filesize) == "0c0940c543d28b134dd55313b27eeb05489902f6c59bb162ff2805ec39d45902"
}

rule MalwareBazaar_Mirai_018_d63bcebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6"
    family = "Mirai"
    file_name = "d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:24"
  condition:
    hash.sha256(0, filesize) == "d63bcebff095babf029f77d80797984c73ba3ba7ab071b1fe43640d29bc249f6"
}

rule MalwareBazaar_Mirai_019_d41653b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa"
    family = "Mirai"
    file_name = "d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:20"
  condition:
    hash.sha256(0, filesize) == "d41653b6ed41c5626788ec35917cc812b703d4559bb133a6b3f22e37a70002fa"
}

rule MalwareBazaar_Mirai_020_b6aec7e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e"
    family = "Mirai"
    file_name = "b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:16"
  condition:
    hash.sha256(0, filesize) == "b6aec7e19e75aa2c85670ff8ded4bf2ab407dd8272416bb1d8d9cdbadf310e2e"
}

rule MalwareBazaar_Mirai_021_5f4b862e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0"
    family = "Mirai"
    file_name = "5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:12"
  condition:
    hash.sha256(0, filesize) == "5f4b862ec05beb9df7363bbf3fc06adac31045759fd80126c6431b7ab4cb60b0"
}

rule MalwareBazaar_Mirai_022_4b49891a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6"
    family = "Mirai"
    file_name = "4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6"
    file_type = "elf"
    first_seen = "2026-10-23 03:17:09"
  condition:
    hash.sha256(0, filesize) == "4b49891a0209264ea901a5b024f30a21af5f0a6a65d2355d8df7de81bda9abd6"
}

rule MalwareBazaar_VShell_023_4feed588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4feed588acc1396e2deeb1fc04f145cfca464ba7617dc3c1c9fe7dcc545d2d1d"
    family = "VShell"
    file_name = ".sysd"
    file_type = "elf"
    first_seen = "2026-10-23 02:41:03"
  condition:
    hash.sha256(0, filesize) == "4feed588acc1396e2deeb1fc04f145cfca464ba7617dc3c1c9fe7dcc545d2d1d"
}

rule MalwareBazaar_Mirai_024_ce233354
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce23335488686504739da1a00270b71a444ab4165b341fda116ff08d705bf914"
    family = "Mirai"
    file_name = "linux_arm"
    file_type = "elf"
    first_seen = "2026-10-23 02:40:53"
  condition:
    hash.sha256(0, filesize) == "ce23335488686504739da1a00270b71a444ab4165b341fda116ff08d705bf914"
}

rule MalwareBazaar_Mirai_025_407fb53e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "407fb53e62d4ed0e2d043b60f0916ff77ef2b8fba3dc0f6594218a4877edb5aa"
    family = "Mirai"
    file_name = "linux_arm64"
    file_type = "elf"
    first_seen = "2026-10-23 02:40:45"
  condition:
    hash.sha256(0, filesize) == "407fb53e62d4ed0e2d043b60f0916ff77ef2b8fba3dc0f6594218a4877edb5aa"
}

rule MalwareBazaar_Mirai_026_5fbd46e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fbd46e376797b75f5455775d0e62dcfdb30e81375c45fb20e0c31593a37da1b"
    family = "Mirai"
    file_name = "linux_i386"
    file_type = "elf"
    first_seen = "2026-10-23 02:40:36"
  condition:
    hash.sha256(0, filesize) == "5fbd46e376797b75f5455775d0e62dcfdb30e81375c45fb20e0c31593a37da1b"
}

rule MalwareBazaar_Mirai_027_187c25e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "187c25e0604530f5f6a8ee79b0798f89ef0a132dbe69b55b6afb1f2583f84b2b"
    family = "Mirai"
    file_name = "linux_amd64"
    file_type = "elf"
    first_seen = "2026-10-23 02:39:59"
  condition:
    hash.sha256(0, filesize) == "187c25e0604530f5f6a8ee79b0798f89ef0a132dbe69b55b6afb1f2583f84b2b"
}

rule MalwareBazaar_unknown_028_5c54ede3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c54ede33db8a4af5c7574eb1cde60444ff3f6c3c742222139abaea3dc6bd6b3"
    family = "unknown"
    file_name = "linux.sh"
    file_type = "sh"
    first_seen = "2026-10-23 02:39:51"
  condition:
    hash.sha256(0, filesize) == "5c54ede33db8a4af5c7574eb1cde60444ff3f6c3c742222139abaea3dc6bd6b3"
}

rule MalwareBazaar_unknown_029_8ce1805f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606"
    family = "unknown"
    file_name = "vq-sp-lure-trimmed.exe"
    file_type = "exe"
    first_seen = "2026-10-23 02:31:14"
  condition:
    hash.sha256(0, filesize) == "8ce1805f5b1ca8c4ecd4d1731caf37de33c52e686200331f4a0ea4e6b31ff606"
}

rule MalwareBazaar_RemcosRAT_030_4e11133d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e"
    family = "RemcosRAT"
    file_name = "pesananpembeliankuartalterakhirtahun2026.JS.js"
    file_type = "js"
    first_seen = "2026-10-23 02:25:10"
  condition:
    hash.sha256(0, filesize) == "4e11133df35ffece8b92c73ee3239a1f85010d1f7a1722b846f9751b5ddc992e"
}

rule MalwareBazaar_unknown_031_c2d65bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94"
    family = "unknown"
    file_name = "c2d65bddfded3873.bin"
    file_type = "exe"
    first_seen = "2026-10-23 02:24:16"
  condition:
    hash.sha256(0, filesize) == "c2d65bddfded387376cf1e79d019684a260b11eb5aaecfd0f5855cfdf2179a94"
}

rule MalwareBazaar_unknown_032_5f7ca145
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f7ca145520351f85350d8a68b9188825cf0f9ef3868bbf32ec7fe703ca049ec"
    family = "unknown"
    file_name = "5f7ca145520351f8.bin"
    file_type = "msi"
    first_seen = "2026-10-23 02:24:08"
  condition:
    hash.sha256(0, filesize) == "5f7ca145520351f85350d8a68b9188825cf0f9ef3868bbf32ec7fe703ca049ec"
}

rule MalwareBazaar_Formbook_033_21af7d77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43"
    family = "Formbook"
    file_name = "21af7d776011760b.bin"
    file_type = "exe"
    first_seen = "2026-10-23 02:24:00"
  condition:
    hash.sha256(0, filesize) == "21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43"
}

rule MalwareBazaar_AsyncRAT_034_1a82e6ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9"
    family = "AsyncRAT"
    file_name = "1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9.exe"
    file_type = "exe"
    first_seen = "2026-10-23 01:47:23"
  condition:
    hash.sha256(0, filesize) == "1a82e6aebae1050a62c1aac0f671f9350e4c76a33b45f82875f818de5ae26fd9"
}

rule MalwareBazaar_RemcosRAT_035_ba981087
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1"
    family = "RemcosRAT"
    file_name = "20261023ISI.pdf.js"
    file_type = "js"
    first_seen = "2026-10-23 01:35:08"
  condition:
    hash.sha256(0, filesize) == "ba9810872fd8b1de1a7068d4175f564997d12bee1d2a0dd2d5b1a6dd5c41bee1"
}

rule MalwareBazaar_Mirai_036_840754d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec"
    family = "Mirai"
    file_name = "840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec"
    file_type = "elf"
    first_seen = "2026-10-23 01:33:02"
  condition:
    hash.sha256(0, filesize) == "840754d6bf7c2f74775330ac82626e8d8ce0ccaba54edfa89d466c15342a7eec"
}

rule MalwareBazaar_Mirai_037_cd355347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f"
    family = "Mirai"
    file_name = "cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f"
    file_type = "elf"
    first_seen = "2026-10-23 01:32:59"
  condition:
    hash.sha256(0, filesize) == "cd3553474afba34406ca288715a01c945dcf63adfd0cfdafbec47d074b86290f"
}

rule MalwareBazaar_Mirai_038_6c310c7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c310c7b49c95c834bf31f53e68578ca0f684b43d5750af6e0092bd191770cac"
    family = "Mirai"
    file_name = "mbupload-4me4pex1.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:30:21"
  condition:
    hash.sha256(0, filesize) == "6c310c7b49c95c834bf31f53e68578ca0f684b43d5750af6e0092bd191770cac"
}

rule MalwareBazaar_unknown_039_4b40fd9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b40fd9ccb2a4e33ebc668f98bcf0c14e0b87c088e0bbc4869d33091f3288488"
    family = "unknown"
    file_name = "4b40fd9ccb2a4e33.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:26:53"
  condition:
    hash.sha256(0, filesize) == "4b40fd9ccb2a4e33ebc668f98bcf0c14e0b87c088e0bbc4869d33091f3288488"
}

rule MalwareBazaar_Mirai_040_6eecc8a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eecc8a6959e2d9c2ad8ed338ef169e077fbd0372c38b41c55528dda0ca8e56b"
    family = "Mirai"
    file_name = "6eecc8a6959e2d9c.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:26:44"
  condition:
    hash.sha256(0, filesize) == "6eecc8a6959e2d9c2ad8ed338ef169e077fbd0372c38b41c55528dda0ca8e56b"
}

rule MalwareBazaar_Mirai_041_c6abdc7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6abdc7bdb43b73bbabe29d21fce583770c5af965ba5c8d23c98bbb24b3b331a"
    family = "Mirai"
    file_name = "c6abdc7bdb43b73b.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:26:33"
  condition:
    hash.sha256(0, filesize) == "c6abdc7bdb43b73bbabe29d21fce583770c5af965ba5c8d23c98bbb24b3b331a"
}

rule MalwareBazaar_unknown_042_d5ef33c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5ef33c409b3d6f6cd6d27d44099edb504ca56e62e15948d5f868ea29385a708"
    family = "unknown"
    file_name = "d5ef33c409b3d6f6.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:26:24"
  condition:
    hash.sha256(0, filesize) == "d5ef33c409b3d6f6cd6d27d44099edb504ca56e62e15948d5f868ea29385a708"
}

rule MalwareBazaar_unknown_043_178e3df3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "178e3df349f467280b6dc13a1ed3e329a54ea2d5e9bf1555b2f2797c07dbc115"
    family = "unknown"
    file_name = "178e3df349f46728.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:26:17"
  condition:
    hash.sha256(0, filesize) == "178e3df349f467280b6dc13a1ed3e329a54ea2d5e9bf1555b2f2797c07dbc115"
}

rule MalwareBazaar_Adware_OfferCore_044_63c825cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c825cdc37d8fda0bc6f3c5edf820c9157582ac7641de9c991499c7576a71ef"
    family = "Adware.OfferCore"
    file_name = "63c825cdc37d8fda.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:26:08"
  condition:
    hash.sha256(0, filesize) == "63c825cdc37d8fda0bc6f3c5edf820c9157582ac7641de9c991499c7576a71ef"
}

rule MalwareBazaar_Mirai_045_102398d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "102398d87e6fc027f91197033254b66504107a103b2d0508a7ca493a7e297f59"
    family = "Mirai"
    file_name = "102398d87e6fc027.bin"
    file_type = "elf"
    first_seen = "2026-10-23 01:25:59"
  condition:
    hash.sha256(0, filesize) == "102398d87e6fc027f91197033254b66504107a103b2d0508a7ca493a7e297f59"
}

rule MalwareBazaar_Adware_OfferCore_046_e2db18e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2db18e2c09abd2acf92d4869c5c3247e85e7ae09e9d5221125f01e1ed80137e"
    family = "Adware.OfferCore"
    file_name = "e2db18e2c09abd2a.bin"
    file_type = "exe"
    first_seen = "2026-10-23 01:25:50"
  condition:
    hash.sha256(0, filesize) == "e2db18e2c09abd2acf92d4869c5c3247e85e7ae09e9d5221125f01e1ed80137e"
}

rule MalwareBazaar_unknown_047_c3bca04a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103"
    family = "unknown"
    file_name = "macho_c3bca04a525e.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:17:15"
  condition:
    hash.sha256(0, filesize) == "c3bca04a525efbce865d03bd7cc7631c7dca3e9c50f4e1949c955541e3660103"
}

rule MalwareBazaar_unknown_048_71fbe49d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d"
    family = "unknown"
    file_name = "macho_71fbe49d223d.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:14:39"
  condition:
    hash.sha256(0, filesize) == "71fbe49d223d272852212f304d1dfa207b671b060426a3e619e6c0c6813b589d"
}

rule MalwareBazaar_unknown_049_54022fe4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54022fe4cfdaf50065aff8ba63fba9f3df77a483fec5c805047fc9a3f9f55245"
    family = "unknown"
    file_name = "macho_54022fe4cfda.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:12:08"
  condition:
    hash.sha256(0, filesize) == "54022fe4cfdaf50065aff8ba63fba9f3df77a483fec5c805047fc9a3f9f55245"
}

rule MalwareBazaar_unknown_050_ab253de6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26"
    family = "unknown"
    file_name = "macho_ab253de69245.bin"
    file_type = "macho"
    first_seen = "2026-10-23 01:09:34"
  condition:
    hash.sha256(0, filesize) == "ab253de6924568c6a4574561fc6ec14ee98e5fd48e98162245c71a612af96a26"
}

rule MalwareBazaar_unknown_051_ec3eab84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b"
    family = "unknown"
    file_name = "ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b"
    file_type = "sh"
    first_seen = "2026-10-23 01:00:04"
  condition:
    hash.sha256(0, filesize) == "ec3eab84f83fc05506e42c081ec3cd2d9d08cbd457f931abc1f09d69930b309b"
}

rule MalwareBazaar_Mirai_052_5bbc0e96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd"
    family = "Mirai"
    file_name = "5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd"
    file_type = "elf"
    first_seen = "2026-10-23 00:46:06"
  condition:
    hash.sha256(0, filesize) == "5bbc0e96d7bb507f8ebfe4739cc20647bab9fc5598519941762397a04df232fd"
}

rule MalwareBazaar_Mirai_053_3934bb8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c"
    family = "Mirai"
    file_name = "3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c"
    file_type = "elf"
    first_seen = "2026-10-23 00:46:04"
  condition:
    hash.sha256(0, filesize) == "3934bb8fe8757867c5f5ec0d68acedb2339fa49adf2afa81822d0868f8b2372c"
}

rule MalwareBazaar_Mirai_054_c38eaf2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595"
    family = "Mirai"
    file_name = "c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595"
    file_type = "elf"
    first_seen = "2026-10-23 00:46:01"
  condition:
    hash.sha256(0, filesize) == "c38eaf2b436cefd15e73bfa0a143d996cac708c1bccc9d3ce9b371b418e85595"
}

rule MalwareBazaar_Mirai_055_629184be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277"
    family = "Mirai"
    file_name = "629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277"
    file_type = "elf"
    first_seen = "2026-10-23 00:45:58"
  condition:
    hash.sha256(0, filesize) == "629184be428a5bfe702aa9efbe710375dbd4ce653f15fecdf052b6797a272277"
}

rule MalwareBazaar_unknown_056_478d4d69
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "478d4d6936c7704f3e9ef4caf15d922bcd5244eab747518d97bdffde4fdbbf92"
    family = "unknown"
    file_name = "greth.dll"
    file_type = "exe"
    first_seen = "2026-10-23 00:34:54"
  condition:
    hash.sha256(0, filesize) == "478d4d6936c7704f3e9ef4caf15d922bcd5244eab747518d97bdffde4fdbbf92"
}

rule MalwareBazaar_unknown_057_0836bbf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0836bbf73331c7727b236e42cea87a7096f58bcf4e3ba04f539f5669be0c8643"
    family = "unknown"
    file_name = "yjhyt.exe"
    file_type = "exe"
    first_seen = "2026-10-23 00:34:28"
  condition:
    hash.sha256(0, filesize) == "0836bbf73331c7727b236e42cea87a7096f58bcf4e3ba04f539f5669be0c8643"
}

rule MalwareBazaar_unknown_058_bb220f8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb220f8a648cfe810397ef0cb69e0c93c5913929828e0696e257d9f149064c7d"
    family = "unknown"
    file_name = "gverbbv.exe"
    file_type = "exe"
    first_seen = "2026-10-23 00:34:13"
  condition:
    hash.sha256(0, filesize) == "bb220f8a648cfe810397ef0cb69e0c93c5913929828e0696e257d9f149064c7d"
}

rule MalwareBazaar_unknown_059_6278c5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602"
    family = "unknown"
    file_name = "6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602.exe"
    file_type = "exe"
    first_seen = "2026-10-23 00:32:26"
  condition:
    hash.sha256(0, filesize) == "6278c5d5f5ae25c76da912cd2d094898ae7c91972cdc8ebac25b7b8ab2bef602"
}

rule MalwareBazaar_unknown_060_6a3a45ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a3a45ed8e0ae10013252651c2eeff306f6b31f9d4379a3e14db961a6ed85914"
    family = "unknown"
    file_name = "6a3a45ed8e0ae100.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:24:38"
  condition:
    hash.sha256(0, filesize) == "6a3a45ed8e0ae10013252651c2eeff306f6b31f9d4379a3e14db961a6ed85914"
}

rule MalwareBazaar_Mirai_061_395f7031
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "395f7031ffaf797e82da79644d29df07e06d010a3dbf2eb930d3a3163ce9d01d"
    family = "Mirai"
    file_name = "395f7031ffaf797e.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:30"
  condition:
    hash.sha256(0, filesize) == "395f7031ffaf797e82da79644d29df07e06d010a3dbf2eb930d3a3163ce9d01d"
}

rule MalwareBazaar_Mirai_062_01e53600
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
    family = "Mirai"
    file_name = "01e5360067eb7576.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:21"
  condition:
    hash.sha256(0, filesize) == "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
}

rule MalwareBazaar_unknown_063_c7bebd02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983"
    family = "unknown"
    file_name = "macho_c7bebd02f8db.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:24:15"
  condition:
    hash.sha256(0, filesize) == "c7bebd02f8db04103ac5f83078e634535db5ff1d3a59fe241b707c36813d2983"
}

rule MalwareBazaar_Mirai_064_1a414a45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a414a458c66e3c967737c7895e01412909bffe28919ecfbad859caddc6aaa38"
    family = "Mirai"
    file_name = "1a414a458c66e3c9.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:12"
  condition:
    hash.sha256(0, filesize) == "1a414a458c66e3c967737c7895e01412909bffe28919ecfbad859caddc6aaa38"
}

rule MalwareBazaar_Mirai_065_aa0f3a50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa0f3a504da0c4a16fb064f5bd2c23d1a977cbf05d6e1dea9f6efd57c3d32324"
    family = "Mirai"
    file_name = "aa0f3a504da0c4a1.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:24:03"
  condition:
    hash.sha256(0, filesize) == "aa0f3a504da0c4a16fb064f5bd2c23d1a977cbf05d6e1dea9f6efd57c3d32324"
}

rule MalwareBazaar_Formbook_066_b6d03e3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299"
    family = "Formbook"
    file_name = "b6d03e3f9c178c77.bin"
    file_type = "exe"
    first_seen = "2026-10-23 00:23:54"
  condition:
    hash.sha256(0, filesize) == "b6d03e3f9c178c77eb32e730e8e690fa844ffd73f49a8fa0c6c37ea09956e299"
}

rule MalwareBazaar_Snowlight_067_561095ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840"
    family = "Snowlight"
    file_name = "561095acf398b0ed.bin"
    file_type = "elf"
    first_seen = "2026-10-23 00:23:46"
  condition:
    hash.sha256(0, filesize) == "561095acf398b0edcdbb36719488782814bf9c4410907c6095107b4414941840"
}

rule MalwareBazaar_unknown_068_3169f139
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71"
    family = "unknown"
    file_name = "macho_3169f1396332.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:21:45"
  condition:
    hash.sha256(0, filesize) == "3169f13963324e6b06335f3f19c672630ddc0c0da423b2d0bdd9378d1de6de71"
}

rule MalwareBazaar_unknown_069_27e4adf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9"
    family = "unknown"
    file_name = "macho_27e4adf26375.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:18:54"
  condition:
    hash.sha256(0, filesize) == "27e4adf26375ac044a8631d8998471b0c4746635cb8e45d9f12e5d6a24d080d9"
}

rule MalwareBazaar_unknown_070_946de91e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "946de91e0b3aaf6bc466d9bf11df1b4ed74f24ef301dff697010ee15918f88f9"
    family = "unknown"
    file_name = "macho_946de91e0b3a.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:16:20"
  condition:
    hash.sha256(0, filesize) == "946de91e0b3aaf6bc466d9bf11df1b4ed74f24ef301dff697010ee15918f88f9"
}

rule MalwareBazaar_unknown_071_9081546d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839"
    family = "unknown"
    file_name = "macho_9081546dcd85.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:13:39"
  condition:
    hash.sha256(0, filesize) == "9081546dcd8528fa3b26aabcab3baf5ece17faadcb0f6e697e7591f73c6ed839"
}

rule MalwareBazaar_unknown_072_6d2c7f18
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5"
    family = "unknown"
    file_name = "macho_6d2c7f1837bd.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:11:01"
  condition:
    hash.sha256(0, filesize) == "6d2c7f1837bd52c975c29c8ac8c0bc2f4b5b688ac987482da05c77e0ea2295c5"
}

rule MalwareBazaar_unknown_073_b2a38245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03"
    family = "unknown"
    file_name = "macho_b2a38245d0cd.bin"
    file_type = "macho"
    first_seen = "2026-10-23 00:08:06"
  condition:
    hash.sha256(0, filesize) == "b2a38245d0cd7985793e03df229a46ea8cee0941b8b1dc116a3a128e8fe1aa03"
}

rule MalwareBazaar_Mirai_074_d2c1df26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c1df26f01a178a3450da75022bdaf24a2427e9367531758969eb61147b9726"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-10-22 23:48:31"
  condition:
    hash.sha256(0, filesize) == "d2c1df26f01a178a3450da75022bdaf24a2427e9367531758969eb61147b9726"
}

rule MalwareBazaar_DCRat_075_10ff3c82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec"
    family = "DCRat"
    file_name = "250df0e912b813ee97bf1408bda36823.exe"
    file_type = "exe"
    first_seen = "2026-10-22 23:40:10"
  condition:
    hash.sha256(0, filesize) == "10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec"
}

rule MalwareBazaar_Mirai_076_13a4f1bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-10-22 23:33:25"
  condition:
    hash.sha256(0, filesize) == "13a4f1bb7f3db7a90412ba7badf1edf7aec3574897d5aaafd1b18d4d375ed144"
}

rule MalwareBazaar_Mirai_077_8d88cda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d88cda5439279eb70e789a8718f8f27a40d328bc674d6d5197731935dbd16a5"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-22 23:27:17"
  condition:
    hash.sha256(0, filesize) == "8d88cda5439279eb70e789a8718f8f27a40d328bc674d6d5197731935dbd16a5"
}

rule MalwareBazaar_Mirai_078_2cf96dfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cf96dfd5f99e9a713385fe5afb63ff97acc88abca00676de7f200d42c70e4e1"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-22 23:24:16"
  condition:
    hash.sha256(0, filesize) == "2cf96dfd5f99e9a713385fe5afb63ff97acc88abca00676de7f200d42c70e4e1"
}

rule MalwareBazaar_Mirai_079_65988926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-22 23:15:18"
  condition:
    hash.sha256(0, filesize) == "65988926d1a02d38a6c08ee0e0dbb966dabcb337aff3344c635fd53e43512d8d"
}

rule MalwareBazaar_Mirai_080_35e9f244
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-22 23:15:16"
  condition:
    hash.sha256(0, filesize) == "35e9f2443d7fa3c500ab7be64d9ffb5f90fd30453f4e4d3adfe43b6ecce8330e"
}

rule MalwareBazaar_Mirai_081_74fd8f8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-22 22:58:20"
  condition:
    hash.sha256(0, filesize) == "74fd8f8e014d46d84e66a98937ee7d35120779f613cdda6c995d233690442061"
}

rule MalwareBazaar_Mirai_082_b9b00a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-22 22:55:18"
  condition:
    hash.sha256(0, filesize) == "b9b00a11b0bdecee5e9e1a56a89611267cc5881b258196e4df6166372ba1ea98"
}

rule MalwareBazaar_Mirai_083_b8529448
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-22 22:34:48"
  condition:
    hash.sha256(0, filesize) == "b8529448ca17ba76f5dbc39be1fd5d82c83bac8e2dd946e84b13414666967d9f"
}

rule MalwareBazaar_Mirai_084_0cbe035f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f"
    family = "Mirai"
    file_name = "main_arm6"
    file_type = "elf"
    first_seen = "2026-10-22 22:29:15"
  condition:
    hash.sha256(0, filesize) == "0cbe035f5448441ebe342c3a8584c8935fff2e62ce7f772ac4baff3342e7ed1f"
}

rule MalwareBazaar_RemusStealer_085_a9892231
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf"
    family = "RemusStealer"
    file_name = "ХLосitуХ64-v.7.911.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:28:26"
  condition:
    hash.sha256(0, filesize) == "a9892231ad0534bac12f3bb619d3a4497aaf52d1c8b7183bcd985ec0c4c10eaf"
}

rule MalwareBazaar_unknown_086_a65c89eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff"
    family = "unknown"
    file_name = "a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:28:07"
  condition:
    hash.sha256(0, filesize) == "a65c89eb77e80859ae06282f65c0df229c09decd34ffb53fa9827b25043acbff"
}

rule MalwareBazaar_unknown_087_9b206fbf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b206fbfb1ffce27c8b641989f690e701437e7e91fdbfdea808dff935c2529f3"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:24:35"
  condition:
    hash.sha256(0, filesize) == "9b206fbfb1ffce27c8b641989f690e701437e7e91fdbfdea808dff935c2529f3"
}

rule MalwareBazaar_Mirai_088_c266ce7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131"
    family = "Mirai"
    file_name = "main_arm"
    file_type = "elf"
    first_seen = "2026-10-22 22:23:23"
  condition:
    hash.sha256(0, filesize) == "c266ce7a2343af69f35a1bc1f5b07678672732765882150fa1789ce48347d131"
}

rule MalwareBazaar_unknown_089_4c6328fa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c6328fa44c5ddb6ebe42728fa85f08cfacee13afdd44f1883a7be80e530b301"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:22:48"
  condition:
    hash.sha256(0, filesize) == "4c6328fa44c5ddb6ebe42728fa85f08cfacee13afdd44f1883a7be80e530b301"
}

rule MalwareBazaar_unknown_090_2f4d8f8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f4d8f8e668dfa68f74167247b15ce87d4e0d3f1eff61d6712aeacce03d87af2"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:22:31"
  condition:
    hash.sha256(0, filesize) == "2f4d8f8e668dfa68f74167247b15ce87d4e0d3f1eff61d6712aeacce03d87af2"
}

rule MalwareBazaar_unknown_091_92774f66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:22:11"
  condition:
    hash.sha256(0, filesize) == "92774f66be66de1cbab4520cbd15144024e6cd50f58758aca335e25266a72c3d"
}

rule MalwareBazaar_unknown_092_5409085e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5409085ecec901891f284ae11b3f1e53acc24483cec458ff5e32f5073caef8f3"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:21:50"
  condition:
    hash.sha256(0, filesize) == "5409085ecec901891f284ae11b3f1e53acc24483cec458ff5e32f5073caef8f3"
}

rule MalwareBazaar_unknown_093_2eefa765
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2eefa765980ba35c50047822903895501061062d17cccc296edd2ae8df3e5099"
    family = "unknown"
    file_name = "DvnX.exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:21:28"
  condition:
    hash.sha256(0, filesize) == "2eefa765980ba35c50047822903895501061062d17cccc296edd2ae8df3e5099"
}

rule MalwareBazaar_Mirai_094_42a05275
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-22 22:20:23"
  condition:
    hash.sha256(0, filesize) == "42a052758f12f875a440a0d8400ad309beda8d55a9e0d7ce32d62f11aa9ccbbf"
}

rule MalwareBazaar_unknown_095_516c06a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "516c06a9dfe146725cd34cd702626f5e68c7f2beff5f44c91f04f816d60ba77f"
    family = "unknown"
    file_name = "Sеt_Uр [UРD].exe"
    file_type = "exe"
    first_seen = "2026-10-22 22:18:49"
  condition:
    hash.sha256(0, filesize) == "516c06a9dfe146725cd34cd702626f5e68c7f2beff5f44c91f04f816d60ba77f"
}

rule MalwareBazaar_Mirai_096_7e8b2f48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4"
    family = "Mirai"
    file_name = "main_x86_64"
    file_type = "elf"
    first_seen = "2026-10-22 22:14:22"
  condition:
    hash.sha256(0, filesize) == "7e8b2f481f827c41ffda69fa73586ed0f20ad67c7eaa23fbb6a3923c9a408cc4"
}

rule MalwareBazaar_unknown_097_d849fb80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d849fb8000891cf3cca1b755eac2eda328135ae73041cfcd6f7eb612f6b9ab20"
    family = "unknown"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-22 22:14:19"
  condition:
    hash.sha256(0, filesize) == "d849fb8000891cf3cca1b755eac2eda328135ae73041cfcd6f7eb612f6b9ab20"
}

rule MalwareBazaar_unknown_098_a0f4f36a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0f4f36aba15058cd3b01bb68c90574d1fb44c5408cd909727f9f60ebdd6fa73"
    family = "unknown"
    file_name = "TikTok18_v1.6.1.apk"
    file_type = "apk"
    first_seen = "2026-10-22 22:05:47"
  condition:
    hash.sha256(0, filesize) == "a0f4f36aba15058cd3b01bb68c90574d1fb44c5408cd909727f9f60ebdd6fa73"
}

rule MalwareBazaar_Mirai_099_273b6cd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "273b6cd05d03c82d836d6ad298bfae66a696ca857856b9f9bf5c77e8d1fee949"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-22 22:05:20"
  condition:
    hash.sha256(0, filesize) == "273b6cd05d03c82d836d6ad298bfae66a696ca857856b9f9bf5c77e8d1fee949"
}

rule MalwareBazaar_Mirai_100_40b37052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40b37052ecb9c65331d7bd23730b95477311ecc468cfe980f2b1201ae3a3eeca"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-22 22:00:03"
  condition:
    hash.sha256(0, filesize) == "40b37052ecb9c65331d7bd23730b95477311ecc468cfe980f2b1201ae3a3eeca"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

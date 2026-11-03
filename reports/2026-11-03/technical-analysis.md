# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-03

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 643 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 643 |
| Unique family labels | 14 |
| Unique file types | 12 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 50 |
| Mirai | 20 |
| AgentTesla | 7 |
| SalatStealer | 6 |
| ConnectWise | 6 |
| AsyncRAT | 2 |
| RustyStealer | 2 |
| RemcosRAT | 1 |
| Formbook | 1 |
| AMOS | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 34 |
| elf | 21 |
| macho | 15 |
| vbs | 8 |
| bat | 8 |
| msi | 4 |
| sh | 4 |
| js | 2 |
| wsf | 1 |
| jse | 1 |

## Per-Sample Analysis

### Sample 1: `0371b2265206832e`

| Field | Value |
|---|---|
| SHA-256 | `0371b2265206832e350a730a3a9da5519e0a7483b94a2602df539a91791a2ec8` |
| Family label | `unknown` |
| File name | `update[1].msi` |
| File type | `msi` |
| First seen | `2026-11-03 06:52:43` |
| Reporter | `smica83` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf8e576222725625b1f08af84b0a6f8d` |
| SHA-1 | `d49fcadf1c12724fe43a05e8518fbfcacc475405` |
| SHA-256 | `0371b2265206832e350a730a3a9da5519e0a7483b94a2602df539a91791a2ec8` |
| SHA3-384 | `5a7f751649ea09230c802535387ea509bd57d7f7ea153532155b3a2670d108340485407a5ec0454e82c71710372d892d` |
| TLSH | `T1E722F7857901C573C1405F3146A70B8A577A2C40CF9B16077BBCB34C9FB60D47AAA3E5` |
| SSDEEP | `192:xSAz4wvQCvL5PCfKm6QCt3BFWyiTR429yaMsSwW0E8SA:xSAMQjEyhvtRFWfR42saJSwS8SA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_0371b226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0371b2265206832e350a730a3a9da5519e0a7483b94a2602df539a91791a2ec8"
    family = "unknown"
    file_name = "update[1].msi"
    file_type = "msi"
    first_seen = "2026-11-03 06:52:43"
  condition:
    hash.sha256(0, filesize) == "0371b2265206832e350a730a3a9da5519e0a7483b94a2602df539a91791a2ec8"
}
```

### Sample 2: `de50f5ae2931b7bd`

| Field | Value |
|---|---|
| SHA-256 | `de50f5ae2931b7bddd1e1d330a92e1c64babb2b5a5c21e728aba391671a50b45` |
| Family label | `unknown` |
| File name | `newisbest.exe` |
| File type | `exe` |
| First seen | `2026-11-03 06:51:27` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09d292bc0294238f04a388aba95d2604` |
| SHA-1 | `4cd44ea8488d0cbe03355aef0e01cbbb045888aa` |
| SHA-256 | `de50f5ae2931b7bddd1e1d330a92e1c64babb2b5a5c21e728aba391671a50b45` |
| SHA3-384 | `4b678d91b8107679d28687c6fb0f9ee989586848ec602568a2d36a95a0100f8af30293375add33ce39bb1ccb2e4ebd52` |
| IMPHASH | `9d8f1618f80035e2a7a248a3a8532599` |
| TLSH | `T19745CE54B7D13DD9C9798E30816D9EECA67D381EF6121FAF0F9C13070E266919A26E0C` |
| SSDEEP | `24576:hHERNKrliiAg0okHoqWCktLUW9arKtqC8X7iP:qR0bsR7` |
| ICON-DHASH | `08649a8a8a9a6408` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_de50f5ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de50f5ae2931b7bddd1e1d330a92e1c64babb2b5a5c21e728aba391671a50b45"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-11-03 06:51:27"
  condition:
    hash.sha256(0, filesize) == "de50f5ae2931b7bddd1e1d330a92e1c64babb2b5a5c21e728aba391671a50b45"
}
```

### Sample 3: `defd6b754c6fa5e1`

| Field | Value |
|---|---|
| SHA-256 | `defd6b754c6fa5e1323d557ad6d1dd1707649a3ef60637e0ad9a806df82feb5f` |
| Family label | `unknown` |
| File name | `export.php` |
| File type | `exe` |
| First seen | `2026-11-03 06:51:21` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5efbe6a9df102220ed99f8d8156c7fa` |
| SHA-1 | `5e4e2dcd23d3a4abbd8d50bd7dcc2d03ae4dfeae` |
| SHA-256 | `defd6b754c6fa5e1323d557ad6d1dd1707649a3ef60637e0ad9a806df82feb5f` |
| SHA3-384 | `29fd872b7aa7b75fe75837a1e64ddb4ff03b167f81a5ae8253c2c29d368ede18f11fa2d8800e7fa79ee441a11d278ab5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B125F1A5774B5B4EC175B931CD84D85085333B3FAAAAC17E088F1D80DD2FB698E8B251` |
| SSDEEP | `24576:AUm4ucbLpm6e89zKUwbDDqAda/jlitPffkajRXqoSit31n:Qce89zKZvD1dk0EyRX5Sit31` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_defd6b75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "defd6b754c6fa5e1323d557ad6d1dd1707649a3ef60637e0ad9a806df82feb5f"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-11-03 06:51:21"
  condition:
    hash.sha256(0, filesize) == "defd6b754c6fa5e1323d557ad6d1dd1707649a3ef60637e0ad9a806df82feb5f"
}
```

### Sample 4: `5f795c3b455a4c4d`

| Field | Value |
|---|---|
| SHA-256 | `5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d` |
| Family label | `unknown` |
| File name | `polkitd` |
| File type | `elf` |
| First seen | `2026-11-03 06:47:22` |
| Reporter | `smica83` |
| Tags | `8-222-164-220, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ffb075398478f817de229788317130e` |
| SHA-1 | `6ac62dff1a84004e1840210067836f6c28ef574b` |
| SHA-256 | `5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d` |
| SHA3-384 | `9738bf4bea99d1b43e008243f5dd9f62df4c4cb64c0c95fa9af97cfd124b85f6ccad58a73f2ea7d200f3c0d9bf6b2796` |
| TLSH | `T1C9644B43F952949CDD6ACD34831DE533F33D788942916A3BB7E49B203F26A61AF09B41` |
| SSDEEP | `3072:Ubnd2TpYnwj0YGOMweH3nw3abwvrtZSRBRY4P7RKwHjyDDGV7WSy5TCXT3iQeona:yapYwZ+ExZcBRyANBy1OheNqJuqBRCH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_5f795c3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d"
    family = "unknown"
    file_name = "polkitd"
    file_type = "elf"
    first_seen = "2026-11-03 06:47:22"
  condition:
    hash.sha256(0, filesize) == "5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d"
}
```

### Sample 5: `2ea72bf67197f652`

| Field | Value |
|---|---|
| SHA-256 | `2ea72bf67197f652c6161fb07b78aa7bb591265e7f0a889dc404387df7538cd5` |
| Family label | `unknown` |
| File name | `systemd-udevd` |
| File type | `elf` |
| First seen | `2026-11-03 06:47:10` |
| Reporter | `smica83` |
| Tags | `8-222-164-220, elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b3d4614a08888e3f80e643a45d1c7f5` |
| SHA-1 | `0d9dc5c9949bf17a7a8f5b7dfd58df05bb30342a` |
| SHA-256 | `2ea72bf67197f652c6161fb07b78aa7bb591265e7f0a889dc404387df7538cd5` |
| SHA3-384 | `eccc39d34dad288b5f0807cf3aa0663a8a02f0b406bc0b28d2d85f00788add6fd594bca5e63bdd9afe1f3329ca00e50a` |
| TLSH | `T168644B43F952949CDD6ACD34821DE533F33D788942916E3BB7E49B203F26A61AF09B41` |
| SSDEEP | `3072:db5YesXJYC8Adj0QrBqDTH4nww6rwv694IRRQYLmws0Kw5jyak+V4W0a5/My+Qjb:1cJYo/40u4SRQ1WGDa9M7yaF3Im9RqD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_2ea72bf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ea72bf67197f652c6161fb07b78aa7bb591265e7f0a889dc404387df7538cd5"
    family = "unknown"
    file_name = "systemd-udevd"
    file_type = "elf"
    first_seen = "2026-11-03 06:47:10"
  condition:
    hash.sha256(0, filesize) == "2ea72bf67197f652c6161fb07b78aa7bb591265e7f0a889dc404387df7538cd5"
}
```

### Sample 6: `ba90978bc50304ef`

| Field | Value |
|---|---|
| SHA-256 | `ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95` |
| Family label | `unknown` |
| File name | `FiyatTeklifIstegi-IDPRNo69611-BUSBARBESLEMEPANOSU.wsf$` |
| File type | `wsf` |
| First seen | `2026-11-03 06:44:37` |
| Reporter | `ni_fi_70` |
| Tags | `exe, wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7ef5a39fe44cb3ec703f9a02782d6e0` |
| SHA-1 | `6f87fae383f12a20a1d760a94d0b3c53026f9a3c` |
| SHA-256 | `ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95` |
| SHA3-384 | `5464f5cd7fdb39f501d2d6dfd3e55ea6f59d676886c748a2a9f30e4d5681f6292d6c72615824193d3ac5e77c3786fe91` |
| TLSH | `T1B091DE8EBD8EA0694A737338CB7F9108FA774923054AC604FD9CA6511F7141486B8EFD` |
| SSDEEP | `96:9i5PuYiHgVgBaLYBz/velIdPYoSlY9awJ:9iygHLwHPlYTlEas` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_ba90978b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95"
    family = "unknown"
    file_name = "FiyatTeklifIstegi-IDPRNo69611-BUSBARBESLEMEPANOSU.wsf$"
    file_type = "wsf"
    first_seen = "2026-11-03 06:44:37"
  condition:
    hash.sha256(0, filesize) == "ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95"
}
```

### Sample 7: `d55a1b7493c995db`

| Field | Value |
|---|---|
| SHA-256 | `d55a1b7493c995dbbcb14e4336ee11e3791c3f865df6e578212dee16509f5fef` |
| Family label | `unknown` |
| File name | `WBKPO20064.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:35` |
| Reporter | `ni_fi_70` |
| Tags | `exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3f746abbc9dd71326cc045501cdb13a` |
| SHA-1 | `1076e9dc20e985c461e8d66c62fa0ce868944097` |
| SHA-256 | `d55a1b7493c995dbbcb14e4336ee11e3791c3f865df6e578212dee16509f5fef` |
| SHA3-384 | `b601201cebedc4f1bb5503197269def3058ee633087efd5e708bb157f6d32720eceac38b1927252a0224893dd2135af1` |
| TLSH | `T136E422E316C5E83595E605ACE897A70245E312BF3D8875D13E8CE3AC29F31053B9B8D9` |
| SSDEEP | `12288:gmJqyj4bWqlNK7zJ6znB89SlHXbdx5JtPLSUw+RwR4ajbHEO11BCVB7VhdngxPrT:fa8MlHXJx5JtDSbbukbHEOgVBBHnyMKB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_d55a1b74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d55a1b7493c995dbbcb14e4336ee11e3791c3f865df6e578212dee16509f5fef"
    family = "unknown"
    file_name = "WBKPO20064.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:35"
  condition:
    hash.sha256(0, filesize) == "d55a1b7493c995dbbcb14e4336ee11e3791c3f865df6e578212dee16509f5fef"
}
```

### Sample 8: `ba15e72ccec9f88b`

| Field | Value |
|---|---|
| SHA-256 | `ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780` |
| Family label | `AgentTesla` |
| File name | `ODEMEDEKONTU.exe$` |
| File type | `exe` |
| First seen | `2026-11-03 06:44:32` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1f1f53ffeff754361d5fe492a8d1e61` |
| SHA-1 | `37faf1005d69c8047f09da4f708fe645bae4f1d5` |
| SHA-256 | `ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780` |
| SHA3-384 | `9a78aad6296f753def005e0682e63cee150d68ce15243dedab6ccce58a29520d8ffc9a6d5d3bbf54af40d9e41621ead2` |
| IMPHASH | `573bb7b41bc641bd95c0f5eec13c233b` |
| TLSH | `T1ACD422013682C145CBE547300D34D655CFF6ACFAEAF88AC763503B586DB26A1A64B7F2` |
| SSDEEP | `12288:PyWZktRWAHdSlhxP+5mPpO4jpFYQ+cehjEhtOjlRy5fP18oL36P/7pO:PyWZsjdYHP+IkuxYQ519qP/7` |
| ICON-DHASH | `69787869f9b9b0f1` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_008_ba15e72c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780"
    family = "AgentTesla"
    file_name = "ODEMEDEKONTU.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:32"
  condition:
    hash.sha256(0, filesize) == "ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780"
}
```

### Sample 9: `83c77e25b92cdb31`

| Field | Value |
|---|---|
| SHA-256 | `83c77e25b92cdb316b2bc363b9ed0d4f36c50679cf2d07b24c3f706492b0def9` |
| Family label | `RemcosRAT` |
| File name | `citibankNAoutwardremittancemt103_PDFPDF.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:29` |
| Reporter | `ni_fi_70` |
| Tags | `exe, RemcosRAT, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc72873f967e7ad0f28f9d07f665be73` |
| SHA-1 | `d958444b24c76c9dd473c66fa2728191f5d74ab9` |
| SHA-256 | `83c77e25b92cdb316b2bc363b9ed0d4f36c50679cf2d07b24c3f706492b0def9` |
| SHA3-384 | `ed76ab708042f715b62db6c6e19652175541dc72e046fcc6aa9c9e5f94d2a7f39c97c002ef7e72196f32762747dcc007` |
| TLSH | `T145E423A13DCC2308E9AD4D6DD7F3CA5789DB49B95005BC033FAA725D2262EC177831A9` |
| SSDEEP | `12288:tVslbxLD6V4Or2fus39qAw/ybrLR7go8a80m9MHL9jB5NoFlmgWkvTZmgVkfWe4s:PsNxtwKLR7EaJ5rk9WkvTZ9he4ZSN` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_009_83c77e25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83c77e25b92cdb316b2bc363b9ed0d4f36c50679cf2d07b24c3f706492b0def9"
    family = "RemcosRAT"
    file_name = "citibankNAoutwardremittancemt103_PDFPDF.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:29"
  condition:
    hash.sha256(0, filesize) == "83c77e25b92cdb316b2bc363b9ed0d4f36c50679cf2d07b24c3f706492b0def9"
}
```

### Sample 10: `a0ef92781e93d265`

| Field | Value |
|---|---|
| SHA-256 | `a0ef92781e93d2651994318d5cbdca72089db7fc977e6cd03739f3096f99ac0c` |
| Family label | `AgentTesla` |
| File name | `BL2337436541766.exe$` |
| File type | `exe` |
| First seen | `2026-11-03 06:44:27` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9fd2062599816e690003e016bc5bca2` |
| SHA-1 | `df7a14222a189e791620599c46b88e6ee90d6b1f` |
| SHA-256 | `a0ef92781e93d2651994318d5cbdca72089db7fc977e6cd03739f3096f99ac0c` |
| SHA3-384 | `473e42ce44e54d410c394227b2cf55066134adbc40d8341881efed50806b4de23824ac33beff45eb9039fdbf71d7caad` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C305E05433AACF06E9BA17F04A71E63923F12D8A5531D34A4EE6ADEF3536F406950383` |
| SSDEEP | `12288:SpF95Iu1zs7yYmXTjHwbGaa0UWfgp4TODj3JpZ5890nJJrkTCcjzh19:6F9TarUw5Tkj5+9eV8dx` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_010_a0ef9278
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0ef92781e93d2651994318d5cbdca72089db7fc977e6cd03739f3096f99ac0c"
    family = "AgentTesla"
    file_name = "BL2337436541766.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:27"
  condition:
    hash.sha256(0, filesize) == "a0ef92781e93d2651994318d5cbdca72089db7fc977e6cd03739f3096f99ac0c"
}
```

### Sample 11: `bf2203e0c49e3485`

| Field | Value |
|---|---|
| SHA-256 | `bf2203e0c49e34852b369811662f28486a8077cb42b735aeee753a6025e02b6d` |
| Family label | `AgentTesla` |
| File name | `Fixtures00000000Drawing000000Specifications.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:24` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca5636d906fe06bad00f3a90bec39d23` |
| SHA-1 | `7a44a394e726e937cf3cffa7baa6e7326f5defcd` |
| SHA-256 | `bf2203e0c49e34852b369811662f28486a8077cb42b735aeee753a6025e02b6d` |
| SHA3-384 | `446d31a8795bb989ebbf6cb2cc56dc89b78c51bc08460f03eaa47e35cf20295a9e571dd7b25ac60c97b22483ac09c9ad` |
| TLSH | `T1ED04125D2A691DB226310BA5ACED8984E3EF8C7F860DED107DCDD52C2BA31570724379` |
| SSDEEP | `3072:30vr8Nhz4ruMzvAOBHwX1c+B3FsZJ2GN2frS47F8xvTdLPyePtKLQRMR:30TCz4KgvANX1FJWZJ2GN2fm47CTVyeu` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_011_bf2203e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf2203e0c49e34852b369811662f28486a8077cb42b735aeee753a6025e02b6d"
    family = "AgentTesla"
    file_name = "Fixtures00000000Drawing000000Specifications.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:24"
  condition:
    hash.sha256(0, filesize) == "bf2203e0c49e34852b369811662f28486a8077cb42b735aeee753a6025e02b6d"
}
```

### Sample 12: `8bd896323c194a21`

| Field | Value |
|---|---|
| SHA-256 | `8bd896323c194a21e854269411af1cce7d0f240f1038af03aaf5c4ca6f94d460` |
| Family label | `unknown` |
| File name | `Facturaproformaimpagada.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:21` |
| Reporter | `ni_fi_70` |
| Tags | `exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6d5b7a4424688beac4906d051f6ccf7` |
| SHA-1 | `ccaad373152ec55290e10959e1c838cb41fe9d01` |
| SHA-256 | `8bd896323c194a21e854269411af1cce7d0f240f1038af03aaf5c4ca6f94d460` |
| SHA3-384 | `51010ceaef48c569b1570915429f19ea154ca96ff8bbe8ac5ff5b5d5275b01a04a602e15276939cb5350e4b9f0ba8876` |
| TLSH | `T1DE14E05B1AB029D0762F0B361CD109B452653EF61A98BCD3BFAD7122B35C2760ADC1E6` |
| SSDEEP | `6144:w/aaogrWfBm+F23kK7/Uyi5taxOH+s1Uq7SnOnPaaqmuHa:9M3TUyi5taxOH+vm2CuHa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_8bd89632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bd896323c194a21e854269411af1cce7d0f240f1038af03aaf5c4ca6f94d460"
    family = "unknown"
    file_name = "Facturaproformaimpagada.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:21"
  condition:
    hash.sha256(0, filesize) == "8bd896323c194a21e854269411af1cce7d0f240f1038af03aaf5c4ca6f94d460"
}
```

### Sample 13: `c39e58a3d4188237`

| Field | Value |
|---|---|
| SHA-256 | `c39e58a3d41882379fed94bfbacc52cacd55d1fb2847515129814808d93d7370` |
| Family label | `AsyncRAT` |
| File name | `PagoOC3256.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:19` |
| Reporter | `ni_fi_70` |
| Tags | `AsyncRAT, exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b362ed00a320228fd3c9ec929d70eda0` |
| SHA-1 | `d21326be099ece8560cb316af8e6b7760a7ab568` |
| SHA-256 | `c39e58a3d41882379fed94bfbacc52cacd55d1fb2847515129814808d93d7370` |
| SHA3-384 | `b264a3b5af49cc1f6cadad66783cef8b5d946f530989d9de7202a9fa9550bc31c882843628121d0150090e24647eb7c2` |
| TLSH | `T12114E17611B6B614BDEDE626F94DE691B6A004F688A2FD923C3CE1113B2B1043B5CD4F` |
| SSDEEP | `6144:TCPHUQ2RItQas0vU9nvlvRpPRP2B698zNfy+5P/vfjW:TKHUQ2RIuas0vU9nvlvF6698hy+FfC` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_013_c39e58a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c39e58a3d41882379fed94bfbacc52cacd55d1fb2847515129814808d93d7370"
    family = "AsyncRAT"
    file_name = "PagoOC3256.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:19"
  condition:
    hash.sha256(0, filesize) == "c39e58a3d41882379fed94bfbacc52cacd55d1fb2847515129814808d93d7370"
}
```

### Sample 14: `2e561ad32eaa0f2f`

| Field | Value |
|---|---|
| SHA-256 | `2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32` |
| Family label | `unknown` |
| File name | `QUOTE20261102.jse$` |
| File type | `jse` |
| First seen | `2026-11-03 06:44:16` |
| Reporter | `ni_fi_70` |
| Tags | `exe, jse` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae6b19c797b69633e3bf6e71985784b3` |
| SHA-1 | `cfab85ed842722d137333f73b666b9ecf0bddd83` |
| SHA-256 | `2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32` |
| SHA3-384 | `1c8a3b18df4992a4e759641f3bfbd0d9bd9db6283bcbb75d4603f61a771db69486ce8d15f7fb4591b393895733695248` |
| TLSH | `T17AC111CDAC56A0299977733E8F2FC509F7A798270102C214BADCD6446F7186881A9EFD` |
| SSDEEP | `96:HHNDggBYghYVB0AfSRD2YJ2iK4CsBF6dg1WO:HigBliBzoCuF6S1b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jse`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_2e561ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32"
    family = "unknown"
    file_name = "QUOTE20261102.jse$"
    file_type = "jse"
    first_seen = "2026-11-03 06:44:16"
  condition:
    hash.sha256(0, filesize) == "2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32"
}
```

### Sample 15: `a6a8ee790a15a6c6`

| Field | Value |
|---|---|
| SHA-256 | `a6a8ee790a15a6c675b8da46ff600e6580bb947336a7aff8dafe13c252187a5d` |
| Family label | `unknown` |
| File name | `AccountReceipt.PDF.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:14` |
| Reporter | `ni_fi_70` |
| Tags | `exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac6a5f3372f4661c22db3de0a5e94bb2` |
| SHA-1 | `9b2724eb771698dcfba9227cfee807ab6ee0d69e` |
| SHA-256 | `a6a8ee790a15a6c675b8da46ff600e6580bb947336a7aff8dafe13c252187a5d` |
| SHA3-384 | `6070f8f622995922de1f25c861dfc7de6a6d5f0a22660121e9aa99d45f2535e9dfcd18ae66a92479c2bc558eeb72c170` |
| TLSH | `T134F3812904062253A9E1588CE8827B97F5436DC3E07E7D6B47BD294CD77F2B698C3B09` |
| SSDEEP | `384:UdtyJnSWNYNLifj1M4ii6gVFiAqoVp58euQtoqB5kDhPpVS2BZjUORaOiFV5ZD2n:NIAGDZpeYaTlVEUb68O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_a6a8ee79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6a8ee790a15a6c675b8da46ff600e6580bb947336a7aff8dafe13c252187a5d"
    family = "unknown"
    file_name = "AccountReceipt.PDF.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:14"
  condition:
    hash.sha256(0, filesize) == "a6a8ee790a15a6c675b8da46ff600e6580bb947336a7aff8dafe13c252187a5d"
}
```

### Sample 16: `149b336d39c21427`

| Field | Value |
|---|---|
| SHA-256 | `149b336d39c214271aa59d4840f43f53b3d9df1394fed57536a8553be2d0f1bb` |
| Family label | `AgentTesla` |
| File name | `Documents.bat$` |
| File type | `exe` |
| First seen | `2026-11-03 06:44:11` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a22d90d5829a47100d66552219e2f0f9` |
| SHA-1 | `a9c2c22d10f12aa353b5a46ad162d5d2c4e41a77` |
| SHA-256 | `149b336d39c214271aa59d4840f43f53b3d9df1394fed57536a8553be2d0f1bb` |
| SHA3-384 | `4b1e4fba4e8f801b832bc5d200b156ac3ded7bd4c7cd240c1a4042f98803aa0d6d76a2f03bc7675b1e3fd6128182c87e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15D15AD4823D4DA0AE47607B6DD6AD1F003B65F56D522D22BEEE1BEDF3839F705A00252` |
| SSDEEP | `24576:HXk/VszR+EDaT82svLaP8giu41BqBhaF9:OI0A2sD8Z4kC` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_016_149b336d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149b336d39c214271aa59d4840f43f53b3d9df1394fed57536a8553be2d0f1bb"
    family = "AgentTesla"
    file_name = "Documents.bat$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:11"
  condition:
    hash.sha256(0, filesize) == "149b336d39c214271aa59d4840f43f53b3d9df1394fed57536a8553be2d0f1bb"
}
```

### Sample 17: `09cacaca92915a89`

| Field | Value |
|---|---|
| SHA-256 | `09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a` |
| Family label | `unknown` |
| File name | `ORDER10-MAREXVTR250RR181-UAE.exe$` |
| File type | `exe` |
| First seen | `2026-11-03 06:44:08` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e3e816d779016ec2f2b0895d23445f2` |
| SHA-1 | `058afe8b4cc6217b2a587d4f9fae24eee286efa4` |
| SHA-256 | `09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a` |
| SHA3-384 | `eb15b3d436788626c564853430087979312207087bc0026e5892e8e990fbf6dd9397b33b5b9316ed748bf834ce5d8d7e` |
| IMPHASH | `8f524208123efcf8a339df5f70d6c82d` |
| TLSH | `T1F6F5BE32A6978D72D1A6027045A9F730936EBE8413718AD7F3A4F72E1D701E15B6B383` |
| SSDEEP | `49152:yzbMUq4RwzRoBE0PeNPENb2SIFoqYiQFvksiCyv98Q44HeKFh+BVAvAbofbqdowO:y8JzRHmhQTXXCV+hzXwGqixrokh` |
| ICON-DHASH | `f4ecc4d0f0e8c8c4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_09cacaca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a"
    family = "unknown"
    file_name = "ORDER10-MAREXVTR250RR181-UAE.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:08"
  condition:
    hash.sha256(0, filesize) == "09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a"
}
```

### Sample 18: `47d11e494ff2e14b`

| Field | Value |
|---|---|
| SHA-256 | `47d11e494ff2e14b9acf0d40460a613ee989a807475e03f23ee17ed2db141233` |
| Family label | `unknown` |
| File name | `UvWlVVVdAU.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:44:05` |
| Reporter | `ni_fi_70` |
| Tags | `exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `950c00640dd7475de8100a4f4121baf4` |
| SHA-1 | `b2f26ed997fca34582a33a81a0a97439c7570350` |
| SHA-256 | `47d11e494ff2e14b9acf0d40460a613ee989a807475e03f23ee17ed2db141233` |
| SHA3-384 | `7c007c3bcaa492d2f83bf8458db66ef7936dfcdef025cacb66cf59e932adc2615edd28d44f7c8c85c09f6d282d25ad18` |
| TLSH | `T12F14F18B16D4E002653B428E3C4E9826FB2743FB1516F8DEBF9D655C7BA0F520BE4480` |
| SSDEEP | `6144:u9zt8nUZcaRsjmf7qca9U4C5+kbnv+HB9JK6:u5lZcaRsjmfOca9UYA6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_47d11e49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d11e494ff2e14b9acf0d40460a613ee989a807475e03f23ee17ed2db141233"
    family = "unknown"
    file_name = "UvWlVVVdAU.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:05"
  condition:
    hash.sha256(0, filesize) == "47d11e494ff2e14b9acf0d40460a613ee989a807475e03f23ee17ed2db141233"
}
```

### Sample 19: `aa788bca2eb8eb89`

| Field | Value |
|---|---|
| SHA-256 | `aa788bca2eb8eb8991e7cb6b4ce7b1a6e51a5051ac89d5d69a6c6868245562ab` |
| Family label | `AgentTesla` |
| File name | `PONoVIVRE691EB25.bat$` |
| File type | `exe` |
| First seen | `2026-11-03 06:43:58` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70ee03d193f2ca5e14530c89da2acfa5` |
| SHA-1 | `b04bb2ae7ed52d34bbca3f0701058ce06c01ac10` |
| SHA-256 | `aa788bca2eb8eb8991e7cb6b4ce7b1a6e51a5051ac89d5d69a6c6868245562ab` |
| SHA3-384 | `c2c0b4e73f61774d998d85fc5c7770ee44e84a0e2cb1690bcaa7841610a055c0e0aba22d6e707a989556b661c0c141f5` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10415AD0823D4DA09E47607B2DD66D1F403B61F46E522D26BEEE1BEDF7839F706A40252` |
| SSDEEP | `12288:886tteXGBUhdA7i5GDNjcMgzOuMxFyrFszaLxb4zrLE+WFVC9ja+4Cak+9p2ppF9:IUQ7yGxjc3MxFcKzaqrXqU4CaVD2XF9` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_019_aa788bca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa788bca2eb8eb8991e7cb6b4ce7b1a6e51a5051ac89d5d69a6c6868245562ab"
    family = "AgentTesla"
    file_name = "PONoVIVRE691EB25.bat$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:58"
  condition:
    hash.sha256(0, filesize) == "aa788bca2eb8eb8991e7cb6b4ce7b1a6e51a5051ac89d5d69a6c6868245562ab"
}
```

### Sample 20: `b6a1d852a41ffd02`

| Field | Value |
|---|---|
| SHA-256 | `b6a1d852a41ffd02e84e21c3a7722f387084e2474984edde06e150ba98063477` |
| Family label | `unknown` |
| File name | `PRO840423SG8_XEZC_1892192.vbs$` |
| File type | `vbs` |
| First seen | `2026-11-03 06:43:55` |
| Reporter | `ni_fi_70` |
| Tags | `exe, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51d3485ef06070745fd0a045612b1a74` |
| SHA-1 | `24d138e4311cadf6eaaae1e1a05bccb75f653b85` |
| SHA-256 | `b6a1d852a41ffd02e84e21c3a7722f387084e2474984edde06e150ba98063477` |
| SHA3-384 | `c6fc0817abc01881c232c0b99a1d4fea78f40fc690c67c17a938bb7b975a46ee973941663a34c4e4e9031d53987bb442` |
| TLSH | `T1F014F1178A49719291FF37837C8A347602B7417780163C633E99E6CA2FE78949FE8857` |
| SSDEEP | `3072:xdbZqMoX3ObN0zyRMqFIoDpsGfEI8aYqX++JM940sYPCUouo3N8SpuUxKIgIPsnS:nZqJcgnoDpsGfEI8ab+pjhRDodkUxKIj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_b6a1d852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a1d852a41ffd02e84e21c3a7722f387084e2474984edde06e150ba98063477"
    family = "unknown"
    file_name = "PRO840423SG8_XEZC_1892192.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:43:55"
  condition:
    hash.sha256(0, filesize) == "b6a1d852a41ffd02e84e21c3a7722f387084e2474984edde06e150ba98063477"
}
```

### Sample 21: `f94fe58fe411cf7b`

| Field | Value |
|---|---|
| SHA-256 | `f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39` |
| Family label | `Formbook` |
| File name | `RFQ_CHG_26-03_017pdf.exe$` |
| File type | `exe` |
| First seen | `2026-11-03 06:43:53` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f71f1bca882fb23e3888c890c4343bc` |
| SHA-1 | `be62200f9c63adbe6ce4acbd8a486ace23063755` |
| SHA-256 | `f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39` |
| SHA3-384 | `e61fd9eb425761dd93833d07aecde700759943b1eb5c4728c9c7fba33a3d34a2aa200ef7ca387af2cf39dc9f29191c37` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CC15AE4823D4DA0AE47607B2DD6AD1F103B66F06E122D26BEED57EDF3839F701A50252` |
| SSDEEP | `12288:M86J6mTyhYNcSyokz1WkfpiUTDmOz896NvRIC45L5xk6WKpF9:LmTMwhwRWkxHPfK5LXk6pF9` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_021_f94fe58f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39"
    family = "Formbook"
    file_name = "RFQ_CHG_26-03_017pdf.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:53"
  condition:
    hash.sha256(0, filesize) == "f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39"
}
```

### Sample 22: `769ad58f860c5143`

| Field | Value |
|---|---|
| SHA-256 | `769ad58f860c5143fa569c1ce81fe125950102e788f5ec93fa96be5050c85455` |
| Family label | `unknown` |
| File name | `Ordendecompra.js$` |
| File type | `js` |
| First seen | `2026-11-03 06:43:50` |
| Reporter | `ni_fi_70` |
| Tags | `exe, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `467a2278bd5bff2904b5cb842bcca5d6` |
| SHA-1 | `059e93ef9ad16e5620c990a9506a8feb05a00757` |
| SHA-256 | `769ad58f860c5143fa569c1ce81fe125950102e788f5ec93fa96be5050c85455` |
| SHA3-384 | `8a12f9fd96883adcb29c205d03bebd392f42967bc7bb13fb68f5904e72721823143ab890f166c2f89de7356f2de9e4e2` |
| TLSH | `T16BC35C70DA11157A4F87BB98FC954AA1C67C9326817701B0F6DE8B0D900B9ECF77C26A` |
| SSDEEP | `3072:9lOOrGlmWK+50c2padsfpZHYvLkErGN0tCl1UtaeJr:uO0JR5ZEYsf3HeoXJ7AJr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_769ad58f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769ad58f860c5143fa569c1ce81fe125950102e788f5ec93fa96be5050c85455"
    family = "unknown"
    file_name = "Ordendecompra.js$"
    file_type = "js"
    first_seen = "2026-11-03 06:43:50"
  condition:
    hash.sha256(0, filesize) == "769ad58f860c5143fa569c1ce81fe125950102e788f5ec93fa96be5050c85455"
}
```

### Sample 23: `24910d37324a8d19`

| Field | Value |
|---|---|
| SHA-256 | `24910d37324a8d19fb454ce94167b1bd19528c8c32e3eddfffd766c7ccf36ee3` |
| Family label | `unknown` |
| File name | `Nectron.exe$` |
| File type | `exe` |
| First seen | `2026-11-03 06:43:48` |
| Reporter | `ni_fi_70` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d71ad4b74d7e9e771bc911c5c2a6915` |
| SHA-1 | `69bfbb2aef7f6e62c54630d02f46092d8b20ea56` |
| SHA-256 | `24910d37324a8d19fb454ce94167b1bd19528c8c32e3eddfffd766c7ccf36ee3` |
| SHA3-384 | `32428a689cc57a0cc02c3561e55180e91b1a896f3080884da2fa01433c9c6f22d0159c3acbbd784d3b88562ea6a33147` |
| IMPHASH | `9be4f90f50c714bc00cc8beb2e137299` |
| TLSH | `T173E41234E7B1D9FBC82A0D7214B2DA015D39BD320254570B6658BBEFBC38AD48D3B256` |
| SSDEEP | `12288:C6qUud0Pv+Kk3qhVVTvMWPoQ3UcHfahqnScM16KGl:HPWKk2VVxorcHfV9iEl` |
| ICON-DHASH | `f3e1ce4c64a6c1b0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_24910d37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24910d37324a8d19fb454ce94167b1bd19528c8c32e3eddfffd766c7ccf36ee3"
    family = "unknown"
    file_name = "Nectron.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:48"
  condition:
    hash.sha256(0, filesize) == "24910d37324a8d19fb454ce94167b1bd19528c8c32e3eddfffd766c7ccf36ee3"
}
```

### Sample 24: `3fb044653334e89c`

| Field | Value |
|---|---|
| SHA-256 | `3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d` |
| Family label | `unknown` |
| File name | `QUOTATIONFROMMINGRAYTECHNOLOGYGROUP.pdf.scr$` |
| File type | `exe` |
| First seen | `2026-11-03 06:43:43` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36c622ee115ddeb6d45993eb0b7c3560` |
| SHA-1 | `dde386a31367ebf46b639fd39479d326bad33c74` |
| SHA-256 | `3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d` |
| SHA3-384 | `15e145441bb5d416dda3fd67038e3730e4d5ae731033919abf92c71e821d38b2603107edf7ea0c6fc4f18160ef22edfc` |
| TLSH | `T145C5020823D4DA09E5B607F2DD26D1F0137A2F5AE522D26BDDD1BEDB7839F702A50242` |
| SSDEEP | `49152:x8qzA1u95oChenXg4lL7j5dOkaKHuhEOkT+ku3dg:dM1aRqhj5zfOOOT53d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_3fb04465
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d"
    family = "unknown"
    file_name = "QUOTATIONFROMMINGRAYTECHNOLOGYGROUP.pdf.scr$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:43"
  condition:
    hash.sha256(0, filesize) == "3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d"
}
```

### Sample 25: `02f9176dd9991231`

| Field | Value |
|---|---|
| SHA-256 | `02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9` |
| Family label | `AgentTesla` |
| File name | `BL2337436541766.exe$` |
| File type | `exe` |
| First seen | `2026-11-03 06:43:40` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31cbdb9bb26b3f9170b73728f913713c` |
| SHA-1 | `d5c4b0c8b0e6605a2fd696e201ae17a3c9c15f51` |
| SHA-256 | `02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9` |
| SHA3-384 | `fd800d0c504a634ccde720fa5900aa0e78ce1bac7e5884604d47276cad3d072aa3b25ec3e919e83ea00d1338140b02f1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11015AD4823D4DA0AE57607B2DD6AD1F403B62F56D022D26BEEE17EDF3839F705A40252` |
| SSDEEP | `12288:X86OJvnldk5Pt6FaFOL2zXotaQB36V7TwOV5OnYf+UX4KB6oi4pF9:Q1nlEPt6FyIaQB36eOmQ+Uxe8F9` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_025_02f9176d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9"
    family = "AgentTesla"
    file_name = "BL2337436541766.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:40"
  condition:
    hash.sha256(0, filesize) == "02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9"
}
```

### Sample 26: `3330d1dc791dc3f5`

| Field | Value |
|---|---|
| SHA-256 | `3330d1dc791dc3f5a53e484ad8c4f3c1738fbd691de5a4e03e86f0e73fed353c` |
| Family label | `AgentTesla` |
| File name | `SWIFTCOPY.bat$` |
| File type | `exe` |
| First seen | `2026-11-03 06:43:36` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09720dbddbf811efbaca23fd430b6d84` |
| SHA-1 | `ec481d5bbc4106e59be1a3dc8f46d8aa21aa77cf` |
| SHA-256 | `3330d1dc791dc3f5a53e484ad8c4f3c1738fbd691de5a4e03e86f0e73fed353c` |
| SHA3-384 | `f27de8855ad6d7d99b4feaba9834bbfa99ba29c4c6330d8370649749050d827a5b6aa40f443b4df3ec4ec7f823f16c52` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15F15AD4823D4DA0AE57607B6DD6AD1F403B66F16E522D26BDED07ECF383AF701A40252` |
| SSDEEP | `24576:kA6zIWvn5t84T+vQTgf/QhV8VXJxCiPF9:kA6Lt84XTgf/KV8RLtP` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_026_3330d1dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3330d1dc791dc3f5a53e484ad8c4f3c1738fbd691de5a4e03e86f0e73fed353c"
    family = "AgentTesla"
    file_name = "SWIFTCOPY.bat$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:36"
  condition:
    hash.sha256(0, filesize) == "3330d1dc791dc3f5a53e484ad8c4f3c1738fbd691de5a4e03e86f0e73fed353c"
}
```

### Sample 27: `47bb403d9a68076e`

| Field | Value |
|---|---|
| SHA-256 | `47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b` |
| Family label | `unknown` |
| File name | `47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:51:33` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a9649365ca91a228364699c83a3c4e7` |
| SHA-1 | `4e2ace51ae347c95355d3a0be097d7234a640965` |
| SHA-256 | `47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b` |
| SHA3-384 | `c1dc25544379bc3b122b1ce53b0d73b5750f41c8a545ca0a9c67d4291a16498ee3589a30cd4ad3799531643e9139b2a5` |
| TLSH | `T1B5D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzW:d` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_47bb403d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b"
    family = "unknown"
    file_name = "47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:33"
  condition:
    hash.sha256(0, filesize) == "47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b"
}
```

### Sample 28: `48331236f5843559`

| Field | Value |
|---|---|
| SHA-256 | `48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d` |
| Family label | `unknown` |
| File name | `48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:51:28` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad9e3c57c50f3f7b1f4df01e14c13bc6` |
| SHA-1 | `916a3f31484e37f6825fec263da69832b06ef422` |
| SHA-256 | `48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d` |
| SHA3-384 | `e832ea81d0908c6b05bfaf7829c894b78028be9468eeb5fbe64c069aa269cea012c364e2929bc557c691a7e0b0a0ae00` |
| TLSH | `T189D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzN:u` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_48331236
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d"
    family = "unknown"
    file_name = "48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:28"
  condition:
    hash.sha256(0, filesize) == "48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d"
}
```

### Sample 29: `2f78ffc4b00d4f31`

| Field | Value |
|---|---|
| SHA-256 | `2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c` |
| Family label | `unknown` |
| File name | `2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:51:23` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad771719e5d76b61b2d1ac020718c3da` |
| SHA-1 | `bca29b14acca957a658e56659023ff46a763f1da` |
| SHA-256 | `2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c` |
| SHA3-384 | `d7cf71d845cbbe3ddc0d06eaff4bd832a25ac77af079b75b6c2077be3471c1a8698d5f30f778f22b8e5ffd88f3725111` |
| TLSH | `T1A0D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzO:x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_2f78ffc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c"
    family = "unknown"
    file_name = "2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:23"
  condition:
    hash.sha256(0, filesize) == "2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c"
}
```

### Sample 30: `dbeb0545b260d4e2`

| Field | Value |
|---|---|
| SHA-256 | `dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794` |
| Family label | `unknown` |
| File name | `dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:51:18` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c15b98c7f44d4547a5f5fcab6006a4e6` |
| SHA-1 | `e897cd750b1ae10b3382daecdb20af2506b4e383` |
| SHA-256 | `dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794` |
| SHA3-384 | `e794449af39c3bd7f2ff7a39730b9dcc4393e9a709bf863d04c4740e343bc1b3243cb91b0dfcb387e748b8e65fdd41e7` |
| TLSH | `T11BD69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzj:Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_dbeb0545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794"
    family = "unknown"
    file_name = "dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:18"
  condition:
    hash.sha256(0, filesize) == "dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794"
}
```

### Sample 31: `faf194b9c9a1174b`

| Field | Value |
|---|---|
| SHA-256 | `faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e` |
| Family label | `unknown` |
| File name | `faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:50:27` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abee05e638c5b41b6d720ff2d7134da6` |
| SHA-1 | `479e56cb5692083a1e54623c7ff0e5794d6b3eed` |
| SHA-256 | `faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e` |
| SHA3-384 | `a275b3c16e585f669fadb0eada4aa43373f1b651c4a53947b7e853a47bebac0c13024e1ebde22915938d12f9f297dbbd` |
| TLSH | `T124D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdz0:X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_faf194b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e"
    family = "unknown"
    file_name = "faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:50:27"
  condition:
    hash.sha256(0, filesize) == "faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e"
}
```

### Sample 32: `cecfbb3b9b9fed21`

| Field | Value |
|---|---|
| SHA-256 | `cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11` |
| Family label | `unknown` |
| File name | `cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:50:22` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `556b0bb33f01abaa49b99e863c4da51c` |
| SHA-1 | `7c02e8094c4b1ebf89f781cf4e74645e6257306a` |
| SHA-256 | `cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11` |
| SHA3-384 | `d888351789e7aefb514a33ad8e86fd89cbba7581a1a60ee4869157486fb1e95f8861cfc9308a5e07c8436236d7f28d04` |
| TLSH | `T1B2D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzr:M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_cecfbb3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11"
    family = "unknown"
    file_name = "cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:50:22"
  condition:
    hash.sha256(0, filesize) == "cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11"
}
```

### Sample 33: `6e2a4b7da1e29ef7`

| Field | Value |
|---|---|
| SHA-256 | `6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123` |
| Family label | `unknown` |
| File name | `6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:46:29` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3892e4b033e1700427f1469508cc834` |
| SHA-256 | `6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_6e2a4b7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123"
    family = "unknown"
    file_name = "6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:46:29"
  condition:
    hash.sha256(0, filesize) == "6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123"
}
```

### Sample 34: `a806109f0901c56b`

| Field | Value |
|---|---|
| SHA-256 | `a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a` |
| Family label | `unknown` |
| File name | `a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a.bin` |
| File type | `bat` |
| First seen | `2026-11-03 05:46:24` |
| Reporter | `Tuxxin` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cff04c0efc1a940258cd962624503b0` |
| SHA-256 | `a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_a806109f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a"
    family = "unknown"
    file_name = "a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:46:24"
  condition:
    hash.sha256(0, filesize) == "a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a"
}
```

### Sample 35: `5dd89d0f9d80c965`

| Field | Value |
|---|---|
| SHA-256 | `5dd89d0f9d80c96554675129cd887391bebba74e0fc4e29c6fa43844f244607e` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-11-03 05:41:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e2e37510ac12f82effc93250c4e3bf4` |
| SHA-1 | `b416f6bc5bd0be0a099222bc1f3c0072f855aae3` |
| SHA-256 | `5dd89d0f9d80c96554675129cd887391bebba74e0fc4e29c6fa43844f244607e` |
| SHA3-384 | `f71a8f47b4b13b6c2924aa5e7d8672c806e69f2db9629d21749d3f4cf3b4d491b06f7a148815f3e14276f2487013b383` |
| TLSH | `T139735BC5F713C4F5E85346701077F7368E71E8BA1125EE53D7A8EE32AC62A01A607A9C` |
| TELFHASH | `t18931e3fb1d7e19e8b3e0a540c31a2b92296ad677162036f14173cda432e7ec10079c3e` |
| SSDEEP | `1536:xOW1gIpHXALK2MBSA1FSQFiRorqw8xRKtFBIhmFul9:YW1gOHXALKdBSA1FSQsR6WRKtzql9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_5dd89d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dd89d0f9d80c96554675129cd887391bebba74e0fc4e29c6fa43844f244607e"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-11-03 05:41:04"
  condition:
    hash.sha256(0, filesize) == "5dd89d0f9d80c96554675129cd887391bebba74e0fc4e29c6fa43844f244607e"
}
```

### Sample 36: `05728fc47ca9a32a`

| Field | Value |
|---|---|
| SHA-256 | `05728fc47ca9a32a83bafa347ff0184325e4752d44316121dcf1cd254785c72f` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-11-03 05:39:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9607a74e0ee1e5f92807750eec5163d5` |
| SHA-1 | `d60a6b08db477331ee4e8f8986507d392390e9ec` |
| SHA-256 | `05728fc47ca9a32a83bafa347ff0184325e4752d44316121dcf1cd254785c72f` |
| SHA3-384 | `72ee8817a2038834115455723a91ed50b590700321718c73559cd27bb19da910798e6093968fa55e4b6f0dc0ab567edb` |
| TLSH | `T180832941BC814A17C6E1227BFB6E468D372623E8D2DA7207DD215F6137C642F0D3BA96` |
| TELFHASH | `t1a511c0711c981fcc2bd08725528f6326957874fea6622456acfd278702129f7601343d` |
| SSDEEP | `1536:yuIgKh3U66oZqD9vzKacl7UiaZR20Zz3TObAKaMzodNjpVgAHvNA1:igK+z8HaZ80tTGE1Vg6+1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_05728fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05728fc47ca9a32a83bafa347ff0184325e4752d44316121dcf1cd254785c72f"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-03 05:39:04"
  condition:
    hash.sha256(0, filesize) == "05728fc47ca9a32a83bafa347ff0184325e4752d44316121dcf1cd254785c72f"
}
```

### Sample 37: `60b4d5298e7dce61`

| Field | Value |
|---|---|
| SHA-256 | `60b4d5298e7dce610f7d2660d995b5a4bb50315a4b562efd4e7286ea742f32a2` |
| Family label | `Mirai` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-11-03 03:52:48` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3366d73661c576a71f9bff225d3f4f64` |
| SHA-1 | `897ee4e14d54db0dc60842b5b9688c2bf251ad00` |
| SHA-256 | `60b4d5298e7dce610f7d2660d995b5a4bb50315a4b562efd4e7286ea742f32a2` |
| SHA3-384 | `ca83991c6f7590deff62416cea38109def85d6cbdd3eebd7c4b85816951ac1dc9c802e711830e205ddc41f0f2deac00c` |
| TLSH | `T1E7A28562BD155375719AD0B56A4FB1D1E703083B0075BB28710EE4283F2A9A5F3BD2FA` |
| SSDEEP | `384:hPFAcJqQ/bTRPb8v7i5/bStq9O3Xasq+WOkGa59awNP:scd/N5DAdaspWOkGaOwNP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_60b4d529
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60b4d5298e7dce610f7d2660d995b5a4bb50315a4b562efd4e7286ea742f32a2"
    family = "Mirai"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-11-03 03:52:48"
  condition:
    hash.sha256(0, filesize) == "60b4d5298e7dce610f7d2660d995b5a4bb50315a4b562efd4e7286ea742f32a2"
}
```

### Sample 38: `a8a01fa91acebe45`

| Field | Value |
|---|---|
| SHA-256 | `a8a01fa91acebe455728219bb94ec3cdb4e3430b3181b9dc77804381b79a6eb3` |
| Family label | `unknown` |
| File name | `.16` |
| File type | `elf` |
| First seen | `2026-11-03 03:50:26` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `730dd9948016637232a4fb8786a88f86` |
| SHA-1 | `de7ca2d51a950d103793a7cd582b87c9d9f1a50a` |
| SHA-256 | `a8a01fa91acebe455728219bb94ec3cdb4e3430b3181b9dc77804381b79a6eb3` |
| SHA3-384 | `47ea114967c4b4fc461a533444ff173fc0a340ad151d33b77a34e5aad6458a61cfb8e7fb180f40037711e4e8b457b879` |
| TLSH | `T12E745C1BF48240BCC0FAD0B047DFA127B9B1B85981347A7F26D56B601E27F12AB5AF51` |
| SSDEEP | `6144:MqUFub42OSuLvpQMnXdgt5J+c7CoosKD7OFotelVzaL2CW:MxwzO77nk5J1IsK+Fs0VmLVW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_a8a01fa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8a01fa91acebe455728219bb94ec3cdb4e3430b3181b9dc77804381b79a6eb3"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-11-03 03:50:26"
  condition:
    hash.sha256(0, filesize) == "a8a01fa91acebe455728219bb94ec3cdb4e3430b3181b9dc77804381b79a6eb3"
}
```

### Sample 39: `e89b412100a616dc`

| Field | Value |
|---|---|
| SHA-256 | `e89b412100a616dc56e576d05a9cb0573f5e0d5a5261c32c2293630119e6c489` |
| Family label | `Mirai` |
| File name | `eclipse.mpsl` |
| File type | `elf` |
| First seen | `2026-11-03 03:26:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cab47eb102644dcb5ec844eb7bf816b4` |
| SHA-1 | `f849f201f7a0855bbc5eccc248530ade946ffe2e` |
| SHA-256 | `e89b412100a616dc56e576d05a9cb0573f5e0d5a5261c32c2293630119e6c489` |
| SHA3-384 | `5379eda31fc5572938b19f5d4c7aa65b31beb133c2db5d8c3c254c3cfc95d2bbe1e0d0dfe3c0af55b327a41f417bc5c6` |
| TLSH | `T10EF43C16AF500DFBD82BCD370AA94B1275CDB89332D53B76357DD904B90A60B4AE3878` |
| SSDEEP | `6144:FhQO3mRyg6rIBUwHl8qC/9kFRR5zUccR/85mr64++YyFrjFne0gscJQ+heSZh2gZ:bQOWAIBUmDw64TbP5pAQ+ESL2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_e89b4121
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e89b412100a616dc56e576d05a9cb0573f5e0d5a5261c32c2293630119e6c489"
    family = "Mirai"
    file_name = "eclipse.mpsl"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:28"
  condition:
    hash.sha256(0, filesize) == "e89b412100a616dc56e576d05a9cb0573f5e0d5a5261c32c2293630119e6c489"
}
```

### Sample 40: `2ad0d0cb2074b6a6`

| Field | Value |
|---|---|
| SHA-256 | `2ad0d0cb2074b6a6ecf94dfc6335df8d679b6682fb2761fa306574693249904b` |
| Family label | `Mirai` |
| File name | `eclipse.mips` |
| File type | `elf` |
| First seen | `2026-11-03 03:26:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23b7365e5327bff186add19460bbcdda` |
| SHA-1 | `a042f0f549a806820c4317a15002a588d6bd098b` |
| SHA-256 | `2ad0d0cb2074b6a6ecf94dfc6335df8d679b6682fb2761fa306574693249904b` |
| SHA3-384 | `3d5f6ddbeaae743c203027071466d609f31741fab7903563d4305f14de9038e5d4eebebc553ff590e6cc1b328dd44fec` |
| TLSH | `T1FDF4F65B6E228F6DF274C7318BF70B24E6AE22D613E1D681E1DCD1051E2064D991FBAC` |
| TELFHASH | `t10fa109a9197403a4aa645c4d45dcef36c9a234ef3e161c33df51e85dab1fa835e10c1d` |
| SSDEEP | `6144:SjmaIggdgeHE9FQvOrp0E25wCGyNU53O6LLYeW3Ypi54tsumqt3/7ny8gOy8stGz:sQGDC9Y6bTd6YDWbi0OOes` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_2ad0d0cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad0d0cb2074b6a6ecf94dfc6335df8d679b6682fb2761fa306574693249904b"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:25"
  condition:
    hash.sha256(0, filesize) == "2ad0d0cb2074b6a6ecf94dfc6335df8d679b6682fb2761fa306574693249904b"
}
```

### Sample 41: `363aace8871088ac`

| Field | Value |
|---|---|
| SHA-256 | `363aace8871088acc93737e2b830343a1b19a4ec24dba301e093b5bb8e307424` |
| Family label | `Mirai` |
| File name | `eclipse.x86_64` |
| File type | `elf` |
| First seen | `2026-11-03 03:26:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d464ede8e8bdf1eb4a0a5150192e668` |
| SHA-1 | `e384774add62a305fbad0fa1b4cf72b06d6bf069` |
| SHA-256 | `363aace8871088acc93737e2b830343a1b19a4ec24dba301e093b5bb8e307424` |
| SHA3-384 | `e49cabf00a0026f551b6d4cc875b0aa280d5300e591056fa3ea2ce31798df47f7174e57f5283caf931a0bcdf8c659bfd` |
| TLSH | `T154C46D07A8D040FEC8C5C1744B8FD32B9EB2B09A3139B61B2BD66E567E2AF61531D750` |
| TELFHASH | `t18cf110352876345d72e3e5107303c2ad1c722c0a95e9b2e979a368e9ddce6c18d778b3` |
| SSDEEP | `6144:laQnajkLFhlkMrMgEAcN85Ni98TU/qyEUi89nG99K6QOKqbG0wRctABl4pvIn9Nl:lDHZg7tP8TbiqbXwRc4QIn9NLOwcoL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_363aace8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363aace8871088acc93737e2b830343a1b19a4ec24dba301e093b5bb8e307424"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:21"
  condition:
    hash.sha256(0, filesize) == "363aace8871088acc93737e2b830343a1b19a4ec24dba301e093b5bb8e307424"
}
```

### Sample 42: `6f9700023209bdb0`

| Field | Value |
|---|---|
| SHA-256 | `6f9700023209bdb0048b9d49a4354512ceb20c9716a4ec9223f609a2ff8d89d6` |
| Family label | `Mirai` |
| File name | `eclipse.arm7` |
| File type | `elf` |
| First seen | `2026-11-03 03:26:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87dc45a369b6d50ee44bcdf40f62978a` |
| SHA-1 | `8ad0ee08e2ef12b9855db6e9d7597ac2971caaf2` |
| SHA-256 | `6f9700023209bdb0048b9d49a4354512ceb20c9716a4ec9223f609a2ff8d89d6` |
| SHA3-384 | `96c9695088b1f3d800d0f4c6dcf42422ab51afe543f25695108bfcb7001e7df33f2166560bd1a6b0e52dcc84f0b3cbb8` |
| TLSH | `T1EAF44C5BED404B43E4D11FBAFBAF835532235679E3DFB2069508AB743BC66994F2A100` |
| TELFHASH | `t1d892cf0e6b1687577e1144dc57aaa7e31803854b9aac8bd1ded8cb0bc6341bbfc128dd` |
| SSDEEP | `12288:9B5xxMAoBByAM4UqFo8qtqxjNa7fmJ2sNNjnXX/8BJWmyV2SFLFInFm:VnoOylfPrjnuJWmyV2SFLFInFm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_6f970002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f9700023209bdb0048b9d49a4354512ceb20c9716a4ec9223f609a2ff8d89d6"
    family = "Mirai"
    file_name = "eclipse.arm7"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:18"
  condition:
    hash.sha256(0, filesize) == "6f9700023209bdb0048b9d49a4354512ceb20c9716a4ec9223f609a2ff8d89d6"
}
```

### Sample 43: `9e0889651694ed7e`

| Field | Value |
|---|---|
| SHA-256 | `9e0889651694ed7e239420c23feef78069ac11ab1f440585863345e7ac02e485` |
| Family label | `Mirai` |
| File name | `eclipse.arm5` |
| File type | `elf` |
| First seen | `2026-11-03 03:26:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a02f938ed599216717623c70fe0887e` |
| SHA-1 | `ffd124cd965156831b8578c98090c5f0639e6261` |
| SHA-256 | `9e0889651694ed7e239420c23feef78069ac11ab1f440585863345e7ac02e485` |
| SHA3-384 | `3a2c41f558d8ab24c82e1ad1fe3f62498765de0e6b41991e4e84fa5494e926a65e263fce224a50a0af879a275bd228fe` |
| TLSH | `T162C45A66FC409B92C6D15ABBFF5E8248731717B8D2EF71039A049B3437EA8960F3A541` |
| TELFHASH | `t102e07d600760a9d3f7f11947d3ab45373455341e78c0fc121cb16d09d8e01df400d00c` |
| SSDEEP | `12288:zSFMkjXAqxDgsy5/4p2GhajLePFw5LaAagQmtBVnjBA:zSTLc4p2GhajLePF6Hxn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_9e088965
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e0889651694ed7e239420c23feef78069ac11ab1f440585863345e7ac02e485"
    family = "Mirai"
    file_name = "eclipse.arm5"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:15"
  condition:
    hash.sha256(0, filesize) == "9e0889651694ed7e239420c23feef78069ac11ab1f440585863345e7ac02e485"
}
```

### Sample 44: `7332b209bc21cad1`

| Field | Value |
|---|---|
| SHA-256 | `7332b209bc21cad1a36367b683e7294633a048ec4e368def8938e2c3259c0f25` |
| Family label | `Mirai` |
| File name | `eclipse.mpsl` |
| File type | `elf` |
| First seen | `2026-11-03 03:25:47` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ec225a0b0f839b5fbb7264c865bed82` |
| SHA-1 | `64a966e72b7a5efa6339fca23d673d266848cc8f` |
| SHA-256 | `7332b209bc21cad1a36367b683e7294633a048ec4e368def8938e2c3259c0f25` |
| SHA3-384 | `5c4528afdce7fe3421ae24c72b46c457f787cffe87491ada9f3cf7dc73bfbb7de6c8ba903e341629a24453e5ead694dc` |
| TLSH | `T12324222D55E0138AFA17397AE1A1E01DA351C8B8E94FA7E6274C57D053D0ABDC8C3B36` |
| SSDEEP | `6144:DGc0owMTtbTB4xjkCT8aQXHGelI7nXv0w6Tvw:63bUbTysaQ3kzz6zw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_7332b209
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7332b209bc21cad1a36367b683e7294633a048ec4e368def8938e2c3259c0f25"
    family = "Mirai"
    file_name = "eclipse.mpsl"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:47"
  condition:
    hash.sha256(0, filesize) == "7332b209bc21cad1a36367b683e7294633a048ec4e368def8938e2c3259c0f25"
}
```

### Sample 45: `5ce97aad32f6535b`

| Field | Value |
|---|---|
| SHA-256 | `5ce97aad32f6535b53af5788b8bbea8d074dcda4ab54cd9367742f714efb986b` |
| Family label | `Mirai` |
| File name | `eclipse.mips` |
| File type | `elf` |
| First seen | `2026-11-03 03:25:47` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97b8ee0027b79d4edda8957287633e12` |
| SHA-1 | `720e6a76be7998deb9628f9959f7cadcc7560fdd` |
| SHA-256 | `5ce97aad32f6535b53af5788b8bbea8d074dcda4ab54cd9367742f714efb986b` |
| SHA3-384 | `a20bf9d458c347193e21556e803cf1ab918ecb59fb5a55080197dd548bceb60d277d065cb6ebcf4886daae39b27bb66f` |
| TLSH | `T1212422041E4A131FEC4709FA13A807FDB8618B78DC47AD2B12B188ABD7806D9F6F7495` |
| SSDEEP | `6144:v8d6oVkosWCIEbvwVn6PiyRpoItfmACJUqt2AjtEB:kd6ORCbIVeiNgm3JUU2AjtEB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_5ce97aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce97aad32f6535b53af5788b8bbea8d074dcda4ab54cd9367742f714efb986b"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:47"
  condition:
    hash.sha256(0, filesize) == "5ce97aad32f6535b53af5788b8bbea8d074dcda4ab54cd9367742f714efb986b"
}
```

### Sample 46: `4a233c9644272bdb`

| Field | Value |
|---|---|
| SHA-256 | `4a233c9644272bdba8f12a66dfe5a4773f2f5a730738f40ea7ecf50349573416` |
| Family label | `Mirai` |
| File name | `eclipse.x86_64` |
| File type | `elf` |
| First seen | `2026-11-03 03:25:47` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a94d70eddce5d681e8431c268dc0aac` |
| SHA-1 | `3a7c5a340db34c62016e4dc2297e9fe7f3f2405b` |
| SHA-256 | `4a233c9644272bdba8f12a66dfe5a4773f2f5a730738f40ea7ecf50349573416` |
| SHA3-384 | `a2bc3bd0e14fc6c00ac17f90d86d7578280e1c7e1bb142f63c6210b0dcf7ae51d4bb69cf28c5483c5f34820f5ef453bf` |
| TLSH | `T1851412AB6B77D8B9E121FEF360164C2EDC28B5579E03493D8C84A240F8FE11D9067DA1` |
| SSDEEP | `6144:YYHqKlv/Y0blrAyScdWLAXtAv+6vq1eHodvJ7Y:JqinXx3flCnvq1ldvJ7Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_4a233c96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a233c9644272bdba8f12a66dfe5a4773f2f5a730738f40ea7ecf50349573416"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:47"
  condition:
    hash.sha256(0, filesize) == "4a233c9644272bdba8f12a66dfe5a4773f2f5a730738f40ea7ecf50349573416"
}
```

### Sample 47: `082c2a714c1a1e7a`

| Field | Value |
|---|---|
| SHA-256 | `082c2a714c1a1e7ac0b21fde84a6c149a06d7644c78d2e45b189fbb0deef5c73` |
| Family label | `Mirai` |
| File name | `eclipse.arm7` |
| File type | `elf` |
| First seen | `2026-11-03 03:25:46` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0f2c8b93059cb68a46d350e53f9ec71` |
| SHA-1 | `617727f3ff2495109bf89de7095c78bc0f4bafb8` |
| SHA-256 | `082c2a714c1a1e7ac0b21fde84a6c149a06d7644c78d2e45b189fbb0deef5c73` |
| SHA3-384 | `608b58891a28bc9149b654af530bc6932fde086cb49d0e4beb6406994c7e8375c5eef0d85d579334433f53465f22dbd1` |
| TLSH | `T1A0341227BC1797B7E6440CADC0BE18C42C9939D7C079B57B06538261D9BAA0FCB882D7` |
| SSDEEP | `6144:S3FdU8G2b55znyE5gbtThhsKW/XzGduLLL1yTlAmn1:adU8Gq5zhgbtHsKs/vL1AlA4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_082c2a71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "082c2a714c1a1e7ac0b21fde84a6c149a06d7644c78d2e45b189fbb0deef5c73"
    family = "Mirai"
    file_name = "eclipse.arm7"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:46"
  condition:
    hash.sha256(0, filesize) == "082c2a714c1a1e7ac0b21fde84a6c149a06d7644c78d2e45b189fbb0deef5c73"
}
```

### Sample 48: `31eb5452a005de36`

| Field | Value |
|---|---|
| SHA-256 | `31eb5452a005de367863a1bfdeb84bf14bb4f0d977d2a6f4f9164c91454e657b` |
| Family label | `Mirai` |
| File name | `eclipse.arm5` |
| File type | `elf` |
| First seen | `2026-11-03 03:25:45` |
| Reporter | `BlinkzSec` |
| Tags | `upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fef42ad77a1b18472672e7f6c7433809` |
| SHA-1 | `b0d378c808b3cdc1ae8d304ad20e377c449777df` |
| SHA-256 | `31eb5452a005de367863a1bfdeb84bf14bb4f0d977d2a6f4f9164c91454e657b` |
| SHA3-384 | `70520cb1bf5334333dca9903167b7a96b937d2d0cde6d07a8738b90a492fdd76b0700dc4566b427784dc311621fca216` |
| TLSH | `T1291412B7C9482369C7A46723E51396408BF0DDE3FC8DF56E32CBD5B866609A680C02D7` |
| SSDEEP | `3072:VkrrIzuYUiLbyyoPFZHRlR0DdFpNBDQ/s1yWCRr9l9FaBZ5IUshznV3g2CAlwus:YrgFFAjR4xNT4v9A7IU2TVHNs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_31eb5452
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31eb5452a005de367863a1bfdeb84bf14bb4f0d977d2a6f4f9164c91454e657b"
    family = "Mirai"
    file_name = "eclipse.arm5"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:45"
  condition:
    hash.sha256(0, filesize) == "31eb5452a005de367863a1bfdeb84bf14bb4f0d977d2a6f4f9164c91454e657b"
}
```

### Sample 49: `84265f88bd31869d`

| Field | Value |
|---|---|
| SHA-256 | `84265f88bd31869d59f95b83ec38dab46c01dd90da933a9b5cc4579c722ff958` |
| Family label | `unknown` |
| File name | `agent.exe` |
| File type | `exe` |
| First seen | `2026-11-03 03:25:08` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `104a3a97a87d128ae871acbedada9509` |
| SHA-1 | `18d528e16c77d4b749ac28ae1b9e8aca8a48aa3e` |
| SHA-256 | `84265f88bd31869d59f95b83ec38dab46c01dd90da933a9b5cc4579c722ff958` |
| SHA3-384 | `a8245574edb69aaa3dfacfd5753fcbcd2b3e275b767442154dbabfef93f2cd204e3e919745969531f93cf0a66e394a30` |
| IMPHASH | `f057f926909a8957481c0cc2a44c7787` |
| TLSH | `T19315AE5AA7A801FDD877C438C5966113E6F2B44613219AF742A14DA93F23BF26F3E701` |
| SSDEEP | `12288:/9O0aPgFoPTF+Uy5jeEhdB3/mTTIyvfAXnJ22aDn5q3bT4w//6fnP4htwkZ9ES:cnF+Uy5jeQvvmTTfvfOiqZ2nP4ht7j` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_84265f88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84265f88bd31869d59f95b83ec38dab46c01dd90da933a9b5cc4579c722ff958"
    family = "unknown"
    file_name = "agent.exe"
    file_type = "exe"
    first_seen = "2026-11-03 03:25:08"
  condition:
    hash.sha256(0, filesize) == "84265f88bd31869d59f95b83ec38dab46c01dd90da933a9b5cc4579c722ff958"
}
```

### Sample 50: `c78b763c78ebb15d`

| Field | Value |
|---|---|
| SHA-256 | `c78b763c78ebb15d49fa6d8addad18b3da65dd8db50c4d4de1dd1a9db6ef7a34` |
| Family label | `unknown` |
| File name | `cat.sh` |
| File type | `sh` |
| First seen | `2026-11-03 03:23:57` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ce545815f901f08770b9a91e4b3ed07` |
| SHA-1 | `5c0aebd89f3b0398db37424ba5eb968abf10ddc5` |
| SHA-256 | `c78b763c78ebb15d49fa6d8addad18b3da65dd8db50c4d4de1dd1a9db6ef7a34` |
| SHA3-384 | `bef77363e0d6b0e6299470e82b405ebbde75ee9e6ea16135a40f40f930817a1c2c74c91cda530451870dec14134aa18b` |
| TLSH | `T16621E2A7F4646D3175BA6079978BA0A406973A335C203D19FC4D38342F359B8B916BA4` |
| SSDEEP | `24:Cy4hYqzvr2yOkIqsEMkzqCMbhR1zkd5Mk/H1MZFsi6JZ7AkFp/n/gu8wXqy:CyIYqziHrhElzLanFkd5lNMXsi6JZ7Aa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_c78b763c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c78b763c78ebb15d49fa6d8addad18b3da65dd8db50c4d4de1dd1a9db6ef7a34"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-11-03 03:23:57"
  condition:
    hash.sha256(0, filesize) == "c78b763c78ebb15d49fa6d8addad18b3da65dd8db50c4d4de1dd1a9db6ef7a34"
}
```

### Sample 51: `9d3df907e1aae137`

| Field | Value |
|---|---|
| SHA-256 | `9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a` |
| Family label | `AMOS` |
| File name | `macho_9d3df907e1aa.bin` |
| File type | `macho` |
| First seen | `2026-11-03 03:23:15` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b25e1d3fbda07e7450a588be1d56c86e` |
| SHA-1 | `4411bcae04950ae19ffbb7202b1bc06669d6ebba` |
| SHA-256 | `9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a` |
| SHA3-384 | `ce880ecd7e5b1985e73fbd98706f91325482b51e81cf638547bb9bcea519fd2940a29f35bc1f13e9fd19177aca39be9b` |
| TLSH | `T14685F1404FAEA106D4AD11335D968B19847432E0CE89CDD96302A39ADE3D7E3B7572FB` |
| SSDEEP | `49152:/xMauMmVOlwYH8i8cEKcqU0ugZ6j46kHD555mULrNjzCwTvtrb0WFApsOrmXuMDk:/xv1j0Pmc` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_051_9d3df907
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a"
    family = "AMOS"
    file_name = "macho_9d3df907e1aa.bin"
    file_type = "macho"
    first_seen = "2026-11-03 03:23:15"
  condition:
    hash.sha256(0, filesize) == "9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a"
}
```

### Sample 52: `5443928a7d209800`

| Field | Value |
|---|---|
| SHA-256 | `5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646` |
| Family label | `SalatStealer` |
| File name | `5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646.exe` |
| File type | `exe` |
| First seen | `2026-11-03 03:14:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22eb216bc0770ff01b55e7e502d39b36` |
| SHA-1 | `f8e39597e93ca8b588d2bedfaf406965e51d087b` |
| SHA-256 | `5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646` |
| SHA3-384 | `9bc05d2620af075e809c90e1eac19fce4df5c828dc54113395358c912fe6c30d54e90c0f57b0c27c920486834733d772` |
| IMPHASH | `7ded604015975929b583962a247d21ca` |
| TLSH | `T192062338E6E428F5D77BA275895A2B0AD66B3C1387A197DF63C00A672E135D0CF39350` |
| SSDEEP | `49152:EshgJjJeX+EGu/4IMhvTpLRVk3OJKwK3vHEWt1WEbheKuL/9TKlvYP:EJM52htFJKwufsVKuLlwYP` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_052_5443928a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646"
    family = "SalatStealer"
    file_name = "5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646.exe"
    file_type = "exe"
    first_seen = "2026-11-03 03:14:10"
  condition:
    hash.sha256(0, filesize) == "5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646"
}
```

### Sample 53: `c3b67f17b19f697f`

| Field | Value |
|---|---|
| SHA-256 | `c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3` |
| Family label | `VShell` |
| File name | `c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3.exe` |
| File type | `exe` |
| First seen | `2026-11-03 02:54:27` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aea7586eb417a1b962d55c6db419f268` |
| SHA-1 | `ace4e2d79c98db408389fbb60e8117936531303a` |
| SHA-256 | `c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3` |
| SHA3-384 | `fdb37f6e4f3db1f5e9469ea3f6ed3257b5d5b388ab4c0ca786d0f50f59c6ed6a8633a41fd8cd95f38ef639058b217613` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1C271B74160501AF2D94CA37F8547B895FD4F7248A2C80B0F0798981A3F7507BB0D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6Ds3Bjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6Ds3Z++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_053_c3b67f17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3"
    family = "VShell"
    file_name = "c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3.exe"
    file_type = "exe"
    first_seen = "2026-11-03 02:54:27"
  condition:
    hash.sha256(0, filesize) == "c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3"
}
```

### Sample 54: `e7439226c3569d26`

| Field | Value |
|---|---|
| SHA-256 | `e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d` |
| Family label | `RustyStealer` |
| File name | `e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d.exe` |
| File type | `exe` |
| First seen | `2026-11-03 02:50:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `056736cb92ef2601e310f54b617afef7` |
| SHA-1 | `fd73f4532a0449a615fce8069cae5633e8837bf1` |
| SHA-256 | `e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d` |
| SHA3-384 | `5921bef6622d8b23e546027a8724866e23fee205b6c8f56ce2b3216944bf31b4589b71219f10b84dbc748a4d117a8f68` |
| IMPHASH | `8ec9ef7bbe6028bc467a6062aac0480d` |
| TLSH | `T168B63399FBA6A3F8E645C7B8C2064C236330B4260F626CAF1F1960312F55EE95E7D171` |
| SSDEEP | `196608:GI2RPC3Hbp4zt2ZwktxLuqV4Zv2kGReYReq44W5p98tV+aSPQyjbCk7TZ:GvRPCXb6IhnLuqVPDNfJW5p98Sy2Bd` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_054_e7439226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d"
    family = "RustyStealer"
    file_name = "e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d.exe"
    file_type = "exe"
    first_seen = "2026-11-03 02:50:04"
  condition:
    hash.sha256(0, filesize) == "e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d"
}
```

### Sample 55: `02b2f61aa7a33067`

| Field | Value |
|---|---|
| SHA-256 | `02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814` |
| Family label | `RustyStealer` |
| File name | `02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814.exe` |
| File type | `exe` |
| First seen | `2026-11-03 02:49:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8b6f4c8326e253b28a04575d6e70a40` |
| SHA-1 | `eea7bfba9db29318165a02c15ebdfe217739f96c` |
| SHA-256 | `02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814` |
| SHA3-384 | `521a29d6e0a2fa6dc697f4d9b60175663767e2cfccc349b342b85e08296b7d2d9df08dd2f31702b7046c8301dfb1b8a8` |
| IMPHASH | `733f32d48f94993fb20bf4c0cb19bc6f` |
| TLSH | `T1E4D52307378E00F9E527857CC642C2579773B8D60B1396DF93E882652F29AF69D39B20` |
| SSDEEP | `49152:UfwXKReZhWs01m5PbmPGNDh1VqApadzopy+HW3Gy9XsOk8Gww2Jt:rJ65PGzFUajWBmn8Gwnt` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_055_02b2f61a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814"
    family = "RustyStealer"
    file_name = "02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814.exe"
    file_type = "exe"
    first_seen = "2026-11-03 02:49:58"
  condition:
    hash.sha256(0, filesize) == "02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814"
}
```

### Sample 56: `5699f25feac04e73`

| Field | Value |
|---|---|
| SHA-256 | `5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnaarch64xnxn` |
| File type | `elf` |
| First seen | `2026-11-03 02:19:05` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0f52299d7ecee94ae19bf6a87102b1d` |
| SHA-1 | `1f8b58ae8d1805465350ed08011cf523f8ee740c` |
| SHA-256 | `5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b` |
| SHA3-384 | `ff9292496095caf84ae0834e159bec0ddeea0b72d5809df69a7e5440cbc4a4d8ddda043e32e4fa35038f1b38977f195f` |
| TLSH | `T142445B56BB8CECC7C0B552F24A4B07331226B875378A9073FA065A5FE69A7DC8D5028D` |
| TELFHASH | `t15b21219c693a890e8b828810ccfc4af83c5d891615e07e95df3cdf605237258624ee0f` |
| SSDEEP | `3072:6CP951CY1ApdMiSRdWSWa9Q26NzzPx/13nelg5WAwOeaVRSsA:DV51CY1ApdMiE4aGbbVhfwOeaVRSsA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_5699f25f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-11-03 02:19:05"
  condition:
    hash.sha256(0, filesize) == "5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b"
}
```

### Sample 57: `1f6bf76318997e43`

| Field | Value |
|---|---|
| SHA-256 | `1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnarmxnxn` |
| File type | `elf` |
| First seen | `2026-11-03 02:19:05` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c40c0f62049771bd8f33d42b8ad59cb2` |
| SHA-1 | `4cc460095d70a608dfcda57ff6984c9c58b06b9d` |
| SHA-256 | `1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241` |
| SHA3-384 | `88dfb3e5905b5385097169539eeceaed8a8a69a126acef57a264f6000291bbdeff06252ae2f9d48ebd4d258603a7a76d` |
| TLSH | `T1CAF318A1A8918A13C5D55B7ABB5F528833724B28C3DB33066D2DAB382F9770D4F3B541` |
| TELFHASH | `t17d21f15c693a890e8b829810ccfc5bf83c5d951615e07ea1df7cdf605273158624ee4e` |
| SSDEEP | `3072:9vm3a3XNpB1PkwLV73RF+zwjfbxWXz+nP7OtXKJepTc:9OqNNcwJ73RFewHkj+nPycJep4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_1f6bf763
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnarmxnxn"
    file_type = "elf"
    first_seen = "2026-11-03 02:19:05"
  condition:
    hash.sha256(0, filesize) == "1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241"
}
```

### Sample 58: `12d279e997c1b6f2`

| Field | Value |
|---|---|
| SHA-256 | `12d279e997c1b6f2b34f0d3a7c50aa6d4ae077618fecee4a4b71dd43dc0e876c` |
| Family label | `Mirai` |
| File name | `run.sh` |
| File type | `sh` |
| First seen | `2026-11-03 02:19:04` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c531db09851fdffe837f0bab6192a592` |
| SHA-1 | `25e199621e75fc95c5cbaf559dd71bd6eed1871e` |
| SHA-256 | `12d279e997c1b6f2b34f0d3a7c50aa6d4ae077618fecee4a4b71dd43dc0e876c` |
| SHA3-384 | `5249fa8d220f3e90e5ee844696c50e362fa85a4e39308a01eb18771663c4c59240d27675aeb04bb3bd70ec8e47813406` |
| TLSH | `T16951FEAA011C4B35E70DCD4EF7FAB174721BE98356DB9618EAD8185E4EC5E4C3381A80` |
| SSDEEP | `24:EkB4Y42JMqRcRbiB+t3tuZmsEpsEnE2EhEbSn5c3cbw7zBlhvcvJUf+2lbYbhM3a:c52JMwKbiBQduZLLcvyMMbwB8hM3a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_12d279e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d279e997c1b6f2b34f0d3a7c50aa6d4ae077618fecee4a4b71dd43dc0e876c"
    family = "Mirai"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-11-03 02:19:04"
  condition:
    hash.sha256(0, filesize) == "12d279e997c1b6f2b34f0d3a7c50aa6d4ae077618fecee4a4b71dd43dc0e876c"
}
```

### Sample 59: `34f608eba7b1d980`

| Field | Value |
|---|---|
| SHA-256 | `34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6` |
| Family label | `Mirai` |
| File name | `sora.arm7` |
| File type | `elf` |
| First seen | `2026-11-03 02:18:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42b431d6ef22570e90df20296c67a0db` |
| SHA-1 | `7149cd1e15eef2858e45ff7382b861926877002f` |
| SHA-256 | `34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6` |
| SHA3-384 | `9cca11984435b2d58a78664aead74c6dcf94ead8a25c40838f74d2eea18b2d6fbf3939097ff26a0d192dee85d523cc0d` |
| TLSH | `T139B32A86BC419E11C5C622B7FB6F008D33026BA9E3EE7212CD115FA077CA95F0E67656` |
| TELFHASH | `t183f08b52df684a9c6fc69260e1dc73271afc3aad2b17241129eeee17c1148d1783ec0e` |
| SSDEEP | `3072:bZRHyVfS7oVkVtzr/p8YYq9fqT5Gx8JGjcPeN1kU1fy:dZyVfS7owtz7pfvx8JGjc615fy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_34f608eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-11-03 02:18:40"
  condition:
    hash.sha256(0, filesize) == "34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6"
}
```

### Sample 60: `3893fa3da89174dd`

| Field | Value |
|---|---|
| SHA-256 | `3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-03 02:18:37` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca61c9cc5c9909f006c55cd8cf8a6c93` |
| SHA-1 | `379227b88254401b001da1bc516ba856e28387f9` |
| SHA-256 | `3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3` |
| SHA3-384 | `05feb0599744d0a42e1795654303470b7fe943b5425302bcf2363c6904717a62ec24ca53cf4352d44d5de9a51b1d7dab` |
| TLSH | `T12B833B03BA808AFEC08AE17407BF763AC415F57D6236B1D737D4FF162909ED01A1A669` |
| TELFHASH | `t14c11a13408cb369c01d78665734ffaf6d69705200988b570ea777e915e6ff908e83961` |
| SSDEEP | `1536:lYo6ORjfMLWxPYOdnVc9wR+WucGY3AbDFLa47YjVZOYhMsQJeFbiqYRKROxkMgk:61OpBxPzdnqenucGY3AbBL/Y3hMsGeFr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_3893fa3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-03 02:18:37"
  condition:
    hash.sha256(0, filesize) == "3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3"
}
```

### Sample 61: `a6447a059d57eb02`

| Field | Value |
|---|---|
| SHA-256 | `a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa` |
| Family label | `Mirai` |
| File name | `vc.sh` |
| File type | `sh` |
| First seen | `2026-11-03 02:18:34` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec4aedb3c7ec02db353ade26cb958cf4` |
| SHA-1 | `38ada4dd2dd634c72dc05d52aa0c38430277b996` |
| SHA-256 | `a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa` |
| SHA3-384 | `a0fc82de347e3b9db9837cefa2a0c4feac7700c162f4806be77b75675ba18a5d410c4739f24becf4decd3849e836fe94` |
| TLSH | `T14B016BF6EAB18D30381CC425FD8C12E469C74E7F41E93887C8DA5821B66C44D949AF71` |
| SSDEEP | `12:5NIhNUljBK8Zu3NtrMjHI7IdJX7M7IQLBjC6HnJFUkl7UwHB:5NC2l15E3bUpJLE+4HIU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_a6447a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa"
    family = "Mirai"
    file_name = "vc.sh"
    file_type = "sh"
    first_seen = "2026-11-03 02:18:34"
  condition:
    hash.sha256(0, filesize) == "a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa"
}
```

### Sample 62: `cca1ee815fea880b`

| Field | Value |
|---|---|
| SHA-256 | `cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83` |
| Family label | `Mirai` |
| File name | `sora.arm` |
| File type | `elf` |
| First seen | `2026-11-03 02:18:33` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2543e718fadd1615971355bca8bf8e9` |
| SHA-1 | `c206fb244aa2b75b5ea774d2d2625300dde049f7` |
| SHA-256 | `cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83` |
| SHA3-384 | `fd90db2be71ac7ec1f5124a50fdf6fff2ecdbd8b2dc7e83acf7fef34e3ed05a8986aaec0e643d642a3760271bcdd557e` |
| TLSH | `T177930982BC41EA16C6C113B7FAAF008D3311BBDDE1DA3242DD216FA47B8A85B0D67755` |
| TELFHASH | `t1abb09233db1200ac2189820261b527045574b36e589b18a162102b9d64578a0e81a9a2` |
| SSDEEP | `1536:/H0fyBBWHgueEsaqHbSAat4ZAt3rAIlys0jyM7k9L7B8t46FbdBJZZKmyQ:/H0MggKFAAtoPgJV84+bPJZzyQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_cca1ee81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-11-03 02:18:33"
  condition:
    hash.sha256(0, filesize) == "cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83"
}
```

### Sample 63: `0e70985db3edea39`

| Field | Value |
|---|---|
| SHA-256 | `0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb` |
| Family label | `unknown` |
| File name | `0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb.bin` |
| File type | `macho` |
| First seen | `2026-11-03 02:05:17` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81539f8665341c9786fad139e076e185` |
| SHA-1 | `ed3d71716d3b2426160110fc6e5f467062dd4720` |
| SHA-256 | `0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb` |
| SHA3-384 | `a28305b92bee0b0133b22eb0f68fa04264158daacf1e03190679aeef6732001a0493f151b4129fa4db3d433a26015eff` |
| TLSH | `T1DAE24E43675C5929D05D83BE22FB1B976609F8A009D45B432F90DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCKfwYjqclS06W1YbqclSl:GI2n5DbDyawYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_0e70985d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb"
    family = "unknown"
    file_name = "0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb.bin"
    file_type = "macho"
    first_seen = "2026-11-03 02:05:17"
  condition:
    hash.sha256(0, filesize) == "0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb"
}
```

### Sample 64: `0931275a4bdc9c65`

| Field | Value |
|---|---|
| SHA-256 | `0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d` |
| Family label | `ConnectWise` |
| File name | `0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:54:10` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `256613a71aca92f8e6604e2445ec21d9` |
| SHA-1 | `0d414363236e4b7741b184c16fdf8665da3aecdb` |
| SHA-256 | `0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d` |
| SHA3-384 | `4efa2f9d12e91cf6df0770881f03d0da73a65e0636f57a7a2e394e36823e87ff764189b4129268e2e433de497ffde1d8` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T14BD61211B3F59675D1FB0638E87AA3615A35BC014B12C7AF6794792A2D327C08E323B7` |
| SSDEEP | `393216:RFri04SOLmX12Fri04SOLmFri04SOLsFri04SOLv:RMrSOL8UMrSOLmMrSOLsMrSOLv` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_064_0931275a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d"
    family = "ConnectWise"
    file_name = "0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:54:10"
  condition:
    hash.sha256(0, filesize) == "0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d"
}
```

### Sample 65: `9d055c051b900212`

| Field | Value |
|---|---|
| SHA-256 | `9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815` |
| Family label | `unknown` |
| File name | `9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815.bin` |
| File type | `macho` |
| First seen | `2026-11-03 01:51:20` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06fd631c3b45f98da70256803383a293` |
| SHA-1 | `d6523ab9d40a3e69a9336a10a83767e1cdb04c49` |
| SHA-256 | `9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815` |
| SHA3-384 | `eb3d6e35c5791f9c1043e883e1885052e7eb71655a1e8122146e252830c82fac7898df64f1cfc98094cb55bb9733035e` |
| TLSH | `T1BFE22D43AB4C8965C26D42301AF71BC6A615F5B09EE16B875750C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUlVZqDDt0TOTLZ0BbFw2CHKk6XrMclSibFqAMcl:z4ZZXvvcVZMt0TO2bVO/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_9d055c05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815"
    family = "unknown"
    file_name = "9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815.bin"
    file_type = "macho"
    first_seen = "2026-11-03 01:51:20"
  condition:
    hash.sha256(0, filesize) == "9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815"
}
```

### Sample 66: `044857a13fb81cd7`

| Field | Value |
|---|---|
| SHA-256 | `044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107` |
| Family label | `unknown` |
| File name | `044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:51:16` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4f4525a91f86323a64149faad7bf733` |
| SHA-1 | `964d2e17e97b83833cc28cbc71415c59c886bfa1` |
| SHA-256 | `044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107` |
| SHA3-384 | `237605cf9585932803c053825e424fb9188841989a02073e0655c92623be5d2f31ba6c7ab7e972a3728432ecee4c2428` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T19B91C64270B989E7E85D55BB4C0FB8A0B919740A41C483A70378A5953E3957BF57CB0E` |
| SSDEEP | `48:6IIF9BlQaexF/gZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMFCA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_044857a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107"
    family = "unknown"
    file_name = "044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:51:16"
  condition:
    hash.sha256(0, filesize) == "044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107"
}
```

### Sample 67: `3fa5057e1be1cfeb`

| Field | Value |
|---|---|
| SHA-256 | `3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8` |
| Family label | `unknown` |
| File name | `sshd` |
| File type | `elf` |
| First seen | `2026-11-03 01:43:08` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a31e97eb6a5b71f13b1376ce52030ca` |
| SHA-1 | `1d44b6f809ddc7bd018b817ffa2c95d7735a5baf` |
| SHA-256 | `3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8` |
| SHA3-384 | `fbe4febae59735f61487e9eccb8db7e9f916b9fc36d23fe3f149733606954dd759410a46998f48fe6edb9c4e71da8596` |
| TLSH | `T14B47DF77814238E9E5B98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQR:cqYUQuVDt0TZEK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_3fa5057e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
    family = "unknown"
    file_name = "sshd"
    file_type = "elf"
    first_seen = "2026-11-03 01:43:08"
  condition:
    hash.sha256(0, filesize) == "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
}
```

### Sample 68: `d148eb058ded0614`

| Field | Value |
|---|---|
| SHA-256 | `d148eb058ded06149b9110e91bbd0c49b626ae0cac4fccfe38c57ea00b4f6106` |
| Family label | `unknown` |
| File name | `install_guard.js` |
| File type | `js` |
| First seen | `2026-11-03 01:36:29` |
| Reporter | `skocherhan` |
| Tags | `api-gaganata-ink, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ddcf4113089325839fad3ee24b446df` |
| SHA-1 | `50414ce4136787f296390a4ca414b68785b94bfa` |
| SHA-256 | `d148eb058ded06149b9110e91bbd0c49b626ae0cac4fccfe38c57ea00b4f6106` |
| SHA3-384 | `978d5deb1ad299e14bca6ff756d971a727bf8b461f9aa67b92a75de22cdc4a9f9b89b2269fb37e7ac3ba49781b0ed8a8` |
| TLSH | `T1867533117F667A6D9660822534ABFF0C96B14FF044BF84DA52D51CA20C8B78A08FFD6C` |
| SSDEEP | `24576:UWPzFIlaND+xZFPGJJG2SOMrZGES9MMWBSntovWGqzjNInUfzsyfCVj9k:kl8koJtSUBM8lGRcwk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_d148eb05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d148eb058ded06149b9110e91bbd0c49b626ae0cac4fccfe38c57ea00b4f6106"
    family = "unknown"
    file_name = "install_guard.js"
    file_type = "js"
    first_seen = "2026-11-03 01:36:29"
  condition:
    hash.sha256(0, filesize) == "d148eb058ded06149b9110e91bbd0c49b626ae0cac4fccfe38c57ea00b4f6106"
}
```

### Sample 69: `aea7eabc5fcd280e`

| Field | Value |
|---|---|
| SHA-256 | `aea7eabc5fcd280ed27d3ecac2f65fd753c6c97acebee78da1d7b5d66b17d55e` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Win32.MalwareX-gen.31186186` |
| File type | `exe` |
| First seen | `2026-11-03 01:31:44` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a5084259adfd165356618cee2ca3b32` |
| SHA-1 | `c2d636dde37e384c21adb8ce4b237d22c92d51a8` |
| SHA-256 | `aea7eabc5fcd280ed27d3ecac2f65fd753c6c97acebee78da1d7b5d66b17d55e` |
| SHA3-384 | `21494b4577ff5795e34f817c7514a3b10aa5c4bbce0300aa0d617069bb2a9d9150fc14a253f2815162f319503f7429a4` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T12D65E00823D4DA09E47607B6DD6AD1F007B65F56E522D26BEEE17ECF7839F706A00242` |
| SSDEEP | `24576:ozFUooFHeYCXaDEHL8r2gonDqm9YGXo4gJCn87iF9:ozdY3aoKgoDqZGY5J0D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_aea7eabc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aea7eabc5fcd280ed27d3ecac2f65fd753c6c97acebee78da1d7b5d66b17d55e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win32.MalwareX-gen.31186186"
    file_type = "exe"
    first_seen = "2026-11-03 01:31:44"
  condition:
    hash.sha256(0, filesize) == "aea7eabc5fcd280ed27d3ecac2f65fd753c6c97acebee78da1d7b5d66b17d55e"
}
```

### Sample 70: `be8ab2520e0a3de2`

| Field | Value |
|---|---|
| SHA-256 | `be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db` |
| Family label | `SalatStealer` |
| File name | `be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:27:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a23219ff465584bda6e560841e238cd1` |
| SHA-1 | `6c492aa72c4c2ada5b46f726b2f806235413e7bf` |
| SHA-256 | `be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db` |
| SHA3-384 | `5b4ca947811d3c86b9bb0a9231ddf16fe195e833863e8048f318ceb484b27eb65f310c988ba8a367017a0938f18deef2` |
| IMPHASH | `16bf19179d4d282835acb65727f9faa8` |
| TLSH | `T195661205FEBD34B4C21B827A00FF751617338A2A10125956B3EEDCA5637DFCA669B42C` |
| SSDEEP | `49152:B8bNYZdeOlBU5ypE/eomn8Fn9SDaLUcpux1w54sxl3/LS7qxsS2lkyEHKy4tW9yU:+J` |
| ICON-DHASH | `4020009758e00108` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_070_be8ab252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db"
    family = "SalatStealer"
    file_name = "be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:27:08"
  condition:
    hash.sha256(0, filesize) == "be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db"
}
```

### Sample 71: `4241ce66cddc1061`

| Field | Value |
|---|---|
| SHA-256 | `4241ce66cddc1061b5549e4cffdd7866c519f3d52e29853e7c582156e0b69eae` |
| Family label | `SalatStealer` |
| File name | `383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:10:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6ba41132bb6333d97cf509a069d7cc6` |
| SHA-1 | `e10d7d55bb0caa16c03ac585cbeaabb32f38e177` |
| SHA-256 | `4241ce66cddc1061b5549e4cffdd7866c519f3d52e29853e7c582156e0b69eae` |
| SHA3-384 | `7f4bc43876e7fb1a8b3a6a24c0f1a86d6ba09179fe9cf9bb6bef25f6396fb4f2505229800869fbbe97a74d6c6a26ebd9` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F5C65B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:8lSrMdq9tmCXNC/nh6bRNOgVBDKofu4tG20CWEq:TMmnNuIbRVmHCq` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_071_4241ce66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4241ce66cddc1061b5549e4cffdd7866c519f3d52e29853e7c582156e0b69eae"
    family = "SalatStealer"
    file_name = "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:10:19"
  condition:
    hash.sha256(0, filesize) == "4241ce66cddc1061b5549e4cffdd7866c519f3d52e29853e7c582156e0b69eae"
}
```

### Sample 72: `02e52ba371be78d8`

| Field | Value |
|---|---|
| SHA-256 | `02e52ba371be78d83f6d3201f7b7cc9ff360f5c8ec8e8e98338e0de241745d54` |
| Family label | `SalatStealer` |
| File name | `6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:09:17` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `729a981d4d549f5b3f5d1ad115504ba9` |
| SHA-1 | `e263fbb121f7cc7061d1ec0fbd395f901e0aeb69` |
| SHA-256 | `02e52ba371be78d83f6d3201f7b7cc9ff360f5c8ec8e8e98338e0de241745d54` |
| SHA3-384 | `2cf07f75a6a4e9e970a837d4a3996cf604642671c984988b3161911c4f1ac1ffb8bb9e3d8b5afd7b4a6941deb2b1d89c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T136C65B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:6YZRvB6FCeCH1/aplmwreXsVlFhl7r4tG20CWE6:pvZ/1iewr/fHC6` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_072_02e52ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02e52ba371be78d83f6d3201f7b7cc9ff360f5c8ec8e8e98338e0de241745d54"
    family = "SalatStealer"
    file_name = "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:09:17"
  condition:
    hash.sha256(0, filesize) == "02e52ba371be78d83f6d3201f7b7cc9ff360f5c8ec8e8e98338e0de241745d54"
}
```

### Sample 73: `383baab18b342eff`

| Field | Value |
|---|---|
| SHA-256 | `383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243` |
| Family label | `SalatStealer` |
| File name | `383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:09:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3f2e844d7e939c4dcc6d690d3aefe7d` |
| SHA-1 | `70b6a1d3f30d0c4d008e259969c3b9d8b5cc45be` |
| SHA-256 | `383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243` |
| SHA3-384 | `c1b0f2f5fe2650d9615c1cf3295ac0f304b33363c20a6ea94bb3b2aae02055763394a13f013a0acc2bcea6b48b66ee78` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1AFF533B9C79F6AE7D7363CB8177B03F930740E3426F4C66A844C23D583A5B592818AB5` |
| SSDEEP | `98304:85jG0dkLlYQ/n7F5YAsYIoTaIEnfOe/kigLFHq:o6PCQ/p5YAsYlT3cOmgLFHq` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_073_383baab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243"
    family = "SalatStealer"
    file_name = "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:09:15"
  condition:
    hash.sha256(0, filesize) == "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243"
}
```

### Sample 74: `6ea8d738dd5d1d4b`

| Field | Value |
|---|---|
| SHA-256 | `6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6` |
| Family label | `SalatStealer` |
| File name | `6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:09:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04ccc50aea59cc73535267cc8315dba5` |
| SHA-1 | `d112f9f31adffb08c4ddf4057d9e0b9aaf8c0873` |
| SHA-256 | `6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6` |
| SHA3-384 | `711a40dd14d8a87810a6fbf0a80afb5532725cc7d73b1d804264bff84e2d51d6896d9c1f2c06da42e9bdc851283cae36` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T139F53321A063CCECF7A47A328DCE55D709CC2DA73FF744359E539461AAA44E684D238B` |
| SSDEEP | `98304:SvZJpEwbceOJn6nRMhERASjTz8LQj8ZJIS0r6:QpEgOJn6nRMhERA280j8ZJh0` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_074_6ea8d738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6"
    family = "SalatStealer"
    file_name = "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:09:10"
  condition:
    hash.sha256(0, filesize) == "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6"
}
```

### Sample 75: `9500e41175cbe66a`

| Field | Value |
|---|---|
| SHA-256 | `9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f` |
| Family label | `unknown` |
| File name | `9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f.exe` |
| File type | `exe` |
| First seen | `2026-11-03 01:01:37` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cd0df522de7a59d97577a2826cfb3d2` |
| SHA-1 | `6eb0a80b9f97768fc3b5b3ab99ef8a72c5982664` |
| SHA-256 | `9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f` |
| SHA3-384 | `17a9e5b00e1b154a0f5cdea7db7ff85d98cbc44d7af981af9bdbd9994f175282d09ec86e8fa60aaf0170b3a344db6479` |
| IMPHASH | `6732989f7f3dc425afb3e1f08e4c2772` |
| TLSH | `T121B343452574BCB8C526803E9203632257B33C4DC33166A7BAA9DD643F97FA06B2D7E1` |
| SSDEEP | `3072:BNhsj7BQl2hwksiTS4EoEfYyHGwphy7GNOEz6JAY2Udqzm25gDKdUm/wJq+5/lSA:BNhs0wCJphy7GNOEz6JAY2Udqzm25gDc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_9500e411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f"
    family = "unknown"
    file_name = "9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:01:37"
  condition:
    hash.sha256(0, filesize) == "9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f"
}
```

### Sample 76: `f5ee612748cedfd6`

| Field | Value |
|---|---|
| SHA-256 | `f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be` |
| Family label | `AsyncRAT` |
| File name | `f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:54:22` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1d1934c74bbafed34ff53e4511a308b5` |
| SHA-1 | `2a96f2221fce85746ece71c98de5251cedb1bf36` |
| SHA-256 | `f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be` |
| SHA3-384 | `2607d000d57ae53af88d1b2bcd899aae0dd81102ae23290c1266a77325a6a110cf1aa1bef2be3f7f273f707269f896de` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T171231B003BE8812BF2BE4F7499F26145467AF2677603D64D2CC452DB5713FC69A02AEE` |
| SSDEEP | `768:xuQSNTvEEaBrWUXFd5mo2qmiWv8n2+Fjw2NLPIPzjbfgXIiE3b8FWC0BDZex:xuQSNT8572xzv9Ew2CP3boXFE3bqCdex` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_076_f5ee6127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be"
    family = "AsyncRAT"
    file_name = "f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:54:22"
  condition:
    hash.sha256(0, filesize) == "f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be"
}
```

### Sample 77: `a541773431123246`

| Field | Value |
|---|---|
| SHA-256 | `a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac` |
| Family label | `ConnectWise` |
| File name | `a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:54:15` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `073813939d8cf7279be68fd877430a16` |
| SHA-1 | `8a99ce24b0459099859fba34e62cd6418493ab50` |
| SHA-256 | `a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac` |
| SHA3-384 | `254d9e863f20d70faff844c47cbcc8808ff0bd3e1e7a7599ed95694b70cd46e011652bfb5c1e41ffec2519e23f61ef0a` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1E646F101B3D695B5D0BF0678D87A42A65634BC108712C7FF57A4BD296D32BC08E723BA` |
| SSDEEP | `49152:SfRBDtJkGYYpT0+TFiH7efP3nrGLq7FVsLBe+1GVxrKlsuwGenGwfZVkVjOi8ifH:eqs6efP3rn/TYGVxz3GBwRVkGuyXOM` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_077_a5417734
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac"
    family = "ConnectWise"
    file_name = "a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:54:15"
  condition:
    hash.sha256(0, filesize) == "a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac"
}
```

### Sample 78: `d12ae777cd027bc8`

| Field | Value |
|---|---|
| SHA-256 | `d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64` |
| Family label | `ConnectWise` |
| File name | `d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64.msi` |
| File type | `msi` |
| First seen | `2026-11-03 00:54:09` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `782526011b68721a08c2b04b5390bd46` |
| SHA-1 | `d9122891a299166bb816357734c542b48f51eb30` |
| SHA-256 | `d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64` |
| SHA3-384 | `56c03818dc69c12f3e1119a5fe5c0d9805a334b38f387db78c163ec9d8f3b32daf0e76fcbe1037ea39be1aff07f2936f` |
| TLSH | `T12BD6232267FD0A18E1F36778ED3A91E19536BC65DF12D08F2654386E6871E4093A333B` |
| SSDEEP | `196608:UrnLYG3zDhukOqrnLYG3zlrnLYG3z3rnLYG3z4rnLYG3zirnLYG3zgrnLYG3z:UbDDDgvqbDDlbDD3bDD4bDDibDDgbDD` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_078_d12ae777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64"
    family = "ConnectWise"
    file_name = "d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64.msi"
    file_type = "msi"
    first_seen = "2026-11-03 00:54:09"
  condition:
    hash.sha256(0, filesize) == "d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64"
}
```

### Sample 79: `4841193715abddab`

| Field | Value |
|---|---|
| SHA-256 | `4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97` |
| Family label | `unknown` |
| File name | `4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:51:38` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00ad47483301469d90af83f3ee40f1c7` |
| SHA-1 | `cb05fc19b8712f62ee0bf6fcb6e08e417fb96e7d` |
| SHA-256 | `4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97` |
| SHA3-384 | `804deba6484055eb9cbc0f8bc0afd0406316996a968859cce8df0a9cf7bf4376c9b1a8ae1432ef4619170cb56cdfa230` |
| IMPHASH | `6732989f7f3dc425afb3e1f08e4c2772` |
| TLSH | `T110B353452574BCB8C566803E9203632253B23C4DC3326667BAE9DD643F97F606B2E7E1` |
| SSDEEP | `3072:m451ccBJgNbZEM7Xq3knfTR2gBB+3Udq8/mJQz6tlFZwpJwiu90bKA5Oa38cG27O:m45SnbRNBB+3Udq8/mJQz6tlFZwpJwi4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_48411937
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97"
    family = "unknown"
    file_name = "4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:51:38"
  condition:
    hash.sha256(0, filesize) == "4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97"
}
```

### Sample 80: `29d09b3ef708a8ef`

| Field | Value |
|---|---|
| SHA-256 | `29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91` |
| Family label | `unknown` |
| File name | `29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:51:31` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44f714c172de377f210f958830b7d88d` |
| SHA-1 | `5e9acea6c217e763e0b45d968520c452fcd1c1fb` |
| SHA-256 | `29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91` |
| SHA3-384 | `c6f909b92cd70ef38ad6026f16fb32bf543fc9b177d081288770ab321e462a495329a9c2e9bfa92eafc3e64d0d63f358` |
| TLSH | `T11BF25F139B1C0A61C05CA33C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRSDPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfnlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_29d09b3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91"
    family = "unknown"
    file_name = "29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:51:31"
  condition:
    hash.sha256(0, filesize) == "29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91"
}
```

### Sample 81: `79667b9fab75fb02`

| Field | Value |
|---|---|
| SHA-256 | `79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856` |
| Family label | `unknown` |
| File name | `79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:50:32` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dda172653a16df80bbefa76e8b5ad6f8` |
| SHA-1 | `3add8003e58c65a5dc3a128bc1a9f230d91bae45` |
| SHA-256 | `79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856` |
| SHA3-384 | `dce0589e72e797a1d7f7bf6aae5ef9767989c6748955e8ca00613fcbf0bea707af07dd5d9c099acf2486e87599c2d445` |
| IMPHASH | `6732989f7f3dc425afb3e1f08e4c2772` |
| TLSH | `T1BBD3641536B47878C667C13E8102632292F23C5D932152376EA9DD643FA7EA12B3E7F4` |
| SSDEEP | `3072:UhRCtSBxyJhIz4T07U3TWff1AVszqZgX+s1aDQZpgD61cPngJKTcF2cLi1ovUal+:UhRCtFDW31yszqZgX+s1aDQZpgD61cPS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_79667b9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856"
    family = "unknown"
    file_name = "79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:50:32"
  condition:
    hash.sha256(0, filesize) == "79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856"
}
```

### Sample 82: `78714f6f57c51772`

| Field | Value |
|---|---|
| SHA-256 | `78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba` |
| Family label | `unknown` |
| File name | `78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:50:27` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7543cca0e3da65caa54a9781fd2850` |
| SHA-1 | `ba43be545dd5c21d756345bd50be97ba54453820` |
| SHA-256 | `78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba` |
| SHA3-384 | `aca4b6dd8c473803e50876524c6e793e6a2e52c874a9cab7656968bad391f1c0c40e30c53c5bce64a0f409a060d48ce8` |
| IMPHASH | `6732989f7f3dc425afb3e1f08e4c2772` |
| TLSH | `T1F7D353153274787CCA67913E8102632292F23C5DD32152376AA9AD743FA7E612B3E7F4` |
| SSDEEP | `3072:L+RMdShItP5x4DIDUL1e8fzjQSrYBuXry18/G4hyLc8aczHp6CWfMVqDQQLTcpk3:L+RMQbL8SrYBuXry18/G4hyLc8aczHpF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_78714f6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba"
    family = "unknown"
    file_name = "78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:50:27"
  condition:
    hash.sha256(0, filesize) == "78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba"
}
```

### Sample 83: `2513641573e48d63`

| Field | Value |
|---|---|
| SHA-256 | `2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75` |
| Family label | `ConnectWise` |
| File name | `2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:49:24` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e648edbb6fcc37b04dd869647df3a840` |
| SHA-1 | `aae92ddbf44d68c5b42b4818825cb11b8ceedad1` |
| SHA-256 | `2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75` |
| SHA3-384 | `72b9031b4df5d670ae02dfb983652852597c97f2b0000d2fa7a5bd22a39130e48a2a383c40213b4b3053aefad72099d2` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1B3D61211B3F59675D1FB0638E87AA3615A35BC014B12C7AF6794792A2D327C08E323B7` |
| SSDEEP | `393216:0Fri04SOLlX10Fri04SOLmFri04SOLIFri04SOLU:0MrSOLR2MrSOLmMrSOLIMrSOLU` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_083_25136415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75"
    family = "ConnectWise"
    file_name = "2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:49:24"
  condition:
    hash.sha256(0, filesize) == "2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75"
}
```

### Sample 84: `38bdba3cb4fb8c92`

| Field | Value |
|---|---|
| SHA-256 | `38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0` |
| Family label | `ConnectWise` |
| File name | `38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0.msi` |
| File type | `msi` |
| First seen | `2026-11-03 00:49:18` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e610d5b84b8ce3e05b3fb68c7ab8f91` |
| SHA-1 | `889b21d471cee3b4ac8d528c974a11f122296c92` |
| SHA-256 | `38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0` |
| SHA3-384 | `173428fecd5f7ca642f8d50da8adac747000ef36ee25d595b19e2a690de56a19d93afe79dbd66f06dc216512d5cba818` |
| TLSH | `T1A3D623226AFD8598F8F39F34F93A99A5853AFC248D62C01F1759780E1972B418673373` |
| SSDEEP | `393216:8cVPOBdGcVPOZcVPOZcVPOtcVPOwcVPOdcVPOk:8cVmBdGcVmZcVmZcVmtcVmwcVmdcVmk` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_084_38bdba3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0"
    family = "ConnectWise"
    file_name = "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0.msi"
    file_type = "msi"
    first_seen = "2026-11-03 00:49:18"
  condition:
    hash.sha256(0, filesize) == "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0"
}
```

### Sample 85: `50f673e15f4acb31`

| Field | Value |
|---|---|
| SHA-256 | `50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3` |
| Family label | `ConnectWise` |
| File name | `50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3.msi` |
| File type | `msi` |
| First seen | `2026-11-03 00:49:10` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30bcb0cf9c4f45510c2d218b7fd05fcc` |
| SHA-1 | `10fb576c19cb7735b2fdca6e9b9862e9e3a51b22` |
| SHA-256 | `50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3` |
| SHA3-384 | `0e4022ffe2abc2cda4d0c902086c6ae3ddb46b05dd96f1391fd1c9fd1b43bdf4407fa1f99c4ec2cc2f1c585ea4770ed2` |
| TLSH | `T10AD623226AFD8599F8F39F34F93AA9A5853AFC248D62C01F1715780E1972B418673373` |
| SSDEEP | `393216:PcVPOBdKcVPOmcVPOtcVPO7cVPOpcVPOFcVPOx:PcVmBdKcVmmcVmtcVm7cVmpcVmFcVmx` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_085_50f673e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3"
    family = "ConnectWise"
    file_name = "50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3.msi"
    file_type = "msi"
    first_seen = "2026-11-03 00:49:10"
  condition:
    hash.sha256(0, filesize) == "50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3"
}
```

### Sample 86: `be9c3f967c470132`

| Field | Value |
|---|---|
| SHA-256 | `be9c3f967c4701326623052636bf7bae66381528a28b519271b0fe0642d569f8` |
| Family label | `Silentnet` |
| File name | `PurxiyClient-1.21.11.jar` |
| File type | `jar` |
| First seen | `2026-11-03 00:46:30` |
| Reporter | `GhostTypes` |
| Tags | `EtherHiding, jar, SilentNet, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa747d0a076e79add67ecec6f0cdd12b` |
| SHA-1 | `a133852cf07511cbf207a80e54ecf3a72c9fd171` |
| SHA-256 | `be9c3f967c4701326623052636bf7bae66381528a28b519271b0fe0642d569f8` |
| SHA3-384 | `3dc8e240b32eb279f6f6a98d7aeaa30ca0a7a5219220888651428e61ddb19c609b99831916813ea1bef710f87710f0e2` |
| TLSH | `T1DEC533B09D1FEC13EC1E6861758E73E98A5CFEF34E49759D7CA42B46880280E67815BC` |
| SSDEEP | `49152:Qc4420JgMAIJvO6BMQJtbjqk4jjoz/zf/n8qJM+4iPjRcdbTONdKepd0J/cG79G:Qch2gJvO3QJtbjqkrrz3hDpPjRcdbTOP` |

#### Technical Assessment

- The sample is tracked as `Silentnet` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Silentnet_086_be9c3f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be9c3f967c4701326623052636bf7bae66381528a28b519271b0fe0642d569f8"
    family = "Silentnet"
    file_name = "PurxiyClient-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-11-03 00:46:30"
  condition:
    hash.sha256(0, filesize) == "be9c3f967c4701326623052636bf7bae66381528a28b519271b0fe0642d569f8"
}
```

### Sample 87: `9a83346aa14e0afe`

| Field | Value |
|---|---|
| SHA-256 | `9a83346aa14e0afedf499aa8ce74e2c2f83b044e13c34ef39d55d2c47da035e8` |
| Family label | `WARDENStealer` |
| File name | `p?t=df801cc0d46ed6482f48d3576e6b64d9_d5bcce35aaf5dafe9c99bbe0105909d2d90d1456` |
| File type | `exe` |
| First seen | `2026-11-03 00:39:24` |
| Reporter | `anonymous` |
| Tags | `ClickFix, exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7a16c8087159587359cf5b79ba2676e` |
| SHA-1 | `e4df600490f551e5eba361a582f9cc6b835abdac` |
| SHA-256 | `9a83346aa14e0afedf499aa8ce74e2c2f83b044e13c34ef39d55d2c47da035e8` |
| SHA3-384 | `52323fa8e04175bc11e11ad251f8a239c79b5c2b8c7c3da52f84e90e07b0917eae8c11fd0eb53d033cf1ba8e3302e6e5` |
| IMPHASH | `dac8af2428df392cc035a1603c2e86f3` |
| TLSH | `T16F353502A7C54DBBFF199C3C85314A139D61681346FA57BE53BC161B1A227848EFBEB0` |
| SSDEEP | `24576:tlWSZaSS0HLf++I6Hie0rZj9H3gqpEFp7Wr:tsyjICgOJ` |
| ICON-DHASH | `0c3161ccc469310c` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_087_9a83346a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a83346aa14e0afedf499aa8ce74e2c2f83b044e13c34ef39d55d2c47da035e8"
    family = "WARDENStealer"
    file_name = "p?t=df801cc0d46ed6482f48d3576e6b64d9_d5bcce35aaf5dafe9c99bbe0105909d2d90d1456"
    file_type = "exe"
    first_seen = "2026-11-03 00:39:24"
  condition:
    hash.sha256(0, filesize) == "9a83346aa14e0afedf499aa8ce74e2c2f83b044e13c34ef39d55d2c47da035e8"
}
```

### Sample 88: `40bd526a2b04656e`

| Field | Value |
|---|---|
| SHA-256 | `40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57` |
| Family label | `WannaCry` |
| File name | `e1e708bd666f6645a561f6b57f1c3e50` |
| File type | `dll` |
| First seen | `2026-11-03 00:31:02` |
| Reporter | `malwareontap` |
| Tags | `dionaea, dll, honeypot, pe, WannaCry, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1e708bd666f6645a561f6b57f1c3e50` |
| SHA-1 | `7e1ff837005680d0bb333bd9124d2369bb2d2bec` |
| SHA-256 | `40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57` |
| SHA3-384 | `684a6875487264af222800e42bdf7ef51dabc589cb8072c1073b48a0c75caa9d102beb858db05fee1c92784ca420bdff` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T12A3623A630EC80B4D2096570986B9E22E6B67C7921BA6D4FDFC04E712E13B63F714753` |
| SSDEEP | `24576:RbLguriILMSirYbcMNgef0QeQjGdD8kIIz6626M+vbOSSqTPVXmiHkQg:RnRMSPbcBVQejdqx+TSqTdX1HkQ` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_088_40bd526a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57"
    family = "WannaCry"
    file_name = "e1e708bd666f6645a561f6b57f1c3e50"
    file_type = "dll"
    first_seen = "2026-11-03 00:31:02"
  condition:
    hash.sha256(0, filesize) == "40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57"
}
```

### Sample 89: `fbb6171ee8310129`

| Field | Value |
|---|---|
| SHA-256 | `fbb6171ee8310129b57960d68b3478d4a803b1f0b6152d36a30763a49a0d85fa` |
| Family label | `unknown` |
| File name | `macho_fbb6171ee831.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:30:43` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e8561b6b3dab5df0f5838fd147750cf` |
| SHA-1 | `19a4336f040d07b4aa663c16832aa2c7c0fb770a` |
| SHA-256 | `fbb6171ee8310129b57960d68b3478d4a803b1f0b6152d36a30763a49a0d85fa` |
| SHA3-384 | `7e41dbfd9b5a41da487d8355b73b9fba94b37495af2d3a57b98dc1647514e4608f7735af87d9d0f7d352f79d6e59c8b7` |
| TLSH | `T16AA5F104467E12A8E46334B29D148FE556F4B9C2695CBEF45732CB22AC37613BA63337` |
| SSDEEP | `24576:cB5xl8vKS42L5TGiWUD0IO5SZp1QoNS2UY3v4CmhuC90Xn9661oQFoUod0E2bTQ/:LCrapngTO331o70E2bTQWWwryLKm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_fbb6171e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbb6171ee8310129b57960d68b3478d4a803b1f0b6152d36a30763a49a0d85fa"
    family = "unknown"
    file_name = "macho_fbb6171ee831.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:30:43"
  condition:
    hash.sha256(0, filesize) == "fbb6171ee8310129b57960d68b3478d4a803b1f0b6152d36a30763a49a0d85fa"
}
```

### Sample 90: `1dffdfbda8c09dd3`

| Field | Value |
|---|---|
| SHA-256 | `1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7` |
| Family label | `unknown` |
| File name | `macho_1dffdfbda8c0.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:28:29` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1705177678bdeaff4da9041f4d6081f` |
| SHA-1 | `82491cc2f1de5f8711a2db9e373bc28b8a79ca19` |
| SHA-256 | `1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7` |
| SHA3-384 | `62711bd5415213d816c4dfa917c6b59b72903833b48faaec57a1f0c936fa3ebe1514b1b00d8b72d5f3f35fbf400932af` |
| TLSH | `T154850150DF3912EAD85528F2DCD47F3994A0AB836E0466F9633593067E31603B67F22E` |
| SSDEEP | `24576:hY4zDkPlXB92s3cYT04vKhmgron8SPMDCuiWpTbV3JNIMcObQVbpLnoH0ArGv463:hbAlEv4vyoGxbV3JNNjbQVbpLnyaX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_1dffdfbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7"
    family = "unknown"
    file_name = "macho_1dffdfbda8c0.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:28:29"
  condition:
    hash.sha256(0, filesize) == "1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7"
}
```

### Sample 91: `08a5355940f391f8`

| Field | Value |
|---|---|
| SHA-256 | `08a5355940f391f82b95b87e76fabe60bb10ba4ca8627748917becfcd457a404` |
| Family label | `unknown` |
| File name | `macho_08a5355940f3.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:27:15` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da5be5c52f1d8c6c20109e864b231e06` |
| SHA-1 | `762a3c47b89f26d13be4432bd2b1cb4a9f8b3505` |
| SHA-256 | `08a5355940f391f82b95b87e76fabe60bb10ba4ca8627748917becfcd457a404` |
| SHA3-384 | `05ece62f076258515aff71d6926cd9ec842d7a7442c52bf8f883df51bde295bf13cc979ee8b1c501457d8d074e4a63a5` |
| TLSH | `T160A5E0404E6E930AD59900B3DC9ACB59457432E0CF88D9E96302639ADE3D3D3B75B2B7` |
| SSDEEP | `24576:ZQFuEITrYIoIsLCnmW2Jz2SkLMaVMZADemHtUzIMLKa5otjqS9/mac3CaVIrA3+E:Tb2ULMWBDeQUzIMLl5ytQ3Cc33+E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_08a53559
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08a5355940f391f82b95b87e76fabe60bb10ba4ca8627748917becfcd457a404"
    family = "unknown"
    file_name = "macho_08a5355940f3.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:27:15"
  condition:
    hash.sha256(0, filesize) == "08a5355940f391f82b95b87e76fabe60bb10ba4ca8627748917becfcd457a404"
}
```

### Sample 92: `d3417a9fac15c3b6`

| Field | Value |
|---|---|
| SHA-256 | `d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927` |
| Family label | `unknown` |
| File name | `d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927.exe` |
| File type | `exe` |
| First seen | `2026-11-03 00:26:21` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a858a7905a949aa32e942748ebb3ae30` |
| SHA-1 | `103c4de5e14c5abbb7b04de881c467decc53830d` |
| SHA-256 | `d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927` |
| SHA3-384 | `4722e4ae152eabc0956a2e5edaa2a9d1082092cee75c469db22a5f4433f09a4ca32f124abf5c201162cdeba0f2aafa8d` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T16991D74270B989E7E85C51BF4C0FB8A0B91D740A41C483A74378A5993E3A57BF5BCB0D` |
| SSDEEP | `48:6IIF9BlQaexjtgZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMUA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_d3417a9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927"
    family = "unknown"
    file_name = "d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:26:21"
  condition:
    hash.sha256(0, filesize) == "d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927"
}
```

### Sample 93: `9f633733db4d5c8d`

| Field | Value |
|---|---|
| SHA-256 | `9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1` |
| Family label | `unknown` |
| File name | `macho_9f633733db4d.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:26:02` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aac5cc6b0f07abf256791c0082dd9ea7` |
| SHA-1 | `0477273d1a66facedb111111b8c64f320a814214` |
| SHA-256 | `9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1` |
| SHA3-384 | `8f662c32e24cad789456e9e1383ff6e3a705a8f5d25681a632dbd860c945fb5167f45a73064ae3dd06730b6da0119e4f` |
| TLSH | `T1A395F1542A7E9256E4822033C8348F4A156077A52A48A5F5A622F30F79F95F7F7A3333` |
| SSDEEP | `49152:N8D/uXFR/ePO6Fs9mswRF4i6wmF4rAj6eVg:+WXj24iogr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_9f633733
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1"
    family = "unknown"
    file_name = "macho_9f633733db4d.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:26:02"
  condition:
    hash.sha256(0, filesize) == "9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1"
}
```

### Sample 94: `48b170f32c51d94f`

| Field | Value |
|---|---|
| SHA-256 | `48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0` |
| Family label | `unknown` |
| File name | `macho_48b170f32c51.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:24:49` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8b69dd468ccc295afa069a552105f59` |
| SHA-1 | `019cce3423c98c8dc34d661bcfc85bb7252a8352` |
| SHA-256 | `48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0` |
| SHA3-384 | `13ea6ad1956beedf4a2c8cabbcf671db17a08899e2beace2dddb2567fbc7f6222ba3272bc150a70463fabcbff60ef574` |
| TLSH | `T1C6950228A6B601ADEDC62C728C140F69446072E23F58B3F56315D7DA1F395E3FA63272` |
| SSDEEP | `49152:swpD4j7B78Q3/uFv9jVn0GZdFRvxCfvTfksnR67:PjZdR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_48b170f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0"
    family = "unknown"
    file_name = "macho_48b170f32c51.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:24:49"
  condition:
    hash.sha256(0, filesize) == "48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0"
}
```

### Sample 95: `c809ce0c610166d7`

| Field | Value |
|---|---|
| SHA-256 | `c809ce0c610166d7cc7f0c7e91f0e7ce3a89b34c511db649e885e1547e0a21fc` |
| Family label | `unknown` |
| File name | `macho_c809ce0c6101.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:23:35` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b9dabb450ba279c1a2d024a4229788c` |
| SHA-1 | `1ccf23af27a7253a95cca2506e82f010c55df924` |
| SHA-256 | `c809ce0c610166d7cc7f0c7e91f0e7ce3a89b34c511db649e885e1547e0a21fc` |
| SHA3-384 | `c700cad79eea2c322eea20625a88739ae71106374c75145845da09b4d523a10ce3c923bf57d386784e9d37e6b01ec5ad` |
| TLSH | `T11BA5E1409E5E9247D88C42739C9A8F5984B47180CE85CDD99315A3CACE3E3D3B7672EB` |
| SSDEEP | `24576:UanEBqlosEURLuLA1NO2tM3K11NghzNMc5JW1Zb1w6zjbHKGT80+KS0ntpI80X9n:tnjlOcLYBjijKGTkEtpBjlLI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_c809ce0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c809ce0c610166d7cc7f0c7e91f0e7ce3a89b34c511db649e885e1547e0a21fc"
    family = "unknown"
    file_name = "macho_c809ce0c6101.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:23:35"
  condition:
    hash.sha256(0, filesize) == "c809ce0c610166d7cc7f0c7e91f0e7ce3a89b34c511db649e885e1547e0a21fc"
}
```

### Sample 96: `910e33613d9ed724`

| Field | Value |
|---|---|
| SHA-256 | `910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a` |
| Family label | `unknown` |
| File name | `macho_910e33613d9e.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:22:20` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cba662470f541e1c4cefdfeeca7a7e0b` |
| SHA-1 | `c74e33c00c129ac62b5057d80161ab90e80817de` |
| SHA-256 | `910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a` |
| SHA3-384 | `e0a565c938c5361fcd1b2a13241ae1267b373bcaca0c050c21d396a118d8bf6ebcd6d975103db664dc23d53635383bf9` |
| TLSH | `T15E95E154EA29C229D4866473AC700F0955A077C05A4CF9FA9123D37B6E36783B2F727E` |
| SSDEEP | `24576:oiM0u5Qduau9G13elOFwkBOcMudIpjIutCd7+oH8bbSnNM8bXLLvbpCTiAntteVS:oTKoloJTMoHvVCTzTOxpMqe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_910e3361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a"
    family = "unknown"
    file_name = "macho_910e33613d9e.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:22:20"
  condition:
    hash.sha256(0, filesize) == "910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a"
}
```

### Sample 97: `bd4fb920575b7fa5`

| Field | Value |
|---|---|
| SHA-256 | `bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e` |
| Family label | `unknown` |
| File name | `macho_bd4fb920575b.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:21:05` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ae75e178ed1c4c085f34235c1270972` |
| SHA-1 | `e79c8a9a20e03b80cc7ae98109e0e31be04c2547` |
| SHA-256 | `bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e` |
| SHA3-384 | `e3325c763488e5f5915a70b6858d9b282c9cfc7a7b3ca05d31cdf749f4728389070a69ca1a58a33e86c1c0aefa41d7a1` |
| TLSH | `T1D09502511AF5027AE08122326E294F4643B376913F9CBEFDA23492325D36693B97335F` |
| SSDEEP | `49152:SsdfmpOcaXjWsn+6mbh99pGWL4W1lRdY7KGsDjyW38+4:gh99pGWLnfu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_bd4fb920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e"
    family = "unknown"
    file_name = "macho_bd4fb920575b.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:21:05"
  condition:
    hash.sha256(0, filesize) == "bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e"
}
```

### Sample 98: `46bcabf552548de2`

| Field | Value |
|---|---|
| SHA-256 | `46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981` |
| Family label | `unknown` |
| File name | `macho_46bcabf55254.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:19:49` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f08caf3ee49e7a3b602bae66ba9c42be` |
| SHA-1 | `63782d547b64830b7c4faf44bfae04083cb9f9b6` |
| SHA-256 | `46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981` |
| SHA3-384 | `30a619d81a4d9e50865eb0fe6bd4fa2fc8eb6b341d3c33103f4b25a95ddff872e70f2fd2a299d4adbf3efd34dad16b96` |
| TLSH | `T16695E1808F5A5097C98E11738C968B1984B47081CE45CEDD6341A78BCE3A7E3B7676FB` |
| SSDEEP | `49152:PmcBEjaX8nFb3BxoGgOdFOK66qqdf2HFPNp1:+YEekoGgOdFOK6630` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_46bcabf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981"
    family = "unknown"
    file_name = "macho_46bcabf55254.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:19:49"
  condition:
    hash.sha256(0, filesize) == "46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981"
}
```

### Sample 99: `ae6a965e363eb206`

| Field | Value |
|---|---|
| SHA-256 | `ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962` |
| Family label | `unknown` |
| File name | `macho_ae6a965e363e.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:18:33` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a18da0a669adb2fcf77806c7cc65f6e5` |
| SHA-1 | `304b38d28de2f6e65b1b35b56409fe4903d5e9a0` |
| SHA-256 | `ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962` |
| SHA3-384 | `57daae5babf58c2bd6c058d10c7f5adc3b2dd5cb7ad68615ce8a4516e49cb74d8ff196edca624010410d547a9e0c26a9` |
| TLSH | `T12E9501200137622BED82A632A9804BE959F066B16C3DB9F76725D75D2C317C376623F3` |
| SSDEEP | `49152:Tr5JkTNPYThaM1yzfIMM/jdUo8lBNFIE90:WyaUI0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_ae6a965e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962"
    family = "unknown"
    file_name = "macho_ae6a965e363e.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:18:33"
  condition:
    hash.sha256(0, filesize) == "ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962"
}
```

### Sample 100: `937e0b01afe0b72a`

| Field | Value |
|---|---|
| SHA-256 | `937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320` |
| Family label | `unknown` |
| File name | `macho_937e0b01afe0.bin` |
| File type | `macho` |
| First seen | `2026-11-03 00:17:17` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a31867b37a226bcccc911a9f5ffd8d9f` |
| SHA-1 | `71562ca45447cba7acbf53fa523e67fcef46ac58` |
| SHA-256 | `937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320` |
| SHA3-384 | `1dd13f86938c5c9d29f459d174eab6587378d8ae59c3fc57ec3c9240f950cdbb8dafb2ff87e46f3b4bde8e31167f35c0` |
| TLSH | `T1D775E150DE1FA1EBD50E11339C994F1844742090CD09EDEE6391F36AEE327977B226BA` |
| SSDEEP | `49152:A8dp/ZkEe3mnE8FJejH/LnMf+qZ0ouz4Me:JREQkj/ofce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_937e0b01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320"
    family = "unknown"
    file_name = "macho_937e0b01afe0.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:17:17"
  condition:
    hash.sha256(0, filesize) == "937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320"
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
 * Generated: 2026-11-03T06:57:59.154618+00:00
 */

rule MalwareBazaar_unknown_001_0371b226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0371b2265206832e350a730a3a9da5519e0a7483b94a2602df539a91791a2ec8"
    family = "unknown"
    file_name = "update[1].msi"
    file_type = "msi"
    first_seen = "2026-11-03 06:52:43"
  condition:
    hash.sha256(0, filesize) == "0371b2265206832e350a730a3a9da5519e0a7483b94a2602df539a91791a2ec8"
}

rule MalwareBazaar_unknown_002_de50f5ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de50f5ae2931b7bddd1e1d330a92e1c64babb2b5a5c21e728aba391671a50b45"
    family = "unknown"
    file_name = "newisbest.exe"
    file_type = "exe"
    first_seen = "2026-11-03 06:51:27"
  condition:
    hash.sha256(0, filesize) == "de50f5ae2931b7bddd1e1d330a92e1c64babb2b5a5c21e728aba391671a50b45"
}

rule MalwareBazaar_unknown_003_defd6b75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "defd6b754c6fa5e1323d557ad6d1dd1707649a3ef60637e0ad9a806df82feb5f"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-11-03 06:51:21"
  condition:
    hash.sha256(0, filesize) == "defd6b754c6fa5e1323d557ad6d1dd1707649a3ef60637e0ad9a806df82feb5f"
}

rule MalwareBazaar_unknown_004_5f795c3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d"
    family = "unknown"
    file_name = "polkitd"
    file_type = "elf"
    first_seen = "2026-11-03 06:47:22"
  condition:
    hash.sha256(0, filesize) == "5f795c3b455a4c4d379aa0113c8f3b267f7f071a11ce7daef461862b8b93c21d"
}

rule MalwareBazaar_unknown_005_2ea72bf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ea72bf67197f652c6161fb07b78aa7bb591265e7f0a889dc404387df7538cd5"
    family = "unknown"
    file_name = "systemd-udevd"
    file_type = "elf"
    first_seen = "2026-11-03 06:47:10"
  condition:
    hash.sha256(0, filesize) == "2ea72bf67197f652c6161fb07b78aa7bb591265e7f0a889dc404387df7538cd5"
}

rule MalwareBazaar_unknown_006_ba90978b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95"
    family = "unknown"
    file_name = "FiyatTeklifIstegi-IDPRNo69611-BUSBARBESLEMEPANOSU.wsf$"
    file_type = "wsf"
    first_seen = "2026-11-03 06:44:37"
  condition:
    hash.sha256(0, filesize) == "ba90978bc50304ef9c6da938a7385852299e59fc160c02f9d24db8007da68b95"
}

rule MalwareBazaar_unknown_007_d55a1b74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d55a1b7493c995dbbcb14e4336ee11e3791c3f865df6e578212dee16509f5fef"
    family = "unknown"
    file_name = "WBKPO20064.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:35"
  condition:
    hash.sha256(0, filesize) == "d55a1b7493c995dbbcb14e4336ee11e3791c3f865df6e578212dee16509f5fef"
}

rule MalwareBazaar_AgentTesla_008_ba15e72c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780"
    family = "AgentTesla"
    file_name = "ODEMEDEKONTU.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:32"
  condition:
    hash.sha256(0, filesize) == "ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780"
}

rule MalwareBazaar_RemcosRAT_009_83c77e25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83c77e25b92cdb316b2bc363b9ed0d4f36c50679cf2d07b24c3f706492b0def9"
    family = "RemcosRAT"
    file_name = "citibankNAoutwardremittancemt103_PDFPDF.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:29"
  condition:
    hash.sha256(0, filesize) == "83c77e25b92cdb316b2bc363b9ed0d4f36c50679cf2d07b24c3f706492b0def9"
}

rule MalwareBazaar_AgentTesla_010_a0ef9278
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0ef92781e93d2651994318d5cbdca72089db7fc977e6cd03739f3096f99ac0c"
    family = "AgentTesla"
    file_name = "BL2337436541766.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:27"
  condition:
    hash.sha256(0, filesize) == "a0ef92781e93d2651994318d5cbdca72089db7fc977e6cd03739f3096f99ac0c"
}

rule MalwareBazaar_AgentTesla_011_bf2203e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf2203e0c49e34852b369811662f28486a8077cb42b735aeee753a6025e02b6d"
    family = "AgentTesla"
    file_name = "Fixtures00000000Drawing000000Specifications.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:24"
  condition:
    hash.sha256(0, filesize) == "bf2203e0c49e34852b369811662f28486a8077cb42b735aeee753a6025e02b6d"
}

rule MalwareBazaar_unknown_012_8bd89632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bd896323c194a21e854269411af1cce7d0f240f1038af03aaf5c4ca6f94d460"
    family = "unknown"
    file_name = "Facturaproformaimpagada.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:21"
  condition:
    hash.sha256(0, filesize) == "8bd896323c194a21e854269411af1cce7d0f240f1038af03aaf5c4ca6f94d460"
}

rule MalwareBazaar_AsyncRAT_013_c39e58a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c39e58a3d41882379fed94bfbacc52cacd55d1fb2847515129814808d93d7370"
    family = "AsyncRAT"
    file_name = "PagoOC3256.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:19"
  condition:
    hash.sha256(0, filesize) == "c39e58a3d41882379fed94bfbacc52cacd55d1fb2847515129814808d93d7370"
}

rule MalwareBazaar_unknown_014_2e561ad3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32"
    family = "unknown"
    file_name = "QUOTE20261102.jse$"
    file_type = "jse"
    first_seen = "2026-11-03 06:44:16"
  condition:
    hash.sha256(0, filesize) == "2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32"
}

rule MalwareBazaar_unknown_015_a6a8ee79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6a8ee790a15a6c675b8da46ff600e6580bb947336a7aff8dafe13c252187a5d"
    family = "unknown"
    file_name = "AccountReceipt.PDF.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:14"
  condition:
    hash.sha256(0, filesize) == "a6a8ee790a15a6c675b8da46ff600e6580bb947336a7aff8dafe13c252187a5d"
}

rule MalwareBazaar_AgentTesla_016_149b336d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149b336d39c214271aa59d4840f43f53b3d9df1394fed57536a8553be2d0f1bb"
    family = "AgentTesla"
    file_name = "Documents.bat$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:11"
  condition:
    hash.sha256(0, filesize) == "149b336d39c214271aa59d4840f43f53b3d9df1394fed57536a8553be2d0f1bb"
}

rule MalwareBazaar_unknown_017_09cacaca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a"
    family = "unknown"
    file_name = "ORDER10-MAREXVTR250RR181-UAE.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:44:08"
  condition:
    hash.sha256(0, filesize) == "09cacaca92915a894a28eb8f32e64b6816c82f412fcc462e5ed83aefc7e13d9a"
}

rule MalwareBazaar_unknown_018_47d11e49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47d11e494ff2e14b9acf0d40460a613ee989a807475e03f23ee17ed2db141233"
    family = "unknown"
    file_name = "UvWlVVVdAU.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:44:05"
  condition:
    hash.sha256(0, filesize) == "47d11e494ff2e14b9acf0d40460a613ee989a807475e03f23ee17ed2db141233"
}

rule MalwareBazaar_AgentTesla_019_aa788bca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa788bca2eb8eb8991e7cb6b4ce7b1a6e51a5051ac89d5d69a6c6868245562ab"
    family = "AgentTesla"
    file_name = "PONoVIVRE691EB25.bat$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:58"
  condition:
    hash.sha256(0, filesize) == "aa788bca2eb8eb8991e7cb6b4ce7b1a6e51a5051ac89d5d69a6c6868245562ab"
}

rule MalwareBazaar_unknown_020_b6a1d852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a1d852a41ffd02e84e21c3a7722f387084e2474984edde06e150ba98063477"
    family = "unknown"
    file_name = "PRO840423SG8_XEZC_1892192.vbs$"
    file_type = "vbs"
    first_seen = "2026-11-03 06:43:55"
  condition:
    hash.sha256(0, filesize) == "b6a1d852a41ffd02e84e21c3a7722f387084e2474984edde06e150ba98063477"
}

rule MalwareBazaar_Formbook_021_f94fe58f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39"
    family = "Formbook"
    file_name = "RFQ_CHG_26-03_017pdf.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:53"
  condition:
    hash.sha256(0, filesize) == "f94fe58fe411cf7b0ddd98636350b7dc20bf57d4d1021853f6889cbfe0bacb39"
}

rule MalwareBazaar_unknown_022_769ad58f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "769ad58f860c5143fa569c1ce81fe125950102e788f5ec93fa96be5050c85455"
    family = "unknown"
    file_name = "Ordendecompra.js$"
    file_type = "js"
    first_seen = "2026-11-03 06:43:50"
  condition:
    hash.sha256(0, filesize) == "769ad58f860c5143fa569c1ce81fe125950102e788f5ec93fa96be5050c85455"
}

rule MalwareBazaar_unknown_023_24910d37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "24910d37324a8d19fb454ce94167b1bd19528c8c32e3eddfffd766c7ccf36ee3"
    family = "unknown"
    file_name = "Nectron.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:48"
  condition:
    hash.sha256(0, filesize) == "24910d37324a8d19fb454ce94167b1bd19528c8c32e3eddfffd766c7ccf36ee3"
}

rule MalwareBazaar_unknown_024_3fb04465
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d"
    family = "unknown"
    file_name = "QUOTATIONFROMMINGRAYTECHNOLOGYGROUP.pdf.scr$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:43"
  condition:
    hash.sha256(0, filesize) == "3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d"
}

rule MalwareBazaar_AgentTesla_025_02f9176d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9"
    family = "AgentTesla"
    file_name = "BL2337436541766.exe$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:40"
  condition:
    hash.sha256(0, filesize) == "02f9176dd9991231551873ed8917050e41cd5d967288d51fc54715446d6182c9"
}

rule MalwareBazaar_AgentTesla_026_3330d1dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3330d1dc791dc3f5a53e484ad8c4f3c1738fbd691de5a4e03e86f0e73fed353c"
    family = "AgentTesla"
    file_name = "SWIFTCOPY.bat$"
    file_type = "exe"
    first_seen = "2026-11-03 06:43:36"
  condition:
    hash.sha256(0, filesize) == "3330d1dc791dc3f5a53e484ad8c4f3c1738fbd691de5a4e03e86f0e73fed353c"
}

rule MalwareBazaar_unknown_027_47bb403d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b"
    family = "unknown"
    file_name = "47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:33"
  condition:
    hash.sha256(0, filesize) == "47bb403d9a68076e927fd3eee563e5e1fa0b6c9f2d142b8ab71c84538c24909b"
}

rule MalwareBazaar_unknown_028_48331236
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d"
    family = "unknown"
    file_name = "48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:28"
  condition:
    hash.sha256(0, filesize) == "48331236f584355935bf49754629e60e13578cb38b2b0ef9e725afa91939e98d"
}

rule MalwareBazaar_unknown_029_2f78ffc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c"
    family = "unknown"
    file_name = "2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:23"
  condition:
    hash.sha256(0, filesize) == "2f78ffc4b00d4f31dc14d414376c813af44398f4fc99e2125149b873ba5b590c"
}

rule MalwareBazaar_unknown_030_dbeb0545
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794"
    family = "unknown"
    file_name = "dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:51:18"
  condition:
    hash.sha256(0, filesize) == "dbeb0545b260d4e207400237d211746cb9a01d2b91e9d7a91e1f628db0b03794"
}

rule MalwareBazaar_unknown_031_faf194b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e"
    family = "unknown"
    file_name = "faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:50:27"
  condition:
    hash.sha256(0, filesize) == "faf194b9c9a1174b063f0d56cf26579b46ea8b6128c72cda0d8ed654bcb4335e"
}

rule MalwareBazaar_unknown_032_cecfbb3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11"
    family = "unknown"
    file_name = "cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:50:22"
  condition:
    hash.sha256(0, filesize) == "cecfbb3b9b9fed2124f728bd8a3bf0ee2b2c32be524dc4ee1c34e032f5000f11"
}

rule MalwareBazaar_unknown_033_6e2a4b7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123"
    family = "unknown"
    file_name = "6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:46:29"
  condition:
    hash.sha256(0, filesize) == "6e2a4b7da1e29ef7d034cca63241b99fd3c478f1742d6fd23a24ca3ec1c01123"
}

rule MalwareBazaar_unknown_034_a806109f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a"
    family = "unknown"
    file_name = "a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a.bin"
    file_type = "bat"
    first_seen = "2026-11-03 05:46:24"
  condition:
    hash.sha256(0, filesize) == "a806109f0901c56ba455ba924076db71d6fe2d04df8863c808c3f9911095fd5a"
}

rule MalwareBazaar_Mirai_035_5dd89d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dd89d0f9d80c96554675129cd887391bebba74e0fc4e29c6fa43844f244607e"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-11-03 05:41:04"
  condition:
    hash.sha256(0, filesize) == "5dd89d0f9d80c96554675129cd887391bebba74e0fc4e29c6fa43844f244607e"
}

rule MalwareBazaar_Mirai_036_05728fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05728fc47ca9a32a83bafa347ff0184325e4752d44316121dcf1cd254785c72f"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-03 05:39:04"
  condition:
    hash.sha256(0, filesize) == "05728fc47ca9a32a83bafa347ff0184325e4752d44316121dcf1cd254785c72f"
}

rule MalwareBazaar_Mirai_037_60b4d529
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60b4d5298e7dce610f7d2660d995b5a4bb50315a4b562efd4e7286ea742f32a2"
    family = "Mirai"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-11-03 03:52:48"
  condition:
    hash.sha256(0, filesize) == "60b4d5298e7dce610f7d2660d995b5a4bb50315a4b562efd4e7286ea742f32a2"
}

rule MalwareBazaar_unknown_038_a8a01fa9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8a01fa91acebe455728219bb94ec3cdb4e3430b3181b9dc77804381b79a6eb3"
    family = "unknown"
    file_name = ".16"
    file_type = "elf"
    first_seen = "2026-11-03 03:50:26"
  condition:
    hash.sha256(0, filesize) == "a8a01fa91acebe455728219bb94ec3cdb4e3430b3181b9dc77804381b79a6eb3"
}

rule MalwareBazaar_Mirai_039_e89b4121
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e89b412100a616dc56e576d05a9cb0573f5e0d5a5261c32c2293630119e6c489"
    family = "Mirai"
    file_name = "eclipse.mpsl"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:28"
  condition:
    hash.sha256(0, filesize) == "e89b412100a616dc56e576d05a9cb0573f5e0d5a5261c32c2293630119e6c489"
}

rule MalwareBazaar_Mirai_040_2ad0d0cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ad0d0cb2074b6a6ecf94dfc6335df8d679b6682fb2761fa306574693249904b"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:25"
  condition:
    hash.sha256(0, filesize) == "2ad0d0cb2074b6a6ecf94dfc6335df8d679b6682fb2761fa306574693249904b"
}

rule MalwareBazaar_Mirai_041_363aace8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "363aace8871088acc93737e2b830343a1b19a4ec24dba301e093b5bb8e307424"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:21"
  condition:
    hash.sha256(0, filesize) == "363aace8871088acc93737e2b830343a1b19a4ec24dba301e093b5bb8e307424"
}

rule MalwareBazaar_Mirai_042_6f970002
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f9700023209bdb0048b9d49a4354512ceb20c9716a4ec9223f609a2ff8d89d6"
    family = "Mirai"
    file_name = "eclipse.arm7"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:18"
  condition:
    hash.sha256(0, filesize) == "6f9700023209bdb0048b9d49a4354512ceb20c9716a4ec9223f609a2ff8d89d6"
}

rule MalwareBazaar_Mirai_043_9e088965
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e0889651694ed7e239420c23feef78069ac11ab1f440585863345e7ac02e485"
    family = "Mirai"
    file_name = "eclipse.arm5"
    file_type = "elf"
    first_seen = "2026-11-03 03:26:15"
  condition:
    hash.sha256(0, filesize) == "9e0889651694ed7e239420c23feef78069ac11ab1f440585863345e7ac02e485"
}

rule MalwareBazaar_Mirai_044_7332b209
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7332b209bc21cad1a36367b683e7294633a048ec4e368def8938e2c3259c0f25"
    family = "Mirai"
    file_name = "eclipse.mpsl"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:47"
  condition:
    hash.sha256(0, filesize) == "7332b209bc21cad1a36367b683e7294633a048ec4e368def8938e2c3259c0f25"
}

rule MalwareBazaar_Mirai_045_5ce97aad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ce97aad32f6535b53af5788b8bbea8d074dcda4ab54cd9367742f714efb986b"
    family = "Mirai"
    file_name = "eclipse.mips"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:47"
  condition:
    hash.sha256(0, filesize) == "5ce97aad32f6535b53af5788b8bbea8d074dcda4ab54cd9367742f714efb986b"
}

rule MalwareBazaar_Mirai_046_4a233c96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a233c9644272bdba8f12a66dfe5a4773f2f5a730738f40ea7ecf50349573416"
    family = "Mirai"
    file_name = "eclipse.x86_64"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:47"
  condition:
    hash.sha256(0, filesize) == "4a233c9644272bdba8f12a66dfe5a4773f2f5a730738f40ea7ecf50349573416"
}

rule MalwareBazaar_Mirai_047_082c2a71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "082c2a714c1a1e7ac0b21fde84a6c149a06d7644c78d2e45b189fbb0deef5c73"
    family = "Mirai"
    file_name = "eclipse.arm7"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:46"
  condition:
    hash.sha256(0, filesize) == "082c2a714c1a1e7ac0b21fde84a6c149a06d7644c78d2e45b189fbb0deef5c73"
}

rule MalwareBazaar_Mirai_048_31eb5452
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31eb5452a005de367863a1bfdeb84bf14bb4f0d977d2a6f4f9164c91454e657b"
    family = "Mirai"
    file_name = "eclipse.arm5"
    file_type = "elf"
    first_seen = "2026-11-03 03:25:45"
  condition:
    hash.sha256(0, filesize) == "31eb5452a005de367863a1bfdeb84bf14bb4f0d977d2a6f4f9164c91454e657b"
}

rule MalwareBazaar_unknown_049_84265f88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84265f88bd31869d59f95b83ec38dab46c01dd90da933a9b5cc4579c722ff958"
    family = "unknown"
    file_name = "agent.exe"
    file_type = "exe"
    first_seen = "2026-11-03 03:25:08"
  condition:
    hash.sha256(0, filesize) == "84265f88bd31869d59f95b83ec38dab46c01dd90da933a9b5cc4579c722ff958"
}

rule MalwareBazaar_unknown_050_c78b763c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c78b763c78ebb15d49fa6d8addad18b3da65dd8db50c4d4de1dd1a9db6ef7a34"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-11-03 03:23:57"
  condition:
    hash.sha256(0, filesize) == "c78b763c78ebb15d49fa6d8addad18b3da65dd8db50c4d4de1dd1a9db6ef7a34"
}

rule MalwareBazaar_AMOS_051_9d3df907
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a"
    family = "AMOS"
    file_name = "macho_9d3df907e1aa.bin"
    file_type = "macho"
    first_seen = "2026-11-03 03:23:15"
  condition:
    hash.sha256(0, filesize) == "9d3df907e1aae13743a47276d4e06ba974e3781763fa23f99c09867609a4fb4a"
}

rule MalwareBazaar_SalatStealer_052_5443928a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646"
    family = "SalatStealer"
    file_name = "5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646.exe"
    file_type = "exe"
    first_seen = "2026-11-03 03:14:10"
  condition:
    hash.sha256(0, filesize) == "5443928a7d2098008bccd89bcdff03e4a5ad834a9ea8e5ac114f1f15b6a12646"
}

rule MalwareBazaar_VShell_053_c3b67f17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3"
    family = "VShell"
    file_name = "c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3.exe"
    file_type = "exe"
    first_seen = "2026-11-03 02:54:27"
  condition:
    hash.sha256(0, filesize) == "c3b67f17b19f697f19719bb36e3556c94f68d78b395c701d9f49fa42504e44c3"
}

rule MalwareBazaar_RustyStealer_054_e7439226
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d"
    family = "RustyStealer"
    file_name = "e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d.exe"
    file_type = "exe"
    first_seen = "2026-11-03 02:50:04"
  condition:
    hash.sha256(0, filesize) == "e7439226c3569d26c7c13124b11c82425908260cd418071e81eb58800fda014d"
}

rule MalwareBazaar_RustyStealer_055_02b2f61a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814"
    family = "RustyStealer"
    file_name = "02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814.exe"
    file_type = "exe"
    first_seen = "2026-11-03 02:49:58"
  condition:
    hash.sha256(0, filesize) == "02b2f61aa7a3306795a0ffe3bc88889d9ecfbf8b0f57e0fbc05107ffc0350814"
}

rule MalwareBazaar_Mirai_056_5699f25f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-11-03 02:19:05"
  condition:
    hash.sha256(0, filesize) == "5699f25feac04e73dbc10f3668ccfb19419d25f25c4859591c3e5753fbf0582b"
}

rule MalwareBazaar_Mirai_057_1f6bf763
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnarmxnxn"
    file_type = "elf"
    first_seen = "2026-11-03 02:19:05"
  condition:
    hash.sha256(0, filesize) == "1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241"
}

rule MalwareBazaar_Mirai_058_12d279e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12d279e997c1b6f2b34f0d3a7c50aa6d4ae077618fecee4a4b71dd43dc0e876c"
    family = "Mirai"
    file_name = "run.sh"
    file_type = "sh"
    first_seen = "2026-11-03 02:19:04"
  condition:
    hash.sha256(0, filesize) == "12d279e997c1b6f2b34f0d3a7c50aa6d4ae077618fecee4a4b71dd43dc0e876c"
}

rule MalwareBazaar_Mirai_059_34f608eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6"
    family = "Mirai"
    file_name = "sora.arm7"
    file_type = "elf"
    first_seen = "2026-11-03 02:18:40"
  condition:
    hash.sha256(0, filesize) == "34f608eba7b1d980574f91df85b4acfc79880ec7fdf9500c7ef93bfc7e017ac6"
}

rule MalwareBazaar_Mirai_060_3893fa3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-03 02:18:37"
  condition:
    hash.sha256(0, filesize) == "3893fa3da89174dd6226d26340f3c70b30b297ac4361c432fcf8c52b202301b3"
}

rule MalwareBazaar_Mirai_061_a6447a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa"
    family = "Mirai"
    file_name = "vc.sh"
    file_type = "sh"
    first_seen = "2026-11-03 02:18:34"
  condition:
    hash.sha256(0, filesize) == "a6447a059d57eb02a91eea1a8e674ccb00aa27badf894d7d82bae1327d58b7fa"
}

rule MalwareBazaar_Mirai_062_cca1ee81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83"
    family = "Mirai"
    file_name = "sora.arm"
    file_type = "elf"
    first_seen = "2026-11-03 02:18:33"
  condition:
    hash.sha256(0, filesize) == "cca1ee815fea880bedc7d6098ef4cc8b275f4510371a364c654db33a43dbcf83"
}

rule MalwareBazaar_unknown_063_0e70985d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb"
    family = "unknown"
    file_name = "0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb.bin"
    file_type = "macho"
    first_seen = "2026-11-03 02:05:17"
  condition:
    hash.sha256(0, filesize) == "0e70985db3edea39c0cead4dd53b660cd38538a62a114a8d6f636ceb31f82ddb"
}

rule MalwareBazaar_ConnectWise_064_0931275a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d"
    family = "ConnectWise"
    file_name = "0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:54:10"
  condition:
    hash.sha256(0, filesize) == "0931275a4bdc9c65646a7342ed8e02ddd5034429e4d599fa339a7df10e75030d"
}

rule MalwareBazaar_unknown_065_9d055c05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815"
    family = "unknown"
    file_name = "9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815.bin"
    file_type = "macho"
    first_seen = "2026-11-03 01:51:20"
  condition:
    hash.sha256(0, filesize) == "9d055c051b9002121c33a692dc770b555cb5fd5fdc89524601ef62f15ce51815"
}

rule MalwareBazaar_unknown_066_044857a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107"
    family = "unknown"
    file_name = "044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:51:16"
  condition:
    hash.sha256(0, filesize) == "044857a13fb81cd7d79bfb84a77e75bed5a21941910777e9372e4d4e842f7107"
}

rule MalwareBazaar_unknown_067_3fa5057e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
    family = "unknown"
    file_name = "sshd"
    file_type = "elf"
    first_seen = "2026-11-03 01:43:08"
  condition:
    hash.sha256(0, filesize) == "3fa5057e1be1cfeb73f6ebcdf84e00c37e9e09f1bec347d5424dd730a2124fa8"
}

rule MalwareBazaar_unknown_068_d148eb05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d148eb058ded06149b9110e91bbd0c49b626ae0cac4fccfe38c57ea00b4f6106"
    family = "unknown"
    file_name = "install_guard.js"
    file_type = "js"
    first_seen = "2026-11-03 01:36:29"
  condition:
    hash.sha256(0, filesize) == "d148eb058ded06149b9110e91bbd0c49b626ae0cac4fccfe38c57ea00b4f6106"
}

rule MalwareBazaar_unknown_069_aea7eabc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aea7eabc5fcd280ed27d3ecac2f65fd753c6c97acebee78da1d7b5d66b17d55e"
    family = "unknown"
    file_name = "SecuriteInfo.com.Win32.MalwareX-gen.31186186"
    file_type = "exe"
    first_seen = "2026-11-03 01:31:44"
  condition:
    hash.sha256(0, filesize) == "aea7eabc5fcd280ed27d3ecac2f65fd753c6c97acebee78da1d7b5d66b17d55e"
}

rule MalwareBazaar_SalatStealer_070_be8ab252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db"
    family = "SalatStealer"
    file_name = "be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:27:08"
  condition:
    hash.sha256(0, filesize) == "be8ab2520e0a3de2a661c37f4cd60e4fbe5459b2b33dd733d1cb9f92654146db"
}

rule MalwareBazaar_SalatStealer_071_4241ce66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4241ce66cddc1061b5549e4cffdd7866c519f3d52e29853e7c582156e0b69eae"
    family = "SalatStealer"
    file_name = "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:10:19"
  condition:
    hash.sha256(0, filesize) == "4241ce66cddc1061b5549e4cffdd7866c519f3d52e29853e7c582156e0b69eae"
}

rule MalwareBazaar_SalatStealer_072_02e52ba3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02e52ba371be78d83f6d3201f7b7cc9ff360f5c8ec8e8e98338e0de241745d54"
    family = "SalatStealer"
    file_name = "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:09:17"
  condition:
    hash.sha256(0, filesize) == "02e52ba371be78d83f6d3201f7b7cc9ff360f5c8ec8e8e98338e0de241745d54"
}

rule MalwareBazaar_SalatStealer_073_383baab1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243"
    family = "SalatStealer"
    file_name = "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:09:15"
  condition:
    hash.sha256(0, filesize) == "383baab18b342eff1039208ea7b5f069fd6deaa17dd560e78d26fd00b21ad243"
}

rule MalwareBazaar_SalatStealer_074_6ea8d738
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6"
    family = "SalatStealer"
    file_name = "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:09:10"
  condition:
    hash.sha256(0, filesize) == "6ea8d738dd5d1d4b665daf5de978a3d5535fd4ec4932fa93d5cadf85b14d04b6"
}

rule MalwareBazaar_unknown_075_9500e411
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f"
    family = "unknown"
    file_name = "9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f.exe"
    file_type = "exe"
    first_seen = "2026-11-03 01:01:37"
  condition:
    hash.sha256(0, filesize) == "9500e41175cbe66a3e95bd863e0e855cf15f51ab9a44024fa082697ec992db0f"
}

rule MalwareBazaar_AsyncRAT_076_f5ee6127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be"
    family = "AsyncRAT"
    file_name = "f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:54:22"
  condition:
    hash.sha256(0, filesize) == "f5ee612748cedfd68340a5394f65072aa052d02820e5e8db5587ac36e53046be"
}

rule MalwareBazaar_ConnectWise_077_a5417734
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac"
    family = "ConnectWise"
    file_name = "a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:54:15"
  condition:
    hash.sha256(0, filesize) == "a54177343112324614289bd62bbd73497d235f97bef0fbc2432c172a27970bac"
}

rule MalwareBazaar_ConnectWise_078_d12ae777
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64"
    family = "ConnectWise"
    file_name = "d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64.msi"
    file_type = "msi"
    first_seen = "2026-11-03 00:54:09"
  condition:
    hash.sha256(0, filesize) == "d12ae777cd027bc89bd337732aa861d94662caabbde28d470cd3871ac7feec64"
}

rule MalwareBazaar_unknown_079_48411937
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97"
    family = "unknown"
    file_name = "4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:51:38"
  condition:
    hash.sha256(0, filesize) == "4841193715abddabd3b85e8d9bab651ffd7169286365f59b6dc0f1fde1be8d97"
}

rule MalwareBazaar_unknown_080_29d09b3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91"
    family = "unknown"
    file_name = "29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:51:31"
  condition:
    hash.sha256(0, filesize) == "29d09b3ef708a8eff5dd1e416cc44dd3be7893232d739035342211205239de91"
}

rule MalwareBazaar_unknown_081_79667b9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856"
    family = "unknown"
    file_name = "79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:50:32"
  condition:
    hash.sha256(0, filesize) == "79667b9fab75fb02b3a2ff59bb1fad5bc1b4feb3cd7942c143ce4a15d6d04856"
}

rule MalwareBazaar_unknown_082_78714f6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba"
    family = "unknown"
    file_name = "78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:50:27"
  condition:
    hash.sha256(0, filesize) == "78714f6f57c5177201837ce7a6185a2b2bb00a074883fc6cf03b8ade192a20ba"
}

rule MalwareBazaar_ConnectWise_083_25136415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75"
    family = "ConnectWise"
    file_name = "2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:49:24"
  condition:
    hash.sha256(0, filesize) == "2513641573e48d63aadac514a11bf76bb5dd2c764b7095cc8fc9450b09d4ad75"
}

rule MalwareBazaar_ConnectWise_084_38bdba3c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0"
    family = "ConnectWise"
    file_name = "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0.msi"
    file_type = "msi"
    first_seen = "2026-11-03 00:49:18"
  condition:
    hash.sha256(0, filesize) == "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0"
}

rule MalwareBazaar_ConnectWise_085_50f673e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3"
    family = "ConnectWise"
    file_name = "50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3.msi"
    file_type = "msi"
    first_seen = "2026-11-03 00:49:10"
  condition:
    hash.sha256(0, filesize) == "50f673e15f4acb31a2ab40f550b797ed0fdd59b29e66dc922d00a24998aa97b3"
}

rule MalwareBazaar_Silentnet_086_be9c3f96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be9c3f967c4701326623052636bf7bae66381528a28b519271b0fe0642d569f8"
    family = "Silentnet"
    file_name = "PurxiyClient-1.21.11.jar"
    file_type = "jar"
    first_seen = "2026-11-03 00:46:30"
  condition:
    hash.sha256(0, filesize) == "be9c3f967c4701326623052636bf7bae66381528a28b519271b0fe0642d569f8"
}

rule MalwareBazaar_WARDENStealer_087_9a83346a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a83346aa14e0afedf499aa8ce74e2c2f83b044e13c34ef39d55d2c47da035e8"
    family = "WARDENStealer"
    file_name = "p?t=df801cc0d46ed6482f48d3576e6b64d9_d5bcce35aaf5dafe9c99bbe0105909d2d90d1456"
    file_type = "exe"
    first_seen = "2026-11-03 00:39:24"
  condition:
    hash.sha256(0, filesize) == "9a83346aa14e0afedf499aa8ce74e2c2f83b044e13c34ef39d55d2c47da035e8"
}

rule MalwareBazaar_WannaCry_088_40bd526a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57"
    family = "WannaCry"
    file_name = "e1e708bd666f6645a561f6b57f1c3e50"
    file_type = "dll"
    first_seen = "2026-11-03 00:31:02"
  condition:
    hash.sha256(0, filesize) == "40bd526a2b04656e8d9e3c514fecf6eda25378f16fd292c37d2fdec7afb5fc57"
}

rule MalwareBazaar_unknown_089_fbb6171e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fbb6171ee8310129b57960d68b3478d4a803b1f0b6152d36a30763a49a0d85fa"
    family = "unknown"
    file_name = "macho_fbb6171ee831.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:30:43"
  condition:
    hash.sha256(0, filesize) == "fbb6171ee8310129b57960d68b3478d4a803b1f0b6152d36a30763a49a0d85fa"
}

rule MalwareBazaar_unknown_090_1dffdfbd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7"
    family = "unknown"
    file_name = "macho_1dffdfbda8c0.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:28:29"
  condition:
    hash.sha256(0, filesize) == "1dffdfbda8c09dd397b1d65ef019202c1dd12c1b172a6f90e1f45918f3a9a4b7"
}

rule MalwareBazaar_unknown_091_08a53559
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08a5355940f391f82b95b87e76fabe60bb10ba4ca8627748917becfcd457a404"
    family = "unknown"
    file_name = "macho_08a5355940f3.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:27:15"
  condition:
    hash.sha256(0, filesize) == "08a5355940f391f82b95b87e76fabe60bb10ba4ca8627748917becfcd457a404"
}

rule MalwareBazaar_unknown_092_d3417a9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927"
    family = "unknown"
    file_name = "d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927.exe"
    file_type = "exe"
    first_seen = "2026-11-03 00:26:21"
  condition:
    hash.sha256(0, filesize) == "d3417a9fac15c3b6add42f3662eba46ace767e96e75ed8a40595b02d27916927"
}

rule MalwareBazaar_unknown_093_9f633733
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1"
    family = "unknown"
    file_name = "macho_9f633733db4d.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:26:02"
  condition:
    hash.sha256(0, filesize) == "9f633733db4d5c8d085beb28c3ec145a7e0d0af6ea29f1092d410e3bbe833ac1"
}

rule MalwareBazaar_unknown_094_48b170f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0"
    family = "unknown"
    file_name = "macho_48b170f32c51.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:24:49"
  condition:
    hash.sha256(0, filesize) == "48b170f32c51d94fa7d9d2040b753500e8e3e23c934e3b900cad733b33687bc0"
}

rule MalwareBazaar_unknown_095_c809ce0c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c809ce0c610166d7cc7f0c7e91f0e7ce3a89b34c511db649e885e1547e0a21fc"
    family = "unknown"
    file_name = "macho_c809ce0c6101.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:23:35"
  condition:
    hash.sha256(0, filesize) == "c809ce0c610166d7cc7f0c7e91f0e7ce3a89b34c511db649e885e1547e0a21fc"
}

rule MalwareBazaar_unknown_096_910e3361
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a"
    family = "unknown"
    file_name = "macho_910e33613d9e.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:22:20"
  condition:
    hash.sha256(0, filesize) == "910e33613d9ed72442909f57564d8aba029b77422b1c3138deadb8732d882d4a"
}

rule MalwareBazaar_unknown_097_bd4fb920
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e"
    family = "unknown"
    file_name = "macho_bd4fb920575b.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:21:05"
  condition:
    hash.sha256(0, filesize) == "bd4fb920575b7fa5f2b856cc49af0e6f55f0062dc67bb378aa4cb36760118c3e"
}

rule MalwareBazaar_unknown_098_46bcabf5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981"
    family = "unknown"
    file_name = "macho_46bcabf55254.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:19:49"
  condition:
    hash.sha256(0, filesize) == "46bcabf552548de2f2fb4f4c3781d10aa2cd8e3699be5b5616a6c4df1039f981"
}

rule MalwareBazaar_unknown_099_ae6a965e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962"
    family = "unknown"
    file_name = "macho_ae6a965e363e.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:18:33"
  condition:
    hash.sha256(0, filesize) == "ae6a965e363eb206757d4b00741e2b7c0937f1efbb256df9007177421ded6962"
}

rule MalwareBazaar_unknown_100_937e0b01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320"
    family = "unknown"
    file_name = "macho_937e0b01afe0.bin"
    file_type = "macho"
    first_seen = "2026-11-03 00:17:17"
  condition:
    hash.sha256(0, filesize) == "937e0b01afe0b72a92d8b5cd0284f057240e833d783f5efb1385f9f5a600c320"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

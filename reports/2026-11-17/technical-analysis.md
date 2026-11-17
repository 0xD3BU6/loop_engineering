# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-17

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 673 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 673 |
| Unique family labels | 16 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 28 |
| Snowlight | 16 |
| GoDDoSAgent | 8 |
| Prometei | 7 |
| AgentTesla | 6 |
| RemcosRAT | 6 |
| Mirai | 5 |
| Formbook | 5 |
| MassLogger | 4 |
| RustyStealer | 4 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 40 |
| exe | 27 |
| js | 23 |
| xls | 3 |
| hta | 2 |
| macho | 2 |
| vbe | 1 |
| bat | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `07574a5dff71c83a`

| Field | Value |
|---|---|
| SHA-256 | `07574a5dff71c83a43b2d087a1dca54bf18b8c4e74bdddbaf4ea9ce58c2d0367` |
| Family label | `unknown` |
| File name | `24c6ad1e70e8bafa00ec2d02b4cfdc64.exe` |
| File type | `exe` |
| First seen | `2026-11-17 08:02:32` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24c6ad1e70e8bafa00ec2d02b4cfdc64` |
| SHA-1 | `a73802283466ce8f87f21b9a612e70d33df94a30` |
| SHA-256 | `07574a5dff71c83a43b2d087a1dca54bf18b8c4e74bdddbaf4ea9ce58c2d0367` |
| SHA3-384 | `f07b08599a74c6587b4d641f47d19d9fc04ae2045e54e5be8d7e52f3530724fa3b8b27078cad182178b3c1f2143b0f04` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CF558D9CB25071DFC957D476EEA82CB8BA28347B530B4603A06716E9AA0CD97DF140F7` |
| SSDEEP | `24576:yophrAs4ISnZuU3JEzv8YYoHHXrmVnlug2rEtViTkhq:TrR49uU3gJLbOl64s` |
| ICON-DHASH | `0026b1693332164c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_07574a5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07574a5dff71c83a43b2d087a1dca54bf18b8c4e74bdddbaf4ea9ce58c2d0367"
    family = "unknown"
    file_name = "24c6ad1e70e8bafa00ec2d02b4cfdc64.exe"
    file_type = "exe"
    first_seen = "2026-11-17 08:02:32"
  condition:
    hash.sha256(0, filesize) == "07574a5dff71c83a43b2d087a1dca54bf18b8c4e74bdddbaf4ea9ce58c2d0367"
}
```

### Sample 2: `0fbd4fe6afb5f555`

| Field | Value |
|---|---|
| SHA-256 | `0fbd4fe6afb5f555fea9d09cf376a2c2e61b0e77a8ee3ab2f7eedc70f47765f8` |
| Family label | `unknown` |
| File name | `RFQspecificationslistandcompanyprofilepresentation.vbe` |
| File type | `vbe` |
| First seen | `2026-11-17 08:01:51` |
| Reporter | `ni_fi_70` |
| Tags | `vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `643eff399eeb6270ea6cea168a83da16` |
| SHA-1 | `c2f10d5db1b697938e4ebaaa05d9542426f888ad` |
| SHA-256 | `0fbd4fe6afb5f555fea9d09cf376a2c2e61b0e77a8ee3ab2f7eedc70f47765f8` |
| SHA3-384 | `903c7df1f2f4131ff35e3aeac1ac1eb20220b6676cf3e1cfb1a690f0bfaacf4acaa28f5391852dccb0a6b4d9c1bea08d` |
| TLSH | `T11F048A75886A37B11EC700E4B6A70FA9B8E1A735A685C02F2674CF0F7D98578F80457E` |
| SSDEEP | `1536:jl2r10LBBipNolO2fXOwqM5W9EXbFHAkPCLq+NBelsRDPIu9o7BFIif3mH5:G12Cx++wX5W9cxELPfewBmceW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_0fbd4fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fbd4fe6afb5f555fea9d09cf376a2c2e61b0e77a8ee3ab2f7eedc70f47765f8"
    family = "unknown"
    file_name = "RFQspecificationslistandcompanyprofilepresentation.vbe"
    file_type = "vbe"
    first_seen = "2026-11-17 08:01:51"
  condition:
    hash.sha256(0, filesize) == "0fbd4fe6afb5f555fea9d09cf376a2c2e61b0e77a8ee3ab2f7eedc70f47765f8"
}
```

### Sample 3: `af44015b97c6d65e`

| Field | Value |
|---|---|
| SHA-256 | `af44015b97c6d65ed6d64f8e865d133370e63f00a66974cb1340b67478275b36` |
| Family label | `unknown` |
| File name | `17116384.bat` |
| File type | `bat` |
| First seen | `2026-11-17 08:01:46` |
| Reporter | `ni_fi_70` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a57d8d3bcd4be82f8aeae2120160a7d3` |
| SHA-1 | `619f1f90400206dd7e388d995890e3d0fc81a82d` |
| SHA-256 | `af44015b97c6d65ed6d64f8e865d133370e63f00a66974cb1340b67478275b36` |
| SHA3-384 | `7a25c283fa5bb640190a5c36725e744bd144cad3aa8afd5ddc8bc5f8879a9fdecb3fb8bf11e6df0bb9fb23b8a71729d3` |
| TLSH | `T114A4AFB876047DE6267F126BCA96ACD9136A57A39B87E4CD4064BFC30563336FF02805` |
| SSDEEP | `12288:mMGgD7+eWBcEGMW56wgzofm3sT95FOWcA/Ow9GSY5I8t9M+U9fr:H/D711M06fzou3sJ5MWc8N9PYm8tzUF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_af44015b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af44015b97c6d65ed6d64f8e865d133370e63f00a66974cb1340b67478275b36"
    family = "unknown"
    file_name = "17116384.bat"
    file_type = "bat"
    first_seen = "2026-11-17 08:01:46"
  condition:
    hash.sha256(0, filesize) == "af44015b97c6d65ed6d64f8e865d133370e63f00a66974cb1340b67478275b36"
}
```

### Sample 4: `1a4ac0d2729d21fd`

| Field | Value |
|---|---|
| SHA-256 | `1a4ac0d2729d21fda92d2fe099f0b4956c006a5a3a6db434605417dd614c6ac9` |
| Family label | `unknown` |
| File name | `PurchaseOrder.js` |
| File type | `js` |
| First seen | `2026-11-17 08:01:43` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20e84c92eefd73e830a6a229ae8f1da1` |
| SHA-1 | `c32aecfdb0005c00f950e4356be231757acb16a1` |
| SHA-256 | `1a4ac0d2729d21fda92d2fe099f0b4956c006a5a3a6db434605417dd614c6ac9` |
| SHA3-384 | `5feff48fffd10e427a2944a9b0f581bef9b14488abd854698d2b3f6ddaf97e50fcedb341dca930dbafba8a7612afa5c6` |
| TLSH | `T1B2A1D08D5E8EA014C93373B9CF5FA109EB25452B4606C289BA9C93E24F7502847F4EFC` |
| SSDEEP | `96:IxLJWf+gc3ilY5P7HzPjGFGZAk+SGjvrTuPfwImpJa:IxL9gc3ilyP7T7GFGZAk+SGzuPfwImpY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_1a4ac0d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a4ac0d2729d21fda92d2fe099f0b4956c006a5a3a6db434605417dd614c6ac9"
    family = "unknown"
    file_name = "PurchaseOrder.js"
    file_type = "js"
    first_seen = "2026-11-17 08:01:43"
  condition:
    hash.sha256(0, filesize) == "1a4ac0d2729d21fda92d2fe099f0b4956c006a5a3a6db434605417dd614c6ac9"
}
```

### Sample 5: `3a20e1d037cb3c04`

| Field | Value |
|---|---|
| SHA-256 | `3a20e1d037cb3c043799fea6fb2c954911fe75ba4568f365e51c5bd178ce6a74` |
| Family label | `unknown` |
| File name | `2026_November_December_paymentplan_xls.js` |
| File type | `js` |
| First seen | `2026-11-17 08:01:40` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cd3c0c601eec760df68e5e0cd20fdcb` |
| SHA-1 | `85187749bbb4a4f7545652c3b9297c7ed8d9228b` |
| SHA-256 | `3a20e1d037cb3c043799fea6fb2c954911fe75ba4568f365e51c5bd178ce6a74` |
| SHA3-384 | `3d8c5f8a9bf1153d9d3f6090fc89601f3f34cb623732d151e39d6210c12ae3c36d226e87e2883051d2da8a7dc37026d9` |
| TLSH | `T101251247BF456A8F0C381AABAF450D860A023D27D57285D139DE4D9F922FCED28BC52D` |
| SSDEEP | `12288:0UYv7N3jluhByWZ4gusRS5ytc71fvG2+nlGjlzqCUDr0l0ptY7xCql8IcIlOoLLb:BQNToT5SQS5ytiSklzq4j7xHTLLme` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_3a20e1d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a20e1d037cb3c043799fea6fb2c954911fe75ba4568f365e51c5bd178ce6a74"
    family = "unknown"
    file_name = "2026_November_December_paymentplan_xls.js"
    file_type = "js"
    first_seen = "2026-11-17 08:01:40"
  condition:
    hash.sha256(0, filesize) == "3a20e1d037cb3c043799fea6fb2c954911fe75ba4568f365e51c5bd178ce6a74"
}
```

### Sample 6: `617a9a4afa9ef4ad`

| Field | Value |
|---|---|
| SHA-256 | `617a9a4afa9ef4ad9c24f77a04ad6c2ba5016921dc574bae090306f7d34f118a` |
| Family label | `unknown` |
| File name | `RFQ-SM657430043652913-20261117.js` |
| File type | `js` |
| First seen | `2026-11-17 08:01:36` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23c9b2ef79df4b55a2b2ceca77d7ef28` |
| SHA-1 | `6fe1204990d94fce381239d4d1f4a1bd6634c079` |
| SHA-256 | `617a9a4afa9ef4ad9c24f77a04ad6c2ba5016921dc574bae090306f7d34f118a` |
| SHA3-384 | `99d1d08ddafa5b974459e1dd04d4bfe3c519b8a0af958445dbab21e0db8f1a5bcb2fd4c2937782c7c582d74d92ab52dc` |
| TLSH | `T19BA35B70CA12157B4F43BB88BCA50A61CA6D8319853705B0F6D9C70DA109DECE7BD6AF` |
| SSDEEP | `3072:hBTOam0xovZEAiUlZ4oeUwHvG84YvUrzkdmpSubII228:h4am0xoRfI9vG82ssx2V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_617a9a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "617a9a4afa9ef4ad9c24f77a04ad6c2ba5016921dc574bae090306f7d34f118a"
    family = "unknown"
    file_name = "RFQ-SM657430043652913-20261117.js"
    file_type = "js"
    first_seen = "2026-11-17 08:01:36"
  condition:
    hash.sha256(0, filesize) == "617a9a4afa9ef4ad9c24f77a04ad6c2ba5016921dc574bae090306f7d34f118a"
}
```

### Sample 7: `82a9eded67865eb2`

| Field | Value |
|---|---|
| SHA-256 | `82a9eded67865eb219a2ec4b0d4b278e0e0929e9f2ac0fee5205376ad55ae6b8` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 08:00:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cbb4cc123120b22eace142988296780` |
| SHA-1 | `87b6a12fa7ec3941fa167f40f7ed35afd4f6b993` |
| SHA-256 | `82a9eded67865eb219a2ec4b0d4b278e0e0929e9f2ac0fee5205376ad55ae6b8` |
| SHA3-384 | `33c4d4d14587d2276c9275e3e9e0ed9e4eb1199c66ee430dac2307bbdac70b21397219714686657f81bc143334826f21` |
| TLSH | `T1EF556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSA:SDjxB4m5n8XlaPWi+d+a4TjxQP4m` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_007_82a9eded
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a9eded67865eb219a2ec4b0d4b278e0e0929e9f2ac0fee5205376ad55ae6b8"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 08:00:05"
  condition:
    hash.sha256(0, filesize) == "82a9eded67865eb219a2ec4b0d4b278e0e0929e9f2ac0fee5205376ad55ae6b8"
}
```

### Sample 8: `6fb751a45e304ba0`

| Field | Value |
|---|---|
| SHA-256 | `6fb751a45e304ba07570f9768a34b549a43c164b35af9bc7d9355c1fb1021c53` |
| Family label | `PureLogsStealer` |
| File name | `RFQ Order_26012-17-11-26.js` |
| File type | `js` |
| First seen | `2026-11-17 07:59:41` |
| Reporter | `abuse_ch` |
| Tags | `js, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaa588d8d5743f14a65b2cd24e89085e` |
| SHA-1 | `6eddf18b0ebe73fa779fe05cd17fcf85e0dc7f0a` |
| SHA-256 | `6fb751a45e304ba07570f9768a34b549a43c164b35af9bc7d9355c1fb1021c53` |
| SHA3-384 | `1266d9505798389e36c8426ed15812ef271080815415c7b2fcc543f62d86603d12ee376db3369eb6f7715e1754277afe` |
| TLSH | `T1FC95D0758B1C9EFC924DDE1980750E1DEFE4891B804AF19C8E82E9CFB9A331AD7190D5` |
| SSDEEP | `24576:eI8J3vroh6ZK16GqrDpS7KFVSzhLsXXV0sfzzWPEW3i/fZDPn+b0zH:mJf9FVXAi/Bq0j` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_008_6fb751a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fb751a45e304ba07570f9768a34b549a43c164b35af9bc7d9355c1fb1021c53"
    family = "PureLogsStealer"
    file_name = "RFQ Order_26012-17-11-26.js"
    file_type = "js"
    first_seen = "2026-11-17 07:59:41"
  condition:
    hash.sha256(0, filesize) == "6fb751a45e304ba07570f9768a34b549a43c164b35af9bc7d9355c1fb1021c53"
}
```

### Sample 9: `0c0342c4f3d1a976`

| Field | Value |
|---|---|
| SHA-256 | `0c0342c4f3d1a976e3344d2f1508ea298fc8e7c65a513d080b17eca76f3315ef` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-17 07:58:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d22d131c80d94f3a620575d0c94d8c8` |
| SHA-1 | `05492c6e5a1d426b373aec8d80c3d773f68e4e8c` |
| SHA-256 | `0c0342c4f3d1a976e3344d2f1508ea298fc8e7c65a513d080b17eca76f3315ef` |
| SHA3-384 | `7cce290491a70685b519aa3a9c486b3552d5ec7184eafe9e55a503529f9be9ccc965b638f27978dc6eb353f0f584bfe5` |
| TLSH | `T1D4D4B60B6E228F6DF675873547F70A24EBAD23D623E1D581D2DDC1141F2028E592FBA8` |
| TELFHASH | `t114b125a9293813e4a7555c8c46dcfe328d9328ef7e551c339e60e85ee71ba835e10c1c` |
| SSDEEP | `6144:QvC3iUYoIyQeRPdN0QgaqphPfyHNqVZmxth+8xQnjaV2kQx/W6zOywjs2rzxYK2+:pSIxPFqGCZ2rz6PFT5qnzn7l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_0c0342c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0342c4f3d1a976e3344d2f1508ea298fc8e7c65a513d080b17eca76f3315ef"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-17 07:58:05"
  condition:
    hash.sha256(0, filesize) == "0c0342c4f3d1a976e3344d2f1508ea298fc8e7c65a513d080b17eca76f3315ef"
}
```

### Sample 10: `a4ee256449363cb6`

| Field | Value |
|---|---|
| SHA-256 | `a4ee256449363cb6b201b46b02fd60c96580dc3b2a86cc940b9c38c6bf293be3` |
| Family label | `Formbook` |
| File name | `INVIN7016D003k.JS` |
| File type | `js` |
| First seen | `2026-11-17 07:52:16` |
| Reporter | `ni_fi_70` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baff51c8ab4fa656ab4f192a1cd445d7` |
| SHA-1 | `b868960c113115a9abee287cd67f9a7bb2dddbb4` |
| SHA-256 | `a4ee256449363cb6b201b46b02fd60c96580dc3b2a86cc940b9c38c6bf293be3` |
| SHA3-384 | `25398dc8e410c88355a578eaf272359e52a623bf9ad156cf8295b449a786ff0fbd0c360b219686ab3070374b99149f9f` |
| TLSH | `T15FF5289A278FD653E1ED4249CA0199ED990DE10BDC30EE31381DA95FFA4DA49E348F70` |
| SSDEEP | `98304:9N96Q7i1Qr3NU7gIkvDakP7jvlbh7uEY2t1rMa0wHjxj7Emedxl0EEoRn4U7olEi:0d7gIi7Yb+51` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_010_a4ee2564
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4ee256449363cb6b201b46b02fd60c96580dc3b2a86cc940b9c38c6bf293be3"
    family = "Formbook"
    file_name = "INVIN7016D003k.JS"
    file_type = "js"
    first_seen = "2026-11-17 07:52:16"
  condition:
    hash.sha256(0, filesize) == "a4ee256449363cb6b201b46b02fd60c96580dc3b2a86cc940b9c38c6bf293be3"
}
```

### Sample 11: `4517429af4bd2ceb`

| Field | Value |
|---|---|
| SHA-256 | `4517429af4bd2cebf542aa7cd708aab90b8a23ff9ac9fe816274687926d4e6e7` |
| Family label | `AgentTesla` |
| File name | `md5001001042242.tmp` |
| File type | `js` |
| First seen | `2026-11-17 07:52:11` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d11b6e39c12aba58a474a7fa4743063` |
| SHA-1 | `3470dcc07f1400a9939004ef20a15f58d2eec952` |
| SHA-256 | `4517429af4bd2cebf542aa7cd708aab90b8a23ff9ac9fe816274687926d4e6e7` |
| SHA3-384 | `65af7c6763e2130459c72b218d6d8406a3203e6980fa03f30baad5e7cd8cd1ee842acce43f6997db7780aa33391a0425` |
| TLSH | `T1D0F51951130C94B3E63E972CD8366A6C0A19A00761C9EF3E35BC1247B795B176B8DBF2` |
| SSDEEP | `98304:KoX6c8fZJ3qWEjg0CvnclxUgL7JqTtrD+ujTPSqie9J6bVZRfRC+wLXW:4JnclKtrDLTji/ZDf8hG` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_011_4517429a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4517429af4bd2cebf542aa7cd708aab90b8a23ff9ac9fe816274687926d4e6e7"
    family = "AgentTesla"
    file_name = "md5001001042242.tmp"
    file_type = "js"
    first_seen = "2026-11-17 07:52:11"
  condition:
    hash.sha256(0, filesize) == "4517429af4bd2cebf542aa7cd708aab90b8a23ff9ac9fe816274687926d4e6e7"
}
```

### Sample 12: `f4f1db3d4a95b59e`

| Field | Value |
|---|---|
| SHA-256 | `f4f1db3d4a95b59e97d1578118eabdf6d2cb23b2ae5642302d8da92075ebc491` |
| Family label | `unknown` |
| File name | `md5001000538870.tmp` |
| File type | `js` |
| First seen | `2026-11-17 07:51:53` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01ce654ed84dc91ea337ccbd649b88de` |
| SHA-1 | `7672aeeb73d0b7a78e964e3dd8f74f9296ea67a0` |
| SHA-256 | `f4f1db3d4a95b59e97d1578118eabdf6d2cb23b2ae5642302d8da92075ebc491` |
| SHA3-384 | `79b3af5b802c7a95f629157d6fd99170be53323d065494871ff2fe871df90ef310a4f51065c7d3541b120a3fa451519c` |
| TLSH | `T132166B456E47B3927B3C3D59C519AEA67B42A05B5C70EA3FB06C865AED4CEC036EC103` |
| SSDEEP | `98304:xJIj8Re/ceQoUTbyVV1yp/87PphFgLXWdvx4ylTGJlyw5WEWX7j85m5ikIpyLtbI:x68Re/ceQoMbyVTyshFgzW9x4ylClT5r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_f4f1db3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f1db3d4a95b59e97d1578118eabdf6d2cb23b2ae5642302d8da92075ebc491"
    family = "unknown"
    file_name = "md5001000538870.tmp"
    file_type = "js"
    first_seen = "2026-11-17 07:51:53"
  condition:
    hash.sha256(0, filesize) == "f4f1db3d4a95b59e97d1578118eabdf6d2cb23b2ae5642302d8da92075ebc491"
}
```

### Sample 13: `6133d4d7b0bb501c`

| Field | Value |
|---|---|
| SHA-256 | `6133d4d7b0bb501c931d5c92cd2ee3101bcd9b866f66478ae1c4cf42244426b8` |
| Family label | `unknown` |
| File name | `NewOrderChainC1809270562.js` |
| File type | `js` |
| First seen | `2026-11-17 07:51:50` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `af48fb1f7b2d99b566f3efdd121cbe70` |
| SHA-1 | `18ab67683a9935223489e118b295b77ef067253d` |
| SHA-256 | `6133d4d7b0bb501c931d5c92cd2ee3101bcd9b866f66478ae1c4cf42244426b8` |
| SHA3-384 | `9924a6e82705ceae5869c904befb9d9d9d7cff4f02de539bc565f14e1019e7a23c9728de47291cd07b66d1d02fd2989f` |
| TLSH | `T18114028826C3ADFFC2B9C31D141A1B0CAEBC6BB1A0CD2D4971A690C547A4F3A1771C99` |
| SSDEEP | `6144:Zq0z1j6SWzX+N9qnRBr4/D6jCC7XlIul8bE/3DOmLFHx:Zq0F6HrdfrUaCoIuibEDzLFR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_6133d4d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6133d4d7b0bb501c931d5c92cd2ee3101bcd9b866f66478ae1c4cf42244426b8"
    family = "unknown"
    file_name = "NewOrderChainC1809270562.js"
    file_type = "js"
    first_seen = "2026-11-17 07:51:50"
  condition:
    hash.sha256(0, filesize) == "6133d4d7b0bb501c931d5c92cd2ee3101bcd9b866f66478ae1c4cf42244426b8"
}
```

### Sample 14: `696fe647000575f3`

| Field | Value |
|---|---|
| SHA-256 | `696fe647000575f3504e9c63add676133493dc9c791183cf4ac82a0a6f22dc00` |
| Family label | `unknown` |
| File name | `PENAWARANHARGAh__PDF.js` |
| File type | `js` |
| First seen | `2026-11-17 07:51:47` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fee7c15c82c7815b7bfcab823456e54` |
| SHA-1 | `233f6557242867299d53b17fd993253d78be519a` |
| SHA-256 | `696fe647000575f3504e9c63add676133493dc9c791183cf4ac82a0a6f22dc00` |
| SHA3-384 | `04fa18b6c28248803e26f6c0c1a431d7a83f9bb96ee88b8b2ac1c07573531be70693f159fb3371d1352f552dda98baec` |
| TLSH | `T11214029433C5BC7FC1FED2B8A69F1E6CF6288D47454957C6E4A8B080379CA715A2EC14` |
| SSDEEP | `6144:S0wZfVrgS2XjzqFrEVhIjYFdlAdTf32/o4b:k90pXnmrkhmYTlA52B` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_696fe647
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "696fe647000575f3504e9c63add676133493dc9c791183cf4ac82a0a6f22dc00"
    family = "unknown"
    file_name = "PENAWARANHARGAh__PDF.js"
    file_type = "js"
    first_seen = "2026-11-17 07:51:47"
  condition:
    hash.sha256(0, filesize) == "696fe647000575f3504e9c63add676133493dc9c791183cf4ac82a0a6f22dc00"
}
```

### Sample 15: `746a0b2f1b824a44`

| Field | Value |
|---|---|
| SHA-256 | `746a0b2f1b824a442a116e3fe0c1c6589c745f39b1a0ac3d7ea352fda6877bcf` |
| Family label | `unknown` |
| File name | `_00079` |
| File type | `js` |
| First seen | `2026-11-17 07:51:44` |
| Reporter | `ni_fi_70` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1496a1ef493780b9546a4dfbfdd757e3` |
| SHA-1 | `5dc2a559858a1b467e6b61684d7ac94c1f43453b` |
| SHA-256 | `746a0b2f1b824a442a116e3fe0c1c6589c745f39b1a0ac3d7ea352fda6877bcf` |
| SHA3-384 | `3feca1bfc17f2617a188ae098e6eaf24ba40887b033dff65626aa6c495cdd238da2bb9e47213d225582e486e55a68ccf` |
| TLSH | `T17F14128429C6BD6F81BCCE35051E1F2C69AD8B91F2D9AF4FB065D0C086F4AB49D79C48` |
| SSDEEP | `3072:h8xHcMCfeHMvmXVMexz4MwgmOnkQgqp2u50p53JYCTpYzdTSHITfAXBlljHzd1:hW8MtMvmXVMkzPRmOf10pR5Y5AXVz3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_746a0b2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "746a0b2f1b824a442a116e3fe0c1c6589c745f39b1a0ac3d7ea352fda6877bcf"
    family = "unknown"
    file_name = "_00079"
    file_type = "js"
    first_seen = "2026-11-17 07:51:44"
  condition:
    hash.sha256(0, filesize) == "746a0b2f1b824a442a116e3fe0c1c6589c745f39b1a0ac3d7ea352fda6877bcf"
}
```

### Sample 16: `579eb5e1d14c654c`

| Field | Value |
|---|---|
| SHA-256 | `579eb5e1d14c654ca683b0b6260059cc0ef2a9b1f157f2894e2e30f667a5fac8` |
| Family label | `unknown` |
| File name | `072e69d8f2e5467f84471cc4ea17203c.MSG` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:29` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb3ccb025782a9d75eaf9861131062b5` |
| SHA-1 | `8461d5b89a17fe7fbc6dfb67b15c04c3a3003802` |
| SHA-256 | `579eb5e1d14c654ca683b0b6260059cc0ef2a9b1f157f2894e2e30f667a5fac8` |
| SHA3-384 | `0d07900cf058d84265b26eb6489bfc18db5db3220e4fb6e6aa3df8671f3aac534e4821e5e83861b2b0fdc2aa2984a07d` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1F005F1143669EB09E97A5BF52AB2F17803F57EAA6920E3054FD17CCBB971B044D00B93` |
| SSDEEP | `24576:q5BWxgC+Gf+8wAbxbST2YGONg1ZDoDey:D3+GdBGKD1jDgd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_579eb5e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579eb5e1d14c654ca683b0b6260059cc0ef2a9b1f157f2894e2e30f667a5fac8"
    family = "unknown"
    file_name = "072e69d8f2e5467f84471cc4ea17203c.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:29"
  condition:
    hash.sha256(0, filesize) == "579eb5e1d14c654ca683b0b6260059cc0ef2a9b1f157f2894e2e30f667a5fac8"
}
```

### Sample 17: `6f0c19f0dcca017e`

| Field | Value |
|---|---|
| SHA-256 | `6f0c19f0dcca017e497eae0d42ad38d21cfd45f783eb8ab770037f3d313d5733` |
| Family label | `RemcosRAT` |
| File name | `0x7E11F91CA56615D` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:26` |
| Reporter | `ni_fi_70` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efe6e4893ac6f4552c266ab408f01f7c` |
| SHA-1 | `6ebae755a04abc82d4e1bb8befc1287f364fb717` |
| SHA-256 | `6f0c19f0dcca017e497eae0d42ad38d21cfd45f783eb8ab770037f3d313d5733` |
| SHA3-384 | `1007ae5ddc25737c0862f2135ebe9390aaed50f4a86ee833ba0bd79adda4c054975ea160e7f37f320d4452619861d747` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A935024832B99B09E97A57F51A72E13813F4AFAB6921D3051FD62CDFB962F005D00B93` |
| SSDEEP | `24576:aw5BZAAXSsPqE9Z4YNe7fnDHQ0UuanW4FxLCl41r1VUb:xQE9A7fdYtLCszU` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_017_6f0c19f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0c19f0dcca017e497eae0d42ad38d21cfd45f783eb8ab770037f3d313d5733"
    family = "RemcosRAT"
    file_name = "0x7E11F91CA56615D"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:26"
  condition:
    hash.sha256(0, filesize) == "6f0c19f0dcca017e497eae0d42ad38d21cfd45f783eb8ab770037f3d313d5733"
}
```

### Sample 18: `605de7f6cf8e15c7`

| Field | Value |
|---|---|
| SHA-256 | `605de7f6cf8e15c7a1d8f0770ed742bededf13d1e794fc59d21364b3a9e83165` |
| Family label | `AgentTesla` |
| File name | `9ae5a1019d0d4ce1b741d6ce6e506249.MSG` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:22` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d179233bec92c093557c09f1878184c0` |
| SHA-1 | `977231468a33da988927d24be6bd16cdcf7fc6c8` |
| SHA-256 | `605de7f6cf8e15c7a1d8f0770ed742bededf13d1e794fc59d21364b3a9e83165` |
| SHA3-384 | `b1b93102cef4f0f6c8b754587c09d0f912f6213bd32a5a482b5d2ce4f2003cdb30a76dfc0650b90445876c2e982aed5e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19B05CE60AAA5EB05C52973F4D861D1F493AD6DAAE412C20BDED47DDB3CF2B067D20243` |
| SSDEEP | `12288:j1zHK+5O+2qki4esNRmMLerTDFYX4kF9rTJOTpWuLRzeQBxFh3bkMo:hzR5BkSsN9ejFg30TtLJXjJ0` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_018_605de7f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "605de7f6cf8e15c7a1d8f0770ed742bededf13d1e794fc59d21364b3a9e83165"
    family = "AgentTesla"
    file_name = "9ae5a1019d0d4ce1b741d6ce6e506249.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:22"
  condition:
    hash.sha256(0, filesize) == "605de7f6cf8e15c7a1d8f0770ed742bededf13d1e794fc59d21364b3a9e83165"
}
```

### Sample 19: `5da95c129af20e6a`

| Field | Value |
|---|---|
| SHA-256 | `5da95c129af20e6ad40f1b1376cc340fc4416c3d5c4d54ff1c84b4d06c15455c` |
| Family label | `AsyncRAT` |
| File name | `e1e0b8bf4b1b4b78acfcf2399a061187.MSG` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:17` |
| Reporter | `ni_fi_70` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1e95db2635d39749088343a6cf5d35d` |
| SHA-1 | `c8a3004363b911d86473994c4f54ebe13c67fc1e` |
| SHA-256 | `5da95c129af20e6ad40f1b1376cc340fc4416c3d5c4d54ff1c84b4d06c15455c` |
| SHA3-384 | `a5e7134992677912ce3969bc6a956a67f784b3f081aa418b017b4099a24f689ccd29fc3ccf0bef70de964bafe78f8b50` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1FEC4EF1032699B09EA7A5BF919B6F27C13F47E96A921D3064FD27DDFB521B004D00BA3` |
| SSDEEP | `12288:a2+5O+2qU4afgr9ua0fB68xd9AJoNlYEJl3:c5B5a4P0fk8xj+glpJR` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_019_5da95c12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da95c129af20e6ad40f1b1376cc340fc4416c3d5c4d54ff1c84b4d06c15455c"
    family = "AsyncRAT"
    file_name = "e1e0b8bf4b1b4b78acfcf2399a061187.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:17"
  condition:
    hash.sha256(0, filesize) == "5da95c129af20e6ad40f1b1376cc340fc4416c3d5c4d54ff1c84b4d06c15455c"
}
```

### Sample 20: `542d630f7e740ecd`

| Field | Value |
|---|---|
| SHA-256 | `542d630f7e740ecd2ff366df0e343145d0a3fc7761587f24b993612a1ceb7f8b` |
| Family label | `AgentTesla` |
| File name | `c9312962de4744af953cb90962e08e1d.MSG` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:14` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e69d0c5f7b20ff2f816020c555b2655` |
| SHA-1 | `c1de173c693bd6ff593df2a91a8eca13d85bae01` |
| SHA-256 | `542d630f7e740ecd2ff366df0e343145d0a3fc7761587f24b993612a1ceb7f8b` |
| SHA3-384 | `bc36c0102d5eff60c3949bb7703f168256fea30d09c50a172a36c6c4355fbef08b0669791fd0324d1f40d03f8aa648b7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C0F4F15436A9DB0AE93A57F41AB6F13813F17EAA6921E3094ED16DDFB532F044C00B93` |
| SSDEEP | `12288:qH+5O+2qsKZwCYlAkzmbDhAzf1mh37qWxYP5L3/ha4R/ZHWu7Z3I7ByO8ge:v5BsKfWqbtAzNmxolUQ9xQBe` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_020_542d630f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "542d630f7e740ecd2ff366df0e343145d0a3fc7761587f24b993612a1ceb7f8b"
    family = "AgentTesla"
    file_name = "c9312962de4744af953cb90962e08e1d.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:14"
  condition:
    hash.sha256(0, filesize) == "542d630f7e740ecd2ff366df0e343145d0a3fc7761587f24b993612a1ceb7f8b"
}
```

### Sample 21: `951d2259cc234143`

| Field | Value |
|---|---|
| SHA-256 | `951d2259cc2341431e9fe1f0c57199161a9389fc01a3534d17a051b8ced2cc72` |
| Family label | `unknown` |
| File name | `_00089` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:10` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `847b5b13cdc908db02a881590c1642be` |
| SHA-1 | `74ebe0191656f4ae1f2cd280ea223f68d8ec6949` |
| SHA-256 | `951d2259cc2341431e9fe1f0c57199161a9389fc01a3534d17a051b8ced2cc72` |
| SHA3-384 | `2f05386e02d70c78c5927affb4cac9e9548e953a7c9651210bc8c7c97587d1caf437f2b6e4fd0fd424efc23ace0d3b71` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19CC47B20AA65EB05C56967F4D861E2F487BD6D9AE412D20F8ED47DDB3CF2B063C20253` |
| SSDEEP | `12288:CdzIk+5O+2qQZLVODgPkq3BS8wUsEROXrSLK/sFg5PTI/md:CMb5Br8T3BS8wUsEROem0gl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_951d2259
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "951d2259cc2341431e9fe1f0c57199161a9389fc01a3534d17a051b8ced2cc72"
    family = "unknown"
    file_name = "_00089"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:10"
  condition:
    hash.sha256(0, filesize) == "951d2259cc2341431e9fe1f0c57199161a9389fc01a3534d17a051b8ced2cc72"
}
```

### Sample 22: `6da6e076ac16d86d`

| Field | Value |
|---|---|
| SHA-256 | `6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801` |
| Family label | `Formbook` |
| File name | `pd2951919258.att` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:07` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79d4ff06f7e4c4578a9675575d14091d` |
| SHA-1 | `ad285c5e63ece35682c6b4939a72b084af852e3b` |
| SHA-256 | `6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801` |
| SHA3-384 | `bbe5d0735b59592a87fa2f5087ce05fbc3ed1e36d229a9d008a3bdc332581a47d11dab7424f94f342462143689715804` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1EE05F1143269DF09E97A5BF51AB1F17813F9BE5A6820E3094FD6BCDBB521B044D00B93` |
| SSDEEP | `12288:tV+5O+2qeNUGzWaOl07x5/ozDBt3gbZY6fAcz15fLQHPoRwYW9ewuNKRU2hxw:K5BFlhzD/Q3FtwAGt06w` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_022_6da6e076
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801"
    family = "Formbook"
    file_name = "pd2951919258.att"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:07"
  condition:
    hash.sha256(0, filesize) == "6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801"
}
```

### Sample 23: `618d20e30e90fce0`

| Field | Value |
|---|---|
| SHA-256 | `618d20e30e90fce0d684db2ba4352ce9a2c57bbc790447ecfc0a64726224cca9` |
| Family label | `unknown` |
| File name | `goodthings.hta` |
| File type | `hta` |
| First seen | `2026-11-17 07:51:06` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96caa7a1039cd4aae2679d17d5700f74` |
| SHA-1 | `ccf22521f71dfef0074d38502019298b60ddb437` |
| SHA-256 | `618d20e30e90fce0d684db2ba4352ce9a2c57bbc790447ecfc0a64726224cca9` |
| SHA3-384 | `fc1e5e874bc6ce613487579997eb4742f27f6ef4fe2eed51cd0e69278dda02d5752a9e43ebe29d2effe7ccab8b4144b6` |
| TLSH | `T113A27EEC4FC88E95132C6A59C86934CCE7EF4B4108C199AFB02514AA367A3D1D17DBF1` |
| SSDEEP | `384:zGbkhx3EkKbxOAzc7wnuUEefa/FXMDdpO3A8MQg9jE306Aj/yWlXkHUrglGTkB/3:Sbkhx3EkKbxOAzc7wnuVefa/FXMDdpOj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_618d20e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618d20e30e90fce0d684db2ba4352ce9a2c57bbc790447ecfc0a64726224cca9"
    family = "unknown"
    file_name = "goodthings.hta"
    file_type = "hta"
    first_seen = "2026-11-17 07:51:06"
  condition:
    hash.sha256(0, filesize) == "618d20e30e90fce0d684db2ba4352ce9a2c57bbc790447ecfc0a64726224cca9"
}
```

### Sample 24: `2f26b6fed6612b40`

| Field | Value |
|---|---|
| SHA-256 | `2f26b6fed6612b40560bbb9fbf6f5ae7f9219cb7d5248181efe69e184398ec9d` |
| Family label | `XWorm` |
| File name | `md5001002645273.tmp` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:04` |
| Reporter | `ni_fi_70` |
| Tags | `exe, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73a563a0c36c279b3b050879283edfa5` |
| SHA-1 | `46e15949dcbb50f39596d373961bd042687b5ca4` |
| SHA-256 | `2f26b6fed6612b40560bbb9fbf6f5ae7f9219cb7d5248181efe69e184398ec9d` |
| SHA3-384 | `41aa54e7d287426135a5de3acbfa3e41c0d755d9398fdd159bbb47dd8c0ebadeb165e259caa5de9eefb918b5dc905f99` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T15AF4BE14AA75EB05C56967F4D861E1F893BC6D9AE422D20B8EC57DDB3CF2B023C24243` |
| SSDEEP | `12288:lrzem+5O+2qRAbuGtFA88R6kIETqTqYhJ3xb5DA5BYyHyo5f/Y/goc3K6/6CZF73:5K15BSusO6PQShJR5Dqcc6gP1ZM8k` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_024_2f26b6fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f26b6fed6612b40560bbb9fbf6f5ae7f9219cb7d5248181efe69e184398ec9d"
    family = "XWorm"
    file_name = "md5001002645273.tmp"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:04"
  condition:
    hash.sha256(0, filesize) == "2f26b6fed6612b40560bbb9fbf6f5ae7f9219cb7d5248181efe69e184398ec9d"
}
```

### Sample 25: `f8578890598dca94`

| Field | Value |
|---|---|
| SHA-256 | `f8578890598dca94cb87620492148b3c938a602e45e232954347baa3bd28a7c2` |
| Family label | `unknown` |
| File name | `WrittenBytes` |
| File type | `exe` |
| First seen | `2026-11-17 07:51:00` |
| Reporter | `ni_fi_70` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51fdf47f5dbe8a2ed57d76f567bf5e9d` |
| SHA-1 | `27295e437756b6ef08897585c60f8734ae5b645d` |
| SHA-256 | `f8578890598dca94cb87620492148b3c938a602e45e232954347baa3bd28a7c2` |
| SHA3-384 | `00646033cd861fd25f0ae91932e41f22d6081a1e4c3c35f556ec6b54f8602eb8b3abdb37bd9852f486d0cbf97abc6879` |
| TLSH | `T13F24E148BBF5ED1CF5BE59BB39A103054975F33724239B4930864F1D9BA36C44A82BA3` |
| SSDEEP | `3072:vLffr4FLwPAbQuV1m2PI6QiwdL3Tz7+RzabXHosZrWZV9uqDefAIqL0YM9bgrg3l:zfT4x/FVHfGT/SsZOuz4IqIN5fek` |
| ICON-DHASH | `30a88ee6988eea73` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_f8578890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8578890598dca94cb87620492148b3c938a602e45e232954347baa3bd28a7c2"
    family = "unknown"
    file_name = "WrittenBytes"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:00"
  condition:
    hash.sha256(0, filesize) == "f8578890598dca94cb87620492148b3c938a602e45e232954347baa3bd28a7c2"
}
```

### Sample 26: `1fec0c36273b609d`

| Field | Value |
|---|---|
| SHA-256 | `1fec0c36273b609de2986119fd13fb46288ee75e542c66873b5362e293d8d537` |
| Family label | `MassLogger` |
| File name | `8075e619` |
| File type | `js` |
| First seen | `2026-11-17 07:50:57` |
| Reporter | `ni_fi_70` |
| Tags | `js, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `481eb411e6bc1e0a455ae9a9ebd16749` |
| SHA-1 | `e8c58a4a974faad04f3feeacbf97e43f70187977` |
| SHA-256 | `1fec0c36273b609de2986119fd13fb46288ee75e542c66873b5362e293d8d537` |
| SHA3-384 | `330867636603766597927ad0bd2debb3d3c1d24627f2ab55f7927f0938b05a7eb56bf10680ef6181dae21651175b4ca7` |
| TLSH | `T190E401365811FDF4E73E3A18CDA51C2DDCB4294783B5D80CA605E2AA7AABA41CF174D3` |
| SSDEEP | `12288:rTxaffKZVU7I9SDK2g+NNTMmty8AgqT2rCTFLq/d5BnUSz+3GUOyUZhlzTIZfkqz:PxaqD9+N9M5nr2OTxMPBn1UOyUhlzBqz` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_026_1fec0c36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fec0c36273b609de2986119fd13fb46288ee75e542c66873b5362e293d8d537"
    family = "MassLogger"
    file_name = "8075e619"
    file_type = "js"
    first_seen = "2026-11-17 07:50:57"
  condition:
    hash.sha256(0, filesize) == "1fec0c36273b609de2986119fd13fb46288ee75e542c66873b5362e293d8d537"
}
```

### Sample 27: `7ca0d9b533effed8`

| Field | Value |
|---|---|
| SHA-256 | `7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971` |
| Family label | `AgentTesla` |
| File name | `COMPROBANTEDEPAGO.exe` |
| File type | `exe` |
| First seen | `2026-11-17 07:50:54` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e708184eeb2369e72120e4407298cc0` |
| SHA-1 | `d9f648c297dc9b1e5afb1824ae4d24e8819c5f82` |
| SHA-256 | `7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971` |
| SHA3-384 | `3fd291dbbafc6882c83c70d63cd13e8e7f7b0b7eaec1932855376ac8311ba97fd91595b56452b5364b933209243897dc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18405BD4423ACCA06C5A6F7B4C561F1F80BA86E6BF4D9C2078ED17DDF7972B845B04262` |
| SSDEEP | `12288:XqpIFGrk89+5O+2qzg3/KhNS6W/KZ9AW5HLN+YZ6JJb91MKJ/qVcIzcr0tvbGri:6pJk8k5BzgvKhbx/AWcL7LSqI+Sr` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_027_7ca0d9b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971"
    family = "AgentTesla"
    file_name = "COMPROBANTEDEPAGO.exe"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:54"
  condition:
    hash.sha256(0, filesize) == "7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971"
}
```

### Sample 28: `f52bad2f6b6fe7d4`

| Field | Value |
|---|---|
| SHA-256 | `f52bad2f6b6fe7d404663bf24b55d38c0504314667894f3ed2600fc2b1988fa0` |
| Family label | `PureLogsStealer` |
| File name | `WrittenBytes` |
| File type | `exe` |
| First seen | `2026-11-17 07:50:51` |
| Reporter | `ni_fi_70` |
| Tags | `exe, PureLogsStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `342a1a3385f7dcfecfaba0c03ba6d4f3` |
| SHA-1 | `11c26a918ea4bb486c4788340c4592e550439807` |
| SHA-256 | `f52bad2f6b6fe7d404663bf24b55d38c0504314667894f3ed2600fc2b1988fa0` |
| SHA3-384 | `3b3a421485aacfe745cedea472a222e05a628fed5afd5deb464a57bd0ad5f61973748dccd492cda9d5feff6f5c0ad5ca` |
| TLSH | `T1323523275BC59E38D925387A2CBA015219F4F84F2033DB8F556E8D2F99F026488DB772` |
| SSDEEP | `24576:q/cNxwhdyXpoxaTyVgYEi0PgI2MWzZrtJ:dxPmEyeYYYzH` |
| ICON-DHASH | `6969cccc84b491d1` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_028_f52bad2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f52bad2f6b6fe7d404663bf24b55d38c0504314667894f3ed2600fc2b1988fa0"
    family = "PureLogsStealer"
    file_name = "WrittenBytes"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:51"
  condition:
    hash.sha256(0, filesize) == "f52bad2f6b6fe7d404663bf24b55d38c0504314667894f3ed2600fc2b1988fa0"
}
```

### Sample 29: `b3515d99bdcf3fcf`

| Field | Value |
|---|---|
| SHA-256 | `b3515d99bdcf3fcff08a1adb526a9b476177c6a7e619a5d7eeddb603312bfd41` |
| Family label | `MassLogger` |
| File name | `md5001000300362.tmp` |
| File type | `exe` |
| First seen | `2026-11-17 07:50:48` |
| Reporter | `ni_fi_70` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30e2296586ae5764384a0977631eace6` |
| SHA-1 | `a77c2e26320582d211793c605dda588ec544f18f` |
| SHA-256 | `b3515d99bdcf3fcff08a1adb526a9b476177c6a7e619a5d7eeddb603312bfd41` |
| SHA3-384 | `8aae350c9411c6b0a606ed339ed8d77ac50a02d7a939e51a687d506dc5eb6069d893ec0560f4ed10010d45d265d080a0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E335024837A4DB19E97D5BF4167AF27813F57EAA6820E30A5ED56CCBB931B040D00B93` |
| SSDEEP | `24576:N5BJ3Y0a4bmLng5TtlyY8fMuoBGMunAM:7Jadbg5TtV+Mu+dv` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_029_b3515d99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3515d99bdcf3fcff08a1adb526a9b476177c6a7e619a5d7eeddb603312bfd41"
    family = "MassLogger"
    file_name = "md5001000300362.tmp"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:48"
  condition:
    hash.sha256(0, filesize) == "b3515d99bdcf3fcff08a1adb526a9b476177c6a7e619a5d7eeddb603312bfd41"
}
```

### Sample 30: `84886f1f4e1e7973`

| Field | Value |
|---|---|
| SHA-256 | `84886f1f4e1e79733f8e052d440ee01ff0f02cd1c6731ee1fc144d32987d6d66` |
| Family label | `AgentTesla` |
| File name | `_00142` |
| File type | `js` |
| First seen | `2026-11-17 07:50:45` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2aa8dae376e175c56740144a46c35b69` |
| SHA-1 | `4419cb4076d27baf8c2f19ac7ce9c5ce8c61ec9f` |
| SHA-256 | `84886f1f4e1e79733f8e052d440ee01ff0f02cd1c6731ee1fc144d32987d6d66` |
| SHA3-384 | `bd29cd30e3bd4e6a51edbb45d3c069d073df50766447ae1e496fb30ab062abeed30eeb43da7bcbc8cd5332022620e4a5` |
| TLSH | `T1660502714E57BCB5622E7B0888A81A0AEFD55507E366E19C9246F2D336A3341FF2D0C7` |
| SSDEEP | `24576:wKR5PQ1liSBGgORrK2Bvb7rQkCpUbpJTTh:TQ1l7YLqkCoJXh` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_030_84886f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84886f1f4e1e79733f8e052d440ee01ff0f02cd1c6731ee1fc144d32987d6d66"
    family = "AgentTesla"
    file_name = "_00142"
    file_type = "js"
    first_seen = "2026-11-17 07:50:45"
  condition:
    hash.sha256(0, filesize) == "84886f1f4e1e79733f8e052d440ee01ff0f02cd1c6731ee1fc144d32987d6d66"
}
```

### Sample 31: `e56f62bf9912d6e8`

| Field | Value |
|---|---|
| SHA-256 | `e56f62bf9912d6e8aac7a094fdb6990be6eaa8a5ef95c5aba708821134b83ff6` |
| Family label | `MassLogger` |
| File name | `PO-Q-2627-2466.exe` |
| File type | `exe` |
| First seen | `2026-11-17 07:50:42` |
| Reporter | `ni_fi_70` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2074f8f6bb5203166c6e5ef6ccf4f862` |
| SHA-1 | `fc21f85921463312def2622a6b80a1401d4c0f45` |
| SHA-256 | `e56f62bf9912d6e8aac7a094fdb6990be6eaa8a5ef95c5aba708821134b83ff6` |
| SHA3-384 | `fe1ad0775344bcb12a89d26826b5d4c56fc044d9b6d1ddd298552df6d6b878a81e1cc66f6b53f18bd11cc4316957a369` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T179E49B48239CCA06C9A5E7B5D961F1F80BA86E9BF4D9D2178EC07DEF7831B905B00653` |
| SSDEEP | `12288:EqTmXkBm+5O+2qXKLfwCThS+tkx0DxLxYuDVxrS5QOIGE2LU:RqkB15BartSbx0LxlG2CT` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_031_e56f62bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e56f62bf9912d6e8aac7a094fdb6990be6eaa8a5ef95c5aba708821134b83ff6"
    family = "MassLogger"
    file_name = "PO-Q-2627-2466.exe"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:42"
  condition:
    hash.sha256(0, filesize) == "e56f62bf9912d6e8aac7a094fdb6990be6eaa8a5ef95c5aba708821134b83ff6"
}
```

### Sample 32: `262a24afffa5b50f`

| Field | Value |
|---|---|
| SHA-256 | `262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1` |
| Family label | `MassLogger` |
| File name | `-.pdf.js` |
| File type | `exe` |
| First seen | `2026-11-17 07:50:39` |
| Reporter | `ni_fi_70` |
| Tags | `exe, MassLogger, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00100e54cdcda37f14bb5a4830384acd` |
| SHA-1 | `37b729af9d218c7bdfdabaf04566afcd653a177e` |
| SHA-256 | `262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1` |
| SHA3-384 | `62ea7d69dce113871fb75282ca45e1ac9df9c316262d5b11c4989310cddf699ba296470b82d2424cedd96ef381d13dcc` |
| TLSH | `T10EC38B7977D9F8A1E5AD673514B14208F6BDF91F3022E74C048F0D5E9BA22C84AB1BB1` |
| SSDEEP | `1536:0nomFQC+0oV/aqVgnbJkxVrcOQgO3/OrnCDPE1s/ktr/WJvBJjw:0n+CVoV/XeJkxJ0jPVgrUvE` |
| ICON-DHASH | `0008001d5a5b5b5a` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_032_262a24af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1"
    family = "MassLogger"
    file_name = "-.pdf.js"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:39"
  condition:
    hash.sha256(0, filesize) == "262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1"
}
```

### Sample 33: `7aa41390346c9925`

| Field | Value |
|---|---|
| SHA-256 | `7aa41390346c9925497f4f1d2574fedfffc0d5684d46a204dc594f0cadefb906` |
| Family label | `unknown` |
| File name | `Zapytanieofertowenr490526.xls` |
| File type | `xls` |
| First seen | `2026-11-17 07:50:34` |
| Reporter | `ni_fi_70` |
| Tags | `CVE-2017-0199, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3df0ad3610ccf55aa79b8b65b2ca39c8` |
| SHA-1 | `b3a8f4e7db0c673af471de53a89552732d345c9e` |
| SHA-256 | `7aa41390346c9925497f4f1d2574fedfffc0d5684d46a204dc594f0cadefb906` |
| SHA3-384 | `5bed1563469ebe4080a6c843d299839133d28a5f78521ce397b5ffac56e8d5b5cee9202a48bafcdeebc74fd1db65a6a2` |
| TLSH | `T149052313B1E5AE6BC863D8B865E282A5E598FC67CB63840B1F04B79D113B7194CE3346` |
| SSDEEP | `12288:nP5sp+4so8RZd/POS3bxfEIGWjLyjUJvm5FZh4dOgOhwR9M7+UKfTac+M:Rn/ZNG4fEaHhJu5SdnO6RGTKfGcH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_7aa41390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aa41390346c9925497f4f1d2574fedfffc0d5684d46a204dc594f0cadefb906"
    family = "unknown"
    file_name = "Zapytanieofertowenr490526.xls"
    file_type = "xls"
    first_seen = "2026-11-17 07:50:34"
  condition:
    hash.sha256(0, filesize) == "7aa41390346c9925497f4f1d2574fedfffc0d5684d46a204dc594f0cadefb906"
}
```

### Sample 34: `e0af51cb8ed95d04`

| Field | Value |
|---|---|
| SHA-256 | `e0af51cb8ed95d04a2b8e85fa7cb3d42d25ba46c6263adfd84761e3d87b443f5` |
| Family label | `RemcosRAT` |
| File name | `RGB.hta` |
| File type | `hta` |
| First seen | `2026-11-17 07:30:06` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cd000175ac332925d2ab18b4df2ea84` |
| SHA-1 | `80f6e1245b6bf6e6ed79c586dc817f72fe730775` |
| SHA-256 | `e0af51cb8ed95d04a2b8e85fa7cb3d42d25ba46c6263adfd84761e3d87b443f5` |
| SHA3-384 | `1f9892a5d99004b541d82a18915c43aae04a24dd3d5cc03023b247c1ccd1a21b3432b71d3bee9e59fa6c7c156c104b47` |
| TLSH | `T1AD620F7C83D4FCC8939B77E4A1B8330BC59D5B7B611DAA6E78CC00A2578C22C8C760A5` |
| SSDEEP | `48:3PCnxi09VNxisp9VyBlZuuWKiXtLWsxihTxi/I11IE9ViKxiEG:/CnkQVNkoVCti9vklksVRkn` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_034_e0af51cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0af51cb8ed95d04a2b8e85fa7cb3d42d25ba46c6263adfd84761e3d87b443f5"
    family = "RemcosRAT"
    file_name = "RGB.hta"
    file_type = "hta"
    first_seen = "2026-11-17 07:30:06"
  condition:
    hash.sha256(0, filesize) == "e0af51cb8ed95d04a2b8e85fa7cb3d42d25ba46c6263adfd84761e3d87b443f5"
}
```

### Sample 35: `4b09a170b5bd96e3`

| Field | Value |
|---|---|
| SHA-256 | `4b09a170b5bd96e31e3c86bef1b70d1da5c525c5e97c412f327ec9fd886db012` |
| Family label | `RemcosRAT` |
| File name | `慶騰精密 CFS 2026年11月19日 基隆--香港 SO.6386(古)(譽銘).exe` |
| File type | `exe` |
| First seen | `2026-11-17 06:56:23` |
| Reporter | `threatcat_ch` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d71e1125f91d9a1f57dd2a0665e9d8a2` |
| SHA-1 | `c31530997e1b5b6a7af0c689c8c49d5ff663bd40` |
| SHA-256 | `4b09a170b5bd96e31e3c86bef1b70d1da5c525c5e97c412f327ec9fd886db012` |
| SHA3-384 | `0641d550277a89efd1a710edee51dae6da75923fd7b5db7415a42f79fdc57285ff3cbb75c1acb7e3263db797c9973385` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11735EF20AA75E705C56967F4D861E1F593AD6DAAE422C20F8EC83DDB3CF27027D24253` |
| SSDEEP | `24576:M1h5Bd/MyMxBt9sChnzG1f3A2Uvm01sTdXVNlr8hMHP7KwrUjDJQHc:S/IxBXh23A2UO4sRXV0MUj1QH` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_035_4b09a170
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b09a170b5bd96e31e3c86bef1b70d1da5c525c5e97c412f327ec9fd886db012"
    family = "RemcosRAT"
    file_name = "慶騰精密 CFS 2026年11月19日 基隆--香港 SO.6386(古)(譽銘).exe"
    file_type = "exe"
    first_seen = "2026-11-17 06:56:23"
  condition:
    hash.sha256(0, filesize) == "4b09a170b5bd96e31e3c86bef1b70d1da5c525c5e97c412f327ec9fd886db012"
}
```

### Sample 36: `e004417825327fc9`

| Field | Value |
|---|---|
| SHA-256 | `e004417825327fc9523b80e877037c4f18112952a0e5d4ed2c19e3cb7b4f7afa` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-11-17 06:11:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8023e7f564d7d9066704607c88212efc` |
| SHA-1 | `30d1ebdbccc75c98b2209e2f9d90495e0dad7e1d` |
| SHA-256 | `e004417825327fc9523b80e877037c4f18112952a0e5d4ed2c19e3cb7b4f7afa` |
| SHA3-384 | `7e0781c2028f2fa16423b350d9974fde24f9d88d22f5ef25029a8619a00136fb726fdae4dfd61879e39cb8f1ca78d04a` |
| TLSH | `T162A46B07BA74E9A4DAF18470618DD33AAC74917212BB984EDE569CF0F9193807B2C35F` |
| TELFHASH | `t1066165250468a093eb3358eff347d211b9365c7b96f8f9904a83385fadf508a04ed692` |
| SSDEEP | `6144:mwM3QofxFi07KZ9lV1ILDHLlTsdejLrF/+S7QLnV8LmJ256NV+DJp9TLRMi:s3/fxFi07Al4LlTsdeLj78GC2o6VRj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_e0044178
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e004417825327fc9523b80e877037c4f18112952a0e5d4ed2c19e3cb7b4f7afa"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-17 06:11:05"
  condition:
    hash.sha256(0, filesize) == "e004417825327fc9523b80e877037c4f18112952a0e5d4ed2c19e3cb7b4f7afa"
}
```

### Sample 37: `b1e1643f6b5f6905`

| Field | Value |
|---|---|
| SHA-256 | `b1e1643f6b5f6905e7711c2be654e29b960ad61178f24d6c861b7b8c2ab004a6` |
| Family label | `RemcosRAT` |
| File name | `Fedex-AWB.js` |
| File type | `js` |
| First seen | `2026-11-17 05:54:44` |
| Reporter | `threatcat_ch` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `587189fb9493c16965c8cb6aee22415b` |
| SHA-1 | `6b33d216823fae78c0875d6c1be2a8982af0b968` |
| SHA-256 | `b1e1643f6b5f6905e7711c2be654e29b960ad61178f24d6c861b7b8c2ab004a6` |
| SHA3-384 | `b1cef98cb747aef0f1423e295885ce8a49b5abfebf5907fc9f37a037cdfe8b9b813fef710c60e96e1a9a10287630c111` |
| TLSH | `T15C623FDC1489D7942807B68FB130FB39F7993929E21517E12A1D3CED3C898E243A679D` |
| SSDEEP | `384:/HRwDURnXHRwDURnXHRwDURn99u6G68MHRwDURnXHRwDURnXHRwDURn/:/xwDURXxwDURXxwDURBxwDURXxwDURXN` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_037_b1e1643f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1e1643f6b5f6905e7711c2be654e29b960ad61178f24d6c861b7b8c2ab004a6"
    family = "RemcosRAT"
    file_name = "Fedex-AWB.js"
    file_type = "js"
    first_seen = "2026-11-17 05:54:44"
  condition:
    hash.sha256(0, filesize) == "b1e1643f6b5f6905e7711c2be654e29b960ad61178f24d6c861b7b8c2ab004a6"
}
```

### Sample 38: `c50ff97d3e0b1938`

| Field | Value |
|---|---|
| SHA-256 | `c50ff97d3e0b19386f6ea33280c22ea03a4386cbb36c51c12c109de0c2b0041c` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 05:49:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b81345958d53e677a3131c1b8934e8fb` |
| SHA-1 | `fdd25a2a369c7cc4fe7f93d4047f735e6928c843` |
| SHA-256 | `c50ff97d3e0b19386f6ea33280c22ea03a4386cbb36c51c12c109de0c2b0041c` |
| SHA3-384 | `c9fd2e993a530722c15071f0d9980e8ba944b3797fa6b372dcfff59d8ab8363bba00dab1995d4c991352fe5bd3020e29` |
| TLSH | `T155556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSK:SDjxB4m5n8XlaPWi+d+a4TjxQP4E` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_038_c50ff97d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50ff97d3e0b19386f6ea33280c22ea03a4386cbb36c51c12c109de0c2b0041c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:49:05"
  condition:
    hash.sha256(0, filesize) == "c50ff97d3e0b19386f6ea33280c22ea03a4386cbb36c51c12c109de0c2b0041c"
}
```

### Sample 39: `0dc8eb6eb2cee7c7`

| Field | Value |
|---|---|
| SHA-256 | `0dc8eb6eb2cee7c7f4be3e5809ba2ed40e70a18942a90eb7327aacf655a60e7b` |
| Family label | `GoDDoSAgent` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-17 05:48:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e33d8cdd11c05a7b296686bfad00ad70` |
| SHA-1 | `ac21f49cfcb60cc3f1df993f8cbefcd469ae2bdb` |
| SHA-256 | `0dc8eb6eb2cee7c7f4be3e5809ba2ed40e70a18942a90eb7327aacf655a60e7b` |
| SHA3-384 | `69af753d3402174b0af369f38073147af80706c5d057d3ce90c0df4e261dc4696e9de349a00316b0d298fd5ef96363c1` |
| TLSH | `T1E3560797B9D25942C4E83A77A8BD80C433674FB98B8752575D09EE383EBE1D90E38314` |
| TELFHASH | `t105e02b018d2eafc827cf804c1966133a7ee131f8a60c6714af7e202f0d02532b4db061` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Xs1LLVh5rj3rsEVe6CWreNyT0Fm6zfZaQQe2RpdVl0p+5EDD:Xs1Pn5rj3jIieNNzfZwEH` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_039_0dc8eb6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc8eb6eb2cee7c7f4be3e5809ba2ed40e70a18942a90eb7327aacf655a60e7b"
    family = "GoDDoSAgent"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-17 05:48:07"
  condition:
    hash.sha256(0, filesize) == "0dc8eb6eb2cee7c7f4be3e5809ba2ed40e70a18942a90eb7327aacf655a60e7b"
}
```

### Sample 40: `e166ea5fe88f2a36`

| Field | Value |
|---|---|
| SHA-256 | `e166ea5fe88f2a36ea05ef597de1ac0666e06aac65c40b055c86890024c10e4c` |
| Family label | `GoDDoSAgent` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-11-17 05:47:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ac9aed7fd0983b72e34b3d2bbd43502` |
| SHA-1 | `0b3fc152816024665628ddd49821ea13f27274a1` |
| SHA-256 | `e166ea5fe88f2a36ea05ef597de1ac0666e06aac65c40b055c86890024c10e4c` |
| SHA3-384 | `dfffc32c14c6bfa0976fb7ec24c85ddf539e4c5b268e5bb761fd1c2d7d3973025b20b17d355676746c024fc0d8cc96e7` |
| TLSH | `T152560757B9D25942C4E83A77A8BD80C437634FBA8B8752175D08FE387EBE5D90A38314` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:1kcPnd7n4oL5hJySZaNTfK0tJ02FKh1cXlO5Ejr:iUdz4oL/JycaE1cCEX` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_040_e166ea5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e166ea5fe88f2a36ea05ef597de1ac0666e06aac65c40b055c86890024c10e4c"
    family = "GoDDoSAgent"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-17 05:47:06"
  condition:
    hash.sha256(0, filesize) == "e166ea5fe88f2a36ea05ef597de1ac0666e06aac65c40b055c86890024c10e4c"
}
```

### Sample 41: `6bdf42a575d2daee`

| Field | Value |
|---|---|
| SHA-256 | `6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18` |
| Family label | `unknown` |
| File name | `heartbreaker` |
| File type | `macho` |
| First seen | `2026-11-17 05:46:07` |
| Reporter | `anonymous` |
| Tags | `Heartbreaker, macho, ransomware, rust` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8aac39631d15fa074586c5dacd583826` |
| SHA-1 | `8df9b7ca833f222da5db7f619e704c46d1f4ff3a` |
| SHA-256 | `6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18` |
| SHA3-384 | `7d405c903856ec868f36bbc0df1293c5d78379380995715468e90a8776a3c6391e3f56826adbf629ceab979c5e2d3775` |
| TLSH | `T1FD76AE06FF9D5D1EDAC770BC4C4D87610267F0948226C2DA3927E66DEC536A2C12F7A2` |
| SSDEEP | `98304:6swlhrYnLLaDsVM4gbRfvqoFbzsbnn2pxVbT:FwlhrYn/aDoMjfHx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_6bdf42a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18"
    family = "unknown"
    file_name = "heartbreaker"
    file_type = "macho"
    first_seen = "2026-11-17 05:46:07"
  condition:
    hash.sha256(0, filesize) == "6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18"
}
```

### Sample 42: `079ee2adc6d1623f`

| Field | Value |
|---|---|
| SHA-256 | `079ee2adc6d1623f7f442415c9766f627644d2690847bdbbaeb95310d45af2c3` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-11-17 05:45:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0be889cd5202c9979e43096ea0166998` |
| SHA-1 | `a119a45988c1dd04da8ba3953e2553361f5dff10` |
| SHA-256 | `079ee2adc6d1623f7f442415c9766f627644d2690847bdbbaeb95310d45af2c3` |
| SHA3-384 | `4ab651f8e2a15293751f180eb2d2dae537c9b0c89703c721e5a1cc0392aba6b553bde990cbe673c0a133524b7f3caa4a` |
| TLSH | `T1BEA4CE461B3D7860DFD5E87C50888BB97B79B8E513B9E30CD91289D8ED00340BA6C76B` |
| SSDEEP | `6144:Zrf6xQHC4ZaPnLQqz2vWmQUsIsqRprPc8nMOn1QLnV8LmJ256NV+DJp9TLRMi:ZrSOecWmQ0sGRMo8GC2o6VRj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_079ee2ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "079ee2adc6d1623f7f442415c9766f627644d2690847bdbbaeb95310d45af2c3"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-17 05:45:07"
  condition:
    hash.sha256(0, filesize) == "079ee2adc6d1623f7f442415c9766f627644d2690847bdbbaeb95310d45af2c3"
}
```

### Sample 43: `b5ddfce1f453b1ce`

| Field | Value |
|---|---|
| SHA-256 | `b5ddfce1f453b1ce2eb81067e4e909d9717707d796482b583559f4d2ac23f050` |
| Family label | `GoDDoSAgent` |
| File name | `amd64` |
| File type | `elf` |
| First seen | `2026-11-17 05:39:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `494f08bf305b7c82008a0011222c42d2` |
| SHA-1 | `f75a743515a0971724550db44a97a15f87df39a7` |
| SHA-256 | `b5ddfce1f453b1ce2eb81067e4e909d9717707d796482b583559f4d2ac23f050` |
| SHA3-384 | `b616061ef149ecc51b215a615aa271e4c4877ed5c62dd04b70eab82064739438b181ee5601e988e7c43b46dc5a287784` |
| TLSH | `T19B565A17ECA918A6C1AE913089769193BB71BC491B3023D32B60F3347F77BD4A9B9354` |
| TELFHASH | `t1cf32497549bc39b4b69ada10b362b4f4a5371da577f938b11023e994efc1e801ce2837` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:wV00bdvc8bv9ZcMjDZcQwIdhmTvDAEM4mlatf57sR23KdKwK5K2Liy5R5ECp:wvRv39ZNqvVmlaL7++Li4E0` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_043_b5ddfce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5ddfce1f453b1ce2eb81067e4e909d9717707d796482b583559f4d2ac23f050"
    family = "GoDDoSAgent"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-11-17 05:39:06"
  condition:
    hash.sha256(0, filesize) == "b5ddfce1f453b1ce2eb81067e4e909d9717707d796482b583559f4d2ac23f050"
}
```

### Sample 44: `ac233f0bfefb8b39`

| Field | Value |
|---|---|
| SHA-256 | `ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815` |
| Family label | `RustyStealer` |
| File name | `ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815` |
| File type | `exe` |
| First seen | `2026-11-17 05:36:00` |
| Reporter | `anonymous` |
| Tags | `exe, HYFLOCK, ransomware, rust, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73e1f8905e2bf79a92443614d0ed4598` |
| SHA-1 | `c5a506d46b41278c0bf0d1d149f4ca946f3be1bb` |
| SHA-256 | `ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815` |
| SHA3-384 | `17e3fe6f8754ec76401cef412d4b1245d29444739f301b80dcd0486dc389bd6ae810522f2f7b22e8d35041b2cb4a02a9` |
| IMPHASH | `a6130854185251b18e79dcecc990a51a` |
| TLSH | `T13DB54B13B6B690F8C55AC074D31A5632BB32788A0B3139FB26D84A253F65FD06B3DB54` |
| SSDEEP | `49152:4KkFTdpGc62NpwQqFM54T26fdRfh7R0x6qHUBra40W+:262/+Bh7RRa4g` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_044_ac233f0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815"
    family = "RustyStealer"
    file_name = "ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815"
    file_type = "exe"
    first_seen = "2026-11-17 05:36:00"
  condition:
    hash.sha256(0, filesize) == "ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815"
}
```

### Sample 45: `ce171065cb02da5f`

| Field | Value |
|---|---|
| SHA-256 | `ce171065cb02da5f0a6b14be8ea17f41d74afe53c9bb99e283a516c671445c33` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 05:35:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d992711b604e2ddaf03417e2b8a93629` |
| SHA-1 | `2713eec6420858a623dee856c32ff75da04bc6e4` |
| SHA-256 | `ce171065cb02da5f0a6b14be8ea17f41d74afe53c9bb99e283a516c671445c33` |
| SHA3-384 | `78d1ebe555cff994a72c86fec555a87ef892cfcec220fc3c4feb30eb658bcc0698cc8d68c3b611d882b93e2aaf48dfe5` |
| TLSH | `T11E556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSv:SDjxB4m5n8XlaPWi+d+a4TjxQP4Z` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_045_ce171065
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce171065cb02da5f0a6b14be8ea17f41d74afe53c9bb99e283a516c671445c33"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:35:05"
  condition:
    hash.sha256(0, filesize) == "ce171065cb02da5f0a6b14be8ea17f41d74afe53c9bb99e283a516c671445c33"
}
```

### Sample 46: `a120f0c0defe4b69`

| Field | Value |
|---|---|
| SHA-256 | `a120f0c0defe4b6943e09f06272a86ae75d1a4524fa9bf21da25c8c0d747ef5a` |
| Family label | `RustyStealer` |
| File name | `eu.exe` |
| File type | `exe` |
| First seen | `2026-11-17 05:34:11` |
| Reporter | `anonymous` |
| Tags | `exe, HYFLOCK, ransomware, rust, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4792b0ad68bb72c6db2413d3f43c26e2` |
| SHA-1 | `434197b77af84b4c80037f469fe41ef66610dda2` |
| SHA-256 | `a120f0c0defe4b6943e09f06272a86ae75d1a4524fa9bf21da25c8c0d747ef5a` |
| SHA3-384 | `db5f8973a17d60bb2d3c70d68b506fe29fa7c7d369a8c6a735ce8a1cd84b245c81f6ea22d159f09e870d46e700e995a7` |
| IMPHASH | `e1468cf5511c19c7448bade0baa4339d` |
| TLSH | `T12AA55C43F6A290FCD06AC17583667632FA72BC4D48357A776BD88B312F64F406A2DB14` |
| SSDEEP | `49152:MbJ/AREQjfWD3X6aXTwcdPbtFqIbd2Gz+yG+jYXSVMWPBo:Md6jfClXHKIbMG3ESeB` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_046_a120f0c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a120f0c0defe4b6943e09f06272a86ae75d1a4524fa9bf21da25c8c0d747ef5a"
    family = "RustyStealer"
    file_name = "eu.exe"
    file_type = "exe"
    first_seen = "2026-11-17 05:34:11"
  condition:
    hash.sha256(0, filesize) == "a120f0c0defe4b6943e09f06272a86ae75d1a4524fa9bf21da25c8c0d747ef5a"
}
```

### Sample 47: `b1f0a2fff8baab47`

| Field | Value |
|---|---|
| SHA-256 | `b1f0a2fff8baab47463fa04b1ee279ef86265db24a58f7fc1b56c5576ec801db` |
| Family label | `RustyStealer` |
| File name | `eu.exe` |
| File type | `exe` |
| First seen | `2026-11-17 05:33:14` |
| Reporter | `anonymous` |
| Tags | `exe, HYFLOCK, ransomware, rust, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8ce57daa150b37accbde3e554dbce00` |
| SHA-1 | `18d25db5d6d3d67083566a8017a1663fdd334669` |
| SHA-256 | `b1f0a2fff8baab47463fa04b1ee279ef86265db24a58f7fc1b56c5576ec801db` |
| SHA3-384 | `05130fc8ee01b192dc65f148c04b77b509e508acfc09a092556a0b212e85c7c7d9b98ddf4bd1b62e632c5c76b631d6bd` |
| IMPHASH | `03977616147535fe09f027555ae51613` |
| TLSH | `T1DFB55C47F2A190ECD06AC17983267632FA76BC4D88357A775BD49F302F64F40AA2DB14` |
| SSDEEP | `49152:O/ajmXzIlj61HUBXtn8dxpLMNDaHvtQxdrJ3Mr2M2:NjmXEjWxpoDSCOrZ2` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_047_b1f0a2ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1f0a2fff8baab47463fa04b1ee279ef86265db24a58f7fc1b56c5576ec801db"
    family = "RustyStealer"
    file_name = "eu.exe"
    file_type = "exe"
    first_seen = "2026-11-17 05:33:14"
  condition:
    hash.sha256(0, filesize) == "b1f0a2fff8baab47463fa04b1ee279ef86265db24a58f7fc1b56c5576ec801db"
}
```

### Sample 48: `80c474154b1df816`

| Field | Value |
|---|---|
| SHA-256 | `80c474154b1df816cf513ae978936875b6dd77f47ef6bce78dda83ab1b89525b` |
| Family label | `RustyStealer` |
| File name | `53nw6lv7.exe` |
| File type | `exe` |
| First seen | `2026-11-17 05:32:24` |
| Reporter | `anonymous` |
| Tags | `exe, HYFLOCK, ransomware, rust` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaf89493dd8e95da247734dc3604910d` |
| SHA-1 | `37d602cc3032e8a6341a4ccf9e353db31ea2f803` |
| SHA-256 | `80c474154b1df816cf513ae978936875b6dd77f47ef6bce78dda83ab1b89525b` |
| SHA3-384 | `8bcd1c491841a4ca6d33d2f00b3f671b0c24a52340a84a23534e3f2325efbfc4371e3c5c76d6843e268f79694f1b2f53` |
| IMPHASH | `279885d84a8226dcaa645b41d26c24b8` |
| TLSH | `T1DAA5D053F68685FCC02BC4B4C2564763EB71748A0B2169FF8294AA783F16AF54F38395` |
| SSDEEP | `49152:HyuAicVhD4WqhYyc4snG/5UU2kNHB4uQHCu7S:HypFq3uUXGziu7S` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_048_80c47415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80c474154b1df816cf513ae978936875b6dd77f47ef6bce78dda83ab1b89525b"
    family = "RustyStealer"
    file_name = "53nw6lv7.exe"
    file_type = "exe"
    first_seen = "2026-11-17 05:32:24"
  condition:
    hash.sha256(0, filesize) == "80c474154b1df816cf513ae978936875b6dd77f47ef6bce78dda83ab1b89525b"
}
```

### Sample 49: `189257961beda2c9`

| Field | Value |
|---|---|
| SHA-256 | `189257961beda2c9617ef04658408616adf3ae77293191db0465bc508d4ee9b9` |
| Family label | `XWorm` |
| File name | `PO20261113143.pdf.JS` |
| File type | `js` |
| First seen | `2026-11-17 05:32:07` |
| Reporter | `ni_fi_70` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e154a142c8cc2b2b370c847d69275e2c` |
| SHA-1 | `bb86b16a479e147712863e9ccbea4dc9b5dbd9e5` |
| SHA-256 | `189257961beda2c9617ef04658408616adf3ae77293191db0465bc508d4ee9b9` |
| SHA3-384 | `c7cdf9213bc9e558808cbfd2548e0b6d01e54a80f2af581fcbe6bf89fa80a355468df32e4b96d64ae28e0f921fb027e2` |
| TLSH | `T189C5E564170C9673E53E6B2CD6725A2C4A16E10B22A5EF3E30BC224772A5B17174DFF2` |
| SSDEEP | `49152:Bl/Afw6pWJMy5eXTVoFS+vOBOn6cVIUsRb0a28e9HYzgOtQ9mdCo27ml94DB2LwY:Bl/Afw6pWJMy5eXTVoFS+vOBOn6cVIUy` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_049_18925796
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189257961beda2c9617ef04658408616adf3ae77293191db0465bc508d4ee9b9"
    family = "XWorm"
    file_name = "PO20261113143.pdf.JS"
    file_type = "js"
    first_seen = "2026-11-17 05:32:07"
  condition:
    hash.sha256(0, filesize) == "189257961beda2c9617ef04658408616adf3ae77293191db0465bc508d4ee9b9"
}
```

### Sample 50: `d872bca80947067b`

| Field | Value |
|---|---|
| SHA-256 | `d872bca80947067bd0c0fe67513adde63f2fce539a9babc92f3b5b12220b9b25` |
| Family label | `Formbook` |
| File name | `pago-20261116085641016.JS` |
| File type | `js` |
| First seen | `2026-11-17 05:32:03` |
| Reporter | `ni_fi_70` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc197ae978c2871dbc7f81ac337917c7` |
| SHA-1 | `f99181a4937bea6f7933553b1eedb97e3bd46984` |
| SHA-256 | `d872bca80947067bd0c0fe67513adde63f2fce539a9babc92f3b5b12220b9b25` |
| SHA3-384 | `9427db827282ab0a3af06bca272d35a6217cde19ff7c737364e59366ef1f503c262830263be81d5074953cffa90c1ede` |
| TLSH | `T1B5F5A2861B959136F325A79C463A9B3B994A500315D6CB30336DE22CFDDCD0BB358BE2` |
| SSDEEP | `98304:yI4j9CQiacW/21aSAqQsG4RFeK0cW9zempPFMXYJtDZvRnYmRoqkzaRan/oZNFCM:yI4j9CQiacW/21aSAqfG4RFeKvoemptV` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_050_d872bca8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d872bca80947067bd0c0fe67513adde63f2fce539a9babc92f3b5b12220b9b25"
    family = "Formbook"
    file_name = "pago-20261116085641016.JS"
    file_type = "js"
    first_seen = "2026-11-17 05:32:03"
  condition:
    hash.sha256(0, filesize) == "d872bca80947067bd0c0fe67513adde63f2fce539a9babc92f3b5b12220b9b25"
}
```

### Sample 51: `a6eee59062b49004`

| Field | Value |
|---|---|
| SHA-256 | `a6eee59062b4900464534edfdd486411c7ec415f9f8a0e3a2599bbb82e8ade7e` |
| Family label | `RemcosRAT` |
| File name | `INV.xls` |
| File type | `xls` |
| First seen | `2026-11-17 05:32:00` |
| Reporter | `ni_fi_70` |
| Tags | `CVE-2017-0199, RemcosRAT, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8257b4fdf0be30ca8c56ba6760e2059` |
| SHA-1 | `56100a82b54f1d55f3fb4761eea9f3fb6f25976f` |
| SHA-256 | `a6eee59062b4900464534edfdd486411c7ec415f9f8a0e3a2599bbb82e8ade7e` |
| SHA3-384 | `4d7c4a0a15e4d794e9c3b6917d5f194e7a132f0bb2a94cfbb7b270880665541171b2a380adb89c2abf6d609f493c50c0` |
| TLSH | `T128052307F8912E1BC0E3947C26D5CDA9FA8CBC959E76C90B3B16B3AA143B36509C570D` |
| SSDEEP | `12288:cPhvWBrRdvvp8TmS3HxnuVDwjjyOxzZ2lF1hwhOambmtfdoAh98YOGPlWK:CWXVCKknu+vxz8l+hdm6tEYLPlW` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_051_a6eee590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6eee59062b4900464534edfdd486411c7ec415f9f8a0e3a2599bbb82e8ade7e"
    family = "RemcosRAT"
    file_name = "INV.xls"
    file_type = "xls"
    first_seen = "2026-11-17 05:32:00"
  condition:
    hash.sha256(0, filesize) == "a6eee59062b4900464534edfdd486411c7ec415f9f8a0e3a2599bbb82e8ade7e"
}
```

### Sample 52: `320e6be256619e7a`

| Field | Value |
|---|---|
| SHA-256 | `320e6be256619e7a5378eb1a03e8ea47d20ee82c8fa04cea534c48ca3b2ed07f` |
| Family label | `LxBaseRAT` |
| File name | `LX_Cm0nHprUp0Q_zQzn.j` |
| File type | `js` |
| First seen | `2026-11-17 05:31:57` |
| Reporter | `ni_fi_70` |
| Tags | `js, LxBaseRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82c958e2598e9ddc9ba21a58de4f47c1` |
| SHA-1 | `89be10adb77439c70e99ac9c40a7f307a4f6077e` |
| SHA-256 | `320e6be256619e7a5378eb1a03e8ea47d20ee82c8fa04cea534c48ca3b2ed07f` |
| SHA3-384 | `989138f7f94fd8a0328d6d1deb844b6de9e897c3f14308cb6f29dea0f3ea83c304b38754614ff72166522416bc7ba566` |
| TLSH | `T12E1412F03EC59DBF81FFCA10E41F0E4C16AC1D9AAA8E66CA211D61D1038F635A77AD15` |
| SSDEEP | `6144:F/Pwl06Ti73h6SKh1PJFSFISTNv9Qcazn3:9PwGrEhzBGFE3` |

#### Technical Assessment

- The sample is tracked as `LxBaseRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LxBaseRAT_052_320e6be2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "320e6be256619e7a5378eb1a03e8ea47d20ee82c8fa04cea534c48ca3b2ed07f"
    family = "LxBaseRAT"
    file_name = "LX_Cm0nHprUp0Q_zQzn.j"
    file_type = "js"
    first_seen = "2026-11-17 05:31:57"
  condition:
    hash.sha256(0, filesize) == "320e6be256619e7a5378eb1a03e8ea47d20ee82c8fa04cea534c48ca3b2ed07f"
}
```

### Sample 53: `2974e0064f6951c7`

| Field | Value |
|---|---|
| SHA-256 | `2974e0064f6951c7cba5cf65e63d1fd521201509c45839341429cbf0eaae86e3` |
| Family label | `Formbook` |
| File name | `Justificante.js` |
| File type | `js` |
| First seen | `2026-11-17 05:31:54` |
| Reporter | `ni_fi_70` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c957b8afcb26686a3ad50e4de5a0979` |
| SHA-1 | `22ab7a7cb6d96590fff100829c93edb042d23da4` |
| SHA-256 | `2974e0064f6951c7cba5cf65e63d1fd521201509c45839341429cbf0eaae86e3` |
| SHA3-384 | `f8d7dce4e338ceabb7e82b0bb6fe009bb0073dc6392cc09cf10799aec858577925b8acbf9baaead890c04f1fc519c628` |
| TLSH | `T14B376C2405A0F1262F51E9D3E5F9EF7454AB8AB7C54B94C88F0A0CC7B2229F6937D12D` |
| SSDEEP | `3072:Lov8roEsCFEGA1U60aI0ZWKbEzJTA+UL+EZhX9SCDXJk5OkDhaN5LDWfsR6H8Mi9:VY/0yGR36nA5MqUV` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_053_2974e006
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2974e0064f6951c7cba5cf65e63d1fd521201509c45839341429cbf0eaae86e3"
    family = "Formbook"
    file_name = "Justificante.js"
    file_type = "js"
    first_seen = "2026-11-17 05:31:54"
  condition:
    hash.sha256(0, filesize) == "2974e0064f6951c7cba5cf65e63d1fd521201509c45839341429cbf0eaae86e3"
}
```

### Sample 54: `b2ecad3135d079fa`

| Field | Value |
|---|---|
| SHA-256 | `b2ecad3135d079fa7eb917e04f05cc744caa21dade23bdf5810237a895c943d7` |
| Family label | `Formbook` |
| File name | `Justificante.js` |
| File type | `js` |
| First seen | `2026-11-17 05:31:46` |
| Reporter | `ni_fi_70` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e2ae295e952a846d68a27a33549ebc4` |
| SHA-1 | `7a5cbc6b7476da5322000d629825f8f3b806cb6b` |
| SHA-256 | `b2ecad3135d079fa7eb917e04f05cc744caa21dade23bdf5810237a895c943d7` |
| SHA3-384 | `0dbc38f58a46ae56ee82ea63a00c0fe31c1d97c778e62ff5fcb2e5a513bb9b0f22dfc1707accb94f63971cbd6c94db3c` |
| TLSH | `T1E147685A438251F33EE7A3877C2672350AEF0BC9D34D438B26E7E51995D8CE5E60138A` |
| SSDEEP | `3072:oGiX7eKh8cExYqNpawYhNY0PIPGnqg6kwpNds4Z9wfPuoYieq+YPsCdcmSgR3urQ:qZdkeBq+Feeb` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_054_b2ecad31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2ecad3135d079fa7eb917e04f05cc744caa21dade23bdf5810237a895c943d7"
    family = "Formbook"
    file_name = "Justificante.js"
    file_type = "js"
    first_seen = "2026-11-17 05:31:46"
  condition:
    hash.sha256(0, filesize) == "b2ecad3135d079fa7eb917e04f05cc744caa21dade23bdf5810237a895c943d7"
}
```

### Sample 55: `95a62caef708b150`

| Field | Value |
|---|---|
| SHA-256 | `95a62caef708b15024e23354b1bfa404f5452fc32c7e4793bc7543a4a79fe918` |
| Family label | `unknown` |
| File name | `awb_shipping_customs_tax_clearance_instructions_11_17_2026.xls` |
| File type | `xls` |
| First seen | `2026-11-17 05:31:41` |
| Reporter | `ni_fi_70` |
| Tags | `CVE-2017-0199, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `493a8d6d1b2cbacad10ed5bed42eac04` |
| SHA-1 | `cb207cd4fbd02d96dca9af2204202b89accf5795` |
| SHA-256 | `95a62caef708b15024e23354b1bfa404f5452fc32c7e4793bc7543a4a79fe918` |
| SHA3-384 | `9cfbb6d13c78418c1a42426d3d1cbc4bd2b833900e6218d5a4353e0575111187ccc776b2b71463d7ff845cf262f7d25a` |
| TLSH | `T115052303F8A56E2BC0D3E8385AC5D669E949BC5D4F53D81B3F0AB3D9087E7690AD1309` |
| SSDEEP | `12288:RPtD4W5nRdvvp8TmS3HxnuVDwjjyOxzZ2lF1hwhOambmtfHkiLYi6y283ekmcKKD:bhVCKknu+vxz8l+hdm6t8sYi/uFK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_95a62cae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a62caef708b15024e23354b1bfa404f5452fc32c7e4793bc7543a4a79fe918"
    family = "unknown"
    file_name = "awb_shipping_customs_tax_clearance_instructions_11_17_2026.xls"
    file_type = "xls"
    first_seen = "2026-11-17 05:31:41"
  condition:
    hash.sha256(0, filesize) == "95a62caef708b15024e23354b1bfa404f5452fc32c7e4793bc7543a4a79fe918"
}
```

### Sample 56: `dfa7c075b704d3b8`

| Field | Value |
|---|---|
| SHA-256 | `dfa7c075b704d3b80a5909850161101b47237411937809345cc963cc19d32134` |
| Family label | `AgentTesla` |
| File name | `RePaymentDishonorNotification--INV33711.JS` |
| File type | `js` |
| First seen | `2026-11-17 05:31:38` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32bc7a53117a182b2b3c7ebd5b07f6fb` |
| SHA-1 | `43e5da786854d8581d323d21d892c281808b36cf` |
| SHA-256 | `dfa7c075b704d3b80a5909850161101b47237411937809345cc963cc19d32134` |
| SHA3-384 | `ff6c81560a4b9598269d0c817d426ad64c43823a03c7f8de8173e6dea9e248f35e7b7e7fa78bacc060452515b9ea527b` |
| TLSH | `T1E1F5F682134C9133E626AB5D8636D93D9A1AE00321C6DF35316DA31BB658D1BA35CFF3` |
| SSDEEP | `98304:QqXKfRPdzbzOT1SA8J4e91DTGIUOIUzsr+9vyID6BavZbSHR0ZRsS4vTNNTXmjHj:QqXKfRPdzbYS3rGysopD6BwZRl4XCjHj` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_056_dfa7c075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfa7c075b704d3b80a5909850161101b47237411937809345cc963cc19d32134"
    family = "AgentTesla"
    file_name = "RePaymentDishonorNotification--INV33711.JS"
    file_type = "js"
    first_seen = "2026-11-17 05:31:38"
  condition:
    hash.sha256(0, filesize) == "dfa7c075b704d3b80a5909850161101b47237411937809345cc963cc19d32134"
}
```

### Sample 57: `5da6ba74a57b7380`

| Field | Value |
|---|---|
| SHA-256 | `5da6ba74a57b73807cdc8c313fdb185cad744f3060c14354a0625e8cf02548bc` |
| Family label | `RemcosRAT` |
| File name | `unknown` |
| File type | `js` |
| First seen | `2026-11-17 05:21:35` |
| Reporter | `ni_fi_70` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cec7d686675d1f9c1b3395e548d1ed1` |
| SHA-1 | `91ceca4f6c15e51a72c8e3189b1d3e9475303c3f` |
| SHA-256 | `5da6ba74a57b73807cdc8c313fdb185cad744f3060c14354a0625e8cf02548bc` |
| SHA3-384 | `7ebe63333949a4884cff0de857087f8f7ea2864e2c721dca709b6464187c5be019536ad7382a45d0814819c858cfd2b8` |
| TLSH | `T11E55E1354B047EFA628C5918B8F80F0D9EE0590B8256F2DD9246F1E727B7319CB2D8D6` |
| SSDEEP | `24576:f2RgeiUljEP8H3TmOY8ixAQzkHj0DtAFLbY4:+W6fD0aFL/` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_057_5da6ba74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da6ba74a57b73807cdc8c313fdb185cad744f3060c14354a0625e8cf02548bc"
    family = "RemcosRAT"
    file_name = "unknown"
    file_type = "js"
    first_seen = "2026-11-17 05:21:35"
  condition:
    hash.sha256(0, filesize) == "5da6ba74a57b73807cdc8c313fdb185cad744f3060c14354a0625e8cf02548bc"
}
```

### Sample 58: `091636fb36bc0874`

| Field | Value |
|---|---|
| SHA-256 | `091636fb36bc0874c7b46135746ee1605bef493ce1d4830898171e2ebe822c2d` |
| Family label | `GoDDoSAgent` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-17 05:20:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `940a4ea7e5d4bccff819ad4b1bff5408` |
| SHA-1 | `b5d9b8909556a71f409ad972ac1d54c0ffc14a70` |
| SHA-256 | `091636fb36bc0874c7b46135746ee1605bef493ce1d4830898171e2ebe822c2d` |
| SHA3-384 | `f7e11c4dc638e143f15b9c81816ff5eeba9087a170ee5aad6e63cfbb777ad2f8f5041968a2f056c0c68cf9d1fdd9265c` |
| TLSH | `T19F560897B8D25942C4E83A77A8BD80C433635EB98B8752175D09FE387EBE5D90E38314` |
| TELFHASH | `t117e0c241dc4c9fe872da40641a4a532829e434f651246784debba19f0e0196121ca865` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:tPv9jsqhw9GVKLP2TPJ+/S2UOQyglP9Rhr5Elr:tn9jhO9rUOQyWXEN` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_058_091636fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "091636fb36bc0874c7b46135746ee1605bef493ce1d4830898171e2ebe822c2d"
    family = "GoDDoSAgent"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-17 05:20:07"
  condition:
    hash.sha256(0, filesize) == "091636fb36bc0874c7b46135746ee1605bef493ce1d4830898171e2ebe822c2d"
}
```

### Sample 59: `30f4b566fe4c460d`

| Field | Value |
|---|---|
| SHA-256 | `30f4b566fe4c460daff28d1c5a2fbe99757aefbb47494a778695a1fd20a48486` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 05:13:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93374a926c7fc86c541d8e790ea3c037` |
| SHA-1 | `e656fb836ce09292d8d7af2c739d575484cc223b` |
| SHA-256 | `30f4b566fe4c460daff28d1c5a2fbe99757aefbb47494a778695a1fd20a48486` |
| SHA3-384 | `0947a579bf67eb815396a48002a2d0f2e1e8735bef869911b22d5b21fcbed069f4ca865fc1065b08b270f9eb221fd159` |
| TLSH | `T1A7556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSj:SDjxB4m5n8XlaPWi+d+a4TjxQP4V` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_059_30f4b566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f4b566fe4c460daff28d1c5a2fbe99757aefbb47494a778695a1fd20a48486"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:13:06"
  condition:
    hash.sha256(0, filesize) == "30f4b566fe4c460daff28d1c5a2fbe99757aefbb47494a778695a1fd20a48486"
}
```

### Sample 60: `1e719597868b05b1`

| Field | Value |
|---|---|
| SHA-256 | `1e719597868b05b1f36a90fbfab4791d07e93369deeef4438c89d4749f494a0d` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 05:12:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03452d7cda1aafe710f41bc02dece1aa` |
| SHA-1 | `ddba6dd6487d0d73f09608212dc9ca563b8e8b38` |
| SHA-256 | `1e719597868b05b1f36a90fbfab4791d07e93369deeef4438c89d4749f494a0d` |
| SHA3-384 | `69f988091fb7f91dae5966a40371b2c249304b41c268ccd5b10fa3cdc14b7b90de4260f3245f0b3717ec591606ca869b` |
| TLSH | `T189556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS+:SDjxB4m5n8XlaPWi+d+a4TjxQP4A` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_060_1e719597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e719597868b05b1f36a90fbfab4791d07e93369deeef4438c89d4749f494a0d"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:12:05"
  condition:
    hash.sha256(0, filesize) == "1e719597868b05b1f36a90fbfab4791d07e93369deeef4438c89d4749f494a0d"
}
```

### Sample 61: `e1e82b492745635c`

| Field | Value |
|---|---|
| SHA-256 | `e1e82b492745635c7a1549c764135e61deb65440cfa8b001fe25317e1452c9ee` |
| Family label | `GoDDoSAgent` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-17 05:10:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56296fe571555ec135d1d4a32bd807fa` |
| SHA-1 | `540679479c0b3ae3b09297b01bb7090f4584b540` |
| SHA-256 | `e1e82b492745635c7a1549c764135e61deb65440cfa8b001fe25317e1452c9ee` |
| SHA3-384 | `6bad70567b51408b48dd50251b1aa8ab11ecd26c8c1a5efb9bcba4d8776e6e3c76f6935f2853e4500280fb90fc1b1317` |
| TLSH | `T12A6629236B28EB0ED62522304DB1CAC5AB391C5641D7D81BA392F718E9F316C5D6ECF4` |
| TELFHASH | `t1b3c092454e590a8e79801e860dc8f2272552fa124838342cff7288c7163e0a2016da1b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Q9I69FEOTAejnmqIJuLGNdhHu1t2hPhhu8S2eFHcTqgwUeKGpdsez/0ysklGEJuP:q5jtgkcTEL0ysVE8BUEr` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_061_e1e82b49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1e82b492745635c7a1549c764135e61deb65440cfa8b001fe25317e1452c9ee"
    family = "GoDDoSAgent"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-17 05:10:08"
  condition:
    hash.sha256(0, filesize) == "e1e82b492745635c7a1549c764135e61deb65440cfa8b001fe25317e1452c9ee"
}
```

### Sample 62: `ff68cb5aa08fb026`

| Field | Value |
|---|---|
| SHA-256 | `ff68cb5aa08fb026044e6132ba4627cfd12a2a72a0e14d039525f574e6ac432e` |
| Family label | `GoDDoSAgent` |
| File name | `android_arm64` |
| File type | `elf` |
| First seen | `2026-11-17 05:09:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9510828605b36d71c8fc2fb9efc9e4b5` |
| SHA-1 | `b27225454cf884058e1d561587e5063363176cb4` |
| SHA-256 | `ff68cb5aa08fb026044e6132ba4627cfd12a2a72a0e14d039525f574e6ac432e` |
| SHA3-384 | `c6a75550598ae325015933c2ef134b458a799c77ea66b86b54e850d4ae8090e6392d27d925af3c04013c5f6d3b48766e` |
| TLSH | `T117467D55FC1D7862E9CD7A311F365294B239BC485F82D3176A18BB3CAAF27448F23261` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:Q5w20bWLEr2CMLM5kfDSc7Hd3kSMlNH4QBVU85q5EL:J20bWLEy+5kfO0Hoo/EL` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_062_ff68cb5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff68cb5aa08fb026044e6132ba4627cfd12a2a72a0e14d039525f574e6ac432e"
    family = "GoDDoSAgent"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-11-17 05:09:05"
  condition:
    hash.sha256(0, filesize) == "ff68cb5aa08fb026044e6132ba4627cfd12a2a72a0e14d039525f574e6ac432e"
}
```

### Sample 63: `965c0185ee062c86`

| Field | Value |
|---|---|
| SHA-256 | `965c0185ee062c8688e5517e72e7849459e9e0f1880fcfd659e15536f23ff3d6` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 05:06:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6c27e8227d255808fe4e385bb6db672` |
| SHA-1 | `1dab48dc33d071fa36c94a09343e96b52135b428` |
| SHA-256 | `965c0185ee062c8688e5517e72e7849459e9e0f1880fcfd659e15536f23ff3d6` |
| SHA3-384 | `083435fdf29878104c8441bcf35c92dcce9f826c5cefa9fbe5596f9876b655bc3d010edd5fd269ee39b96db13d5cff21` |
| TLSH | `T1F0556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSn:SDjxB4m5n8XlaPWi+d+a4TjxQP4d` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_063_965c0185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965c0185ee062c8688e5517e72e7849459e9e0f1880fcfd659e15536f23ff3d6"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:06:22"
  condition:
    hash.sha256(0, filesize) == "965c0185ee062c8688e5517e72e7849459e9e0f1880fcfd659e15536f23ff3d6"
}
```

### Sample 64: `08093330c6b57283`

| Field | Value |
|---|---|
| SHA-256 | `08093330c6b57283fd60c90032aa33d396d19f07da802e7017af1e814845e1b6` |
| Family label | `GoDDoSAgent` |
| File name | `mipsle` |
| File type | `elf` |
| First seen | `2026-11-17 05:06:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79fb894877add18dbb1f2e329fd77050` |
| SHA-1 | `94194d875fa930755924e73b2f8b95d0c8c272ac` |
| SHA-256 | `08093330c6b57283fd60c90032aa33d396d19f07da802e7017af1e814845e1b6` |
| SHA3-384 | `d30ee61d517004c665b62022ff8044bba0ec74dd2f0734c1af915204075908c6f9ce4265aadaefb82a1a5090589f4b30` |
| TLSH | `T1D8660915ADC53BE7C81E4E3450EACA9216B05D144BF2876A51A4FBA9BC772387F07C8C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:xV6fvMbeDT+1LL2WGM0CtZdvPAqgBseN4wbeIyJTl5q5EY:HLyAIwXgEY` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_064_08093330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08093330c6b57283fd60c90032aa33d396d19f07da802e7017af1e814845e1b6"
    family = "GoDDoSAgent"
    file_name = "mipsle"
    file_type = "elf"
    first_seen = "2026-11-17 05:06:18"
  condition:
    hash.sha256(0, filesize) == "08093330c6b57283fd60c90032aa33d396d19f07da802e7017af1e814845e1b6"
}
```

### Sample 65: `ef0557f44c104b27`

| Field | Value |
|---|---|
| SHA-256 | `ef0557f44c104b27216dd677630320c367a6a7e511f1c2b65e75c0cf34861752` |
| Family label | `GoDDoSAgent` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-17 05:06:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, GoDDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62feab06a840b27ee950049d8ed9e681` |
| SHA-1 | `ab3c51eeae5c133df1af9c06aac242c7a13c0819` |
| SHA-256 | `ef0557f44c104b27216dd677630320c367a6a7e511f1c2b65e75c0cf34861752` |
| SHA3-384 | `79d77f4af4c3daae8f2a8f6b1b8b60cca2d441ed62d97ee82e8d63d41212de7e104ace9e2edddb1f56204c33d1609b84` |
| TLSH | `T198564A21EECB54F6E9030E3104BBA26F67315D098B24DBD7DB407E25FDBBA911932219` |
| TELFHASH | `t113e2feb3159da4ec67e0840797bf7520cbe6e07726d038f119f7b8c1aa72d43a626874` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:79pOgVqIDRoXzY2VPIWZu4/hN4g+HrwRdSdrSbqqUtheqRFmaKpBCQoh85WKg5Ez:791sIDR2Zu4/hWrwTSdrSBQ+CQoZKSEz` |

#### Technical Assessment

- The sample is tracked as `GoDDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GoDDoSAgent_065_ef0557f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef0557f44c104b27216dd677630320c367a6a7e511f1c2b65e75c0cf34861752"
    family = "GoDDoSAgent"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-17 05:06:11"
  condition:
    hash.sha256(0, filesize) == "ef0557f44c104b27216dd677630320c367a6a7e511f1c2b65e75c0cf34861752"
}
```

### Sample 66: `e40ae2794551e891`

| Field | Value |
|---|---|
| SHA-256 | `e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79` |
| Family label | `Mirai` |
| File name | `e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79` |
| File type | `elf` |
| First seen | `2026-11-17 04:36:18` |
| Reporter | `cybersecproject` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a57449bce3f09e9549eb14046ae5e3b` |
| SHA-1 | `a7eb25e658aa3efe832697c61672800e9e89c170` |
| SHA-256 | `e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79` |
| SHA3-384 | `3b3f2eea98f1085f901aaf36cd923cf3777de0eda7e32ab1eaa44c8ac284aa27ceb990a37886d2317f7d2d1ffdcc9eab` |
| TLSH | `T1DF82D000EE8043D5CDC17DBA1E8C9631A3BBA780F9A6E47153F9C5EAC736D51D972110` |
| SSDEEP | `384:GaiAgXHo4zkejSudOylMns6PmUipfaES8TR057HUkOeZHo0:GfI4zlmuIruFUZ+47HU49o0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_e40ae279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79"
    family = "Mirai"
    file_name = "e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79"
    file_type = "elf"
    first_seen = "2026-11-17 04:36:18"
  condition:
    hash.sha256(0, filesize) == "e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79"
}
```

### Sample 67: `e768f1d3e6388eb8`

| Field | Value |
|---|---|
| SHA-256 | `e768f1d3e6388eb82f4d7387850d0b07900c695d8b2ed8d05c42a275ef786c47` |
| Family label | `WARDENStealer` |
| File name | `e768f1d3e6388eb8.ps1` |
| File type | `ps1` |
| First seen | `2026-11-17 04:32:48` |
| Reporter | `Tuxxin` |
| Tags | `ps1, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16e7df5d95b43a664fdf56ec0e0f4814` |
| SHA-1 | `9988666cf070e5a56552d9c34a84f14eb64ce641` |
| SHA-256 | `e768f1d3e6388eb82f4d7387850d0b07900c695d8b2ed8d05c42a275ef786c47` |
| SHA3-384 | `298b2e4dc1d4e13500fd5137bfe00700d88d2305162bae686765d84f6ff733d0cc10d1093b1fb094e7f87ccab93eec40` |
| TLSH | `T1F45211615298B3E7825EF5A20F98DB6E432F03D1C2A4B5EC42D61CC45F12F4BDA6CCA1` |
| SSDEEP | `384:PFCf612j3PS1rK3huDixujjGJoyfBpnfoO:P4Nj3PS1rTDi0jKJoyppgO` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_067_e768f1d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e768f1d3e6388eb82f4d7387850d0b07900c695d8b2ed8d05c42a275ef786c47"
    family = "WARDENStealer"
    file_name = "e768f1d3e6388eb8.ps1"
    file_type = "ps1"
    first_seen = "2026-11-17 04:32:48"
  condition:
    hash.sha256(0, filesize) == "e768f1d3e6388eb82f4d7387850d0b07900c695d8b2ed8d05c42a275ef786c47"
}
```

### Sample 68: `aab6ded474ab1a87`

| Field | Value |
|---|---|
| SHA-256 | `aab6ded474ab1a87456df056d8fe2fb908e637fbcac0f878f68764b16b680c1d` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-17 04:24:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7e5678c272ae6de6779c8eeef272e58` |
| SHA-1 | `c9e159c121fec392191cc22484c2d128bd63ee5a` |
| SHA-256 | `aab6ded474ab1a87456df056d8fe2fb908e637fbcac0f878f68764b16b680c1d` |
| SHA3-384 | `a07d55970889e8c6914b85e65f813cabbc6b87d97fce334f94c5b6e155933b2ce5288b25ebf3744656408a21b6eb5144` |
| TLSH | `T133556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSu:SDjxB4m5n8XlaPWi+d+a4TjxQP4M` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_068_aab6ded4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aab6ded474ab1a87456df056d8fe2fb908e637fbcac0f878f68764b16b680c1d"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 04:24:05"
  condition:
    hash.sha256(0, filesize) == "aab6ded474ab1a87456df056d8fe2fb908e637fbcac0f878f68764b16b680c1d"
}
```

### Sample 69: `b063baa641bfcd4c`

| Field | Value |
|---|---|
| SHA-256 | `b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d` |
| Family label | `WARDENStealer` |
| File name | `b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d.exe` |
| File type | `exe` |
| First seen | `2026-11-17 03:51:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d14110bacaa9e4704800cd5512b0854a` |
| SHA-1 | `1bca727a920a13a48dcca0c6416e6af49f816a64` |
| SHA-256 | `b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d` |
| SHA3-384 | `3ca57c7bd16fbd494e7fd96dc8b9389a60768e2cc496fc5f9f4bd3bad17c4d4a536cfd58445a77e3c6c5047bcef0b871` |
| IMPHASH | `e6b01b58c198e47764bdd3132d7ebeea` |
| TLSH | `T1E805F192F78607D9E86EC93586126926D672BC211F1258FF2388538F4D367D0CF3AB19` |
| SSDEEP | `24576:bG+nAjn1izGwzp5IFaB15Hw6btymFkwm:bG+AjnYr9M7` |
| ICON-DHASH | `2254aaaa9a966806` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_069_b063baa6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d"
    family = "WARDENStealer"
    file_name = "b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d.exe"
    file_type = "exe"
    first_seen = "2026-11-17 03:51:41"
  condition:
    hash.sha256(0, filesize) == "b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d"
}
```

### Sample 70: `a273bf60739c53c5`

| Field | Value |
|---|---|
| SHA-256 | `a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e` |
| Family label | `Mirai` |
| File name | `a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e.elf` |
| File type | `elf` |
| First seen | `2026-11-17 03:16:41` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `678c777e3a75de1cfcacd2c4bc96c77a` |
| SHA-1 | `2d9afb0ffc8b74885a6fa05169cc6ea5426a7089` |
| SHA-256 | `a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e` |
| SHA3-384 | `f9f1af0b117d7f9aaa95ad96a89aed170209d436f9ea5fb75e711f810d77bc270d8ad5ebd4fcac66fc6b0912a47f7192` |
| TLSH | `T170C40966B950D722C6C426B6BA5DC2BC37131FB4D5FA3002ED107F2826BA91E4F36B51` |
| SSDEEP | `12288:0AJdiw59mIjIWg3SomEb65oDeh5n5kANRlKlXsqQS+uzo/ctGnbW0ajwCL:ZP90WSSEeX9/cEnbW0ajw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_a273bf60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e"
    family = "Mirai"
    file_name = "a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e.elf"
    file_type = "elf"
    first_seen = "2026-11-17 03:16:41"
  condition:
    hash.sha256(0, filesize) == "a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e"
}
```

### Sample 71: `2e6fa3d0b90d18da`

| Field | Value |
|---|---|
| SHA-256 | `2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3` |
| Family label | `unknown` |
| File name | `2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3.bin` |
| File type | `js` |
| First seen | `2026-11-17 02:01:40` |
| Reporter | `Tuxxin` |
| Tags | `js, script` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79fd49643ae51a7394bdf7b91a6bcec2` |
| SHA-1 | `395ffdd832a768877fa9509a34d0e8320bda91e2` |
| SHA-256 | `2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3` |
| SHA3-384 | `ae9f4c3880cc2be19b4afd7fb189bb3cae78c2e0a249c42ad9428c0ad6cdb8741e571d6958f34f03b7dc08b26d1b506e` |
| TLSH | `T13D338EEEB38016DC48B4CCE7A532066D63F8DB076C14326DB38BAE55F45F71199A1728` |
| SSDEEP | `768:gM3zThFJqWx7EyYPWtBBYBS/8XuxzddhycF45cNR83V4VJlCB39E/ynXAae9LMl:Hz9qQEyruiDyTcNaKAdX/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_2e6fa3d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3"
    family = "unknown"
    file_name = "2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3.bin"
    file_type = "js"
    first_seen = "2026-11-17 02:01:40"
  condition:
    hash.sha256(0, filesize) == "2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3"
}
```

### Sample 72: `86f089f0d452efec`

| Field | Value |
|---|---|
| SHA-256 | `86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e` |
| Family label | `unknown` |
| File name | `86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e.bin` |
| File type | `js` |
| First seen | `2026-11-17 01:56:42` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd3dae459dc045754d2e333dffdce68c` |
| SHA-1 | `dcf3a39d00f03a80f718cc21e768496c6accb1cf` |
| SHA-256 | `86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e` |
| SHA3-384 | `e2b5e8bb3eb591595f97a8eab5289f927cf1ecef7361f55d59d62beaca3b481670ee1b0e7f71e747070d76e4fc0dc30e` |
| TLSH | `T151A309DDB3D1B06257BB30BD006F540FB236195D284D8850F129E8E9BC74A49A277FAD` |
| SSDEEP | `1536:Z4mCgi8DyCuXXFiJ+L0kJQsJVPEKLQRZdC/RAfDknv+p0WzH/Io9Z7qABZnu0sFV:ZGsKXAI2p0WP9bDrstfaar` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_86f089f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e"
    family = "unknown"
    file_name = "86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e.bin"
    file_type = "js"
    first_seen = "2026-11-17 01:56:42"
  condition:
    hash.sha256(0, filesize) == "86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e"
}
```

### Sample 73: `3fb3930c3097a988`

| Field | Value |
|---|---|
| SHA-256 | `3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752` |
| Family label | `Snowlight` |
| File name | `3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:48:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4eef59090e251f9fbca7e4ed5332387b` |
| SHA-1 | `3ab41f8f73742112e9a2ad8308694f2955767e5b` |
| SHA-256 | `3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752` |
| SHA3-384 | `192d5415edebaa8e93ad2237163b0c45be0793b7980ebea240f941f9c5bbf96181c6fb89e11b973ca7dee2229991c148` |
| TLSH | `T136220D27F3D4DDFFC8AA5335899307713223C83ADB828383691C56593F9A29D1E65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMOXmx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7ZeX4+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_073_3fb3930c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752"
    family = "Snowlight"
    file_name = "3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:48:08"
  condition:
    hash.sha256(0, filesize) == "3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752"
}
```

### Sample 74: `9f32835cf0a5fe62`

| Field | Value |
|---|---|
| SHA-256 | `9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0` |
| Family label | `unknown` |
| File name | `9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:46:50` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a08469df4b66bc14b64da2c249bd68a6` |
| SHA-1 | `05adbe45f3a23c5ecf8ad97f9dce2e7cffddbb67` |
| SHA-256 | `9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0` |
| SHA3-384 | `28e3feac3c58b4e3ffddf00036f0e6115e64e872bc24be0b59ba957bd2b24b00f21892fed3314984c5d07ed7c99437ef` |
| TLSH | `T157E12382B9D6CE3BCCA9627A1673C6203372C951AB439B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScszLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv2g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_9f32835c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0"
    family = "unknown"
    file_name = "9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:46:50"
  condition:
    hash.sha256(0, filesize) == "9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0"
}
```

### Sample 75: `d7a27896b2627f73`

| Field | Value |
|---|---|
| SHA-256 | `d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3` |
| Family label | `Snowlight` |
| File name | `d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:46:45` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3225d34ec83b742db7b4dce089f64e1e` |
| SHA-1 | `706b2a27df6adc15b2c0156104d32a6dbe2d0e6d` |
| SHA-256 | `d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3` |
| SHA3-384 | `c7423299e050908ef02f42764997da2219257fe5749482b72230f0793f075ed663e4e91b8b73ba9672170e794ae71cbe` |
| TLSH | `T172125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9VwNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpVwdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_075_d7a27896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3"
    family = "Snowlight"
    file_name = "d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:46:45"
  condition:
    hash.sha256(0, filesize) == "d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3"
}
```

### Sample 76: `b7444db17b2496a2`

| Field | Value |
|---|---|
| SHA-256 | `b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb` |
| Family label | `Snowlight` |
| File name | `b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:41:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `099b514366c10974fa7aebf2256c777b` |
| SHA-1 | `e3c62c22584a2700fe9f1529a5dd57f84cd73451` |
| SHA-256 | `b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb` |
| SHA3-384 | `00057da3eb977669bd294919316755a5e1d35a052c723291c36e1b3abd10e3da1b43e32dddcf61659d7a2ae307ee23f4` |
| TLSH | `T1C5E17217E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3vJheuhicE5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb/JhAjZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_076_b7444db1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb"
    family = "Snowlight"
    file_name = "b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:41:44"
  condition:
    hash.sha256(0, filesize) == "b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb"
}
```

### Sample 77: `e6b5657e701f1c1a`

| Field | Value |
|---|---|
| SHA-256 | `e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c` |
| Family label | `unknown` |
| File name | `e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c.exe` |
| File type | `exe` |
| First seen | `2026-11-17 01:39:08` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f98e99d00439416768777eac252f8ce5` |
| SHA-1 | `423423ac1e26c81311fb1c0a2f2aa7f9cd25f504` |
| SHA-256 | `e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c` |
| SHA3-384 | `2f861f69e878a1e3b7d57dff446b18e4f5f0d1b45f0488be50ee8814d7ce3810d7e22c4570f4a60597b3673f99bb379c` |
| IMPHASH | `c5e8d6ea417feddb4c4dbaa3c79784dd` |
| TLSH | `T136C3022CA7B78C7AF8DB573CCA4ADB329F645C41603093AD5156743FBE6C00129A3B5A` |
| SSDEEP | `3072:19fKfHLqc5Hc5uN7V+eOhAE6bYcpEqbcC:1BKfGc585uN7V+eOhAT0cKq` |
| ICON-DHASH | `6562e6d6d6d0d099` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_e6b5657e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c"
    family = "unknown"
    file_name = "e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:39:08"
  condition:
    hash.sha256(0, filesize) == "e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c"
}
```

### Sample 78: `dbf6597ec246d523`

| Field | Value |
|---|---|
| SHA-256 | `dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00` |
| Family label | `Snowlight` |
| File name | `dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:36:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc54f64f5be5dead3e1f0f24a15a5a7b` |
| SHA-1 | `92e62a70a4681c458de2b2cbb99ce1ef49b327d5` |
| SHA-256 | `dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00` |
| SHA3-384 | `100c1b11527be0084dc6d66dc90a6f8b45419c99db2fedd195479d2ef51e025db1a9f1f4926a1c84538be9305c5938ce` |
| TLSH | `T1E4E17217E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3GJheuhicX5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb2JhAEZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_078_dbf6597e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00"
    family = "Snowlight"
    file_name = "dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:36:56"
  condition:
    hash.sha256(0, filesize) == "dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00"
}
```

### Sample 79: `95a29b2d29318afa`

| Field | Value |
|---|---|
| SHA-256 | `95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f` |
| Family label | `unknown` |
| File name | `95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f.exe` |
| File type | `exe` |
| First seen | `2026-11-17 01:36:51` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0773b41b7cc39ba889a275c77c3cfa5f` |
| SHA-1 | `1330451d9af1c370698005a4494bfa613283368a` |
| SHA-256 | `95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f` |
| SHA3-384 | `3b6de4261e4066ee87380f03908c953c2213d5bcb8bc6c66d0eb46113509fd117d3676d89c7cdba7d01fb2cedae991e8` |
| IMPHASH | `7182b1ea6f92adbf459a2c65d8d4dd9e` |
| TLSH | `T108C3275AB2E01198EBF581F6D5920746EB7074311B15A3DB6B7863B31B2B8C58F3D3A0` |
| SSDEEP | `3072:EV3J6kkt5h1X+HqTi0BW69hd1MMdxPe9N9uA0/+hL9TBfnPT4:pt5hBPi0BW69hd1MMdxPe9N9uA069TB8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_95a29b2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f"
    family = "unknown"
    file_name = "95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:36:51"
  condition:
    hash.sha256(0, filesize) == "95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f"
}
```

### Sample 80: `de319ee2e3983ff0`

| Field | Value |
|---|---|
| SHA-256 | `de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a` |
| Family label | `Snowlight` |
| File name | `de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:34:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `124159f0c78031ad7d96fa35a7e8bfdb` |
| SHA-1 | `67a99e6edfb8f0654734a9b5a4595ea75890ebcd` |
| SHA-256 | `de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a` |
| SHA3-384 | `5c578756dfc88739616b4491b252df9302ff50959cdacbf30b92afc7e32580feb8413515211484b83df3c8317d061e73` |
| TLSH | `T134123047A2D0CE3FC8D953384467122472B794BEDF629723064825B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6GH5ML09V1J9G8Yma+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHdZMWT1YmnhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_080_de319ee2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a"
    family = "Snowlight"
    file_name = "de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:34:19"
  condition:
    hash.sha256(0, filesize) == "de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a"
}
```

### Sample 81: `62d3e930de6ffb7d`

| Field | Value |
|---|---|
| SHA-256 | `62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06` |
| Family label | `Snowlight` |
| File name | `62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:34:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `022624415575b53de45ee428838747da` |
| SHA-1 | `d9e7ec176a75697f7b426288f1ca3e25d1e8e550` |
| SHA-256 | `62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06` |
| SHA3-384 | `cbab87afc6e8eb7d127ed9958ea8d4aaf57e7926487bbd0e345e259224426561d8406da0d1b8c3b61feda586632a5198` |
| TLSH | `T1A8E15207E2D5CD72D8CD133846935749213AC86EAB83EF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFjd146ywz7cSym4S2ofahbpZiQ:fsue7cIJ9Fym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_081_62d3e930
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06"
    family = "Snowlight"
    file_name = "62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:34:14"
  condition:
    hash.sha256(0, filesize) == "62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06"
}
```

### Sample 82: `c9ae60b2d7d9aef3`

| Field | Value |
|---|---|
| SHA-256 | `c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b` |
| Family label | `unknown` |
| File name | `c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b.bin` |
| File type | `macho` |
| First seen | `2026-11-17 01:33:32` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24131c6a344d7c69448ba9d08c7820f2` |
| SHA-1 | `6d42ab944075cf889759c6c0e19122907709ea3a` |
| SHA-256 | `c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b` |
| SHA3-384 | `dd9c39911d060beb9a1d895f11d5ea4141c3e1404b933f1f11fab24cca63cef727a40f9a2dd912608818425f5d763f24` |
| TLSH | `T1A4F25F239B1C1A61C05C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRMrPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJf9Dlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_c9ae60b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b"
    family = "unknown"
    file_name = "c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b.bin"
    file_type = "macho"
    first_seen = "2026-11-17 01:33:32"
  condition:
    hash.sha256(0, filesize) == "c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b"
}
```

### Sample 83: `a32fccd1a53a411f`

| Field | Value |
|---|---|
| SHA-256 | `a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1` |
| Family label | `Snowlight` |
| File name | `a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:33:27` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3605ec65ccc38ef43f9154aa88745e13` |
| SHA-1 | `a2cd6e90c5b6032d3b6f5f52d2f5e14e28c905d4` |
| SHA-256 | `a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1` |
| SHA3-384 | `39e42ff1d56d476c2c351615daf8e4f21e9a0a794f230af55c0a9aaad073596dfb7c7934b5a42dd7fa55678a48ac344c` |
| TLSH | `T18EE17117E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3jJheuhij5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbzJhAVZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_083_a32fccd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1"
    family = "Snowlight"
    file_name = "a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:33:27"
  condition:
    hash.sha256(0, filesize) == "a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1"
}
```

### Sample 84: `b78deb91085bfdc2`

| Field | Value |
|---|---|
| SHA-256 | `b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c` |
| Family label | `Snowlight` |
| File name | `b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:33:22` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa92086e2c02af1a24334294ad2857cc` |
| SHA-1 | `a2f99dfdd72c9d62504a735572a99275a0f0b9a9` |
| SHA-256 | `b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c` |
| SHA3-384 | `2c143970e2ae8e2a093c49e3726cff96b0943a88ff4f1558203cf090ce5b560f97026fe004a6c50e5509589acff6711b` |
| TLSH | `T13BE18217E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3/Jheuhii5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbvJhAcZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_084_b78deb91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c"
    family = "Snowlight"
    file_name = "b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:33:22"
  condition:
    hash.sha256(0, filesize) == "b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c"
}
```

### Sample 85: `64bbf57617cf414f`

| Field | Value |
|---|---|
| SHA-256 | `64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3` |
| Family label | `unknown` |
| File name | `64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3.exe` |
| File type | `exe` |
| First seen | `2026-11-17 01:33:18` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42ac521ac3369dc5abb99a81fa30fb6c` |
| SHA-1 | `e8234e7025281f629fac0e45266eda10699e0075` |
| SHA-256 | `64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3` |
| SHA3-384 | `97b3f120edb2cf96e385dd20acec88a15c41999501c767ea23b9d73f18a21caaac5578357e2722af7533b53ecb65614a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T177254D5537B54952F1F65F3820BCB203AA68F4F7492BC71E45A1C09DCA12B17DAB8F22` |
| SSDEEP | `12288:7ftCp9Y6659p6vpYBoGK9rL66P659p6M6:YjYZQvpYBo1JZSQj` |
| ICON-DHASH | `30e09432322a9ce0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_64bbf576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3"
    family = "unknown"
    file_name = "64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:33:18"
  condition:
    hash.sha256(0, filesize) == "64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3"
}
```

### Sample 86: `dc0092c25a090b3b`

| Field | Value |
|---|---|
| SHA-256 | `dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9` |
| Family label | `WARDENStealer` |
| File name | `dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9.exe` |
| File type | `exe` |
| First seen | `2026-11-17 01:33:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27b140288861ce4a02c92d1804707e21` |
| SHA-1 | `a6788d685820a747ac7ec906558365775c912e77` |
| SHA-256 | `dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9` |
| SHA3-384 | `83c0374091d99a8f59d7de5117fe6c4e61276fc74ef637c465bb982db6345495d7815a982bff5f546e111472cfb10e61` |
| IMPHASH | `6514e75dacfccf5a57ec97d220195b42` |
| TLSH | `T1F605F161F66513D9E83AC67586AB9E14C62578120F2118FF5394130E0F367E2EF3BB29` |
| SSDEEP | `24576:D6GyewSeXwotoB36QWrQ3SHcVq+BZneT:D6XtxgoFr+3` |
| ICON-DHASH | `2c0cb26161b21c30` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_086_dc0092c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9"
    family = "WARDENStealer"
    file_name = "dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:33:13"
  condition:
    hash.sha256(0, filesize) == "dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9"
}
```

### Sample 87: `2e620e14d1d04df5`

| Field | Value |
|---|---|
| SHA-256 | `2e620e14d1d04df59b09b27a9ade51fdc3977dc9f6cda902349b12ebcdb81a9a` |
| Family label | `Vidar` |
| File name | `5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d.exe` |
| File type | `exe` |
| First seen | `2026-11-17 01:32:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `119688856192211a8232526954c68cf5` |
| SHA-1 | `964d618b250f20bdbd0aebf1febe152557b7f2a1` |
| SHA-256 | `2e620e14d1d04df59b09b27a9ade51fdc3977dc9f6cda902349b12ebcdb81a9a` |
| SHA3-384 | `43e484d39e9c7894521789f3045fa25bc927811af4f908dcda6e7d40ac64593d9b9345dfaeccd9f3fb1355961610d632` |
| TLSH | `T1A3157C10B2A352D6E036553ED1CEBA17B9B2BC155AE4DF7B1A408FC23AD3220275B357` |
| SSDEEP | `12288:0TL2QwIcXrNP76BmenSkQJ28uCpkOjMjjKGfaDmOaB0XRF:w8IcSHl8uU5wpQmOm0hF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_087_2e620e14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e620e14d1d04df59b09b27a9ade51fdc3977dc9f6cda902349b12ebcdb81a9a"
    family = "Vidar"
    file_name = "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:32:23"
  condition:
    hash.sha256(0, filesize) == "2e620e14d1d04df59b09b27a9ade51fdc3977dc9f6cda902349b12ebcdb81a9a"
}
```

### Sample 88: `5a198f7571caa1fc`

| Field | Value |
|---|---|
| SHA-256 | `5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d` |
| Family label | `Vidar` |
| File name | `5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d.exe` |
| File type | `exe` |
| First seen | `2026-11-17 01:32:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `110d09c9dc1a00b78de06d30f12188f1` |
| SHA-1 | `519b7b1495d17fcb551572e9767ade8ba58d0718` |
| SHA-256 | `5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d` |
| SHA3-384 | `d6b82e8c8ed2feb4c59fc38772cc0c503af48f9d8b3d45bd855b040fb1cb4d36e688f94b83f14e7d4c75478bbf915396` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E5642329D6071082F7C6F77BEB92D007810B242B429E6BA7C911C7DDF4B69D1FC91992` |
| SSDEEP | `6144:JdXcBAWDC30t07wA81TXwsd1hVYUR2Z20L5Ui3XxLYPIE3y4nvZIflk5LAU:LclZfA8FX/1nRynyi3XKgE3zvIlk5LX` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_088_5a198f75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d"
    family = "Vidar"
    file_name = "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:32:10"
  condition:
    hash.sha256(0, filesize) == "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d"
}
```

### Sample 89: `81e604f67abbd8bf`

| Field | Value |
|---|---|
| SHA-256 | `81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4` |
| Family label | `Snowlight` |
| File name | `81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:32:05` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `113866dfbb8139d884103dc264139ce9` |
| SHA-1 | `13dbf0e6332ff60373699ef169a58d4b9fe509af` |
| SHA-256 | `81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4` |
| SHA3-384 | `64a749c878eb9afd1e8ae6efcd0f223a65e5f55f42ecba980159db0abf5da8f97774b32b150581350ba616b64315894a` |
| TLSH | `T16C124047A2D0CE3FC8D953384867122472B794BEDF629713064815B63F423E81E2EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6cH5ML09V1J9G8Ym1+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHHZMWT1YmohrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_089_81e604f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4"
    family = "Snowlight"
    file_name = "81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:32:05"
  condition:
    hash.sha256(0, filesize) == "81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4"
}
```

### Sample 90: `9426f0a696becbcd`

| Field | Value |
|---|---|
| SHA-256 | `9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750` |
| Family label | `unknown` |
| File name | `9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:32:01` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b07cd79bd53f97dc5711f4e032eb70fe` |
| SHA-1 | `4f30f7d716757f8cfd0b0dcd9bada5ae6081e228` |
| SHA-256 | `9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750` |
| SHA3-384 | `027bf50517544ac420a1349b0b8a636f83e97d34ada7e440a08e6d8e2c45a626e8f852f611f541fc500f708a2c101f2f` |
| TLSH | `T19022ED17F3E5DDFFC8AA577409A712703223C836DB428783680C46547FAB29E6EA5744` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMOUtsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dxUtsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_9426f0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750"
    family = "unknown"
    file_name = "9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:32:01"
  condition:
    hash.sha256(0, filesize) == "9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750"
}
```

### Sample 91: `f3e135a02c6d939a`

| Field | Value |
|---|---|
| SHA-256 | `f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c` |
| Family label | `Snowlight` |
| File name | `f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:31:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d9fedf42f9359bff97056ac64153eab` |
| SHA-1 | `a69f780c9a77ba8fe2d0a3deb5b737775408cbf3` |
| SHA-256 | `f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c` |
| SHA3-384 | `c6cf8ffb0479227610cf5dd2a6e9772dee18dce58fe60c6a34b070f9681b6497cb32131ac2bbc5217f2c81e272f13a94` |
| TLSH | `T181E15207E2D5CE72D8CD133846935749213AC86EAB83EF03650C599AEE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccF7146Iwz7cSym4S2ofahbpZiQ:fsue7c2JjFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_091_f3e135a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c"
    family = "Snowlight"
    file_name = "f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:31:56"
  condition:
    hash.sha256(0, filesize) == "f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c"
}
```

### Sample 92: `1b9b97943c718b8a`

| Field | Value |
|---|---|
| SHA-256 | `1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652` |
| Family label | `unknown` |
| File name | `1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:31:52` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `344cdc48329bc2ca33ebcca384a3a1e9` |
| SHA-1 | `1349391fc15d1493c1f878083475887170ad2788` |
| SHA-256 | `1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652` |
| SHA3-384 | `8c6ea527cd37e14b945843dde03ae154e3e17e895dffae21fdaf18a69b8137e8ba83826ba1393f0cf679ba930cfb1c02` |
| TLSH | `T11622ED17F3E5DDFFC8AA577409A713703223C836DB428783680C46547FAB29E6EA5644` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:B74+elu6BS8TddeqMO1tsVVQEnqN42mqMf7q1aiBcNQ2yMBxdxefnbuP:Bso0dx1tsVif42QfagQ23jdE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_1b9b9794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652"
    family = "unknown"
    file_name = "1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:31:52"
  condition:
    hash.sha256(0, filesize) == "1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652"
}
```

### Sample 93: `4e303839820a9fbd`

| Field | Value |
|---|---|
| SHA-256 | `4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899` |
| Family label | `Snowlight` |
| File name | `4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:29:19` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9e7a2983c32e8e3f36eed16ecf87f2c` |
| SHA-1 | `82ddf12e0abc904caa9c4c96d2a258a49bfb879b` |
| SHA-256 | `4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899` |
| SHA3-384 | `add1f5131c4716c49604705f68efa2c7bf8f79b3f203d4d0acdd64028ca5e38791e11972a377e6af689f5eea522e5897` |
| TLSH | `T102E17117E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3PJheuhiK5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb/JhAEZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_093_4e303839
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899"
    family = "Snowlight"
    file_name = "4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:19"
  condition:
    hash.sha256(0, filesize) == "4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899"
}
```

### Sample 94: `4eb9db275ded302e`

| Field | Value |
|---|---|
| SHA-256 | `4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9` |
| Family label | `Snowlight` |
| File name | `4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:29:15` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7ffad6e804c33e56dec59af8e19b622` |
| SHA-1 | `f0c0bf284fe3b9d48e61d45e189878a4e43cbb13` |
| SHA-256 | `4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9` |
| SHA3-384 | `d3636459f69d0271d9b3a6a30b84df81cbaafa645ee6eef966c6d30f14d90ffdcbb662a4cea3b85338c95f2fed56e5a6` |
| TLSH | `T1D9123047A2D0CE3FC8D953384467122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6VH5ML09V1J9G8YmJx+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHKZMWT1YmmhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_094_4eb9db27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9"
    family = "Snowlight"
    file_name = "4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:15"
  condition:
    hash.sha256(0, filesize) == "4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9"
}
```

### Sample 95: `272614fd09723ffa`

| Field | Value |
|---|---|
| SHA-256 | `272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06` |
| Family label | `Snowlight` |
| File name | `272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:29:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c62c6cffaef5145975af2b8ba7dcda55` |
| SHA-1 | `f3e17411669587070b313d8299ef38ed51ddfe20` |
| SHA-256 | `272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06` |
| SHA3-384 | `f76eaa471d241893a18a9fc51380c08fbf36431ee23d7a5175933342e2bafd9b910d8d0ab030d24d804139861513264f` |
| TLSH | `T184220E27F3D4DDFFC8AA5335899307713223C83ADB828383691C56593F9A29D1D65A84` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:M7obxnzM5qu7ZVqMO5dx+sAz9lmWIy/q1f7q1aiBINQ2yMBxTlnbuXI:M0xi7Ze5+sAz9sg+fagQ23jTl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_095_272614fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06"
    family = "Snowlight"
    file_name = "272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:11"
  condition:
    hash.sha256(0, filesize) == "272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06"
}
```

### Sample 96: `010930eacb72c660`

| Field | Value |
|---|---|
| SHA-256 | `010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2` |
| Family label | `Snowlight` |
| File name | `010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:29:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3763b17a808bbf85aa818d28d0782293` |
| SHA-1 | `40db4d41e4401fe64b4158829963cb74b28b3ac6` |
| SHA-256 | `010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2` |
| SHA3-384 | `f39187de571fd1d748eec10749b92cde90b2e0b25e8215a48a7ab3f415c5a79c54cb46f8ebd53b5784fd1c4869f8c12a` |
| TLSH | `T1DBE15207E2D5CD72D8CD133846935749213AC86EAB83AF03650C5999EE43BDC7A63752` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFp146zwz7cSym4S2ofahbpZiQ:fsue7ccJMFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_096_010930ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2"
    family = "Snowlight"
    file_name = "010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:07"
  condition:
    hash.sha256(0, filesize) == "010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2"
}
```

### Sample 97: `55c06886505f9111`

| Field | Value |
|---|---|
| SHA-256 | `55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb` |
| Family label | `Snowlight` |
| File name | `55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:29:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99a3e000128212714dd0b00499cefd07` |
| SHA-1 | `0721b7fc4c709be2eab8d079eb02175499649a8f` |
| SHA-256 | `55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb` |
| SHA3-384 | `26baa40046a30c91598bbd297cdf40a839d417e9682424c3c977a92e0ed8f70b53e3324309ba8e22c3355982721c59c3` |
| TLSH | `T133123047A2D0CE3FC8D9533844A7122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6WH5ML09V1J9G8Ymk+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHJZMWT1YmFhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_097_55c06886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb"
    family = "Snowlight"
    file_name = "55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:03"
  condition:
    hash.sha256(0, filesize) == "55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb"
}
```

### Sample 98: `51b32c91938a3eb2`

| Field | Value |
|---|---|
| SHA-256 | `51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90` |
| Family label | `unknown` |
| File name | `51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:28:05` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d18a37ab4f955762a91ebda80ef1e07` |
| SHA-1 | `931aee3ddaecc93d645e7661f4c8e828c18a2288` |
| SHA-256 | `51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90` |
| SHA3-384 | `4f73a3bedddada9d3213982d8a2bdaa8c2755eaf98efdfc105012a6cd5ab2f75c96c945fa26bc87add8737e7871061ba` |
| TLSH | `T155E14482BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AECAD76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsmLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv7g/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_51b32c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90"
    family = "unknown"
    file_name = "51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:28:05"
  condition:
    hash.sha256(0, filesize) == "51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90"
}
```

### Sample 99: `4ab97ad29c6869eb`

| Field | Value |
|---|---|
| SHA-256 | `4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069` |
| Family label | `Snowlight` |
| File name | `4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069.elf` |
| File type | `elf` |
| First seen | `2026-11-17 01:28:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32c651faba17f502a697f7b13f11443b` |
| SHA-1 | `5b397b46731a68ed7d99be534a9dccd770089585` |
| SHA-256 | `4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069` |
| SHA3-384 | `c11c1e4b4b2fdf4224f0a0ad1a56d2849323ee7ab3d03c7f0dccec651e2fd466561d30c9bf107498df30e657a6e967aa` |
| TLSH | `T14AF14256BAEBCD73CCAD233A07678714337588D2AB42AB13610C08752D835ECAD76AD1` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:yE/Fxnz9kUHnXE8DtgWC4OUoKKoMEfO9Of721a5BI31BBghcxgPaFq1sqll:r/3R/7Y4OmO0O9OfN+1B6hcPoLl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_099_4ab97ad2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069"
    family = "Snowlight"
    file_name = "4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:28:01"
  condition:
    hash.sha256(0, filesize) == "4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069"
}
```

### Sample 100: `f5a4e6789142e111`

| Field | Value |
|---|---|
| SHA-256 | `f5a4e6789142e111ae9aa35d5f8ffa7f8c38b473b8dbc0d37341c300de641e81` |
| Family label | `unknown` |
| File name | `f5a4e6789142e111.js` |
| File type | `js` |
| First seen | `2026-11-17 01:27:40` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b789ac1957652ef2ccd4f60bcc916eac` |
| SHA-1 | `2625a253c44ae952c16f0b99e3ba907584460af0` |
| SHA-256 | `f5a4e6789142e111ae9aa35d5f8ffa7f8c38b473b8dbc0d37341c300de641e81` |
| SHA3-384 | `89c7d2c6ca594784a0a4fff4732ae4ff41f3ba241aae6a661453e86e1b780fcefda59b43411cad5c853c54ebb00fa479` |
| TLSH | `T1D491B6DF3445145A807B233897BF8A4FF231856B2546C969BE9C89203F708179661FDC` |
| SSDEEP | `48:EKmrLzyc5EjvT/sZu60oQP8xvlhimBheM3IeOPcAP1Gql9tuFOiGm0rKsYQzB3:3yv8/tJkYmBAM3xbiGqFEVsYAB3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_f5a4e678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5a4e6789142e111ae9aa35d5f8ffa7f8c38b473b8dbc0d37341c300de641e81"
    family = "unknown"
    file_name = "f5a4e6789142e111.js"
    file_type = "js"
    first_seen = "2026-11-17 01:27:40"
  condition:
    hash.sha256(0, filesize) == "f5a4e6789142e111ae9aa35d5f8ffa7f8c38b473b8dbc0d37341c300de641e81"
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
 * Generated: 2026-11-17T08:05:18.435637+00:00
 */

rule MalwareBazaar_unknown_001_07574a5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07574a5dff71c83a43b2d087a1dca54bf18b8c4e74bdddbaf4ea9ce58c2d0367"
    family = "unknown"
    file_name = "24c6ad1e70e8bafa00ec2d02b4cfdc64.exe"
    file_type = "exe"
    first_seen = "2026-11-17 08:02:32"
  condition:
    hash.sha256(0, filesize) == "07574a5dff71c83a43b2d087a1dca54bf18b8c4e74bdddbaf4ea9ce58c2d0367"
}

rule MalwareBazaar_unknown_002_0fbd4fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fbd4fe6afb5f555fea9d09cf376a2c2e61b0e77a8ee3ab2f7eedc70f47765f8"
    family = "unknown"
    file_name = "RFQspecificationslistandcompanyprofilepresentation.vbe"
    file_type = "vbe"
    first_seen = "2026-11-17 08:01:51"
  condition:
    hash.sha256(0, filesize) == "0fbd4fe6afb5f555fea9d09cf376a2c2e61b0e77a8ee3ab2f7eedc70f47765f8"
}

rule MalwareBazaar_unknown_003_af44015b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af44015b97c6d65ed6d64f8e865d133370e63f00a66974cb1340b67478275b36"
    family = "unknown"
    file_name = "17116384.bat"
    file_type = "bat"
    first_seen = "2026-11-17 08:01:46"
  condition:
    hash.sha256(0, filesize) == "af44015b97c6d65ed6d64f8e865d133370e63f00a66974cb1340b67478275b36"
}

rule MalwareBazaar_unknown_004_1a4ac0d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a4ac0d2729d21fda92d2fe099f0b4956c006a5a3a6db434605417dd614c6ac9"
    family = "unknown"
    file_name = "PurchaseOrder.js"
    file_type = "js"
    first_seen = "2026-11-17 08:01:43"
  condition:
    hash.sha256(0, filesize) == "1a4ac0d2729d21fda92d2fe099f0b4956c006a5a3a6db434605417dd614c6ac9"
}

rule MalwareBazaar_unknown_005_3a20e1d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a20e1d037cb3c043799fea6fb2c954911fe75ba4568f365e51c5bd178ce6a74"
    family = "unknown"
    file_name = "2026_November_December_paymentplan_xls.js"
    file_type = "js"
    first_seen = "2026-11-17 08:01:40"
  condition:
    hash.sha256(0, filesize) == "3a20e1d037cb3c043799fea6fb2c954911fe75ba4568f365e51c5bd178ce6a74"
}

rule MalwareBazaar_unknown_006_617a9a4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "617a9a4afa9ef4ad9c24f77a04ad6c2ba5016921dc574bae090306f7d34f118a"
    family = "unknown"
    file_name = "RFQ-SM657430043652913-20261117.js"
    file_type = "js"
    first_seen = "2026-11-17 08:01:36"
  condition:
    hash.sha256(0, filesize) == "617a9a4afa9ef4ad9c24f77a04ad6c2ba5016921dc574bae090306f7d34f118a"
}

rule MalwareBazaar_Prometei_007_82a9eded
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82a9eded67865eb219a2ec4b0d4b278e0e0929e9f2ac0fee5205376ad55ae6b8"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 08:00:05"
  condition:
    hash.sha256(0, filesize) == "82a9eded67865eb219a2ec4b0d4b278e0e0929e9f2ac0fee5205376ad55ae6b8"
}

rule MalwareBazaar_PureLogsStealer_008_6fb751a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fb751a45e304ba07570f9768a34b549a43c164b35af9bc7d9355c1fb1021c53"
    family = "PureLogsStealer"
    file_name = "RFQ Order_26012-17-11-26.js"
    file_type = "js"
    first_seen = "2026-11-17 07:59:41"
  condition:
    hash.sha256(0, filesize) == "6fb751a45e304ba07570f9768a34b549a43c164b35af9bc7d9355c1fb1021c53"
}

rule MalwareBazaar_Mirai_009_0c0342c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0342c4f3d1a976e3344d2f1508ea298fc8e7c65a513d080b17eca76f3315ef"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-17 07:58:05"
  condition:
    hash.sha256(0, filesize) == "0c0342c4f3d1a976e3344d2f1508ea298fc8e7c65a513d080b17eca76f3315ef"
}

rule MalwareBazaar_Formbook_010_a4ee2564
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4ee256449363cb6b201b46b02fd60c96580dc3b2a86cc940b9c38c6bf293be3"
    family = "Formbook"
    file_name = "INVIN7016D003k.JS"
    file_type = "js"
    first_seen = "2026-11-17 07:52:16"
  condition:
    hash.sha256(0, filesize) == "a4ee256449363cb6b201b46b02fd60c96580dc3b2a86cc940b9c38c6bf293be3"
}

rule MalwareBazaar_AgentTesla_011_4517429a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4517429af4bd2cebf542aa7cd708aab90b8a23ff9ac9fe816274687926d4e6e7"
    family = "AgentTesla"
    file_name = "md5001001042242.tmp"
    file_type = "js"
    first_seen = "2026-11-17 07:52:11"
  condition:
    hash.sha256(0, filesize) == "4517429af4bd2cebf542aa7cd708aab90b8a23ff9ac9fe816274687926d4e6e7"
}

rule MalwareBazaar_unknown_012_f4f1db3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f1db3d4a95b59e97d1578118eabdf6d2cb23b2ae5642302d8da92075ebc491"
    family = "unknown"
    file_name = "md5001000538870.tmp"
    file_type = "js"
    first_seen = "2026-11-17 07:51:53"
  condition:
    hash.sha256(0, filesize) == "f4f1db3d4a95b59e97d1578118eabdf6d2cb23b2ae5642302d8da92075ebc491"
}

rule MalwareBazaar_unknown_013_6133d4d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6133d4d7b0bb501c931d5c92cd2ee3101bcd9b866f66478ae1c4cf42244426b8"
    family = "unknown"
    file_name = "NewOrderChainC1809270562.js"
    file_type = "js"
    first_seen = "2026-11-17 07:51:50"
  condition:
    hash.sha256(0, filesize) == "6133d4d7b0bb501c931d5c92cd2ee3101bcd9b866f66478ae1c4cf42244426b8"
}

rule MalwareBazaar_unknown_014_696fe647
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "696fe647000575f3504e9c63add676133493dc9c791183cf4ac82a0a6f22dc00"
    family = "unknown"
    file_name = "PENAWARANHARGAh__PDF.js"
    file_type = "js"
    first_seen = "2026-11-17 07:51:47"
  condition:
    hash.sha256(0, filesize) == "696fe647000575f3504e9c63add676133493dc9c791183cf4ac82a0a6f22dc00"
}

rule MalwareBazaar_unknown_015_746a0b2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "746a0b2f1b824a442a116e3fe0c1c6589c745f39b1a0ac3d7ea352fda6877bcf"
    family = "unknown"
    file_name = "_00079"
    file_type = "js"
    first_seen = "2026-11-17 07:51:44"
  condition:
    hash.sha256(0, filesize) == "746a0b2f1b824a442a116e3fe0c1c6589c745f39b1a0ac3d7ea352fda6877bcf"
}

rule MalwareBazaar_unknown_016_579eb5e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "579eb5e1d14c654ca683b0b6260059cc0ef2a9b1f157f2894e2e30f667a5fac8"
    family = "unknown"
    file_name = "072e69d8f2e5467f84471cc4ea17203c.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:29"
  condition:
    hash.sha256(0, filesize) == "579eb5e1d14c654ca683b0b6260059cc0ef2a9b1f157f2894e2e30f667a5fac8"
}

rule MalwareBazaar_RemcosRAT_017_6f0c19f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f0c19f0dcca017e497eae0d42ad38d21cfd45f783eb8ab770037f3d313d5733"
    family = "RemcosRAT"
    file_name = "0x7E11F91CA56615D"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:26"
  condition:
    hash.sha256(0, filesize) == "6f0c19f0dcca017e497eae0d42ad38d21cfd45f783eb8ab770037f3d313d5733"
}

rule MalwareBazaar_AgentTesla_018_605de7f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "605de7f6cf8e15c7a1d8f0770ed742bededf13d1e794fc59d21364b3a9e83165"
    family = "AgentTesla"
    file_name = "9ae5a1019d0d4ce1b741d6ce6e506249.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:22"
  condition:
    hash.sha256(0, filesize) == "605de7f6cf8e15c7a1d8f0770ed742bededf13d1e794fc59d21364b3a9e83165"
}

rule MalwareBazaar_AsyncRAT_019_5da95c12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da95c129af20e6ad40f1b1376cc340fc4416c3d5c4d54ff1c84b4d06c15455c"
    family = "AsyncRAT"
    file_name = "e1e0b8bf4b1b4b78acfcf2399a061187.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:17"
  condition:
    hash.sha256(0, filesize) == "5da95c129af20e6ad40f1b1376cc340fc4416c3d5c4d54ff1c84b4d06c15455c"
}

rule MalwareBazaar_AgentTesla_020_542d630f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "542d630f7e740ecd2ff366df0e343145d0a3fc7761587f24b993612a1ceb7f8b"
    family = "AgentTesla"
    file_name = "c9312962de4744af953cb90962e08e1d.MSG"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:14"
  condition:
    hash.sha256(0, filesize) == "542d630f7e740ecd2ff366df0e343145d0a3fc7761587f24b993612a1ceb7f8b"
}

rule MalwareBazaar_unknown_021_951d2259
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "951d2259cc2341431e9fe1f0c57199161a9389fc01a3534d17a051b8ced2cc72"
    family = "unknown"
    file_name = "_00089"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:10"
  condition:
    hash.sha256(0, filesize) == "951d2259cc2341431e9fe1f0c57199161a9389fc01a3534d17a051b8ced2cc72"
}

rule MalwareBazaar_Formbook_022_6da6e076
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801"
    family = "Formbook"
    file_name = "pd2951919258.att"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:07"
  condition:
    hash.sha256(0, filesize) == "6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801"
}

rule MalwareBazaar_unknown_023_618d20e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618d20e30e90fce0d684db2ba4352ce9a2c57bbc790447ecfc0a64726224cca9"
    family = "unknown"
    file_name = "goodthings.hta"
    file_type = "hta"
    first_seen = "2026-11-17 07:51:06"
  condition:
    hash.sha256(0, filesize) == "618d20e30e90fce0d684db2ba4352ce9a2c57bbc790447ecfc0a64726224cca9"
}

rule MalwareBazaar_XWorm_024_2f26b6fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f26b6fed6612b40560bbb9fbf6f5ae7f9219cb7d5248181efe69e184398ec9d"
    family = "XWorm"
    file_name = "md5001002645273.tmp"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:04"
  condition:
    hash.sha256(0, filesize) == "2f26b6fed6612b40560bbb9fbf6f5ae7f9219cb7d5248181efe69e184398ec9d"
}

rule MalwareBazaar_unknown_025_f8578890
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8578890598dca94cb87620492148b3c938a602e45e232954347baa3bd28a7c2"
    family = "unknown"
    file_name = "WrittenBytes"
    file_type = "exe"
    first_seen = "2026-11-17 07:51:00"
  condition:
    hash.sha256(0, filesize) == "f8578890598dca94cb87620492148b3c938a602e45e232954347baa3bd28a7c2"
}

rule MalwareBazaar_MassLogger_026_1fec0c36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fec0c36273b609de2986119fd13fb46288ee75e542c66873b5362e293d8d537"
    family = "MassLogger"
    file_name = "8075e619"
    file_type = "js"
    first_seen = "2026-11-17 07:50:57"
  condition:
    hash.sha256(0, filesize) == "1fec0c36273b609de2986119fd13fb46288ee75e542c66873b5362e293d8d537"
}

rule MalwareBazaar_AgentTesla_027_7ca0d9b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971"
    family = "AgentTesla"
    file_name = "COMPROBANTEDEPAGO.exe"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:54"
  condition:
    hash.sha256(0, filesize) == "7ca0d9b533effed8c75019d2bfaa6525201c61f80ef1bcbffddc4481be9d4971"
}

rule MalwareBazaar_PureLogsStealer_028_f52bad2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f52bad2f6b6fe7d404663bf24b55d38c0504314667894f3ed2600fc2b1988fa0"
    family = "PureLogsStealer"
    file_name = "WrittenBytes"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:51"
  condition:
    hash.sha256(0, filesize) == "f52bad2f6b6fe7d404663bf24b55d38c0504314667894f3ed2600fc2b1988fa0"
}

rule MalwareBazaar_MassLogger_029_b3515d99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3515d99bdcf3fcff08a1adb526a9b476177c6a7e619a5d7eeddb603312bfd41"
    family = "MassLogger"
    file_name = "md5001000300362.tmp"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:48"
  condition:
    hash.sha256(0, filesize) == "b3515d99bdcf3fcff08a1adb526a9b476177c6a7e619a5d7eeddb603312bfd41"
}

rule MalwareBazaar_AgentTesla_030_84886f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84886f1f4e1e79733f8e052d440ee01ff0f02cd1c6731ee1fc144d32987d6d66"
    family = "AgentTesla"
    file_name = "_00142"
    file_type = "js"
    first_seen = "2026-11-17 07:50:45"
  condition:
    hash.sha256(0, filesize) == "84886f1f4e1e79733f8e052d440ee01ff0f02cd1c6731ee1fc144d32987d6d66"
}

rule MalwareBazaar_MassLogger_031_e56f62bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e56f62bf9912d6e8aac7a094fdb6990be6eaa8a5ef95c5aba708821134b83ff6"
    family = "MassLogger"
    file_name = "PO-Q-2627-2466.exe"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:42"
  condition:
    hash.sha256(0, filesize) == "e56f62bf9912d6e8aac7a094fdb6990be6eaa8a5ef95c5aba708821134b83ff6"
}

rule MalwareBazaar_MassLogger_032_262a24af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1"
    family = "MassLogger"
    file_name = "-.pdf.js"
    file_type = "exe"
    first_seen = "2026-11-17 07:50:39"
  condition:
    hash.sha256(0, filesize) == "262a24afffa5b50f3ce7f8c26929f8b4042c93b6a30b7612ad59216d935963c1"
}

rule MalwareBazaar_unknown_033_7aa41390
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7aa41390346c9925497f4f1d2574fedfffc0d5684d46a204dc594f0cadefb906"
    family = "unknown"
    file_name = "Zapytanieofertowenr490526.xls"
    file_type = "xls"
    first_seen = "2026-11-17 07:50:34"
  condition:
    hash.sha256(0, filesize) == "7aa41390346c9925497f4f1d2574fedfffc0d5684d46a204dc594f0cadefb906"
}

rule MalwareBazaar_RemcosRAT_034_e0af51cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0af51cb8ed95d04a2b8e85fa7cb3d42d25ba46c6263adfd84761e3d87b443f5"
    family = "RemcosRAT"
    file_name = "RGB.hta"
    file_type = "hta"
    first_seen = "2026-11-17 07:30:06"
  condition:
    hash.sha256(0, filesize) == "e0af51cb8ed95d04a2b8e85fa7cb3d42d25ba46c6263adfd84761e3d87b443f5"
}

rule MalwareBazaar_RemcosRAT_035_4b09a170
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b09a170b5bd96e31e3c86bef1b70d1da5c525c5e97c412f327ec9fd886db012"
    family = "RemcosRAT"
    file_name = "慶騰精密 CFS 2026年11月19日 基隆--香港 SO.6386(古)(譽銘).exe"
    file_type = "exe"
    first_seen = "2026-11-17 06:56:23"
  condition:
    hash.sha256(0, filesize) == "4b09a170b5bd96e31e3c86bef1b70d1da5c525c5e97c412f327ec9fd886db012"
}

rule MalwareBazaar_Mirai_036_e0044178
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e004417825327fc9523b80e877037c4f18112952a0e5d4ed2c19e3cb7b4f7afa"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-17 06:11:05"
  condition:
    hash.sha256(0, filesize) == "e004417825327fc9523b80e877037c4f18112952a0e5d4ed2c19e3cb7b4f7afa"
}

rule MalwareBazaar_RemcosRAT_037_b1e1643f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1e1643f6b5f6905e7711c2be654e29b960ad61178f24d6c861b7b8c2ab004a6"
    family = "RemcosRAT"
    file_name = "Fedex-AWB.js"
    file_type = "js"
    first_seen = "2026-11-17 05:54:44"
  condition:
    hash.sha256(0, filesize) == "b1e1643f6b5f6905e7711c2be654e29b960ad61178f24d6c861b7b8c2ab004a6"
}

rule MalwareBazaar_Prometei_038_c50ff97d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50ff97d3e0b19386f6ea33280c22ea03a4386cbb36c51c12c109de0c2b0041c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:49:05"
  condition:
    hash.sha256(0, filesize) == "c50ff97d3e0b19386f6ea33280c22ea03a4386cbb36c51c12c109de0c2b0041c"
}

rule MalwareBazaar_GoDDoSAgent_039_0dc8eb6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dc8eb6eb2cee7c7f4be3e5809ba2ed40e70a18942a90eb7327aacf655a60e7b"
    family = "GoDDoSAgent"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-17 05:48:07"
  condition:
    hash.sha256(0, filesize) == "0dc8eb6eb2cee7c7f4be3e5809ba2ed40e70a18942a90eb7327aacf655a60e7b"
}

rule MalwareBazaar_GoDDoSAgent_040_e166ea5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e166ea5fe88f2a36ea05ef597de1ac0666e06aac65c40b055c86890024c10e4c"
    family = "GoDDoSAgent"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-17 05:47:06"
  condition:
    hash.sha256(0, filesize) == "e166ea5fe88f2a36ea05ef597de1ac0666e06aac65c40b055c86890024c10e4c"
}

rule MalwareBazaar_unknown_041_6bdf42a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18"
    family = "unknown"
    file_name = "heartbreaker"
    file_type = "macho"
    first_seen = "2026-11-17 05:46:07"
  condition:
    hash.sha256(0, filesize) == "6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18"
}

rule MalwareBazaar_Mirai_042_079ee2ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "079ee2adc6d1623f7f442415c9766f627644d2690847bdbbaeb95310d45af2c3"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-17 05:45:07"
  condition:
    hash.sha256(0, filesize) == "079ee2adc6d1623f7f442415c9766f627644d2690847bdbbaeb95310d45af2c3"
}

rule MalwareBazaar_GoDDoSAgent_043_b5ddfce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5ddfce1f453b1ce2eb81067e4e909d9717707d796482b583559f4d2ac23f050"
    family = "GoDDoSAgent"
    file_name = "amd64"
    file_type = "elf"
    first_seen = "2026-11-17 05:39:06"
  condition:
    hash.sha256(0, filesize) == "b5ddfce1f453b1ce2eb81067e4e909d9717707d796482b583559f4d2ac23f050"
}

rule MalwareBazaar_RustyStealer_044_ac233f0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815"
    family = "RustyStealer"
    file_name = "ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815"
    file_type = "exe"
    first_seen = "2026-11-17 05:36:00"
  condition:
    hash.sha256(0, filesize) == "ac233f0bfefb8b39ea84c61b0bec54037285caf5fe439f2c5160842fa4eea815"
}

rule MalwareBazaar_Prometei_045_ce171065
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce171065cb02da5f0a6b14be8ea17f41d74afe53c9bb99e283a516c671445c33"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:35:05"
  condition:
    hash.sha256(0, filesize) == "ce171065cb02da5f0a6b14be8ea17f41d74afe53c9bb99e283a516c671445c33"
}

rule MalwareBazaar_RustyStealer_046_a120f0c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a120f0c0defe4b6943e09f06272a86ae75d1a4524fa9bf21da25c8c0d747ef5a"
    family = "RustyStealer"
    file_name = "eu.exe"
    file_type = "exe"
    first_seen = "2026-11-17 05:34:11"
  condition:
    hash.sha256(0, filesize) == "a120f0c0defe4b6943e09f06272a86ae75d1a4524fa9bf21da25c8c0d747ef5a"
}

rule MalwareBazaar_RustyStealer_047_b1f0a2ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1f0a2fff8baab47463fa04b1ee279ef86265db24a58f7fc1b56c5576ec801db"
    family = "RustyStealer"
    file_name = "eu.exe"
    file_type = "exe"
    first_seen = "2026-11-17 05:33:14"
  condition:
    hash.sha256(0, filesize) == "b1f0a2fff8baab47463fa04b1ee279ef86265db24a58f7fc1b56c5576ec801db"
}

rule MalwareBazaar_RustyStealer_048_80c47415
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80c474154b1df816cf513ae978936875b6dd77f47ef6bce78dda83ab1b89525b"
    family = "RustyStealer"
    file_name = "53nw6lv7.exe"
    file_type = "exe"
    first_seen = "2026-11-17 05:32:24"
  condition:
    hash.sha256(0, filesize) == "80c474154b1df816cf513ae978936875b6dd77f47ef6bce78dda83ab1b89525b"
}

rule MalwareBazaar_XWorm_049_18925796
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189257961beda2c9617ef04658408616adf3ae77293191db0465bc508d4ee9b9"
    family = "XWorm"
    file_name = "PO20261113143.pdf.JS"
    file_type = "js"
    first_seen = "2026-11-17 05:32:07"
  condition:
    hash.sha256(0, filesize) == "189257961beda2c9617ef04658408616adf3ae77293191db0465bc508d4ee9b9"
}

rule MalwareBazaar_Formbook_050_d872bca8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d872bca80947067bd0c0fe67513adde63f2fce539a9babc92f3b5b12220b9b25"
    family = "Formbook"
    file_name = "pago-20261116085641016.JS"
    file_type = "js"
    first_seen = "2026-11-17 05:32:03"
  condition:
    hash.sha256(0, filesize) == "d872bca80947067bd0c0fe67513adde63f2fce539a9babc92f3b5b12220b9b25"
}

rule MalwareBazaar_RemcosRAT_051_a6eee590
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6eee59062b4900464534edfdd486411c7ec415f9f8a0e3a2599bbb82e8ade7e"
    family = "RemcosRAT"
    file_name = "INV.xls"
    file_type = "xls"
    first_seen = "2026-11-17 05:32:00"
  condition:
    hash.sha256(0, filesize) == "a6eee59062b4900464534edfdd486411c7ec415f9f8a0e3a2599bbb82e8ade7e"
}

rule MalwareBazaar_LxBaseRAT_052_320e6be2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "320e6be256619e7a5378eb1a03e8ea47d20ee82c8fa04cea534c48ca3b2ed07f"
    family = "LxBaseRAT"
    file_name = "LX_Cm0nHprUp0Q_zQzn.j"
    file_type = "js"
    first_seen = "2026-11-17 05:31:57"
  condition:
    hash.sha256(0, filesize) == "320e6be256619e7a5378eb1a03e8ea47d20ee82c8fa04cea534c48ca3b2ed07f"
}

rule MalwareBazaar_Formbook_053_2974e006
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2974e0064f6951c7cba5cf65e63d1fd521201509c45839341429cbf0eaae86e3"
    family = "Formbook"
    file_name = "Justificante.js"
    file_type = "js"
    first_seen = "2026-11-17 05:31:54"
  condition:
    hash.sha256(0, filesize) == "2974e0064f6951c7cba5cf65e63d1fd521201509c45839341429cbf0eaae86e3"
}

rule MalwareBazaar_Formbook_054_b2ecad31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2ecad3135d079fa7eb917e04f05cc744caa21dade23bdf5810237a895c943d7"
    family = "Formbook"
    file_name = "Justificante.js"
    file_type = "js"
    first_seen = "2026-11-17 05:31:46"
  condition:
    hash.sha256(0, filesize) == "b2ecad3135d079fa7eb917e04f05cc744caa21dade23bdf5810237a895c943d7"
}

rule MalwareBazaar_unknown_055_95a62cae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a62caef708b15024e23354b1bfa404f5452fc32c7e4793bc7543a4a79fe918"
    family = "unknown"
    file_name = "awb_shipping_customs_tax_clearance_instructions_11_17_2026.xls"
    file_type = "xls"
    first_seen = "2026-11-17 05:31:41"
  condition:
    hash.sha256(0, filesize) == "95a62caef708b15024e23354b1bfa404f5452fc32c7e4793bc7543a4a79fe918"
}

rule MalwareBazaar_AgentTesla_056_dfa7c075
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfa7c075b704d3b80a5909850161101b47237411937809345cc963cc19d32134"
    family = "AgentTesla"
    file_name = "RePaymentDishonorNotification--INV33711.JS"
    file_type = "js"
    first_seen = "2026-11-17 05:31:38"
  condition:
    hash.sha256(0, filesize) == "dfa7c075b704d3b80a5909850161101b47237411937809345cc963cc19d32134"
}

rule MalwareBazaar_RemcosRAT_057_5da6ba74
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5da6ba74a57b73807cdc8c313fdb185cad744f3060c14354a0625e8cf02548bc"
    family = "RemcosRAT"
    file_name = "unknown"
    file_type = "js"
    first_seen = "2026-11-17 05:21:35"
  condition:
    hash.sha256(0, filesize) == "5da6ba74a57b73807cdc8c313fdb185cad744f3060c14354a0625e8cf02548bc"
}

rule MalwareBazaar_GoDDoSAgent_058_091636fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "091636fb36bc0874c7b46135746ee1605bef493ce1d4830898171e2ebe822c2d"
    family = "GoDDoSAgent"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-17 05:20:07"
  condition:
    hash.sha256(0, filesize) == "091636fb36bc0874c7b46135746ee1605bef493ce1d4830898171e2ebe822c2d"
}

rule MalwareBazaar_Prometei_059_30f4b566
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f4b566fe4c460daff28d1c5a2fbe99757aefbb47494a778695a1fd20a48486"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:13:06"
  condition:
    hash.sha256(0, filesize) == "30f4b566fe4c460daff28d1c5a2fbe99757aefbb47494a778695a1fd20a48486"
}

rule MalwareBazaar_Prometei_060_1e719597
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e719597868b05b1f36a90fbfab4791d07e93369deeef4438c89d4749f494a0d"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:12:05"
  condition:
    hash.sha256(0, filesize) == "1e719597868b05b1f36a90fbfab4791d07e93369deeef4438c89d4749f494a0d"
}

rule MalwareBazaar_GoDDoSAgent_061_e1e82b49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1e82b492745635c7a1549c764135e61deb65440cfa8b001fe25317e1452c9ee"
    family = "GoDDoSAgent"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-17 05:10:08"
  condition:
    hash.sha256(0, filesize) == "e1e82b492745635c7a1549c764135e61deb65440cfa8b001fe25317e1452c9ee"
}

rule MalwareBazaar_GoDDoSAgent_062_ff68cb5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff68cb5aa08fb026044e6132ba4627cfd12a2a72a0e14d039525f574e6ac432e"
    family = "GoDDoSAgent"
    file_name = "android_arm64"
    file_type = "elf"
    first_seen = "2026-11-17 05:09:05"
  condition:
    hash.sha256(0, filesize) == "ff68cb5aa08fb026044e6132ba4627cfd12a2a72a0e14d039525f574e6ac432e"
}

rule MalwareBazaar_Prometei_063_965c0185
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965c0185ee062c8688e5517e72e7849459e9e0f1880fcfd659e15536f23ff3d6"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 05:06:22"
  condition:
    hash.sha256(0, filesize) == "965c0185ee062c8688e5517e72e7849459e9e0f1880fcfd659e15536f23ff3d6"
}

rule MalwareBazaar_GoDDoSAgent_064_08093330
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08093330c6b57283fd60c90032aa33d396d19f07da802e7017af1e814845e1b6"
    family = "GoDDoSAgent"
    file_name = "mipsle"
    file_type = "elf"
    first_seen = "2026-11-17 05:06:18"
  condition:
    hash.sha256(0, filesize) == "08093330c6b57283fd60c90032aa33d396d19f07da802e7017af1e814845e1b6"
}

rule MalwareBazaar_GoDDoSAgent_065_ef0557f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef0557f44c104b27216dd677630320c367a6a7e511f1c2b65e75c0cf34861752"
    family = "GoDDoSAgent"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-17 05:06:11"
  condition:
    hash.sha256(0, filesize) == "ef0557f44c104b27216dd677630320c367a6a7e511f1c2b65e75c0cf34861752"
}

rule MalwareBazaar_Mirai_066_e40ae279
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79"
    family = "Mirai"
    file_name = "e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79"
    file_type = "elf"
    first_seen = "2026-11-17 04:36:18"
  condition:
    hash.sha256(0, filesize) == "e40ae2794551e8913fbb58b9ff8eea4570b97cd66d4f1b3758c66090559a1f79"
}

rule MalwareBazaar_WARDENStealer_067_e768f1d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e768f1d3e6388eb82f4d7387850d0b07900c695d8b2ed8d05c42a275ef786c47"
    family = "WARDENStealer"
    file_name = "e768f1d3e6388eb8.ps1"
    file_type = "ps1"
    first_seen = "2026-11-17 04:32:48"
  condition:
    hash.sha256(0, filesize) == "e768f1d3e6388eb82f4d7387850d0b07900c695d8b2ed8d05c42a275ef786c47"
}

rule MalwareBazaar_Prometei_068_aab6ded4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aab6ded474ab1a87456df056d8fe2fb908e637fbcac0f878f68764b16b680c1d"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-17 04:24:05"
  condition:
    hash.sha256(0, filesize) == "aab6ded474ab1a87456df056d8fe2fb908e637fbcac0f878f68764b16b680c1d"
}

rule MalwareBazaar_WARDENStealer_069_b063baa6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d"
    family = "WARDENStealer"
    file_name = "b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d.exe"
    file_type = "exe"
    first_seen = "2026-11-17 03:51:41"
  condition:
    hash.sha256(0, filesize) == "b063baa641bfcd4c2b5c0ff458eb6ed293553611c35ca0cbf378894519372c8d"
}

rule MalwareBazaar_Mirai_070_a273bf60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e"
    family = "Mirai"
    file_name = "a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e.elf"
    file_type = "elf"
    first_seen = "2026-11-17 03:16:41"
  condition:
    hash.sha256(0, filesize) == "a273bf60739c53c5af2a961843e4e7865793435f6618f90a74be75bcce77dd9e"
}

rule MalwareBazaar_unknown_071_2e6fa3d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3"
    family = "unknown"
    file_name = "2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3.bin"
    file_type = "js"
    first_seen = "2026-11-17 02:01:40"
  condition:
    hash.sha256(0, filesize) == "2e6fa3d0b90d18dabf42be6d4136f806f57100d6218a49719e10e994a97aa5b3"
}

rule MalwareBazaar_unknown_072_86f089f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e"
    family = "unknown"
    file_name = "86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e.bin"
    file_type = "js"
    first_seen = "2026-11-17 01:56:42"
  condition:
    hash.sha256(0, filesize) == "86f089f0d452efec1190e267c67447f529360508451b77d03644a7b9f56fea7e"
}

rule MalwareBazaar_Snowlight_073_3fb3930c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752"
    family = "Snowlight"
    file_name = "3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:48:08"
  condition:
    hash.sha256(0, filesize) == "3fb3930c3097a988ceda9c58dc018fd36af3885465aec96ba03b64cf49849752"
}

rule MalwareBazaar_unknown_074_9f32835c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0"
    family = "unknown"
    file_name = "9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:46:50"
  condition:
    hash.sha256(0, filesize) == "9f32835cf0a5fe627778fbad2f68a079c389cb93fc8008bb89d5ca5496ed6eb0"
}

rule MalwareBazaar_Snowlight_075_d7a27896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3"
    family = "Snowlight"
    file_name = "d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:46:45"
  condition:
    hash.sha256(0, filesize) == "d7a27896b2627f734785676e64db072ef156687c8fb610556ad33783e80dcfe3"
}

rule MalwareBazaar_Snowlight_076_b7444db1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb"
    family = "Snowlight"
    file_name = "b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:41:44"
  condition:
    hash.sha256(0, filesize) == "b7444db17b2496a25103d312b6a3c95aa6a6e22c45a80b54a3589723445edbdb"
}

rule MalwareBazaar_unknown_077_e6b5657e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c"
    family = "unknown"
    file_name = "e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:39:08"
  condition:
    hash.sha256(0, filesize) == "e6b5657e701f1c1a546fb7a319bc9a5ac2f691d2671d0828c28a91521c789c7c"
}

rule MalwareBazaar_Snowlight_078_dbf6597e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00"
    family = "Snowlight"
    file_name = "dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:36:56"
  condition:
    hash.sha256(0, filesize) == "dbf6597ec246d523ca5dcefe89343e0f3c467da133a9e7836827f3536ba6bf00"
}

rule MalwareBazaar_unknown_079_95a29b2d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f"
    family = "unknown"
    file_name = "95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:36:51"
  condition:
    hash.sha256(0, filesize) == "95a29b2d29318afab23e6d73ba41102e10f1d56218cbf6773f08ebb854c7544f"
}

rule MalwareBazaar_Snowlight_080_de319ee2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a"
    family = "Snowlight"
    file_name = "de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:34:19"
  condition:
    hash.sha256(0, filesize) == "de319ee2e3983ff03e3aac2ce574e17f5f2dc02dc60a7f23bd43eb79f8a1c95a"
}

rule MalwareBazaar_Snowlight_081_62d3e930
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06"
    family = "Snowlight"
    file_name = "62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:34:14"
  condition:
    hash.sha256(0, filesize) == "62d3e930de6ffb7d4169a168d9d89ec448ef6fc448d59ca708ef1a24e0da6f06"
}

rule MalwareBazaar_unknown_082_c9ae60b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b"
    family = "unknown"
    file_name = "c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b.bin"
    file_type = "macho"
    first_seen = "2026-11-17 01:33:32"
  condition:
    hash.sha256(0, filesize) == "c9ae60b2d7d9aef3f2b6a2a073ae8bcada4699ea1d125815e541703662a47d4b"
}

rule MalwareBazaar_Snowlight_083_a32fccd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1"
    family = "Snowlight"
    file_name = "a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:33:27"
  condition:
    hash.sha256(0, filesize) == "a32fccd1a53a411f16abca3f514c07b8bd4afb19cf910c6dfe766243fd5832f1"
}

rule MalwareBazaar_Snowlight_084_b78deb91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c"
    family = "Snowlight"
    file_name = "b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:33:22"
  condition:
    hash.sha256(0, filesize) == "b78deb91085bfdc2f9ea8bbc8d2dd02a3763904fd2065c38551abd76f0e6e61c"
}

rule MalwareBazaar_unknown_085_64bbf576
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3"
    family = "unknown"
    file_name = "64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:33:18"
  condition:
    hash.sha256(0, filesize) == "64bbf57617cf414fff31e76e8045b320e73a905d80fdc2d0307766274689cbd3"
}

rule MalwareBazaar_WARDENStealer_086_dc0092c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9"
    family = "WARDENStealer"
    file_name = "dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:33:13"
  condition:
    hash.sha256(0, filesize) == "dc0092c25a090b3b066be0bfe1c660adf3a09e864ca9c947215c99b743e08ec9"
}

rule MalwareBazaar_Vidar_087_2e620e14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e620e14d1d04df59b09b27a9ade51fdc3977dc9f6cda902349b12ebcdb81a9a"
    family = "Vidar"
    file_name = "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:32:23"
  condition:
    hash.sha256(0, filesize) == "2e620e14d1d04df59b09b27a9ade51fdc3977dc9f6cda902349b12ebcdb81a9a"
}

rule MalwareBazaar_Vidar_088_5a198f75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d"
    family = "Vidar"
    file_name = "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d.exe"
    file_type = "exe"
    first_seen = "2026-11-17 01:32:10"
  condition:
    hash.sha256(0, filesize) == "5a198f7571caa1fc00751e17e04feed6904e61f2683ae6c64c811d6a559e913d"
}

rule MalwareBazaar_Snowlight_089_81e604f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4"
    family = "Snowlight"
    file_name = "81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:32:05"
  condition:
    hash.sha256(0, filesize) == "81e604f67abbd8bfdaa379cb1133a2bb7dc40bad64af2b580ba3afcc458f59d4"
}

rule MalwareBazaar_unknown_090_9426f0a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750"
    family = "unknown"
    file_name = "9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:32:01"
  condition:
    hash.sha256(0, filesize) == "9426f0a696becbcd890712280bafa98c0829e0ace911dda333f17d77f7916750"
}

rule MalwareBazaar_Snowlight_091_f3e135a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c"
    family = "Snowlight"
    file_name = "f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:31:56"
  condition:
    hash.sha256(0, filesize) == "f3e135a02c6d939af4df05093d10262f49730f219baab2cbac4f26e175730e2c"
}

rule MalwareBazaar_unknown_092_1b9b9794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652"
    family = "unknown"
    file_name = "1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:31:52"
  condition:
    hash.sha256(0, filesize) == "1b9b97943c718b8a79f751fad4be5f9aa2bd3ac9ab360c3328ddb2937cf23652"
}

rule MalwareBazaar_Snowlight_093_4e303839
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899"
    family = "Snowlight"
    file_name = "4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:19"
  condition:
    hash.sha256(0, filesize) == "4e303839820a9fbd12d5e607502fb09a84a5215c9ef8a4091dcc5e7f83caa899"
}

rule MalwareBazaar_Snowlight_094_4eb9db27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9"
    family = "Snowlight"
    file_name = "4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:15"
  condition:
    hash.sha256(0, filesize) == "4eb9db275ded302e37e623bf501238da8ac6b2b06730ed6010930f4ee52ecff9"
}

rule MalwareBazaar_Snowlight_095_272614fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06"
    family = "Snowlight"
    file_name = "272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:11"
  condition:
    hash.sha256(0, filesize) == "272614fd09723ffa75129af4e1a523b8d7ebf076d80a9403863b274f87258e06"
}

rule MalwareBazaar_Snowlight_096_010930ea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2"
    family = "Snowlight"
    file_name = "010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:07"
  condition:
    hash.sha256(0, filesize) == "010930eacb72c660d3dab3dc73e07870863b34ba64c86300aaa2e19ae61ee4e2"
}

rule MalwareBazaar_Snowlight_097_55c06886
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb"
    family = "Snowlight"
    file_name = "55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:29:03"
  condition:
    hash.sha256(0, filesize) == "55c06886505f9111df2ea9f83fb967894676e17c69afcf5a4d4844804dcbe4eb"
}

rule MalwareBazaar_unknown_098_51b32c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90"
    family = "unknown"
    file_name = "51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:28:05"
  condition:
    hash.sha256(0, filesize) == "51b32c91938a3eb21d63e6083af56f9c89a9165f8276d8d2d0819ca63cf34f90"
}

rule MalwareBazaar_Snowlight_099_4ab97ad2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069"
    family = "Snowlight"
    file_name = "4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069.elf"
    file_type = "elf"
    first_seen = "2026-11-17 01:28:01"
  condition:
    hash.sha256(0, filesize) == "4ab97ad29c6869eba7b6d13a47d75fd1e64695ed05851b8504b1239b490ac069"
}

rule MalwareBazaar_unknown_100_f5a4e678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5a4e6789142e111ae9aa35d5f8ffa7f8c38b473b8dbc0d37341c300de641e81"
    family = "unknown"
    file_name = "f5a4e6789142e111.js"
    file_type = "js"
    first_seen = "2026-11-17 01:27:40"
  condition:
    hash.sha256(0, filesize) == "f5a4e6789142e111ae9aa35d5f8ffa7f8c38b473b8dbc0d37341c300de641e81"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

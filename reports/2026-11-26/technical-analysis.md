# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-26

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 648 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 648 |
| Unique family labels | 19 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 35 |
| Formbook | 11 |
| Prometei | 9 |
| AgentTesla | 9 |
| RemcosRAT | 8 |
| njrat | 4 |
| WARDENStealer | 3 |
| XWorm | 3 |
| PureLogsStealer | 3 |
| ValleyRAT | 3 |

### File Type Distribution

| File type | Samples |
|---|---:|
| js | 44 |
| exe | 29 |
| elf | 15 |
| sh | 3 |
| hta | 2 |
| vbe | 2 |
| xls | 2 |
| zip | 1 |
| jar | 1 |
| docx | 1 |

## Per-Sample Analysis

### Sample 1: `3cc8eaa41525dcea`

| Field | Value |
|---|---|
| SHA-256 | `3cc8eaa41525dceabd9d34a39298fc8e54bbb3e422530375d4c45aae6d6078ea` |
| Family label | `unknown` |
| File name | `09790-PR-26-14927-PO-14928-14930.scr` |
| File type | `exe` |
| First seen | `2026-11-26 08:34:28` |
| Reporter | `lowmal3` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3451c48e4374f04d7a900b9cdb615541` |
| SHA-1 | `11021723cfaf4f628a8869c255afb6caae25047a` |
| SHA-256 | `3cc8eaa41525dceabd9d34a39298fc8e54bbb3e422530375d4c45aae6d6078ea` |
| SHA3-384 | `668ec064d8afcd62ef0263d4d4bdf8f6fdb8d227177d2261560621b0b3744539eaeaada51a3e16c4339e2d7b31bcddc2` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14205F151326DDE02E8FB1BF80961F2B013B59D89A531E602AFD76DEB7936B104D443A3` |
| SSDEEP | `12288:Dan1qwmkAOb026lrZ1EoiA4IX+34wji5Vj06mrTiRO45EJQk9S/m49i9c:D0qwmvOb0BXiA+34w27d8p45Nhm49i9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_3cc8eaa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cc8eaa41525dceabd9d34a39298fc8e54bbb3e422530375d4c45aae6d6078ea"
    family = "unknown"
    file_name = "09790-PR-26-14927-PO-14928-14930.scr"
    file_type = "exe"
    first_seen = "2026-11-26 08:34:28"
  condition:
    hash.sha256(0, filesize) == "3cc8eaa41525dceabd9d34a39298fc8e54bbb3e422530375d4c45aae6d6078ea"
}
```

### Sample 2: `81f34962e5ee4ebf`

| Field | Value |
|---|---|
| SHA-256 | `81f34962e5ee4ebfc1699e525a129faca9816f0fea40a0a255d160555c3dfbdd` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 08:23:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df25c9e3e76febb6e9fa116db9ad2fe1` |
| SHA-1 | `b2ac1a46eb31b92c6cb22739108e57988ef6e6ee` |
| SHA-256 | `81f34962e5ee4ebfc1699e525a129faca9816f0fea40a0a255d160555c3dfbdd` |
| SHA3-384 | `03494aedfccc1fb029c660c6a8180f0da4281fe8062a56d6cf456ba4022406a9285d848cbd402ea248bd35090d8dd3ef` |
| TLSH | `T1BE556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSh:SDjxB4m5n8XlaPWi+d+a4TjxQP4L` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_002_81f34962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f34962e5ee4ebfc1699e525a129faca9816f0fea40a0a255d160555c3dfbdd"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 08:23:03"
  condition:
    hash.sha256(0, filesize) == "81f34962e5ee4ebfc1699e525a129faca9816f0fea40a0a255d160555c3dfbdd"
}
```

### Sample 3: `8b970e600b06d991`

| Field | Value |
|---|---|
| SHA-256 | `8b970e600b06d991f1e5dcd6220e9a904cb11b4d008f17b277adc0ef88e0c622` |
| Family label | `AgentTesla` |
| File name | `Payment_Advice-SOA-26_NOV-PDF.JS` |
| File type | `js` |
| First seen | `2026-11-26 08:19:10` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb21663cbd4ab3520613ee64d1cb75cb` |
| SHA-1 | `3495fa8e738025c2f2694ea5bed33d96ca19a8a6` |
| SHA-256 | `8b970e600b06d991f1e5dcd6220e9a904cb11b4d008f17b277adc0ef88e0c622` |
| SHA3-384 | `4c23db89efa5b13b36a866ee9691f362e0b926eb989a4e50dcb41a45deeb83658d3d2fb85659b047a1c23a0c0eca42b6` |
| TLSH | `T13A36D586A78491727B246B9CC63ADD30A40A554315C2CB377AFDD6183B1CD4BA3BC6E3` |
| SSDEEP | `98304:XPFjvYdlZjXyZTibuwHnd/Ttu6OzlcCaRur2JzKUOpfYDQe7Ee9m6fkDCvZO+vik:XPFjvYdlZjXyZTibuwHdbtu6OiCkhbOI` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_003_8b970e60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b970e600b06d991f1e5dcd6220e9a904cb11b4d008f17b277adc0ef88e0c622"
    family = "AgentTesla"
    file_name = "Payment_Advice-SOA-26_NOV-PDF.JS"
    file_type = "js"
    first_seen = "2026-11-26 08:19:10"
  condition:
    hash.sha256(0, filesize) == "8b970e600b06d991f1e5dcd6220e9a904cb11b4d008f17b277adc0ef88e0c622"
}
```

### Sample 4: `341374dce202a5f5`

| Field | Value |
|---|---|
| SHA-256 | `341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9` |
| Family label | `WannaCry` |
| File name | `341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9` |
| File type | `exe` |
| First seen | `2026-11-26 08:15:13` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29cbd8747b5959d8a4c7d06bd05c9e3f` |
| SHA-1 | `6f2ce2684974be50ef565f6bede4699fdbb93e85` |
| SHA-256 | `341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9` |
| SHA3-384 | `bf723e6218032c591e68133fd42a08366d248b5e21cc38a73808949f3f932a1d47237bfe7bcb78290434edd16d20a604` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1CD363358676891FCE04209B484F78E1AB7B37C59AB7E5B0F9780426B0D33B97AF94701` |
| SSDEEP | `98304:DpDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2HvCx6WIZ:DpDqPe1Cxcxk3ZAEUadzR8yc4HvE6WI` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_004_341374dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9"
    family = "WannaCry"
    file_name = "341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9"
    file_type = "exe"
    first_seen = "2026-11-26 08:15:13"
  condition:
    hash.sha256(0, filesize) == "341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9"
}
```

### Sample 5: `77aa7a04c23669bc`

| Field | Value |
|---|---|
| SHA-256 | `77aa7a04c23669bc478653fd6e0fd90eb5f6b1342105deeebc497e284c8688aa` |
| Family label | `unknown` |
| File name | `GSTR-MT103__ConfirmationPDF.js` |
| File type | `js` |
| First seen | `2026-11-26 08:05:32` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db0912f642d826657fb380464f9fa478` |
| SHA-1 | `8aea185b7bea5433713f4ee08ce06f178ea7e05b` |
| SHA-256 | `77aa7a04c23669bc478653fd6e0fd90eb5f6b1342105deeebc497e284c8688aa` |
| SHA3-384 | `7d8ada8f70c49938e10b096ff35e2dc551b942b51b06592d7e111a4fceaf142c178ce40f64f1689593e35c64333d998d` |
| TLSH | `T11F53DF4A43C222FAB250DCCEC50561ABB4F4A4B2385F5CD5F68956DBEBECA58D0347E0` |
| SSDEEP | `768:8DqLkAbnDv7xY+o4zDhE1fis45OPK2IhPafw+50G703PFnWkW:8DvAnl9HG4sohPadB2JxW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_77aa7a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77aa7a04c23669bc478653fd6e0fd90eb5f6b1342105deeebc497e284c8688aa"
    family = "unknown"
    file_name = "GSTR-MT103__ConfirmationPDF.js"
    file_type = "js"
    first_seen = "2026-11-26 08:05:32"
  condition:
    hash.sha256(0, filesize) == "77aa7a04c23669bc478653fd6e0fd90eb5f6b1342105deeebc497e284c8688aa"
}
```

### Sample 6: `b21a44ab76ee4f99`

| Field | Value |
|---|---|
| SHA-256 | `b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e` |
| Family label | `unknown` |
| File name | `b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e.exe` |
| File type | `exe` |
| First seen | `2026-11-26 07:49:54` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8627bedae0eda87ebe389a67d71e8b17` |
| SHA-1 | `8eb319fd4a85ca080d59b88bdd0faec62cdfc1ba` |
| SHA-256 | `b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e` |
| SHA3-384 | `2854387b4afe7241d3acbe44f79ba5e68ddb7437bc06b058275c8269dafca83369915342f010c7f9346b507ec59818f9` |
| IMPHASH | `afdd28f90a7cd892d91024b87691d910` |
| TLSH | `T19E150203FA9A41ECD42BC67946528522FA627C164B606EFF57845B270E37AE1CF3E710` |
| SSDEEP | `24576:1Ar2NRWfca5/jjtwZXtBSxMqi+Jpik8lm+6:ir2evd/qVp` |
| ICON-DHASH | `10689671b22a4c30` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_b21a44ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e"
    family = "unknown"
    file_name = "b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e.exe"
    file_type = "exe"
    first_seen = "2026-11-26 07:49:54"
  condition:
    hash.sha256(0, filesize) == "b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e"
}
```

### Sample 7: `70c33f33097d17b7`

| Field | Value |
|---|---|
| SHA-256 | `70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659` |
| Family label | `unknown` |
| File name | `70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659` |
| File type | `elf` |
| First seen | `2026-11-26 07:39:52` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdc964ff518cf7ac8844fd3ca7825ae1` |
| SHA-1 | `1ba87b3fd40e6e6a4544e104e72d81471f46174f` |
| SHA-256 | `70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659` |
| SHA3-384 | `69cbd6e64d934ec0c6aa851c3d066afd08847d62b95c5bb049b18f1c4234d2e443946a8b136ce3a0cfd12477a178becc` |
| TLSH | `T103119E1A4FF02F1BCE66DC3200A5A78D27DD601FB35E7B96A3749500BE0AA4686C35A4` |
| SSDEEP | `24:9FwU25VgVNmpj2av1fJjlyo0UwGz2bmt8tReQgXYtkLgsYW:Xj2kkVtf58o9wGz/2yX+s` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_70c33f33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659"
    family = "unknown"
    file_name = "70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659"
    file_type = "elf"
    first_seen = "2026-11-26 07:39:52"
  condition:
    hash.sha256(0, filesize) == "70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659"
}
```

### Sample 8: `c6544286dcdf3597`

| Field | Value |
|---|---|
| SHA-256 | `c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d` |
| Family label | `unknown` |
| File name | `c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d` |
| File type | `elf` |
| First seen | `2026-11-26 07:32:25` |
| Reporter | `honeyglass` |
| Tags | `elf, honeypot, ssh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `556219c79e80bbc521ae3ccbacd073b8` |
| SHA-1 | `6c7e2a776fcac12ae6c72073f2d5d09eacde91f5` |
| SHA-256 | `c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d` |
| SHA3-384 | `60364858a99e9942c2893f7e24fba581c25dc96268d33235dc267beac5a1793dda71fc5ec27ba35788d0ffa2069a88af` |
| TLSH | `T127362873A49154E4D2EED574C6256213BEE0389B273423CB7BD076E11B7ABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQN:cqYUQuVDt0TZES` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_c6544286
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d"
    family = "unknown"
    file_name = "c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d"
    file_type = "elf"
    first_seen = "2026-11-26 07:32:25"
  condition:
    hash.sha256(0, filesize) == "c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d"
}
```

### Sample 9: `511f058ee0f47263`

| Field | Value |
|---|---|
| SHA-256 | `511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1` |
| Family label | `unknown` |
| File name | `511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1` |
| File type | `elf` |
| First seen | `2026-11-26 07:25:10` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `801968bc1c608f261155edda4de70d06` |
| SHA-1 | `a6ee2ed1caf9ffdba237af161059068bfa7ccc68` |
| SHA-256 | `511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1` |
| SHA3-384 | `7ebcde1099c028465f43040ba224db0eb924f3661bdb02273bd56e1d41edeba3893e3730f30541fba0c4c5f5c95e3470` |
| TLSH | `T11341DD95AFA03F3FC81EDC314050DA4A13EC001E636EBFA52364D500FB0664959C399C` |
| SSDEEP | `24:9FwU25VgVNmpj2av1fJjlyo0UwGz2bmt8tReQgXYtkLgsYEQLrdS7tMPiZz9r0+a:Xj2kkVtf58o9wGz/2yX+ZdSJLDiv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_511f058e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1"
    family = "unknown"
    file_name = "511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1"
    file_type = "elf"
    first_seen = "2026-11-26 07:25:10"
  condition:
    hash.sha256(0, filesize) == "511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1"
}
```

### Sample 10: `26bbe6772c0f6b8b`

| Field | Value |
|---|---|
| SHA-256 | `26bbe6772c0f6b8b3d865aba425812faf7df9687891950ca07a9eb3d24c96dd9` |
| Family label | `GuLoader` |
| File name | `IMAGES-REQUEST FOR QUOTAION RO-C-27299,28275.28277,27921,28282,28276 RFQ 730038262 CLOSING DATE 04-12- 2026.jpg.exe` |
| File type | `exe` |
| First seen | `2026-11-26 07:22:35` |
| Reporter | `lowmal3` |
| Tags | `exe, GuLoader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73a0ac5576acfaa06a0b9ac06795f2f1` |
| SHA-1 | `e2d683e21f8ff7071fa120c35eb6b1899c53de7c` |
| SHA-256 | `26bbe6772c0f6b8b3d865aba425812faf7df9687891950ca07a9eb3d24c96dd9` |
| SHA3-384 | `07f50dcc2c5f32daba9cee9ef59c8493af99dbf72f9ac86e674b382841902c3082bb5e2c4d90a79d2d1a68a59b8ad1f3` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T1034512817380D92AC25E1F3B45D2B31D6E7ECFC22F1A923606893257DF3AE9D0B59485` |
| SSDEEP | `24576:RTafdG04YOVIP3JllKF8zbfU/fTj/4PwnJTprxDgxkVNm4rp2kaeIfX:1i804YkQ3TlKazbfU/3TJTprJIyg4rPY` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_010_26bbe677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26bbe6772c0f6b8b3d865aba425812faf7df9687891950ca07a9eb3d24c96dd9"
    family = "GuLoader"
    file_name = "IMAGES-REQUEST FOR QUOTAION RO-C-27299,28275.28277,27921,28282,28276 RFQ 730038262 CLOSING DATE 04-12- 2026.jpg.exe"
    file_type = "exe"
    first_seen = "2026-11-26 07:22:35"
  condition:
    hash.sha256(0, filesize) == "26bbe6772c0f6b8b3d865aba425812faf7df9687891950ca07a9eb3d24c96dd9"
}
```

### Sample 11: `0ace26141b9fad0a`

| Field | Value |
|---|---|
| SHA-256 | `0ace26141b9fad0a395a43c0b208e5e943d6de25bdd0bbd1d37bf991b4fa1053` |
| Family label | `unknown` |
| File name | `자금출처 소명서CaryPact 동적 수익 참고표 V1-V10..zip` |
| File type | `zip` |
| First seen | `2026-11-26 07:15:48` |
| Reporter | `smica83` |
| Tags | `apt, DPRK, Kimsuky, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fe05084e3d6b0221cd09cfa35220b20` |
| SHA-1 | `3d8c6c8ed0eb5c50004ff013561fcec4bae78a34` |
| SHA-256 | `0ace26141b9fad0a395a43c0b208e5e943d6de25bdd0bbd1d37bf991b4fa1053` |
| SHA3-384 | `0fc3ad24528a82bf375c5c5dc19d5c88be42d0ce587e87f373aae18da6c5ef3e113bb199994155bf50831548081d68c9` |
| TLSH | `T18AC533E8C88D0181E964B196B78CA739C91BD229DD5190333B1787EFBB670D4E1EA13D` |
| SSDEEP | `49152:Db9IGSVH/yzyBAG6Lb9IGSVesWfc4DV+IXRnzJfoTE8luvi:DZIJH/fZ6LZIJesWfVD9RnzJfn8lgi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_0ace2614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ace26141b9fad0a395a43c0b208e5e943d6de25bdd0bbd1d37bf991b4fa1053"
    family = "unknown"
    file_name = "자금출처 소명서CaryPact 동적 수익 참고표 V1-V10..zip"
    file_type = "zip"
    first_seen = "2026-11-26 07:15:48"
  condition:
    hash.sha256(0, filesize) == "0ace26141b9fad0a395a43c0b208e5e943d6de25bdd0bbd1d37bf991b4fa1053"
}
```

### Sample 12: `f9b2704547ee9f79`

| Field | Value |
|---|---|
| SHA-256 | `f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc` |
| Family label | `Mirai` |
| File name | `f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc` |
| File type | `elf` |
| First seen | `2026-11-26 07:12:11` |
| Reporter | `BlackdomeIntel` |
| Tags | `blackdome, elf, honeypot, Mirai, x86_64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `231ac9ea1ecbd084d9071cc5a0a1ebb1` |
| SHA-1 | `622553d846a4e9b666ec741b052fe722355c65cd` |
| SHA-256 | `f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc` |
| SHA3-384 | `95affa7a64ff2966beb526b049bd66f062f14e2134f193ba14579fa19f07957883848b4ceac166e561c5f462ef0cfc4f` |
| TLSH | `T18E155C1AF2B374AEC093C039479BDB72A939F47902126D7B31819A353D06EE05F19B67` |
| TELFHASH | `t1ad119cb4072d76211660de9c88dcb397056dca06971dfe33a8b2886c610809ee237c4f` |
| SSDEEP | `12288:nI1HtP8xZAY4I8yxmTpLGZALQAgg7MbtQELYADWT8IIoQ:nI1tIA6xxmlG0Q8WsWWAI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_f9b27045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc"
    family = "Mirai"
    file_name = "f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc"
    file_type = "elf"
    first_seen = "2026-11-26 07:12:11"
  condition:
    hash.sha256(0, filesize) == "f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc"
}
```

### Sample 13: `3fe5c3f6e949ca1d`

| Field | Value |
|---|---|
| SHA-256 | `3fe5c3f6e949ca1d08a421a9bf08ed3b5cadcaeeeae4cd427a40eb938a1931b3` |
| Family label | `RemcosRAT` |
| File name | `asc.hta` |
| File type | `hta` |
| First seen | `2026-11-26 07:00:04` |
| Reporter | `abuse_ch` |
| Tags | `hta, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcd89dad650a982a5f67eff3f07893a3` |
| SHA-1 | `b7a86889031effd3c103ff469048727174f50079` |
| SHA-256 | `3fe5c3f6e949ca1d08a421a9bf08ed3b5cadcaeeeae4cd427a40eb938a1931b3` |
| SHA3-384 | `53811a2eac1cb5179f98ebb985d8da6822a2fd2c0821e948a6c952fee99a9b32c26d99accc123adb93dd129a1ef26cf0` |
| TLSH | `T1DC722038DFAAFD948F8B51DC044426228C15863FD1286B0CF95D417BB73821D6E1D2DB` |
| SSDEEP | `48:3OtZYtZ3Q48+nhWuuuWeuuVSIPBuuu0eXtZDG:h88Fz` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_013_3fe5c3f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fe5c3f6e949ca1d08a421a9bf08ed3b5cadcaeeeae4cd427a40eb938a1931b3"
    family = "RemcosRAT"
    file_name = "asc.hta"
    file_type = "hta"
    first_seen = "2026-11-26 07:00:04"
  condition:
    hash.sha256(0, filesize) == "3fe5c3f6e949ca1d08a421a9bf08ed3b5cadcaeeeae4cd427a40eb938a1931b3"
}
```

### Sample 14: `994bcf81a9faaf1e`

| Field | Value |
|---|---|
| SHA-256 | `994bcf81a9faaf1ec96be49c99d68cde37ed9981aaf01aa76271c1e02851991e` |
| Family label | `unknown` |
| File name | `goodwords.hta` |
| File type | `hta` |
| First seen | `2026-11-26 06:57:07` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82d05fbc888bcc80c1eaba725a395e39` |
| SHA-1 | `122c6a08944e95bbb7f8c3ad169dfd5338732527` |
| SHA-256 | `994bcf81a9faaf1ec96be49c99d68cde37ed9981aaf01aa76271c1e02851991e` |
| SHA3-384 | `c1437754c91e389b0e1d1bdff072b548f1eb4a1580f53349a6cb103b19cc186e8e444ea11b565a5e0cc250d16dca69f5` |
| TLSH | `T1E972CD7C1390FC4693AFA1ED400826077899D27BF189EAAAB45C402397B432DCC3E18B` |
| SSDEEP | `48:3I87Fwlr47FwvJ4w/KfMNuuuuYbhHuuuuuuuGhvMzVDj037FwE8rG:D7WW7WB1UMWbhxhR7Wq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_994bcf81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994bcf81a9faaf1ec96be49c99d68cde37ed9981aaf01aa76271c1e02851991e"
    family = "unknown"
    file_name = "goodwords.hta"
    file_type = "hta"
    first_seen = "2026-11-26 06:57:07"
  condition:
    hash.sha256(0, filesize) == "994bcf81a9faaf1ec96be49c99d68cde37ed9981aaf01aa76271c1e02851991e"
}
```

### Sample 15: `70dc1383b66ae641`

| Field | Value |
|---|---|
| SHA-256 | `70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301` |
| Family label | `unknown` |
| File name | `70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301` |
| File type | `elf` |
| First seen | `2026-11-26 06:55:24` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d247954c09b1cb058718e28b0da60b8f` |
| SHA-1 | `215d1125dff6da42b6c20dd9b1961afef2db373f` |
| SHA-256 | `70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301` |
| SHA3-384 | `ac21aa059733e00eaefd278b3fe20c47cee7796339177426d8aabf47120a5d25d1a935cf118ea8d6e4a2cab2a8d31ede` |
| TLSH | `T19B518CA6EEA03B3FCC0DD8315595D68A03FE126D135A6FB65350D408BF0A78A06C3B9C` |
| SSDEEP | `48:Xj2kkVtf58o9wGz/2yX+ZdSJLDiteOr3AtNWKOTuXbDrB:XakkHz/r+HSdDioOr3GNWKOwbDrB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_70dc1383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301"
    family = "unknown"
    file_name = "70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301"
    file_type = "elf"
    first_seen = "2026-11-26 06:55:24"
  condition:
    hash.sha256(0, filesize) == "70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301"
}
```

### Sample 16: `d3160d819505de05`

| Field | Value |
|---|---|
| SHA-256 | `d3160d819505de05b40bf4afeec50743bd6941433f0458e3cb74273fe3d700cc` |
| Family label | `RemcosRAT` |
| File name | `SO.0421-FZY3220STX0421-宝柚-TXG to SHIHU-要保險 CLS11302026 SO#0421.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:52:06` |
| Reporter | `threatcat_ch` |
| Tags | `exe, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5192509d4607d506fa1a284123e1081` |
| SHA-1 | `e628cb79b2b9cdb453b48bff0a0a26435f0a1468` |
| SHA-256 | `d3160d819505de05b40bf4afeec50743bd6941433f0458e3cb74273fe3d700cc` |
| SHA3-384 | `b3a5b7f4aeb6ba45e8a3baf9f7c313fa932155bcbf1e7857fb18ed1ccad57927d5a46c7db6cd44d0882f9dc83aecb6c8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11C350255327EDF02E8B70BF819A0F1B047B6BD896A31D2065ED62EEF793670019057A3` |
| SSDEEP | `24576:1sDqwm/PRupABf30YY0xzMDqjJnjmllMn6Jt5lj:A48pABc6gDgFKMn6L` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_016_d3160d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3160d819505de05b40bf4afeec50743bd6941433f0458e3cb74273fe3d700cc"
    family = "RemcosRAT"
    file_name = "SO.0421-FZY3220STX0421-宝柚-TXG to SHIHU-要保險 CLS11302026 SO#0421.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:52:06"
  condition:
    hash.sha256(0, filesize) == "d3160d819505de05b40bf4afeec50743bd6941433f0458e3cb74273fe3d700cc"
}
```

### Sample 17: `35d34ec00a6610b3`

| Field | Value |
|---|---|
| SHA-256 | `35d34ec00a6610b3a90a4c2b6df568c119fe320899f698bff65632e023e34f69` |
| Family label | `WARDENStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:50:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba4c3bd0caa58fbd5a14814d12b4b9d4` |
| SHA-1 | `beffc05676b9f87697958e56e7514ea3750d43ac` |
| SHA-256 | `35d34ec00a6610b3a90a4c2b6df568c119fe320899f698bff65632e023e34f69` |
| SHA3-384 | `17335847f89dd357c4cdf680ca1411aff6db725726441037272c6c481a94208bf07bb0d4ddbcf4ff4209ed6bd8e0fd79` |
| IMPHASH | `475540456ba6d683a1e32a4a569d9a9f` |
| TLSH | `T1F7150142F68140EDC42BC6784A515532F6A27C0B0B606EFF67955B2A1E3EAD0DF3EB11` |
| SSDEEP | `24576:W8FgJBXy+3Q8DV3pQgh4w/nZC8o68g+NT5BeXenCt/PbI8L:WX0KDzDLDWBd` |
| ICON-DHASH | `2851b27171b29408` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_017_35d34ec0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d34ec00a6610b3a90a4c2b6df568c119fe320899f698bff65632e023e34f69"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:23"
  condition:
    hash.sha256(0, filesize) == "35d34ec00a6610b3a90a4c2b6df568c119fe320899f698bff65632e023e34f69"
}
```

### Sample 18: `6d09632e3a4be09c`

| Field | Value |
|---|---|
| SHA-256 | `6d09632e3a4be09caabadb562ed7eac2a2b99eba1a3745d2ded9e05b251d85fd` |
| Family label | `njrat` |
| File name | `0baf09147567304bbba75d169a6c92cb.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:50:18` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0baf09147567304bbba75d169a6c92cb` |
| SHA-1 | `f2bec02090ea22ea686ebdb5ad4f361b32372f1b` |
| SHA-256 | `6d09632e3a4be09caabadb562ed7eac2a2b99eba1a3745d2ded9e05b251d85fd` |
| SHA3-384 | `3fdff4562fe3987bfc114fca55664519d7307491d67fb3b4b0e190054bbaa6c5364e5ec87cf77b31219df8ccedb96395` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19AA22A8EB7A88218C39D1EB44CA3231487F1F68B8951DF4B5CD950DE2F13AD15542AFD` |
| SSDEEP | `384:6W6ZUSl0XMz/s9ADAfJh6RmHTaOWQ+dcs//34LAZST3YP:r6ZUq0XOQ/xk8nWQuHqaP` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_018_6d09632e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d09632e3a4be09caabadb562ed7eac2a2b99eba1a3745d2ded9e05b251d85fd"
    family = "njrat"
    file_name = "0baf09147567304bbba75d169a6c92cb.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:18"
  condition:
    hash.sha256(0, filesize) == "6d09632e3a4be09caabadb562ed7eac2a2b99eba1a3745d2ded9e05b251d85fd"
}
```

### Sample 19: `95c9eca51d1099d7`

| Field | Value |
|---|---|
| SHA-256 | `95c9eca51d1099d7f4eab495222961b2bad03ea64c08175822b72d4141a3cae6` |
| Family label | `njrat` |
| File name | `1f3f689669e10696eaca535dec865bcc.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:50:12` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f3f689669e10696eaca535dec865bcc` |
| SHA-1 | `0d00d95b9707e3f4467a623a7d6f0bc6f9263f98` |
| SHA-256 | `95c9eca51d1099d7f4eab495222961b2bad03ea64c08175822b72d4141a3cae6` |
| SHA3-384 | `c5e708dd8bc8b2280ef5538c625b01cb93ea8c5d2c1aad4bc69a4a720b6b5ea6a21f91b0de7a9034cf0fad7beda96b66` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17DA2298E77548218D3AE1A7809E3232447F1FA8B8951DF4B1CDA50DA6F23AD06542FFD` |
| SSDEEP | `384:0W67USlmXM2b+6BIAfJhsD9mHAaOWQ+dcs//34LAZSTX1X:167UqmXry63xO8oWQuHqPX` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_019_95c9eca5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95c9eca51d1099d7f4eab495222961b2bad03ea64c08175822b72d4141a3cae6"
    family = "njrat"
    file_name = "1f3f689669e10696eaca535dec865bcc.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:12"
  condition:
    hash.sha256(0, filesize) == "95c9eca51d1099d7f4eab495222961b2bad03ea64c08175822b72d4141a3cae6"
}
```

### Sample 20: `473fac24fd67ef5c`

| Field | Value |
|---|---|
| SHA-256 | `473fac24fd67ef5c596d9b46b6db74b2ea2eb7931aed0a19a960d6a294730fe8` |
| Family label | `njrat` |
| File name | `0a1542f4c9f53aa1937648d22e46be78.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:50:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a1542f4c9f53aa1937648d22e46be78` |
| SHA-1 | `6e735a9c982d14e3879f6350bcb0eb01bb6f7a27` |
| SHA-256 | `473fac24fd67ef5c596d9b46b6db74b2ea2eb7931aed0a19a960d6a294730fe8` |
| SHA3-384 | `5c2f0ae01c6c7964a6a93ddd8e369afe1360efa859b68731ba9049637cd4587c1a08409b4a3ef7d941518349c1eb744f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T147A2198EB7548218D3AE1A7809E3232447F1FA8B8951DF4B1CDA50DA6F23AD05542FFD` |
| SSDEEP | `384:bW67USlmXM2b+6BIAfJhsD9mHAaOWQ+dcs//34LAZSTXvX:667UqmXry63xO8oWQuHqJX` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_020_473fac24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "473fac24fd67ef5c596d9b46b6db74b2ea2eb7931aed0a19a960d6a294730fe8"
    family = "njrat"
    file_name = "0a1542f4c9f53aa1937648d22e46be78.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:07"
  condition:
    hash.sha256(0, filesize) == "473fac24fd67ef5c596d9b46b6db74b2ea2eb7931aed0a19a960d6a294730fe8"
}
```

### Sample 21: `a1eb7ac383f39dd2`

| Field | Value |
|---|---|
| SHA-256 | `a1eb7ac383f39dd26c0e9a4b0536df58384dda3710ea6643fb19620b8e046cbd` |
| Family label | `unknown` |
| File name | `bot.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:50:05` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ecc5e31ab1755480dfe5958429db0a8d` |
| SHA-1 | `0d630fe542855387169eacefb49b2836e76666ec` |
| SHA-256 | `a1eb7ac383f39dd26c0e9a4b0536df58384dda3710ea6643fb19620b8e046cbd` |
| SHA3-384 | `d85789ca960a771012ebbb0c31ea1d513b2024b60f636a2a0f50e10a92d90e3d9c798937a3935892e1243e12d199363d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T181563907ECA555E9C0EAE2308A679212BB717C485B3123D36F50F7282F76BD0AE78754` |
| SSDEEP | `49152:0d9qTEJ7FBx9NEKU+1EITFhJeF4z0TllkQbyCxL+MgO1ek8v5k/fKiK9KYA6e5E:03peZyetTlKQeDXqUAtE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_a1eb7ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1eb7ac383f39dd26c0e9a4b0536df58384dda3710ea6643fb19620b8e046cbd"
    family = "unknown"
    file_name = "bot.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:05"
  condition:
    hash.sha256(0, filesize) == "a1eb7ac383f39dd26c0e9a4b0536df58384dda3710ea6643fb19620b8e046cbd"
}
```

### Sample 22: `59c315105c6dd7b1`

| Field | Value |
|---|---|
| SHA-256 | `59c315105c6dd7b1cca56a767974b53297cd4a8b043752e45cb19408401656bf` |
| Family label | `WARDENStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:49:58` |
| Reporter | `abuse_ch` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23b7c8cc26d1369cd06bce2973ab0edb` |
| SHA-1 | `9d0834f2568beb933cafd06b1fb6eccf2330d9fc` |
| SHA-256 | `59c315105c6dd7b1cca56a767974b53297cd4a8b043752e45cb19408401656bf` |
| SHA3-384 | `8966b76a8d7f546286488f066fea46a19e8735bc23b32051de30baf0488735a1ec2df431e2005a20449f390a953b81dd` |
| IMPHASH | `7135ad422ac078a74b14a9ab247cf804` |
| TLSH | `T1FB15F152F79644EEC52BC17886225636F6A17C470B20A7FF47942B1A1E3AAD1CF3DB10` |
| SSDEEP | `24576:XgzV0xEvyfL8661VnWgihZGhcx6JMm0sJ7J:XgzV0xMY8CnQT` |
| ICON-DHASH | `9671e8cccce87196` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_022_59c31510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59c315105c6dd7b1cca56a767974b53297cd4a8b043752e45cb19408401656bf"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:49:58"
  condition:
    hash.sha256(0, filesize) == "59c315105c6dd7b1cca56a767974b53297cd4a8b043752e45cb19408401656bf"
}
```

### Sample 23: `df712eff0fb0bc9e`

| Field | Value |
|---|---|
| SHA-256 | `df712eff0fb0bc9e37926002e1aad70edb1e03a7eb64403a82415cd461674f30` |
| Family label | `unknown` |
| File name | `sysd` |
| File type | `exe` |
| First seen | `2026-11-26 06:49:55` |
| Reporter | `abuse_ch` |
| Tags | `exe, sysd` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2df795bb77f2dae73cbac79a816d2ecd` |
| SHA-1 | `044b7a202e65d09bca2224026c2c6da880996494` |
| SHA-256 | `df712eff0fb0bc9e37926002e1aad70edb1e03a7eb64403a82415cd461674f30` |
| SHA3-384 | `a44a208e6461cd5f612767baf14ca8c22c18599b24607288db118cc7f50c5c78184c9b37faa61c84f170fee2ebc83059` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T198563907ECA555E9C0EAE2308A679212BB717C485B3123D36F50F7282F76BD0AE78754` |
| SSDEEP | `49152:0d9qTEJ7FBx9NEKU+1EITFhJeF4z0TllkQbyCxL+MgO1ek8v5k/fKiK9KYA6e5E:03peZyetTlKQeTXqUAtE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_df712eff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df712eff0fb0bc9e37926002e1aad70edb1e03a7eb64403a82415cd461674f30"
    family = "unknown"
    file_name = "sysd"
    file_type = "exe"
    first_seen = "2026-11-26 06:49:55"
  condition:
    hash.sha256(0, filesize) == "df712eff0fb0bc9e37926002e1aad70edb1e03a7eb64403a82415cd461674f30"
}
```

### Sample 24: `95ecf420c6c9650f`

| Field | Value |
|---|---|
| SHA-256 | `95ecf420c6c9650f7080eca8860b577990a8284ff2f4613a6b44056e15127fad` |
| Family label | `WARDENStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:49:38` |
| Reporter | `abuse_ch` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c007ac9f3bec3ea32ba23e7582151ded` |
| SHA-1 | `ec24602e7eb13c0eff1890b1307cd27091d384a9` |
| SHA-256 | `95ecf420c6c9650f7080eca8860b577990a8284ff2f4613a6b44056e15127fad` |
| SHA3-384 | `dcb40121b7ed825aec5bbee982cdd79858b9f3a2953a81ad0ad2594d4a850377baca1e49f15936792baaa22e9c68af47` |
| IMPHASH | `00c2e8725512a35c6da648c24593a4fc` |
| TLSH | `T1C5150152F7D900EDC437D27889128532F6A67C076B70AEEB1765066D0E3AAD09F3EB50` |
| SSDEEP | `24576:eSFwaN46fMTocxQlYTiMYCAP9b/OaLYghs1:eSFR/2lxQlL3fPXLd` |
| ICON-DHASH | `08341272b1125a24` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_024_95ecf420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95ecf420c6c9650f7080eca8860b577990a8284ff2f4613a6b44056e15127fad"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:49:38"
  condition:
    hash.sha256(0, filesize) == "95ecf420c6c9650f7080eca8860b577990a8284ff2f4613a6b44056e15127fad"
}
```

### Sample 25: `128ac40378b231c0`

| Field | Value |
|---|---|
| SHA-256 | `128ac40378b231c03ec490ee2628cc0b02e1a113314beff6f0b1d71f1723a7b1` |
| Family label | `unknown` |
| File name | `Ikov.jar` |
| File type | `jar` |
| First seen | `2026-11-26 06:49:35` |
| Reporter | `abuse_ch` |
| Tags | `jar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66646ba25b3fb8f4c7362d688c8aef71` |
| SHA-1 | `b09de513c1655b90bb735ade1c847e37884a8af1` |
| SHA-256 | `128ac40378b231c03ec490ee2628cc0b02e1a113314beff6f0b1d71f1723a7b1` |
| SHA3-384 | `4e0893f85a04b6b04539b4d74436cf38eacbb24a6aa8fa7cd51ab6443231d9d0f4dcece27c59c2492f29ffc4df5caf76` |
| TLSH | `T1CB072323BEDEC92DDA6755B391D38182647F65A4AC0B807E03985DC6CA20C4B1753FFA` |
| SSDEEP | `393216:aIIPaQysuMfCS8/EJ6pGBw1i8nJ0Hp+tR/qPyHJf3CADsop:fIJysuMfyEopGa1nJgeR5HJvjjp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_128ac403
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "128ac40378b231c03ec490ee2628cc0b02e1a113314beff6f0b1d71f1723a7b1"
    family = "unknown"
    file_name = "Ikov.jar"
    file_type = "jar"
    first_seen = "2026-11-26 06:49:35"
  condition:
    hash.sha256(0, filesize) == "128ac40378b231c03ec490ee2628cc0b02e1a113314beff6f0b1d71f1723a7b1"
}
```

### Sample 26: `eb1c3d52bd01ed52`

| Field | Value |
|---|---|
| SHA-256 | `eb1c3d52bd01ed52a6d87cdf908fcae036723f7b413360ad09df130368520210` |
| Family label | `SnappyClient` |
| File name | `1.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:48:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SnappyClient` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4538fabe78f03912212a302b2e23781` |
| SHA-1 | `b24db8e6f39d0349c434b7405a617854514bc456` |
| SHA-256 | `eb1c3d52bd01ed52a6d87cdf908fcae036723f7b413360ad09df130368520210` |
| SHA3-384 | `d7075494a5b59d2f6201013b6c07fa0c57b2ddb3809eac8d5c730e3662f805902a09ed2e08228aa85b7e8c8e2004be8a` |
| IMPHASH | `b5a014d7eeb4c2042897567e1288a095` |
| TLSH | `T1A5963383B3B518F8C4A181729FE8DB46D131DB6C5B525E5A03C98F263EB32B26603DD5` |
| SSDEEP | `196608:+pbj5ix+wywSBcWyJ8EPhydVh3oPekIAJzMvFtEVgn/e8j4klzeOE+Ay:+pbj5SdBWxUUVh3YeXyoEueSlzgy` |
| ICON-DHASH | `c292ecd8f2f6fe1c` |

#### Technical Assessment

- The sample is tracked as `SnappyClient` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SnappyClient_026_eb1c3d52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb1c3d52bd01ed52a6d87cdf908fcae036723f7b413360ad09df130368520210"
    family = "SnappyClient"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:48:59"
  condition:
    hash.sha256(0, filesize) == "eb1c3d52bd01ed52a6d87cdf908fcae036723f7b413360ad09df130368520210"
}
```

### Sample 27: `0d58852a37057c6d`

| Field | Value |
|---|---|
| SHA-256 | `0d58852a37057c6dcda37c1f956d1463bd78b8bb8f3475bdf8dde1acc7e0bdf9` |
| Family label | `Formbook` |
| File name | `Permintaan Penawaran Harga Nov. 2026.vbe` |
| File type | `vbe` |
| First seen | `2026-11-26 06:48:24` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a18a0f6d383621f60abebbc94b94689a` |
| SHA-1 | `aa2a6c665fcf42c58b029ac33b60b210385299a1` |
| SHA-256 | `0d58852a37057c6dcda37c1f956d1463bd78b8bb8f3475bdf8dde1acc7e0bdf9` |
| SHA3-384 | `836d9da34ff244edb499e0e9834ba5c33cf52e187890a1c1ddbad3b7f445a4b141db47aff8fb0149edd41d33038ca7c2` |
| TLSH | `T1B5910D0F6D06E2724576CABACD2FA42FDBE0115B9949A814701C92832F3077EE57D5E8` |
| SSDEEP | `96:FZMf1AbgF3Yxg0N/hEB64cW/j/EeJE34c/uhZ2kp14h/YJdX/ywFug:A2bgF38/45/j/W/6Z2k8/YH/V` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_027_0d58852a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d58852a37057c6dcda37c1f956d1463bd78b8bb8f3475bdf8dde1acc7e0bdf9"
    family = "Formbook"
    file_name = "Permintaan Penawaran Harga Nov. 2026.vbe"
    file_type = "vbe"
    first_seen = "2026-11-26 06:48:24"
  condition:
    hash.sha256(0, filesize) == "0d58852a37057c6dcda37c1f956d1463bd78b8bb8f3475bdf8dde1acc7e0bdf9"
}
```

### Sample 28: `1e46feda5f8e095f`

| Field | Value |
|---|---|
| SHA-256 | `1e46feda5f8e095f291ee5f696bbc982db4c5005170423c22a13f3031d8b28ab` |
| Family label | `unknown` |
| File name | `TSSA_0947_262611.vbe` |
| File type | `vbe` |
| First seen | `2026-11-26 06:48:21` |
| Reporter | `abuse_ch` |
| Tags | `vbe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31a13b0c34fc288b9ea2fd4bd84acc63` |
| SHA-1 | `f5fab007cb5e28f630c1222e05a60aaa5bfd3fa9` |
| SHA-256 | `1e46feda5f8e095f291ee5f696bbc982db4c5005170423c22a13f3031d8b28ab` |
| SHA3-384 | `b14a258cb111024887d66db1e366ed6af70e06305482081b38804cccdd9636737c084fb994d4e5fdc0bdf633b5b889e0` |
| TLSH | `T137023117FE07F133C4F2CD67A86BA45AE76610136A9604107D9C81862F3275F96EC4FA` |
| SSDEEP | `192:RZVheAi0+w/Y/GEhc/o4kQ8/v1XW/TR/U7/RSw2uO/6:vDeAR+8F/Hi0C7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_1e46feda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e46feda5f8e095f291ee5f696bbc982db4c5005170423c22a13f3031d8b28ab"
    family = "unknown"
    file_name = "TSSA_0947_262611.vbe"
    file_type = "vbe"
    first_seen = "2026-11-26 06:48:21"
  condition:
    hash.sha256(0, filesize) == "1e46feda5f8e095f291ee5f696bbc982db4c5005170423c22a13f3031d8b28ab"
}
```

### Sample 29: `47ae865c1ad1abd1`

| Field | Value |
|---|---|
| SHA-256 | `47ae865c1ad1abd1c35bd1b8a02550c7a5410273439eebcace33ab6e7f316fcb` |
| Family label | `AsyncRAT` |
| File name | `PAGO PROVEEDOR _EBERSPAECHER.js` |
| File type | `js` |
| First seen | `2026-11-26 06:48:02` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, js, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cffcb92379749a993036415acc2add25` |
| SHA-1 | `4c56dc75e4bb431bfaa74fd26822d8537abbb671` |
| SHA-256 | `47ae865c1ad1abd1c35bd1b8a02550c7a5410273439eebcace33ab6e7f316fcb` |
| SHA3-384 | `112a49157ebae6274d28d8f3a01e12bd5c73909de008433dd3db3988349b4d2b2fb574e05ad8efd1e3fd4846ea6d09a3` |
| TLSH | `T14753C00B4AE6116411421A3D476F6211A1DF143F1C1EF18977ACE1A73FBEAE00F7AA67` |
| SSDEEP | `1536:rqrUyMKZ9nTCAb+aRdy8ZTuyjcGcGfLbUAGa:uUyMKZ9TvLzZiyIKfLt` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_029_47ae865c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47ae865c1ad1abd1c35bd1b8a02550c7a5410273439eebcace33ab6e7f316fcb"
    family = "AsyncRAT"
    file_name = "PAGO PROVEEDOR _EBERSPAECHER.js"
    file_type = "js"
    first_seen = "2026-11-26 06:48:02"
  condition:
    hash.sha256(0, filesize) == "47ae865c1ad1abd1c35bd1b8a02550c7a5410273439eebcace33ab6e7f316fcb"
}
```

### Sample 30: `8228dbfd21179528`

| Field | Value |
|---|---|
| SHA-256 | `8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa` |
| Family label | `XWorm` |
| File name | `Comprobante PDF - 2026-11-26T164039.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:58` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `134053953cc100695d429b396c6a63e7` |
| SHA-1 | `4315ddb5c98e4dfd63434528c68f84493e4210eb` |
| SHA-256 | `8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa` |
| SHA3-384 | `70e01fa4a7059e711d01511fd3f65f82dba86f3088904aacbe603841e7ddc5cdd48edcca0242e5c783054520c30e6120` |
| TLSH | `T17216A442AB8490327F246B5CC27AA930581A504354C2EF333AFDD6197B58D57A7FCAE3` |
| SSDEEP | `98304:kaNZKxgJqMxSXm1Mbe7k/5hjLswJXvHtHHtKSi5fy1X6hSS0GxatPSpTLt2PeweT:RN6Zby7k/3sCHtHliW6AIx469aFW` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_030_8228dbfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa"
    family = "XWorm"
    file_name = "Comprobante PDF - 2026-11-26T164039.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:58"
  condition:
    hash.sha256(0, filesize) == "8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa"
}
```

### Sample 31: `15e545dd76205cc6`

| Field | Value |
|---|---|
| SHA-256 | `15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1` |
| Family label | `AgentTesla` |
| File name | `Curriculum vitae.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:55` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72be9fba54ed515a3be3e2b0b0a38e3f` |
| SHA-1 | `108d11fdfba40b589b56999775fd1e13f759f6ca` |
| SHA-256 | `15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1` |
| SHA3-384 | `917e2f669863a6c7960fae505cc9113532308cd44c4d4b6402257c638e89184f8a29201de92a10d5a772d72a0306ed6e` |
| TLSH | `T16536F652D608A870AE7E672CD07A6A500A1921176285FF3F3BFC4644B392B1767FD4E3` |
| SSDEEP | `98304:rcCFpxcAmZM4SDD6SnoB/8Iqhkb0bqpoEovjih+MF4xR8mCzFEmGfhQG9CRMIG9c:LDv+06GHSejhQ8UtU7/ckTsFhTd` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_031_15e545dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1"
    family = "AgentTesla"
    file_name = "Curriculum vitae.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:55"
  condition:
    hash.sha256(0, filesize) == "15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1"
}
```

### Sample 32: `b044838e9f77994b`

| Field | Value |
|---|---|
| SHA-256 | `b044838e9f77994bae0b9b4a6cd0e07e35c3059988d33a23931e967af52faf82` |
| Family label | `Formbook` |
| File name | `29092684116444.Pdf.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:51` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57d47fcd18ba0611ddc4b18284f8c34d` |
| SHA-1 | `0852c7c48b566f0344e2ebdf68db19377ce8280b` |
| SHA-256 | `b044838e9f77994bae0b9b4a6cd0e07e35c3059988d33a23931e967af52faf82` |
| SHA3-384 | `2a4b8126a09132625aa797ddc1c0c7447fa8856596bfa50ad40d0c5752ca6b20a868790a7a9022bad905da18edc1b946` |
| TLSH | `T10D36C586A784A1327B65A75CC2369930A90A544354C2DF333AFDD218775CD1BA3FCAE3` |
| SSDEEP | `98304:fK+X7wzqA6obFsjTM1xn3hDSNUNfkzins371jEsjujvtLTElHiJ+y8/J1Y1SeqoG:fK+X7wzqA6obFsjTM3hD/XnsVCvtHKoK` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_032_b044838e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b044838e9f77994bae0b9b4a6cd0e07e35c3059988d33a23931e967af52faf82"
    family = "Formbook"
    file_name = "29092684116444.Pdf.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:51"
  condition:
    hash.sha256(0, filesize) == "b044838e9f77994bae0b9b4a6cd0e07e35c3059988d33a23931e967af52faf82"
}
```

### Sample 33: `7e7ca98773b9f2ba`

| Field | Value |
|---|---|
| SHA-256 | `7e7ca98773b9f2ba0b0d5d0a448600c4fb9b981f1e7710f8194b41ee77064e56` |
| Family label | `Formbook` |
| File name | `BBK_Payment Advice-OCT SOA-PDF.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:48` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb93f66a5d31144b3d985ada9454022c` |
| SHA-1 | `bd42c72ca002efd050987d6a5247d64f74c7ed88` |
| SHA-256 | `7e7ca98773b9f2ba0b0d5d0a448600c4fb9b981f1e7710f8194b41ee77064e56` |
| SHA3-384 | `64c97ec56f45acaae3f91ef636301105ac8721d3e582dd5f231fe003a4671e85f8870db7507f5b44779e4e093a0f83b3` |
| TLSH | `T15F360A86AAD492333B21AB99C23DDD30A90A45431441CB377FFDE618371CD4AA6BC767` |
| SSDEEP | `98304:Hry90cIt+pWTmclhzT7akEzUkWcNkHXTKgYp0EvX36WaffDu59429KWCB2baE+fo:Hry90cIt+pWTmclhzT7akEzUkWcNkHXq` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_033_7e7ca987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e7ca98773b9f2ba0b0d5d0a448600c4fb9b981f1e7710f8194b41ee77064e56"
    family = "Formbook"
    file_name = "BBK_Payment Advice-OCT SOA-PDF.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:48"
  condition:
    hash.sha256(0, filesize) == "7e7ca98773b9f2ba0b0d5d0a448600c4fb9b981f1e7710f8194b41ee77064e56"
}
```

### Sample 34: `3f5428de8294f7ee`

| Field | Value |
|---|---|
| SHA-256 | `3f5428de8294f7ee820aa77d092164d02c54cbb1fdd110eb9999ef68de540e31` |
| Family label | `unknown` |
| File name | `New Purchase Order.js` |
| File type | `js` |
| First seen | `2026-11-26 06:47:45` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6f6d3c4928d956316934bfddaae81b9` |
| SHA-1 | `a275d6f0d6ffbbd7f5430e23e3bee119a9889bef` |
| SHA-256 | `3f5428de8294f7ee820aa77d092164d02c54cbb1fdd110eb9999ef68de540e31` |
| SHA3-384 | `12f6370eed0337a00cf5b5fd1313e602f3076e3659ef954673058edf3c1d7d3ab65bb090b216d69fe70f347b83cd29a3` |
| TLSH | `T17521E494D565D0654617329A822ED50CDAD664427B84D132768CDB5C3F30C706ED98E1` |
| SSDEEP | `24:BJcLY/l6bmBorfKnvVO+KKiL+6H4ql3UTUkV0PePFuYwyqyOHLeWf:bcLY/lqR7Knv8lIRVHkyqRHB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_3f5428de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f5428de8294f7ee820aa77d092164d02c54cbb1fdd110eb9999ef68de540e31"
    family = "unknown"
    file_name = "New Purchase Order.js"
    file_type = "js"
    first_seen = "2026-11-26 06:47:45"
  condition:
    hash.sha256(0, filesize) == "3f5428de8294f7ee820aa77d092164d02c54cbb1fdd110eb9999ef68de540e31"
}
```

### Sample 35: `b0a3a6f22d097483`

| Field | Value |
|---|---|
| SHA-256 | `b0a3a6f22d097483fae5d601ee018a235f5922d62219e01283b2a614165d2eba` |
| Family label | `unknown` |
| File name | `PO-2062060 - HOWYOU.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:42` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca32f488918b2b16cf91c2748133044a` |
| SHA-1 | `425402d21935055b72ff98d4fd557df956d014bb` |
| SHA-256 | `b0a3a6f22d097483fae5d601ee018a235f5922d62219e01283b2a614165d2eba` |
| SHA3-384 | `e97fc4fdbb995d3ad63029cfef5914d7d2a3fafad38246b185df6afc497fed04d6641fdda268761b65f10e2884f45f1c` |
| TLSH | `T18C26C4529744A432BE2D671CC23A9A20581A610355C6EF3F3AFCD6147758E17A3FCAE3` |
| SSDEEP | `98304:UwKhAzjbBkmu0M9GrcWi6egwGfRD3JH2UqW3rTn3CHbZrR+UIEEpL2wyHvqEcmz:9rcWagffFIxST3SFVSxkfz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_b0a3a6f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0a3a6f22d097483fae5d601ee018a235f5922d62219e01283b2a614165d2eba"
    family = "unknown"
    file_name = "PO-2062060 - HOWYOU.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:42"
  condition:
    hash.sha256(0, filesize) == "b0a3a6f22d097483fae5d601ee018a235f5922d62219e01283b2a614165d2eba"
}
```

### Sample 36: `c9148ab32c4ae2fd`

| Field | Value |
|---|---|
| SHA-256 | `c9148ab32c4ae2fd683384f7d59226bc56c1620f8564cd913a1d47bb3bf1510e` |
| Family label | `unknown` |
| File name | `PIT00027301pdf.js` |
| File type | `js` |
| First seen | `2026-11-26 06:47:39` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf5312a2629b2cca701f28bd364e90e6` |
| SHA-1 | `7a650b593270d147314698afb49021fbae033624` |
| SHA-256 | `c9148ab32c4ae2fd683384f7d59226bc56c1620f8564cd913a1d47bb3bf1510e` |
| SHA3-384 | `b12dc56e48285d8fc31702d3c16e2d29291a7cfd0f89f00b67dc3480d126c322922babbc9aecb7d3c56883245117a4eb` |
| TLSH | `T134F27C50DD2756BA4E131BC4FD990A38CEBC0207852641A1F2EE631A1622ECCD7FD5EE` |
| SSDEEP | `768:oygZfvUN/B1Lrn87MWRUnhLMXYma2E9wOzKx8Fx:oxfcKRoMo/9w8Kx8Fx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_c9148ab3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9148ab32c4ae2fd683384f7d59226bc56c1620f8564cd913a1d47bb3bf1510e"
    family = "unknown"
    file_name = "PIT00027301pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:47:39"
  condition:
    hash.sha256(0, filesize) == "c9148ab32c4ae2fd683384f7d59226bc56c1620f8564cd913a1d47bb3bf1510e"
}
```

### Sample 37: `eb362791a0f98c39`

| Field | Value |
|---|---|
| SHA-256 | `eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa` |
| Family label | `AgentTesla` |
| File name | `RFQ180813.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:36` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2fdf5bf8c1bdcaba58511770ac6c78a7` |
| SHA-1 | `6d283cb6a98f1d2cd7e86ace9c7dff7f1ff4eef6` |
| SHA-256 | `eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa` |
| SHA3-384 | `c9b1c7f793e26480e866d041902a9508446785b2d0b224b536145888690732470bc3bd94ffd14aae079ef22b93cf815a` |
| TLSH | `T12816B285E380A2327F21AB8DD27A9931580A544365C5DB333AFDD2153B5CD4BA3BC6E3` |
| SSDEEP | `98304:ECiCzmMBmlqGt6yhxu+PQOx6fKFg5OVcjyJxWmO95/2owtrs6GCuxPH9iWEw838u:ECiCzmMBmlqGt6yhxu+PQFfKFgYSW2vA` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_037_eb362791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa"
    family = "AgentTesla"
    file_name = "RFQ180813.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:36"
  condition:
    hash.sha256(0, filesize) == "eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa"
}
```

### Sample 38: `7965c7bf90e8c255`

| Field | Value |
|---|---|
| SHA-256 | `7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768` |
| Family label | `AgentTesla` |
| File name | `payment-invoice.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:26` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `504a3fed37fbc1d3b17ff20bc49d0028` |
| SHA-1 | `5147e13747b7dabf5006a3c1a6c2f6f6e16a44d7` |
| SHA-256 | `7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768` |
| SHA3-384 | `a4c212d3734fe7deeb1f3b4e36ec62970267b9b1c4ddd56fe1cf86634802cc4d6ce3e0b92e46b83ff5e7d12fef455d2d` |
| TLSH | `T18936C446A79491727B20AB8CC23AED30950A95435482DB333AFDD618775CD4BA3FC6E3` |
| SSDEEP | `98304:VAm4pjGzdqmjDQFVTo3vj4xKoZPNMsVt+ILCTfJHWsotu5R/8TAbpa/rTuTzuGIn:VAm4pjGzdqmjDuV03vj4xKobn+sCt1oB` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_038_7965c7bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768"
    family = "AgentTesla"
    file_name = "payment-invoice.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:26"
  condition:
    hash.sha256(0, filesize) == "7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768"
}
```

### Sample 39: `2dd56382a3883bd4`

| Field | Value |
|---|---|
| SHA-256 | `2dd56382a3883bd46ec6bbc06e43ac35ae36274e182980d6a5f7cfd8ce4e1abf` |
| Family label | `Formbook` |
| File name | `Invoice.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:20` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ba9db45eee486ef21b64e6b59e3221f` |
| SHA-1 | `5192d5376abe65af1fdf1907870807214c3a0d69` |
| SHA-256 | `2dd56382a3883bd46ec6bbc06e43ac35ae36274e182980d6a5f7cfd8ce4e1abf` |
| SHA3-384 | `d811aa882f5015ef22239b6f4648ef891f0a5b20eb7ef4af927995f87b71bb90860a67c51c35a13f22c0b9e1e28588e9` |
| TLSH | `T18436C686A78491727B65A75CC23A9930A80A540355C1DF333AFDD6187B1CD1BA3FCAE3` |
| SSDEEP | `98304:+Afx9/Ox8f+n5CZ5zImxA5g+wd89OERRv93yZqeERzmXPIn0u6mVwG8kgKdKeqLh:+Afx9/Ox8f+n5CZ5zImxA5g+wd893RRO` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_039_2dd56382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd56382a3883bd46ec6bbc06e43ac35ae36274e182980d6a5f7cfd8ce4e1abf"
    family = "Formbook"
    file_name = "Invoice.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:20"
  condition:
    hash.sha256(0, filesize) == "2dd56382a3883bd46ec6bbc06e43ac35ae36274e182980d6a5f7cfd8ce4e1abf"
}
```

### Sample 40: `dab45baa839f4136`

| Field | Value |
|---|---|
| SHA-256 | `dab45baa839f4136fc1beedea78f7a273b363b166b4cd3cbc6c599ed751f1df5` |
| Family label | `Formbook` |
| File name | `Payment-Invoice9765.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:11` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ed0301dc3731d3a1ebbe2e856b9062e` |
| SHA-1 | `3f9585b3e5873850b17bc1212cae0e9d5f25763c` |
| SHA-256 | `dab45baa839f4136fc1beedea78f7a273b363b166b4cd3cbc6c599ed751f1df5` |
| SHA3-384 | `36bf4d63d035b5d3cccf67e5cc633e3805a610492e54bedee22af892da984921410471a4d4c1c3be8b5cd823f8b35041` |
| TLSH | `T10E36D786A785A2337B25AB9CC13AD930A40A540354C5DB373AFDD618371CD5BA3BC6E3` |
| SSDEEP | `98304:YpIacpHx4vlLxUq68GBfdyltrGSdjYsoOj92rCPg89J2U0LsFH26BFHcT/HgBOK3:YpIacpHx4vlLxUq68GBfdyltrGSdjYsx` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_040_dab45baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dab45baa839f4136fc1beedea78f7a273b363b166b4cd3cbc6c599ed751f1df5"
    family = "Formbook"
    file_name = "Payment-Invoice9765.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:11"
  condition:
    hash.sha256(0, filesize) == "dab45baa839f4136fc1beedea78f7a273b363b166b4cd3cbc6c599ed751f1df5"
}
```

### Sample 41: `27231f6d7f7d07ab`

| Field | Value |
|---|---|
| SHA-256 | `27231f6d7f7d07abbca294874cf8a09ce35a6d987259a2ddbf1c41d3206f2d78` |
| Family label | `unknown` |
| File name | `PURCHASE-RFQ-SC5681.js` |
| File type | `js` |
| First seen | `2026-11-26 06:47:08` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36385e178011f8c377f9aa7672d3a41f` |
| SHA-1 | `2bdb12434aa58ddd84a258dd748d3ec26ae737bd` |
| SHA-256 | `27231f6d7f7d07abbca294874cf8a09ce35a6d987259a2ddbf1c41d3206f2d78` |
| SHA3-384 | `a3e68d7b9fcb4ff29cc6b2f5881e5ce94e258d135e12bfc485338237880dfdaa7d37a03f66352208da4e24d75fe123db` |
| TLSH | `T1D7639442C3C68354E2452DA4851A630DF6FF9413F7B54CC3A6FA59EFAA2FDD0E064628` |
| SSDEEP | `1536:/HeHyS5RKkfXznhilikfYOTIvHUZB9bYLuK:2SSNkd4kLUuK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_27231f6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27231f6d7f7d07abbca294874cf8a09ce35a6d987259a2ddbf1c41d3206f2d78"
    family = "unknown"
    file_name = "PURCHASE-RFQ-SC5681.js"
    file_type = "js"
    first_seen = "2026-11-26 06:47:08"
  condition:
    hash.sha256(0, filesize) == "27231f6d7f7d07abbca294874cf8a09ce35a6d987259a2ddbf1c41d3206f2d78"
}
```

### Sample 42: `eb6187b82408366b`

| Field | Value |
|---|---|
| SHA-256 | `eb6187b82408366bd31b890db5e81519cf5dd504105b08eb83408b4a0b6ed09e` |
| Family label | `unknown` |
| File name | `PO-0001334282.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:47:05` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `717ece5447368480bc9d6a50d8280abd` |
| SHA-1 | `60b5167e5623cf23440042ec9595a59cdbb0ff29` |
| SHA-256 | `eb6187b82408366bd31b890db5e81519cf5dd504105b08eb83408b4a0b6ed09e` |
| SHA3-384 | `2e5d672cd6b3f3e2f58b40c2681a6fd20e85f374064b5266255f77cb78dd627a5e9b06dabc1d32e7cdb27da6089460a7` |
| TLSH | `T172363948E484B755DCAC1D50CE1E2FCA163D2687DB10D82B3BFC95E52B89B9221FD12B` |
| SSDEEP | `98304:BL3/gAC26D/PYhwrCGCalxR6rJ22eLcJgUEnTelzwaWQTqDNwtOS1O/vI468ePFz:BLzqzawrCfMxosrLcaTuWQTqRK8/vHpk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_eb6187b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb6187b82408366bd31b890db5e81519cf5dd504105b08eb83408b4a0b6ed09e"
    family = "unknown"
    file_name = "PO-0001334282.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:05"
  condition:
    hash.sha256(0, filesize) == "eb6187b82408366bd31b890db5e81519cf5dd504105b08eb83408b4a0b6ed09e"
}
```

### Sample 43: `922112f27b5e470b`

| Field | Value |
|---|---|
| SHA-256 | `922112f27b5e470b6e8fe32879cac3f392a796b725c07a46722eb1e2dcd14712` |
| Family label | `RemcosRAT` |
| File name | `Revised PO Order.js` |
| File type | `js` |
| First seen | `2026-11-26 06:46:40` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc44e2ec99716f1443c4bcb3927ce32f` |
| SHA-1 | `c3624a701023c6ec1882d8ec1c558a236a38c7a5` |
| SHA-256 | `922112f27b5e470b6e8fe32879cac3f392a796b725c07a46722eb1e2dcd14712` |
| SHA3-384 | `fcaa1cf81e6dcf79d5b08c2a6a82f7fabfc9706608f5c809a395bafa3847dcadd04b890f4b9ad5e82c6421af7f8ab34c` |
| TLSH | `T19856CC244B886738146B470C75AA2FCDBFC4DEC524C992DEA3A944B1FAD57C2AEC740D` |
| SSDEEP | `24576:h4NujptzCQnYeMcBnX7lDFzNLjdW8xmllBLWxrdAE9Ed//7r2sPGZI+oDUGeC7LE:HXMcBrDWcmKc3DlTNPa7` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_043_922112f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "922112f27b5e470b6e8fe32879cac3f392a796b725c07a46722eb1e2dcd14712"
    family = "RemcosRAT"
    file_name = "Revised PO Order.js"
    file_type = "js"
    first_seen = "2026-11-26 06:46:40"
  condition:
    hash.sha256(0, filesize) == "922112f27b5e470b6e8fe32879cac3f392a796b725c07a46722eb1e2dcd14712"
}
```

### Sample 44: `ebc2f78345184618`

| Field | Value |
|---|---|
| SHA-256 | `ebc2f783451846183d6c435a952fd8223b1f81154d58e6d749c0ca175cd1c2f9` |
| Family label | `unknown` |
| File name | `PO#2026.1194.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:46:32` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11df61496783d66822b19cc7e1416707` |
| SHA-1 | `3d568db8a722074c7ca8fe6140f7f74062420b01` |
| SHA-256 | `ebc2f783451846183d6c435a952fd8223b1f81154d58e6d749c0ca175cd1c2f9` |
| SHA3-384 | `c005ade503d5a1fcd460acb4919872d1e15981a9c5f38afbfb3e277ebe8a0b88abf6c3564d9b056cc03c560f16bec149` |
| TLSH | `T1A326A242A784A0327B296B5CD236D931681A504364C6DB3B3AFCD654771CD1BA3FCAE3` |
| SSDEEP | `98304:iXlGVotJQ182TCugeV3VvKqSRpS7XDKnHU+6PW7ebIP2xgnjHgoIKKhJ58bBw1wz:3oKBg0CuT6+xurlT3qSltbJB2SP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_ebc2f783
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebc2f783451846183d6c435a952fd8223b1f81154d58e6d749c0ca175cd1c2f9"
    family = "unknown"
    file_name = "PO#2026.1194.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:32"
  condition:
    hash.sha256(0, filesize) == "ebc2f783451846183d6c435a952fd8223b1f81154d58e6d749c0ca175cd1c2f9"
}
```

### Sample 45: `27b79c3e852e0c55`

| Field | Value |
|---|---|
| SHA-256 | `27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57` |
| Family label | `XWorm` |
| File name | `Reckless Driver Cam 5 Photos 20261126SKM.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:46:24` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2cc18cbe9ced9d9a4c8444d8b587d265` |
| SHA-1 | `b1141c3babc94a797fe2d305c5730e32c2ca0a39` |
| SHA-256 | `27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57` |
| SHA3-384 | `ac7466b4f5694d31b9caca69587cd382c17d74ec7f02697699129c00e8b7bd622bb4493c45921df8c089739599ad9993` |
| TLSH | `T10616B346E708A4316E6D671CC176A920191A210361C5EF3F3BFC96597361E1BA3FCAE3` |
| SSDEEP | `98304:YBXZ+x7PgFIgl6uQ22Gs5JHqJjLEv1ukP/sgfW7C1kc7dG1xmZL55:SXZMgagIu1PsbQ4k0z5` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_045_27b79c3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57"
    family = "XWorm"
    file_name = "Reckless Driver Cam 5 Photos 20261126SKM.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:24"
  condition:
    hash.sha256(0, filesize) == "27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57"
}
```

### Sample 46: `4eced92a45627ced`

| Field | Value |
|---|---|
| SHA-256 | `4eced92a45627ced182aeff6ad2f5f520eeccb579c35aeb8e8388260b05f8823` |
| Family label | `Formbook` |
| File name | `RFQ-TM262581 MMGENERALTRADING.pdf.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:46:20` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3baeb8b3a4953195709096e22e95f04f` |
| SHA-1 | `87b3a8d1c18b732af25619819375f6470f55afea` |
| SHA-256 | `4eced92a45627ced182aeff6ad2f5f520eeccb579c35aeb8e8388260b05f8823` |
| SHA3-384 | `a34c98e7cea91b88828d106a2438b098245a111640b5d363534d6cc6b622f3ea7d4a9ba5aca4495fff265caaf3cd37b0` |
| TLSH | `T169360986AAD492333B21AB99C23EDD31A41A85431441DB337FFDE618371CD49A2BC767` |
| SSDEEP | `98304:WRMY01raKodYecjrRDyjAfln3bW2T1R1N7LiVOa7MsarHj7QEA7Je9g6xSjvkkc0:WRMY01raKodYecjrRDyjAfln3bW2T1RG` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_046_4eced92a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eced92a45627ced182aeff6ad2f5f520eeccb579c35aeb8e8388260b05f8823"
    family = "Formbook"
    file_name = "RFQ-TM262581 MMGENERALTRADING.pdf.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:20"
  condition:
    hash.sha256(0, filesize) == "4eced92a45627ced182aeff6ad2f5f520eeccb579c35aeb8e8388260b05f8823"
}
```

### Sample 47: `c4e39f47a0613d48`

| Field | Value |
|---|---|
| SHA-256 | `c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0` |
| Family label | `AgentTesla` |
| File name | `SOA 610952480.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:46:17` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00353b29bc608c1a4e2d7d3a288c2fbe` |
| SHA-1 | `55bfd41d7a1da06586f926bd2bf3e80580edab81` |
| SHA-256 | `c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0` |
| SHA3-384 | `87f7869c3d74f001e3f5f2b2113c3812eb911c82433c6fe44c0d9bf2283ba3c43e92615cb41fa7ed3743e37e5ae2ac0a` |
| TLSH | `T11D36C442A744A432BE2D675CC1769920590A204365C6EF3F3AFDD2147768E17A3FCAE3` |
| SSDEEP | `98304:pQbhpE28GvaIFgGAARqHsEoG0zDQ0mzoxYp18D0yjxoGCKnv8Mxd9KVsc4LeHD8Y:pQlpE28GvaIDnR6sTGEDLYbyFkKvdrK7` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_047_c4e39f47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0"
    family = "AgentTesla"
    file_name = "SOA 610952480.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:17"
  condition:
    hash.sha256(0, filesize) == "c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0"
}
```

### Sample 48: `abcab64d869df02a`

| Field | Value |
|---|---|
| SHA-256 | `abcab64d869df02accdf6b1269cb0d204096ef57cc07580312bf928e58246f55` |
| Family label | `unknown` |
| File name | `ใบสั่งซื้อใหม่_PO24100034.pdf.js` |
| File type | `js` |
| First seen | `2026-11-26 06:46:04` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63ac5b15165e386f1bbe2554b3868d5e` |
| SHA-1 | `5031bfc17c427f67f70f3e10686eb9faa688d938` |
| SHA-256 | `abcab64d869df02accdf6b1269cb0d204096ef57cc07580312bf928e58246f55` |
| SHA3-384 | `fb1fd0d34685d0b8de0873160a12ff130169375d96653d5b3212dd1ce27cd40a8e3a18a79fc9550c43d7299d7f295f2a` |
| TLSH | `T104A412D02BA2697FC6E0C32578AE670C19BCA3131D4D664FCEB971CA4F6EF916245E04` |
| SSDEEP | `12288:0zvLovyvFqrxaniKJjJyugUao+korC4fR:65vFqrxaiKThYkh4J` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_abcab64d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abcab64d869df02accdf6b1269cb0d204096ef57cc07580312bf928e58246f55"
    family = "unknown"
    file_name = "ใบสั่งซื้อใหม่_PO24100034.pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:46:04"
  condition:
    hash.sha256(0, filesize) == "abcab64d869df02accdf6b1269cb0d204096ef57cc07580312bf928e58246f55"
}
```

### Sample 49: `1c505207dc503f37`

| Field | Value |
|---|---|
| SHA-256 | `1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09` |
| Family label | `AgentTesla` |
| File name | `DRAFT BL 0001288577.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:46:01` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa319337b9242bed6a292cdc1ccb2a30` |
| SHA-1 | `9ab6f1445632dc90027c1201be1e48f3f2669e30` |
| SHA-256 | `1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09` |
| SHA3-384 | `7ad64d8e35a51239cf2ad6631b87d586f87e52f222bbffab0265e9cf0ec91f07782f7a647dfa39c6b38cbbad10a50e9f` |
| TLSH | `T1D336B246A78490327B65AB5CC23AD930A91A904354C2DB373AFDD614371CD5BA3FCAE3` |
| SSDEEP | `98304:0SXpQ/t39+5QI4J+fisfe4HSDVH3J74o/OPuCdkMx6lp0D4lfwaAV4AOraTjM8Jn:p5Q/p+fis9cHb/OPuCFUtxA0rW5gJ1t0` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_049_1c505207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09"
    family = "AgentTesla"
    file_name = "DRAFT BL 0001288577.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:01"
  condition:
    hash.sha256(0, filesize) == "1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09"
}
```

### Sample 50: `dc7f6694ce30cf3d`

| Field | Value |
|---|---|
| SHA-256 | `dc7f6694ce30cf3d8d79ba01f3c76f402e8c6554b3762d9501f9e548ac64f5b1` |
| Family label | `AgentTesla` |
| File name | `SOA SEPT-OCT 2026.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:58` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4602b6fb006fb94db5b5497e321b7f1d` |
| SHA-1 | `d454d383fad8e150182c13a9dc00a7d4df22d022` |
| SHA-256 | `dc7f6694ce30cf3d8d79ba01f3c76f402e8c6554b3762d9501f9e548ac64f5b1` |
| SHA3-384 | `df69cb7da4ff30ce98ab76b37f2f6983e6f019137296967e1ddde2150c52afcc0c9756c90f7471f33a1b64b909ea50f2` |
| TLSH | `T17B36B342A78490327B296B5CC2369930581A504365C6EF373AFDD6147B6CD4BA3FCAE3` |
| SSDEEP | `98304:eLeY5YJOmZX84AIZNHnHYQhFstWClywDZZ8xGa9IrJPMC6bUEKUUTyx9xIiV8HKJ:ieY5zm9b7s9S9IrlEKUBx9X3LObQJzDp` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_050_dc7f6694
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc7f6694ce30cf3d8d79ba01f3c76f402e8c6554b3762d9501f9e548ac64f5b1"
    family = "AgentTesla"
    file_name = "SOA SEPT-OCT 2026.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:58"
  condition:
    hash.sha256(0, filesize) == "dc7f6694ce30cf3d8d79ba01f3c76f402e8c6554b3762d9501f9e548ac64f5b1"
}
```

### Sample 51: `66692977bf502809`

| Field | Value |
|---|---|
| SHA-256 | `66692977bf502809e698ff16b278e14e1fda9289b0b89c6f6266514377e249e7` |
| Family label | `AveMariaRAT` |
| File name | `OOLU2341072700 电放保函.js` |
| File type | `js` |
| First seen | `2026-11-26 06:45:54` |
| Reporter | `abuse_ch` |
| Tags | `AveMariaRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69f2aa4d739a0c8b14035ef0d3dfc662` |
| SHA-1 | `b1619eafda45bac2748afb3667ec61b054494a35` |
| SHA-256 | `66692977bf502809e698ff16b278e14e1fda9289b0b89c6f6266514377e249e7` |
| SHA3-384 | `e6bdfde5acf27c3b1f2a1bf5be164b4f0dbe35213f6b9e3311508ae7d9347ad7a9a9fcadde5af9ff1bc433e90faa9eca` |
| TLSH | `T106F100D959616074AA33633E8F2B9A09E77A443B0605C165B4CC92DC1FB536082E9FFE` |
| SSDEEP | `96:S0XweTxkMvERJxYa/DFiYPD2bx+sgmz7ziE1I5Q7kLjmE:BDxQRJxr/YNFCE1YQ7kLj` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_051_66692977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66692977bf502809e698ff16b278e14e1fda9289b0b89c6f6266514377e249e7"
    family = "AveMariaRAT"
    file_name = "OOLU2341072700 电放保函.js"
    file_type = "js"
    first_seen = "2026-11-26 06:45:54"
  condition:
    hash.sha256(0, filesize) == "66692977bf502809e698ff16b278e14e1fda9289b0b89c6f6266514377e249e7"
}
```

### Sample 52: `c7fcca617e6c4f5f`

| Field | Value |
|---|---|
| SHA-256 | `c7fcca617e6c4f5f28ff49c68f3cd25087690ebe7d0f2e82774f30661b704299` |
| Family label | `PureLogsStealer` |
| File name | `Tender Items List – RFQ_HD-2026-59554.js` |
| File type | `js` |
| First seen | `2026-11-26 06:45:51` |
| Reporter | `abuse_ch` |
| Tags | `js, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `848443e0a92142367a57919ad5f9c6b4` |
| SHA-1 | `c1ed0a9f60206b63143933d21520f79f91de217c` |
| SHA-256 | `c7fcca617e6c4f5f28ff49c68f3cd25087690ebe7d0f2e82774f30661b704299` |
| SHA3-384 | `03e19e4542de95360e6be7bc41e65914eb7bcf4afb46a5af72ece999717364e63e0ace670d8fa238b0f4b8726c338af0` |
| TLSH | `T179755B0F454D6C3D4410C50273EE4B63EADE9F95869CD0A1FC6EDB26B3090ADA5F292E` |
| SSDEEP | `49152:EoTn56d7frKvXyIV0t6xKWefxQ61fXWv2SIpBrQwEhWHwc:umvCIit6xKWyxQ65XWvEpBrQwEhDc` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_052_c7fcca61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7fcca617e6c4f5f28ff49c68f3cd25087690ebe7d0f2e82774f30661b704299"
    family = "PureLogsStealer"
    file_name = "Tender Items List – RFQ_HD-2026-59554.js"
    file_type = "js"
    first_seen = "2026-11-26 06:45:51"
  condition:
    hash.sha256(0, filesize) == "c7fcca617e6c4f5f28ff49c68f3cd25087690ebe7d0f2e82774f30661b704299"
}
```

### Sample 53: `250950cb26986488`

| Field | Value |
|---|---|
| SHA-256 | `250950cb2698648849e23a5e51698dd4241fda73c87473ddd300ae5edbab5c41` |
| Family label | `unknown` |
| File name | `การชำระเงิน_PO_11.25.2026.pdf.js` |
| File type | `js` |
| First seen | `2026-11-26 06:45:48` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a9638d6498e0138033e8a19e518c543` |
| SHA-1 | `45115cf7189ab58e9132d847de676023c4fbba05` |
| SHA-256 | `250950cb2698648849e23a5e51698dd4241fda73c87473ddd300ae5edbab5c41` |
| SHA3-384 | `f90cbf2c11b5854569a7bfb318db71d9a84b4f4b854c4c570f52d45bfe6ffd8c20f6ce475a0315047c91c113abb2dccc` |
| TLSH | `T15CA412E0BBD31C6F81F9D2305D4F17496EF6A3A2298B675F41B621D30B6E3211663D28` |
| SSDEEP | `12288:ao3dqrN6rpNrXegQCurr01xLC6CgA9CVQp+QDSPI+rjQWRB:PArcHQr0xLWrpF+zAWRB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_250950cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "250950cb2698648849e23a5e51698dd4241fda73c87473ddd300ae5edbab5c41"
    family = "unknown"
    file_name = "การชำระเงิน_PO_11.25.2026.pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:45:48"
  condition:
    hash.sha256(0, filesize) == "250950cb2698648849e23a5e51698dd4241fda73c87473ddd300ae5edbab5c41"
}
```

### Sample 54: `4f13673279d80132`

| Field | Value |
|---|---|
| SHA-256 | `4f13673279d8013297fc618c739774895837998c8678c7792cb16664c37cd374` |
| Family label | `unknown` |
| File name | `J-033.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:45` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faa9689b32c259d4905a1c1dc6ee51e8` |
| SHA-1 | `4dc61e82f1826f4763b0ecfc1b6a825abd05470c` |
| SHA-256 | `4f13673279d8013297fc618c739774895837998c8678c7792cb16664c37cd374` |
| SHA3-384 | `2122c5a2faf0983e970145930022bc466c7d2e92d82ed312dfd5ecc23e3a3de9684817046ffccee52c70b403c757c7fc` |
| TLSH | `T1AC3619C6E6C4A2323F61AE89C22ADC31940A85432545CB337BFDD619371DE56A2FC763` |
| SSDEEP | `98304:QPpQyk3cqfI1MF1MnBH2UyrZD4nCoO11qs+swwrN94v4JE4prpB9x+lXXzWnwYKH:QPpQyk3cqfI1MPMnBWUyrZD4nCoO11qB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_4f136732
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f13673279d8013297fc618c739774895837998c8678c7792cb16664c37cd374"
    family = "unknown"
    file_name = "J-033.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:45"
  condition:
    hash.sha256(0, filesize) == "4f13673279d8013297fc618c739774895837998c8678c7792cb16664c37cd374"
}
```

### Sample 55: `ad50059d9b34101e`

| Field | Value |
|---|---|
| SHA-256 | `ad50059d9b34101ee98fcc9dd09a0e81ecf473f932c941562dd829304612c99b` |
| Family label | `Formbook` |
| File name | `University Of Mauritius Tender UOM_11-26.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:41` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fd014f074013c725617d84999d6adab` |
| SHA-1 | `45500b54d3ed2159cf1b541913cdad4ce0e0ce12` |
| SHA-256 | `ad50059d9b34101ee98fcc9dd09a0e81ecf473f932c941562dd829304612c99b` |
| SHA3-384 | `7be7cfecdf9a81093b124ad07bc720f468449bb20c0be289f1391dbb13ba353f5aad5ff289c1b6cfffaf9e74957ed2e4` |
| TLSH | `T10836C486AB4490727F29A75CC53A9930691A200355C6DF3B3AFCD2147758D1BA3FCAE3` |
| SSDEEP | `98304:mrcIgX9QVNR8L0I3RW5hHY/dEaZFKfWkVUz/QjUtAUq5nhenU2xfvJtuvdw9tsHY:mrcIgX9QVNR8L0I3qlCzQQ9qynU2xSGR` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_055_ad50059d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad50059d9b34101ee98fcc9dd09a0e81ecf473f932c941562dd829304612c99b"
    family = "Formbook"
    file_name = "University Of Mauritius Tender UOM_11-26.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:41"
  condition:
    hash.sha256(0, filesize) == "ad50059d9b34101ee98fcc9dd09a0e81ecf473f932c941562dd829304612c99b"
}
```

### Sample 56: `cf2fe09e88bb9044`

| Field | Value |
|---|---|
| SHA-256 | `cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d` |
| Family label | `AgentTesla` |
| File name | `PO_4500102673_S.S. Grow_2026.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:38` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b139f67ae6f752109bb79cfc230b1c23` |
| SHA-1 | `366520af4858cb5366f9c0598ec8fdf5eba76e7e` |
| SHA-256 | `cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d` |
| SHA3-384 | `53af8caf5536d277083d1eb2269d2313664d42e5be45ee2e32e6f117fcce48b5209200cfba7dfad7da4399a3c44e876e` |
| TLSH | `T118164948E245F3929CAC1910CD0D6A914B35A547EE51E8337FFC88A67B85BC272FC61B` |
| SSDEEP | `98304:EPOrhUSZ6qzpZVcc/WKeu6UtYts1I+JrzMUHv6WvHe6FcqhNEHI1w/EUcyZ4KD8S:s6h2qLVcc/iLUSyukr4UHboI1LKZf` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_056_cf2fe09e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d"
    family = "AgentTesla"
    file_name = "PO_4500102673_S.S. Grow_2026.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:38"
  condition:
    hash.sha256(0, filesize) == "cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d"
}
```

### Sample 57: `c4df5fc57e9ffcb2`

| Field | Value |
|---|---|
| SHA-256 | `c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9` |
| Family label | `Formbook` |
| File name | `550MW_에 대한 문의입니다.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:17` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fec547e37cdc8610457e2608adee216` |
| SHA-1 | `3322e5269b57548ac5065f66e623e1afe2baebc4` |
| SHA-256 | `c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9` |
| SHA3-384 | `08e8d10fef51f1835b33fa86c659613181f63301c926fa8778de40c3eead6d286e9ec03d5e0cd73fc0699cf96913cf78` |
| TLSH | `T19D368D45D944A3B37F782A19C11E6AA22E16949B5840EE373FFCCA9A670CF0572FC153` |
| SSDEEP | `98304:YBHoTAa6jnXY2JrhsR6jKTLwxkmhIf/cZ9FEOG+jCc0++jOfMC+8kIjL6p7UvAr4:YBIsa6jnI2Jro6jKT0xEHcZbEOG+jCzu` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_057_c4df5fc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9"
    family = "Formbook"
    file_name = "550MW_에 대한 문의입니다.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:17"
  condition:
    hash.sha256(0, filesize) == "c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9"
}
```

### Sample 58: `44ff65bdeaae8b23`

| Field | Value |
|---|---|
| SHA-256 | `44ff65bdeaae8b235e6d6000f3af6efd54a737f6c9d4722e8bb0ce60db70baea` |
| Family label | `DarkCoreRAT` |
| File name | `Order Confirmation 11-26-2026.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:13` |
| Reporter | `abuse_ch` |
| Tags | `DarkCoreRAT, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7565e4be47c830485646eca868919077` |
| SHA-1 | `55d804ebc8869660930c1608a7f5f1ddbbd75bb4` |
| SHA-256 | `44ff65bdeaae8b235e6d6000f3af6efd54a737f6c9d4722e8bb0ce60db70baea` |
| SHA3-384 | `bd8f876672774ac6da58f1f99d7ca544a5a988831ddfa835d94969676872b714c807cf805c06adcdcee3963bb63b4e53` |
| TLSH | `T11146AE8E6C7BD346A07C0951C7D4ADD60A56853BB930EA33799D8EEDAA09F4D32CC143` |
| SSDEEP | `98304:wxNjKtsSb1w+tPT2vsSY3oPc2WwLVqd5qJLmHGEs2mXOVR/sSaFm9bSKKw2rtik0:Gp3+4vsSYYPYwhqnELmHGGQi3aqb3Kw7` |

#### Technical Assessment

- The sample is tracked as `DarkCoreRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCoreRAT_058_44ff65bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ff65bdeaae8b235e6d6000f3af6efd54a737f6c9d4722e8bb0ce60db70baea"
    family = "DarkCoreRAT"
    file_name = "Order Confirmation 11-26-2026.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:13"
  condition:
    hash.sha256(0, filesize) == "44ff65bdeaae8b235e6d6000f3af6efd54a737f6c9d4722e8bb0ce60db70baea"
}
```

### Sample 59: `a14c9168da21a61d`

| Field | Value |
|---|---|
| SHA-256 | `a14c9168da21a61d6c85e4ba14583b23c2f3b19eeefef70196b2fdc337ad3515` |
| Family label | `RemcosRAT` |
| File name | `mfvyxskd.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:45:02` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86f872eafa4751e206f0427c9e94728d` |
| SHA-1 | `f929a8fac855887dcd5e9459ea17210c87e54814` |
| SHA-256 | `a14c9168da21a61d6c85e4ba14583b23c2f3b19eeefef70196b2fdc337ad3515` |
| SHA3-384 | `198d38fee22f500af3295265d8f9818a07009938c1c27c50ac852c34a650d78c855bfe67db618e8acc02e39b3b5050a2` |
| TLSH | `T186560886A6D492333B21AB89C239DD31D40E85532545CB337AFDD618372CD4AA3BC7A7` |
| SSDEEP | `98304:sSj7TeBQF0I7Hr1qoIrzE31U9+vZ8LQPzNbTufdUFHj/UAfc2X+c3ECUNDCrG4xb:sSj7TeBQF0I7Hr1qo4zE31U9+vZ8LQPt` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_059_a14c9168
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14c9168da21a61d6c85e4ba14583b23c2f3b19eeefef70196b2fdc337ad3515"
    family = "RemcosRAT"
    file_name = "mfvyxskd.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:02"
  condition:
    hash.sha256(0, filesize) == "a14c9168da21a61d6c85e4ba14583b23c2f3b19eeefef70196b2fdc337ad3515"
}
```

### Sample 60: `4978c249869c364f`

| Field | Value |
|---|---|
| SHA-256 | `4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3` |
| Family label | `Formbook` |
| File name | `PIT00027301.pdf.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:52` |
| Reporter | `abuse_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8427fb81e5be2639232b62807891689` |
| SHA-1 | `c7e98b380e7fc11c57085198698aee58675138c2` |
| SHA-256 | `4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3` |
| SHA3-384 | `2e299f72e59e0fa83b60021aa2537a63591ed1ee3da967f5f26e08af60cf6b917bc50a869f429f4c873e36603a611d81` |
| TLSH | `T1B1E27D50FA7603790E4B0BC9EDB50A69CABD821B943245A5F6EC43466506CCCE3BE97C` |
| SSDEEP | `384:7y873Nca7+It5jwUkYv1JFPsKLSY6nGSFgK4Fu5Ua+YmlhHy4PL8LXA8tRvJxJ:7yqvIKLanhD+Ymn1zyA8zRb` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_060_4978c249
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3"
    family = "Formbook"
    file_name = "PIT00027301.pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:52"
  condition:
    hash.sha256(0, filesize) == "4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3"
}
```

### Sample 61: `646cada448f89b14`

| Field | Value |
|---|---|
| SHA-256 | `646cada448f89b14e5a403b8bbafca97ce26b9e49fd23ea5d9b77bbc3f041e3e` |
| Family label | `unknown` |
| File name | `Biên lai giao hàng_55.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:49` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b22f093b1f9d37ed156ef8f753901a70` |
| SHA-1 | `0b8c8b6389cf611bb7ece147120b8346ab8ee41b` |
| SHA-256 | `646cada448f89b14e5a403b8bbafca97ce26b9e49fd23ea5d9b77bbc3f041e3e` |
| SHA3-384 | `9aaa5c65c873a068c193c755fed3f91ef80682826aebda82b786bf6c37c5f81ffeebf04cb191f55780c7871c89a186e6` |
| TLSH | `T1B254F1706EC92AC9753B664583AFBA0ED382B3233E06E45B75BC11450F31A92B597C1F` |
| SSDEEP | `6144:hTjPrKOB4AHVk+H53jGZMh0HClL3qtqoBgud7n5empxv2F:djeOOIVX2MqHCNUBgudZbvW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_646cada4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "646cada448f89b14e5a403b8bbafca97ce26b9e49fd23ea5d9b77bbc3f041e3e"
    family = "unknown"
    file_name = "Biên lai giao hàng_55.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:49"
  condition:
    hash.sha256(0, filesize) == "646cada448f89b14e5a403b8bbafca97ce26b9e49fd23ea5d9b77bbc3f041e3e"
}
```

### Sample 62: `cd1d62ce3c34143b`

| Field | Value |
|---|---|
| SHA-256 | `cd1d62ce3c34143bc656201f398c67c98a754f9bf6ef5898bd7be83f2e47d67b` |
| Family label | `unknown` |
| File name | `Payment advice.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:46` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfbaf1019d40aeedb0cfbc4845508662` |
| SHA-1 | `87d9e90cab4925b8e646c6e7ec5458b09cd8e921` |
| SHA-256 | `cd1d62ce3c34143bc656201f398c67c98a754f9bf6ef5898bd7be83f2e47d67b` |
| SHA3-384 | `187f7c90f7762a72b46beab1ced1d2322cbe85d4006fbb8e440bd8c7082ac2f15e8e60f18e04e1853af5e0c1ed6e4cb1` |
| TLSH | `T11171218C6C82B1644673F33DCF6B810DE27B85332A069A19B8ADE2401F7142442BDFDD` |
| SSDEEP | `48:ecun23NOuOxIOGemJeRCPr87DtpJXGHzdJZ3xp:eX0gPyPARCippNGHzdv3xp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_cd1d62ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1d62ce3c34143bc656201f398c67c98a754f9bf6ef5898bd7be83f2e47d67b"
    family = "unknown"
    file_name = "Payment advice.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:46"
  condition:
    hash.sha256(0, filesize) == "cd1d62ce3c34143bc656201f398c67c98a754f9bf6ef5898bd7be83f2e47d67b"
}
```

### Sample 63: `6eb055b39b6a1374`

| Field | Value |
|---|---|
| SHA-256 | `6eb055b39b6a137485334e5435e8f3cefd4a9a1b342efaf396b2d6641baa824b` |
| Family label | `unknown` |
| File name | `Biên lai giao hàng_Ip.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:43` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de902bb4026d28889a1e229b4ca87ec6` |
| SHA-1 | `04b8c872b298ab75c3585223866a6f251f7fe158` |
| SHA-256 | `6eb055b39b6a137485334e5435e8f3cefd4a9a1b342efaf396b2d6641baa824b` |
| SHA3-384 | `59f4c34f7391c64d5373b295df3170ce97a3c1c248d7c73c5c75bc12c33b5e15e1414a8918810afb67b864c50da38cd6` |
| TLSH | `T1ED1402A4BFC51DAF83F8E2750D5F370C95E8A3A2375F496D536EA0C345BE6930062A09` |
| SSDEEP | `6144:KfOG5BHF8zswLFRUnfB1SLNVe8Qh2NkdSE:4OG5BOd+Bs3erUNkdT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_6eb055b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb055b39b6a137485334e5435e8f3cefd4a9a1b342efaf396b2d6641baa824b"
    family = "unknown"
    file_name = "Biên lai giao hàng_Ip.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:43"
  condition:
    hash.sha256(0, filesize) == "6eb055b39b6a137485334e5435e8f3cefd4a9a1b342efaf396b2d6641baa824b"
}
```

### Sample 64: `274ad8e7e88f48ae`

| Field | Value |
|---|---|
| SHA-256 | `274ad8e7e88f48ae03f222161bc052910ee80925d0a46dd79f588e0f9dc4af72` |
| Family label | `unknown` |
| File name | `Biên lai giao hàng0.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:41` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `863e78a3665cfc16a93220a448db575e` |
| SHA-1 | `c2a160b5fb03dee01adbbc322d3aea7dbb929ef3` |
| SHA-256 | `274ad8e7e88f48ae03f222161bc052910ee80925d0a46dd79f588e0f9dc4af72` |
| SHA3-384 | `438c1f80d0a672795e9e6f9cd9eecaecb5832885ab08243893718040dc20cecc20401e56fd98736335bff993b75b6eb9` |
| TLSH | `T10B1402D24BCC6EAF87E6C122198F3F0C59E8FAD34D6D920F425994D31EBDB600169C66` |
| SSDEEP | `3072:wEoxA8mD4hmfvLANqU+MdPb1FemfOV8OrNW7stLjlA7urTjsC7VjwRIYbd:O29BMN9+MZbVWhisFjMurToC7VjwD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_274ad8e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "274ad8e7e88f48ae03f222161bc052910ee80925d0a46dd79f588e0f9dc4af72"
    family = "unknown"
    file_name = "Biên lai giao hàng0.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:41"
  condition:
    hash.sha256(0, filesize) == "274ad8e7e88f48ae03f222161bc052910ee80925d0a46dd79f588e0f9dc4af72"
}
```

### Sample 65: `1b9cd0e9d64c8bbe`

| Field | Value |
|---|---|
| SHA-256 | `1b9cd0e9d64c8bbe16e340e6282429b3b47576449708bf439b3b5ceb2d5e3bd6` |
| Family label | `RemcosRAT` |
| File name | `Tender Bidding details.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:38` |
| Reporter | `abuse_ch` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05b4baf2711a5a01bc62589e13a04321` |
| SHA-1 | `c214258098c65dc60220eaaed3b14cfe350f4fd8` |
| SHA-256 | `1b9cd0e9d64c8bbe16e340e6282429b3b47576449708bf439b3b5ceb2d5e3bd6` |
| SHA3-384 | `854a8c4709df775aa3df12fb480e2b0fe9831ead986024038ab3544544a7a7538f663f47b12d00603d1549dc0604d167` |
| TLSH | `T1234768C792F8B36803373790CDC552446C168E6B5AD563EBB43F4DCA53413DF28A6AA2` |
| SSDEEP | `3072:aKQQbicZUP5do2h5fX/3fpUQXtCP0b9pdClkAwEk67536Dsp9ke1pLiA1espZiBl:6rAr0fi8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_065_1b9cd0e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9cd0e9d64c8bbe16e340e6282429b3b47576449708bf439b3b5ceb2d5e3bd6"
    family = "RemcosRAT"
    file_name = "Tender Bidding details.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:38"
  condition:
    hash.sha256(0, filesize) == "1b9cd0e9d64c8bbe16e340e6282429b3b47576449708bf439b3b5ceb2d5e3bd6"
}
```

### Sample 66: `4750e4be0b50d499`

| Field | Value |
|---|---|
| SHA-256 | `4750e4be0b50d49992a299ebced7a468ebde13e5b238812c9c926bbe2ba25f2e` |
| Family label | `RemcosRAT` |
| File name | `Whatsapp-0931 26-11-2026.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:34` |
| Reporter | `abuse_ch` |
| Tags | `js, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0938d1feda6e49443d813c4b7827d22a` |
| SHA-1 | `33080aa7b2111749f7121b8450a929d97a73ef97` |
| SHA-256 | `4750e4be0b50d49992a299ebced7a468ebde13e5b238812c9c926bbe2ba25f2e` |
| SHA3-384 | `9bca2f2d6185dec28ad7434b34f9ceab2acae443b23556bba13511bbc57ec0c5bd87f25da7e0d03a7df10a9af0a8cdae` |
| TLSH | `T1FE45180F854D6C3D4401C54273EE4B23EAEE9F95869CD095FC5EDB26B3090ACA5F292E` |
| SSDEEP | `24576:DsTq49HSCO5CyqYy9NBYM6AkpNLnsgixpducEuSG2m:DsTq49HhO5C9Yy9LoAk3YgixDufuSG2m` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_066_4750e4be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4750e4be0b50d49992a299ebced7a468ebde13e5b238812c9c926bbe2ba25f2e"
    family = "RemcosRAT"
    file_name = "Whatsapp-0931 26-11-2026.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:34"
  condition:
    hash.sha256(0, filesize) == "4750e4be0b50d49992a299ebced7a468ebde13e5b238812c9c926bbe2ba25f2e"
}
```

### Sample 67: `99a1193448e31b2b`

| Field | Value |
|---|---|
| SHA-256 | `99a1193448e31b2ba7357c5b0cdc307c9c3a574ecafb393042981c6be2f521be` |
| Family label | `unknown` |
| File name | `AWB no 530526.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:31` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfbb7604b7c866fd2a4e6912be39423c` |
| SHA-1 | `bdeaad2010e1a12e5434528668c5e5b5fe305bde` |
| SHA-256 | `99a1193448e31b2ba7357c5b0cdc307c9c3a574ecafb393042981c6be2f521be` |
| SHA3-384 | `d79524462a241635208f406b9e7919d84d827a79ca850ae9078a37709b086bbc484d2f100c47a2c22dd11af9dbf40c55` |
| TLSH | `T114C23CEB17A6FB9C10AB39625335D5A28616C838676141B1EF0C74CD3C3292B6B53F2D` |
| SSDEEP | `384:fRRs7fSXRRs7fSXRRs7fS26oHc5LMpiPRRs7fSXRRs7fSXRRs7fSu:JRMfsRMfsRMfsPRMfsRMfsRMfd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_99a11934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a1193448e31b2ba7357c5b0cdc307c9c3a574ecafb393042981c6be2f521be"
    family = "unknown"
    file_name = "AWB no 530526.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:31"
  condition:
    hash.sha256(0, filesize) == "99a1193448e31b2ba7357c5b0cdc307c9c3a574ecafb393042981c6be2f521be"
}
```

### Sample 68: `d459116d0d913162`

| Field | Value |
|---|---|
| SHA-256 | `d459116d0d91316205238b0e457f6a3ecafd5dec7099e1cf35fa6172b213e436` |
| Family label | `PhantomStealer` |
| File name | `rfq20mt HV XLPE 4700020778.js` |
| File type | `js` |
| First seen | `2026-11-26 06:44:26` |
| Reporter | `abuse_ch` |
| Tags | `js, PhantomStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bacc904832582d53fde42ecb74f3b82` |
| SHA-1 | `3a5b2d6bd142f62e5ff2419a74a43392e601113c` |
| SHA-256 | `d459116d0d91316205238b0e457f6a3ecafd5dec7099e1cf35fa6172b213e436` |
| SHA3-384 | `3dac10aeae133de7178670bcdfae36adf505c1cdbcd77702cf9bdf28086e9bb55c8ce9d2ec951d65d4abaa83d6448f55` |
| TLSH | `T1D1037D60EE2655BD0F530BC4ECE90624CEBD4207891744B0F6EE93192516E8CE6BD9EF` |
| SSDEEP | `384:/y873Ni7G++y55Qdk8f5vCvKDIbC2SYaRnGSFgKNgxpWuOtAYmvH8+4A8LGE8wsQ:/yBT8fMi26nhGYmfkjKeznloSavmrz` |

#### Technical Assessment

- The sample is tracked as `PhantomStealer` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PhantomStealer_068_d459116d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d459116d0d91316205238b0e457f6a3ecafd5dec7099e1cf35fa6172b213e436"
    family = "PhantomStealer"
    file_name = "rfq20mt HV XLPE 4700020778.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:26"
  condition:
    hash.sha256(0, filesize) == "d459116d0d91316205238b0e457f6a3ecafd5dec7099e1cf35fa6172b213e436"
}
```

### Sample 69: `ecc6e9348321bf0b`

| Field | Value |
|---|---|
| SHA-256 | `ecc6e9348321bf0b5ca399a93791af5d67e719968de70f8dbe37f07eecb95390` |
| Family label | `AsyncRAT` |
| File name | `200ae945e6d154ce322c04d480aba416.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:42:50` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `200ae945e6d154ce322c04d480aba416` |
| SHA-1 | `6089f5d97eb2d0a3e6ca4d19ce43dc0756d5cf86` |
| SHA-256 | `ecc6e9348321bf0b5ca399a93791af5d67e719968de70f8dbe37f07eecb95390` |
| SHA3-384 | `d2c21442cf7c9c313c3a0648df30bcdc6193b2a336ff284a2a4c76fe7833746d5ab1c59751408dfb0b2ff595f6a97201` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1A4535C003798C965E2AE87B8BCF3550106B1D17B2112DA1E7CC810DBAB9FFC656526FE` |
| SSDEEP | `768:Cm0vnfEXf78awC8A+XU2azcBRL5JTk1+T4KSBGHmDbD/ph0oX0LeDbYSusdpqKYC:qEXiLdSJYUbdh9FXusdpqKmY7` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_069_ecc6e934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecc6e9348321bf0b5ca399a93791af5d67e719968de70f8dbe37f07eecb95390"
    family = "AsyncRAT"
    file_name = "200ae945e6d154ce322c04d480aba416.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:42:50"
  condition:
    hash.sha256(0, filesize) == "ecc6e9348321bf0b5ca399a93791af5d67e719968de70f8dbe37f07eecb95390"
}
```

### Sample 70: `2ac2e964c4d28cb4`

| Field | Value |
|---|---|
| SHA-256 | `2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8` |
| Family label | `unknown` |
| File name | `2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8` |
| File type | `sh` |
| First seen | `2026-11-26 06:40:55` |
| Reporter | `ArchonLabs` |
| Tags | `sh, Shell dropper, shell script` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0595c5fb1633d8227b40a575f050170` |
| SHA-1 | `77b9e9637b02afdb36a91e08373c6991e2659947` |
| SHA-256 | `2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8` |
| SHA3-384 | `60dbd47647302887c515f2f25b14aaca1ee39421faef3ab7c56c270289c78cc7321387df2c1ecbb7a4e9c2af9047a86b` |
| TLSH | `T14011EDADF4408B34B346407E2E6F80101856892F8A723530790FFCC87FBCA12A54CB67` |
| SSDEEP | `24:N0M4RHytCgB2kwMf/E/OS4Ad6B+G/aCL0u6zMoBFdRH5:uThytWVMf/ogAd6//tousMoBFdh5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_2ac2e964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8"
    family = "unknown"
    file_name = "2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8"
    file_type = "sh"
    first_seen = "2026-11-26 06:40:55"
  condition:
    hash.sha256(0, filesize) == "2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8"
}
```

### Sample 71: `826ce3fe579833e9`

| Field | Value |
|---|---|
| SHA-256 | `826ce3fe579833e99adce2ed24a3c7d57cb58289d9a533759e52e2b338b9c709` |
| Family label | `RemcosRAT` |
| File name | `Product_Catalog_2026.xls` |
| File type | `xls` |
| First seen | `2026-11-26 06:40:18` |
| Reporter | `abuse_ch` |
| Tags | `RemcosRAT, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81459d9868b081aa6b40c9daf648a40a` |
| SHA-1 | `bba2b7ed515cf905da27a73838900d9cdc434e79` |
| SHA-256 | `826ce3fe579833e99adce2ed24a3c7d57cb58289d9a533759e52e2b338b9c709` |
| SHA3-384 | `1a6c657c2293b105f6ab364030213b668db58058ebdd43b011dc5eb06558f3cdf35ddc91856ec2233f46f873fe994cf0` |
| TLSH | `T14B452209F5C2BF05E5258338A5F7D6DA5326FC4259128B0B358C372D4B72B3507BB2AA` |
| SSDEEP | `24576:/wELyg77sT+0UT9dKYwKUYyJYlhOYHGa0THq73g1:Zug77sBUTmYwKZyOlgYH30TKDg` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_071_826ce3fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "826ce3fe579833e99adce2ed24a3c7d57cb58289d9a533759e52e2b338b9c709"
    family = "RemcosRAT"
    file_name = "Product_Catalog_2026.xls"
    file_type = "xls"
    first_seen = "2026-11-26 06:40:18"
  condition:
    hash.sha256(0, filesize) == "826ce3fe579833e99adce2ed24a3c7d57cb58289d9a533759e52e2b338b9c709"
}
```

### Sample 72: `4b745504580314e6`

| Field | Value |
|---|---|
| SHA-256 | `4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717` |
| Family label | `XWorm` |
| File name | `Reckless Driver Cam 5 Photos 20261126.JS` |
| File type | `js` |
| First seen | `2026-11-26 06:40:16` |
| Reporter | `abuse_ch` |
| Tags | `js, XWorm` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56a274d768340ac53919cf302bed9c19` |
| SHA-1 | `2b1777eab47ec460decd0607edbb941c7fa738df` |
| SHA-256 | `4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717` |
| SHA3-384 | `db2248bde3187d59cbae455e7a54f9f5c0888e8c398db2dd4f4d7680017318025f2cb1b956b48f0598840391fed072ad` |
| TLSH | `T1D016E646D704A432AE2D6B1CC1769930181A201351C6EF3F3AFCA654B765E1B93FDAE3` |
| SSDEEP | `98304:gkEO/l2pLqEO/l2pkqEO/l2p0qEO/l2pbmSj20835GLGokNvD0xT8lTy20NBqLk1:WxVnHX++2gl` |

#### Technical Assessment

- The sample is tracked as `XWorm` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_XWorm_072_4b745504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717"
    family = "XWorm"
    file_name = "Reckless Driver Cam 5 Photos 20261126.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:40:16"
  condition:
    hash.sha256(0, filesize) == "4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717"
}
```

### Sample 73: `d4aa0b3d25fa124d`

| Field | Value |
|---|---|
| SHA-256 | `d4aa0b3d25fa124d80b195ebda0d004c0ba468b0c4ab15fa8613103c3fb02272` |
| Family label | `unknown` |
| File name | `Grade certificate..docx` |
| File type | `docx` |
| First seen | `2026-11-26 06:40:12` |
| Reporter | `abuse_ch` |
| Tags | `docx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee24f8630d71a62db7a180914aec0126` |
| SHA-1 | `4b5f9c98787adb438b8c40ccfc98ef0c6b5d3895` |
| SHA-256 | `d4aa0b3d25fa124d80b195ebda0d004c0ba468b0c4ab15fa8613103c3fb02272` |
| SHA3-384 | `0168d74e1f4989b698fbcfcc38eeea5f219711e6d3dd20d5f3dd53d238451bd36849c4404e3b4aed483420e05d782319` |
| TLSH | `T16D463334C70082CFC490FEAF944B9FCF1CE514EB5EBC59E691DA25B862B29109256ED3` |
| SSDEEP | `98304:xiSA89jq4hbAhUavBTJlm3to1CLsBLCTtZaxLXXL0XGeio9XvgFMafNRXZUYTomK:gSA8hQvZY6e02n+jXLk1XMMafNKf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `docx`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_d4aa0b3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4aa0b3d25fa124d80b195ebda0d004c0ba468b0c4ab15fa8613103c3fb02272"
    family = "unknown"
    file_name = "Grade certificate..docx"
    file_type = "docx"
    first_seen = "2026-11-26 06:40:12"
  condition:
    hash.sha256(0, filesize) == "d4aa0b3d25fa124d80b195ebda0d004c0ba468b0c4ab15fa8613103c3fb02272"
}
```

### Sample 74: `b904cc1ef88171d2`

| Field | Value |
|---|---|
| SHA-256 | `b904cc1ef88171d2b3e3cebde14e92847e858360e02099714dcaeaf6c71ab4a1` |
| Family label | `RemcosRAT` |
| File name | `Quotation 2026.xls` |
| File type | `xls` |
| First seen | `2026-11-26 06:40:07` |
| Reporter | `abuse_ch` |
| Tags | `CVE-2017-0199, RemcosRAT, xls` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72fd4ad4b6ae0b7b68a2f076ac3c99cd` |
| SHA-1 | `cac339387a251b87882dd946896ff4b75944922d` |
| SHA-256 | `b904cc1ef88171d2b3e3cebde14e92847e858360e02099714dcaeaf6c71ab4a1` |
| SHA3-384 | `52766679d6bfa25254aec45c7444d82686dccfc53b0f3cf82829f170ad308c626db8b37ff00146103782eba71498d0a6` |
| TLSH | `T15945230AF992BF1DC626873595F6DEDA5722FC0259028A0B364C331C1B717740BE77AA` |
| SSDEEP | `24576:UwELyg77sT+0UT9hKYwKUYyJYlhHlln3aS5:yug77sBUTCYwKZyOlFjn3H` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `xls`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_074_b904cc1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b904cc1ef88171d2b3e3cebde14e92847e858360e02099714dcaeaf6c71ab4a1"
    family = "RemcosRAT"
    file_name = "Quotation 2026.xls"
    file_type = "xls"
    first_seen = "2026-11-26 06:40:07"
  condition:
    hash.sha256(0, filesize) == "b904cc1ef88171d2b3e3cebde14e92847e858360e02099714dcaeaf6c71ab4a1"
}
```

### Sample 75: `d8d80c729b59fce3`

| Field | Value |
|---|---|
| SHA-256 | `d8d80c729b59fce3c828d489cd4051d1fe244bd33ecdd5bee9e200a7dee61d96` |
| Family label | `ValleyRAT` |
| File name | `dpinst_x64.in.07.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:36:39` |
| Reporter | `CNGaoLing` |
| Tags | `exe, PatchedHostLoader, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2e9e34cb52f5b7f26648c69f0b7017f0` |
| SHA-1 | `8ecf07a6b533b7cc9c272b64633a7ee6320655b4` |
| SHA-256 | `d8d80c729b59fce3c828d489cd4051d1fe244bd33ecdd5bee9e200a7dee61d96` |
| SHA3-384 | `0cecaf5e2835927164ffb70d900658e8c532a78a0bc25267e3d89a9b7b8f21cb5d3569fb53f765e48f886c02bb3b1e1c` |
| IMPHASH | `20abbe0f6ab059ea4a375bcb6b8a717b` |
| TLSH | `T18587E6466A059DCAE062A2F4108B7F40E3FEFD615AF1D37713F927585EEA34C8AA3444` |
| SSDEEP | `49152:80ogYOBUcituYonIyelFn22gxuLxxuLexuLYMCwirXUlM93TDuUEczY1zHmKaLKz:pjyyMgCVb57/PEkOgA29o` |
| ICON-DHASH | `009269ecd4d42900` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_075_d8d80c72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8d80c729b59fce3c828d489cd4051d1fe244bd33ecdd5bee9e200a7dee61d96"
    family = "ValleyRAT"
    file_name = "dpinst_x64.in.07.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:36:39"
  condition:
    hash.sha256(0, filesize) == "d8d80c729b59fce3c828d489cd4051d1fe244bd33ecdd5bee9e200a7dee61d96"
}
```

### Sample 76: `49f2c2a674ac0eef`

| Field | Value |
|---|---|
| SHA-256 | `49f2c2a674ac0eefda886d4d7ff832613f90802a350f8e4576d9af45d6411606` |
| Family label | `unknown` |
| File name | `e512cd279dd50d0e8eb2f8f36f2c3b00` |
| File type | `exe` |
| First seen | `2026-11-26 06:33:00` |
| Reporter | `ni_fi_70` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e512cd279dd50d0e8eb2f8f36f2c3b00` |
| SHA-1 | `78fb005b890066cf493340fdc4ae47a56f868e53` |
| SHA-256 | `49f2c2a674ac0eefda886d4d7ff832613f90802a350f8e4576d9af45d6411606` |
| SHA3-384 | `2a73c52d3f13f4d4f0e10409906e75d2ae4ca050aa0dc30cab30dbdb086f939d6e5c3afb912cff99cde651b4388f700c` |
| IMPHASH | `e3e80a143805ea18936c8f612e25d363` |
| TLSH | `T1C1E63318E360C0A7EAE6F03C32E3E456E371F48167B1CA5742250A553DAB3D64E3979E` |
| SSDEEP | `393216:6gISKly1pw6er1SulXtRQMAySLrp3bp1zCHweZty/:6gINly7w6iSulXtRdSLd3/z/eby/` |
| ICON-DHASH | `8623496d25592792` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_49f2c2a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49f2c2a674ac0eefda886d4d7ff832613f90802a350f8e4576d9af45d6411606"
    family = "unknown"
    file_name = "e512cd279dd50d0e8eb2f8f36f2c3b00"
    file_type = "exe"
    first_seen = "2026-11-26 06:33:00"
  condition:
    hash.sha256(0, filesize) == "49f2c2a674ac0eefda886d4d7ff832613f90802a350f8e4576d9af45d6411606"
}
```

### Sample 77: `67d76863b812ef96`

| Field | Value |
|---|---|
| SHA-256 | `67d76863b812ef960b44e32a67fd2f3a6eebc857c073a448d8dccf3f18002622` |
| Family label | `ValleyRAT` |
| File name | `dpinst_x64.in.06.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:32:19` |
| Reporter | `CNGaoLing` |
| Tags | `exe, PatchedHostLoader, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3490c4b6dc11c46fb85b838554608098` |
| SHA-1 | `d03b02a22842fe1782194e46f3519c88f7053c41` |
| SHA-256 | `67d76863b812ef960b44e32a67fd2f3a6eebc857c073a448d8dccf3f18002622` |
| SHA3-384 | `fe51df9ad9e918ff792bec67b14c22de11ff90a5d49686183daf7c0ea0e9e59790a8c2c2c4bbb801407f83bcea367c13` |
| IMPHASH | `20abbe0f6ab059ea4a375bcb6b8a717b` |
| TLSH | `T11487E6466A059DCAE062A2F4108B7F40E3FEFD615AF1D37713F927585EEA34C8AA3444` |
| SSDEEP | `49152:80ogYOBUcituYonIyelFn22gxuLxxuLexuLYMCwirXUlM93TDuUEczY1zHmKaLKc:pjyyMgCVb57/PEkOgA29H` |
| ICON-DHASH | `009269ecd4d42900` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_077_67d76863
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67d76863b812ef960b44e32a67fd2f3a6eebc857c073a448d8dccf3f18002622"
    family = "ValleyRAT"
    file_name = "dpinst_x64.in.06.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:32:19"
  condition:
    hash.sha256(0, filesize) == "67d76863b812ef960b44e32a67fd2f3a6eebc857c073a448d8dccf3f18002622"
}
```

### Sample 78: `7317f68c0a92198d`

| Field | Value |
|---|---|
| SHA-256 | `7317f68c0a92198d6c7858d3ee96ab9bbebb9acaba11c5871bd93dc1fced7e70` |
| Family label | `ValleyRAT` |
| File name | `dpinst_x64.in.02.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:29:17` |
| Reporter | `CNGaoLing` |
| Tags | `exe, PatchedHostLoader, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b23b9f0b828b313d70d1a2e799932976` |
| SHA-1 | `fff10fb81aa4eaefca2da1e68fe03ed64ae9b17e` |
| SHA-256 | `7317f68c0a92198d6c7858d3ee96ab9bbebb9acaba11c5871bd93dc1fced7e70` |
| SHA3-384 | `bd4d2ff2caebc219806a4847e991e023fff3090305c2d7de2923caba6259a13edae87be1c226574147abf96cf025878f` |
| IMPHASH | `20abbe0f6ab059ea4a375bcb6b8a717b` |
| TLSH | `T11587E6466A059DCAE062A2F4108B7F40E3FEFD615AF1D37713F927585EEA34C8AA3444` |
| SSDEEP | `49152:J0ogYOBUcituYonIyelFn22gxuLxxuLexuLYMCwirXUlM93TDuUEczY1zHmKaLKe:KjyyMgCVb57/PEkOgA29Z` |
| ICON-DHASH | `009269ecd4d42900` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_078_7317f68c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7317f68c0a92198d6c7858d3ee96ab9bbebb9acaba11c5871bd93dc1fced7e70"
    family = "ValleyRAT"
    file_name = "dpinst_x64.in.02.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:29:17"
  condition:
    hash.sha256(0, filesize) == "7317f68c0a92198d6c7858d3ee96ab9bbebb9acaba11c5871bd93dc1fced7e70"
}
```

### Sample 79: `06f272750f81540d`

| Field | Value |
|---|---|
| SHA-256 | `06f272750f81540d8cb1808be0b79c4e963bb67ff035cb96ee4d1568fe70ace6` |
| Family label | `unknown` |
| File name | `145.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:26:42` |
| Reporter | `CNGaoLing` |
| Tags | `exe, signed, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `567a5b8402fccde1755ee4b5cc5b20a9` |
| SHA-1 | `4b00f100708b73133a16baea73332f918eb9df72` |
| SHA-256 | `06f272750f81540d8cb1808be0b79c4e963bb67ff035cb96ee4d1568fe70ace6` |
| SHA3-384 | `9b14c5357e0cd3cae202fe8fbf31b284dceb9b0297449b6e07229ea03d0f9d124559705a2b362003d20ea3896978427d` |
| IMPHASH | `09d0478591d4f788cb3e5ea416c25237` |
| TLSH | `T1FC3633C717989AE1F9C88A35EA790571BFD7EDA6B3104B0D2A4F48C7DB80B9DC854270` |
| SSDEEP | `98304:E8NfX2tUotTT05O+OCFnQSjvMgrHdAXlH/9OXTbiyFz0AMjOdIrRu:EdTY5OYvJ09gTj0A3dIrRu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_06f27275
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06f272750f81540d8cb1808be0b79c4e963bb67ff035cb96ee4d1568fe70ace6"
    family = "unknown"
    file_name = "145.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:26:42"
  condition:
    hash.sha256(0, filesize) == "06f272750f81540d8cb1808be0b79c4e963bb67ff035cb96ee4d1568fe70ace6"
}
```

### Sample 80: `0acbe43aa884db90`

| Field | Value |
|---|---|
| SHA-256 | `0acbe43aa884db90122d4596da79a266582c98a478b0a4a4e559480252fd3f28` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 06:26:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae38fcbdb77a3ceb6056f1f782dc95ea` |
| SHA-1 | `32d75dbd7ff8bc44899e7771a332d31d53cf6b87` |
| SHA-256 | `0acbe43aa884db90122d4596da79a266582c98a478b0a4a4e559480252fd3f28` |
| SHA3-384 | `26473374dae3255c126d0316b4a206cb88f4c31c04e2eff5584b75c2d61959fcc709b4163877d73a3cf8d82c9717a649` |
| TLSH | `T193556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS3:SDjxB4m5n8XlaPWi+d+a4TjxQP4Z` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_080_0acbe43a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0acbe43aa884db90122d4596da79a266582c98a478b0a4a4e559480252fd3f28"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:26:03"
  condition:
    hash.sha256(0, filesize) == "0acbe43aa884db90122d4596da79a266582c98a478b0a4a4e559480252fd3f28"
}
```

### Sample 81: `93f9815582688e65`

| Field | Value |
|---|---|
| SHA-256 | `93f9815582688e65458050489de1c99f8acc28548b3a957c67a87b734c9c3ba6` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 06:23:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34c31da258d323ecfdf65375f7e04f31` |
| SHA-1 | `2b40127d81277acfcb4a37fccdbae6722fc51589` |
| SHA-256 | `93f9815582688e65458050489de1c99f8acc28548b3a957c67a87b734c9c3ba6` |
| SHA3-384 | `eacf7c63c60d25edb61f4f39dc6fa255e7d8b7db9343f8635b7143686570fa22f4e20ce35c7f4d57466ac9769ec057a4` |
| TLSH | `T150556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSu:SDjxB4m5n8XlaPWi+d+a4TjxQP4k` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_081_93f98155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93f9815582688e65458050489de1c99f8acc28548b3a957c67a87b734c9c3ba6"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:23:04"
  condition:
    hash.sha256(0, filesize) == "93f9815582688e65458050489de1c99f8acc28548b3a957c67a87b734c9c3ba6"
}
```

### Sample 82: `aa23c2caeb41f761`

| Field | Value |
|---|---|
| SHA-256 | `aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42` |
| Family label | `unknown` |
| File name | `aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42` |
| File type | `sh` |
| First seen | `2026-11-26 06:18:55` |
| Reporter | `timtty` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fd92dba3bce70aa9b4a933c2963d4c1` |
| SHA-1 | `e41171ee0ac0a9cbe38a1da6386363494812df3e` |
| SHA-256 | `aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42` |
| SHA3-384 | `60cbd27f3773aa9dcdee978123d1b41eb0e9faeacfc8f60033f22c3e1fe3745a1f4eb8252daf6015f2d7100edcc31a6e` |
| TLSH | `T1010147B9F8158A24B30A00386FABC0515C42493F8A32A570750FED997FFEA116998A67` |
| SSDEEP | `12:NhSyYQ4KeHytKS56gBLN3gyW8zMf/bI7DOqAVcSu6SuKXBljjUKeH2WS:N0M4RHytCgB2oMf/E/OqAif65oBFQRHY` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_aa23c2ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42"
    family = "unknown"
    file_name = "aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42"
    file_type = "sh"
    first_seen = "2026-11-26 06:18:55"
  condition:
    hash.sha256(0, filesize) == "aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42"
}
```

### Sample 83: `caa42ce9f5fc5fe0`

| Field | Value |
|---|---|
| SHA-256 | `caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec` |
| Family label | `Prometei` |
| File name | `caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec` |
| File type | `elf` |
| First seen | `2026-11-26 06:18:44` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `010d51a1452f883254be42564a346b21` |
| SHA-1 | `0c6bd14df43bc2796d9d8f419b0a856f9fec7f6e` |
| SHA-256 | `caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec` |
| SHA3-384 | `ed4369e2b910dd366a172d0884738fedaddcafea5970d2218ba942aecfd622778d0c76a005aee705796e50ae2cd2e61d` |
| TLSH | `T1ABA4237EBAE3213FF8259970770F75CAD010A0E89A6F0A7B931C6A138B3D4525D75872` |
| SSDEEP | `12288:qooQepOXnbyu+aDL9nS19GEMFz3D9p4FRVeTm7H8Vaav:zo7peVVnSizT9pqHoVaav` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_083_caa42ce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec"
    family = "Prometei"
    file_name = "caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec"
    file_type = "elf"
    first_seen = "2026-11-26 06:18:44"
  condition:
    hash.sha256(0, filesize) == "caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec"
}
```

### Sample 84: `685183ff4c8da6f4`

| Field | Value |
|---|---|
| SHA-256 | `685183ff4c8da6f4f3fbf3f485bff80831e512c4c9daf8f13e0736da8a13d15c` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 06:17:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12b930a07e14d0a5e9c2fc85727528af` |
| SHA-1 | `b689bb042a09958fb1e221bab1b2c9b88461f7bc` |
| SHA-256 | `685183ff4c8da6f4f3fbf3f485bff80831e512c4c9daf8f13e0736da8a13d15c` |
| SHA3-384 | `234858dc991214781e025dcac1c6b4f0b1b754581ef9c9166a0c5f0df709705386ad7b51eddc36aab5476c6ceeb5caa8` |
| TLSH | `T1BA556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSv:SDjxB4m5n8XlaPWi+d+a4TjxQP4F` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_084_685183ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "685183ff4c8da6f4f3fbf3f485bff80831e512c4c9daf8f13e0736da8a13d15c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:17:06"
  condition:
    hash.sha256(0, filesize) == "685183ff4c8da6f4f3fbf3f485bff80831e512c4c9daf8f13e0736da8a13d15c"
}
```

### Sample 85: `1dc1c026505f10be`

| Field | Value |
|---|---|
| SHA-256 | `1dc1c026505f10be2a4eec854482ffc66bfd37853c0648a31bfc581a2ab695fc` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 06:17:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72108c9dbb6e6ce9b8f59b71ac08b71b` |
| SHA-1 | `8ebdba54daa817b0c057a6b5a2b10df573699d39` |
| SHA-256 | `1dc1c026505f10be2a4eec854482ffc66bfd37853c0648a31bfc581a2ab695fc` |
| SHA3-384 | `d5dd9e627657c14be6059cf1fbadadaf8a290c5f9f4fa0c498c6cfccb8e7a675e74d2e1852c33edd550c65b96b3b316b` |
| TLSH | `T1E3556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS/:SDjxB4m5n8XlaPWi+d+a4TjxQP4Z` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_085_1dc1c026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dc1c026505f10be2a4eec854482ffc66bfd37853c0648a31bfc581a2ab695fc"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:17:03"
  condition:
    hash.sha256(0, filesize) == "1dc1c026505f10be2a4eec854482ffc66bfd37853c0648a31bfc581a2ab695fc"
}
```

### Sample 86: `cfcbccc833f403ea`

| Field | Value |
|---|---|
| SHA-256 | `cfcbccc833f403ea88d41787306e263b7fdbe7f45f00f913378d0cb30c227e9d` |
| Family label | `Formbook` |
| File name | `9F3CC576B5E16BF62F0D55529DF09C8DF91F0A28` |
| File type | `exe` |
| First seen | `2026-11-26 06:00:24` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd2eaf17e423ea65e211fb360870bf91` |
| SHA-1 | `bb74f9f347c7259b4ba46836c1517ce5630957c1` |
| SHA-256 | `cfcbccc833f403ea88d41787306e263b7fdbe7f45f00f913378d0cb30c227e9d` |
| SHA3-384 | `922ff0efce1775e5a63c49f2a7ffa27bc60daa456655fe04a88b7c1b5b72a1180b2e53066435a7b3b445da95a16779df` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14205F114223ECB07D4B71FF45862E2B403F5AE89A536C6168ED72DEF79397404A847A3` |
| SSDEEP | `24576:cJXpPZ3h3LqoGyXtAFLxc1INxtA0H9wO3rIspqwm:2pPbLqoj9yO1E247h` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_086_cfcbccc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfcbccc833f403ea88d41787306e263b7fdbe7f45f00f913378d0cb30c227e9d"
    family = "Formbook"
    file_name = "9F3CC576B5E16BF62F0D55529DF09C8DF91F0A28"
    file_type = "exe"
    first_seen = "2026-11-26 06:00:24"
  condition:
    hash.sha256(0, filesize) == "cfcbccc833f403ea88d41787306e263b7fdbe7f45f00f913378d0cb30c227e9d"
}
```

### Sample 87: `d38a4fd6039fc8ee`

| Field | Value |
|---|---|
| SHA-256 | `d38a4fd6039fc8ee36eae3185aac45640165b20c208277ccdb77c6289064abd7` |
| Family label | `PureLogsStealer` |
| File name | `_00168` |
| File type | `exe` |
| First seen | `2026-11-26 06:00:21` |
| Reporter | `ni_fi_70` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b19d296da044576c14fa382610a276f` |
| SHA-1 | `8c0ec4a41891c5ed69546404e8f11671bb7d3863` |
| SHA-256 | `d38a4fd6039fc8ee36eae3185aac45640165b20c208277ccdb77c6289064abd7` |
| SHA3-384 | `db2e3eed1a2ca6c31d4cd2bae833fba240c51c15373b1821110de4cd13fc0bfeddb1db69d29ecda5f85ced5a91b65994` |
| IMPHASH | `c49f3890f2dbe6e16286e5baa6ee27f5` |
| TLSH | `T116854A6C5654E77389472B113C216B6593BFB34927840A34A46DE6BFFF8160E8B009FE` |
| SSDEEP | `24576:qi+9MYJAjwI+EQFJbgNN5WxHU0rv4Xw+KMmEg0bYoR3+nvIHA0:aGYK8IT2gNN0x0UwAjMN8oEQD` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_087_d38a4fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d38a4fd6039fc8ee36eae3185aac45640165b20c208277ccdb77c6289064abd7"
    family = "PureLogsStealer"
    file_name = "_00168"
    file_type = "exe"
    first_seen = "2026-11-26 06:00:21"
  condition:
    hash.sha256(0, filesize) == "d38a4fd6039fc8ee36eae3185aac45640165b20c208277ccdb77c6289064abd7"
}
```

### Sample 88: `97cbb90c2fdb71c8`

| Field | Value |
|---|---|
| SHA-256 | `97cbb90c2fdb71c84cb302309212ee5be356d1e5d1b1e2162e25b3318924fdaa` |
| Family label | `njrat` |
| File name | `6372875880C71C07EA54681687401B75.exe` |
| File type | `exe` |
| First seen | `2026-11-26 06:00:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6372875880c71c07ea54681687401b75` |
| SHA-1 | `64abf1fc5aaebe44f92f44ac49dcd8ea2008a5b9` |
| SHA-256 | `97cbb90c2fdb71c84cb302309212ee5be356d1e5d1b1e2162e25b3318924fdaa` |
| SHA3-384 | `789f447dbadc72b2910deae4d19f21d868e110e68c46ca0639bbab9fd9e3a00168f86899a73324af318f89d187170751` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T173A2184E77988618D3AD1AB84CF3632447F1F68B8981DF4B1CDA10DA2F236D05652AFD` |
| SSDEEP | `384:mW6J/USlvpJkBXMGvgMQTmKByzWnqhwYmHGaOWQ+dcs//34LAZSTqa12:36JUqvpJkBXXvgMQTmKKirKWQuHq/2` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_088_97cbb90c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97cbb90c2fdb71c84cb302309212ee5be356d1e5d1b1e2162e25b3318924fdaa"
    family = "njrat"
    file_name = "6372875880C71C07EA54681687401B75.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:00:10"
  condition:
    hash.sha256(0, filesize) == "97cbb90c2fdb71c84cb302309212ee5be356d1e5d1b1e2162e25b3318924fdaa"
}
```

### Sample 89: `eb65f0d4105d47e7`

| Field | Value |
|---|---|
| SHA-256 | `eb65f0d4105d47e7a320798fe70de8da676287e169c090f611652dd06dbb4cbf` |
| Family label | `unknown` |
| File name | `load.sh` |
| File type | `sh` |
| First seen | `2026-11-26 05:59:14` |
| Reporter | `Jerry1113` |
| Tags | `cowrie, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5360d38eeaaf44a33f163918befa2132` |
| SHA-1 | `3f4e5f5820e3163c300ffa9b1b507ff5393bac9f` |
| SHA-256 | `eb65f0d4105d47e7a320798fe70de8da676287e169c090f611652dd06dbb4cbf` |
| SHA3-384 | `da7b04aeace4bebb6418d32b4b98fe182263c70f37f88da072d22d2be905d9de543a9caf73198ce1ba51451ce53bed8b` |
| TLSH | `T16741D08A79B3D63643CB84741F86B301E356654308A7D8D8B49E7D313FEA050FDA1E9A` |
| SSDEEP | `48:ZVdtxzIIamf1KG1efwFWZY4r/YNgNimQp/P8p1MlmlBFInKIYgVDF9jQul4dQEso:7d78/mdwfkepbgnm/2nKI3VDv6wGHBl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_eb65f0d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb65f0d4105d47e7a320798fe70de8da676287e169c090f611652dd06dbb4cbf"
    family = "unknown"
    file_name = "load.sh"
    file_type = "sh"
    first_seen = "2026-11-26 05:59:14"
  condition:
    hash.sha256(0, filesize) == "eb65f0d4105d47e7a320798fe70de8da676287e169c090f611652dd06dbb4cbf"
}
```

### Sample 90: `6cc8947eff1f6335`

| Field | Value |
|---|---|
| SHA-256 | `6cc8947eff1f63359f1434fc35004651ee5453f754caf94b703edc8a226dd14c` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 05:57:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `139043618786672e96e09369db27b6ab` |
| SHA-1 | `632610e822652bd418002b8185a2cc3079c5743b` |
| SHA-256 | `6cc8947eff1f63359f1434fc35004651ee5453f754caf94b703edc8a226dd14c` |
| SHA3-384 | `50ca80a2559579bb02c707065dbd4f1ac152427e04c2d59e2c0ea29ef816021659709130eb73ee316f45c7bb420eb873` |
| TLSH | `T17C556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS7:SDjxB4m5n8XlaPWi+d+a4TjxQP49` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_090_6cc8947e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc8947eff1f63359f1434fc35004651ee5453f754caf94b703edc8a226dd14c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 05:57:04"
  condition:
    hash.sha256(0, filesize) == "6cc8947eff1f63359f1434fc35004651ee5453f754caf94b703edc8a226dd14c"
}
```

### Sample 91: `70a0aa9032eddb4d`

| Field | Value |
|---|---|
| SHA-256 | `70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68` |
| Family label | `unknown` |
| File name | `70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68.bin` |
| File type | `js` |
| First seen | `2026-11-26 05:55:54` |
| Reporter | `Tuxxin` |
| Tags | `js, script` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca06c8a16f431f7eabab45b69bfc9091` |
| SHA-1 | `6772936ceceb1ea5cfe4e4e29b33831684e097f1` |
| SHA-256 | `70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68` |
| SHA3-384 | `cf448dc12637145e9ab63647b43ff317490b957cc7a5ee5c0a7c61f028e4130cec09c7818800c25fcf266af708000cab` |
| TLSH | `T1FE1463105F1219F9C866C4D43EB69840E2E71A03DD3D7532B43D8E2C5F9F16C69F6AA8` |
| SSDEEP | `1536:C8GN8ZMi4yi4sZAhP46u+Wu+B4+s4+8Zy6ZyvsFrlF/lFm3V3e+h+MH3HFhqhRX5:ChRWQefs78Mn2CflFBaA/D` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_70a0aa90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68"
    family = "unknown"
    file_name = "70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68.bin"
    file_type = "js"
    first_seen = "2026-11-26 05:55:54"
  condition:
    hash.sha256(0, filesize) == "70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68"
}
```

### Sample 92: `239043953b148005`

| Field | Value |
|---|---|
| SHA-256 | `239043953b148005c185ecf69d57df64d2a0feca0fcb573e3dd9323df0e17093` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 05:55:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12a2a9b862f98236808e9cbda8ace6c3` |
| SHA-1 | `d453c91ba10d73233ce176c6bb3bd67742181960` |
| SHA-256 | `239043953b148005c185ecf69d57df64d2a0feca0fcb573e3dd9323df0e17093` |
| SHA3-384 | `ec69ff9a528946f8406d2cba939f0fb0b9fa1acccfe6a7df1895e62ebac64b95258f5cc4ced258aaa31397deb7c206a4` |
| TLSH | `T161556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSP:SDjxB4m5n8XlaPWi+d+a4TjxQP45` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_092_23904395
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239043953b148005c185ecf69d57df64d2a0feca0fcb573e3dd9323df0e17093"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 05:55:03"
  condition:
    hash.sha256(0, filesize) == "239043953b148005c185ecf69d57df64d2a0feca0fcb573e3dd9323df0e17093"
}
```

### Sample 93: `486e90103cb806d3`

| Field | Value |
|---|---|
| SHA-256 | `486e90103cb806d3fe94fd91b752684f7de818c80f6f08ea3c3a637a158e7a5d` |
| Family label | `Prometei` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-26 05:53:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24f1834e0adaf09973c70742ba129356` |
| SHA-1 | `d8870a2b2109ccad6a8e950eb34a9b5c36a83266` |
| SHA-256 | `486e90103cb806d3fe94fd91b752684f7de818c80f6f08ea3c3a637a158e7a5d` |
| SHA3-384 | `644d6a11b7a0e13b0ee6d4c7dce80e71de0165c351673ce5ad8cbeb82c2f6e4a78cf3bee9bd568c446a5b113fd4bcac3` |
| TLSH | `T13E556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSe:SDjxB4m5n8XlaPWi+d+a4TjxQP4M` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_093_486e9010
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "486e90103cb806d3fe94fd91b752684f7de818c80f6f08ea3c3a637a158e7a5d"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 05:53:03"
  condition:
    hash.sha256(0, filesize) == "486e90103cb806d3fe94fd91b752684f7de818c80f6f08ea3c3a637a158e7a5d"
}
```

### Sample 94: `e9b07e9ef6a8feb3`

| Field | Value |
|---|---|
| SHA-256 | `e9b07e9ef6a8feb3999d9cb9142d12b2c1eec90d7cc5229e1df7761a5279acc8` |
| Family label | `Mirai` |
| File name | `iranbot-ultimate.aarch64` |
| File type | `elf` |
| First seen | `2026-11-26 05:51:31` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `394db62becf477790fb417cddfe60013` |
| SHA-1 | `fa169a0c960a30d577c18a0c269cbe39770258cf` |
| SHA-256 | `e9b07e9ef6a8feb3999d9cb9142d12b2c1eec90d7cc5229e1df7761a5279acc8` |
| SHA3-384 | `b4bd3ecd22cf966e2ec5d71d84e4a8eba078fdf15f564445a35383bfc9736c0445cee02e22c62d4bc52d9a8e944c24d0` |
| TLSH | `T101938E68DA0FBC82D2C7E7BDBD950FA2301B3CE48715C1B26A00A65CD8FADD4C956167` |
| SSDEEP | `1536:2tGxtxG4wQ9N6m/2RJlcrxwaJM+Bf+OGu5MOsCCQ8On3xyffovwKauTLfIr:iGxtxPOm+HlcXM+YXUMWBy3gwKI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_e9b07e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b07e9ef6a8feb3999d9cb9142d12b2c1eec90d7cc5229e1df7761a5279acc8"
    family = "Mirai"
    file_name = "iranbot-ultimate.aarch64"
    file_type = "elf"
    first_seen = "2026-11-26 05:51:31"
  condition:
    hash.sha256(0, filesize) == "e9b07e9ef6a8feb3999d9cb9142d12b2c1eec90d7cc5229e1df7761a5279acc8"
}
```

### Sample 95: `5990121aa1cb12cb`

| Field | Value |
|---|---|
| SHA-256 | `5990121aa1cb12cb10cbccf370a337570edcc3c4073babab62bb1648038f52be` |
| Family label | `MassLogger` |
| File name | `ea72a2651983449da93d8858b5c173db.MSG` |
| File type | `exe` |
| First seen | `2026-11-26 05:30:47` |
| Reporter | `ni_fi_70` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf7e4ee5f95b24276d4c6b1921ccc43a` |
| SHA-1 | `0700b20bdbecaa84e3e4b409799ed7b2cdb9fe6f` |
| SHA-256 | `5990121aa1cb12cb10cbccf370a337570edcc3c4073babab62bb1648038f52be` |
| SHA3-384 | `7e7c5c7b30e439495405d0b713f826d45b339d57dc3f12958991db8bf8be3298b86082fa585eef4bebf95fa736a3adf0` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BED4D054227DDB07E4B62BF569B1E2B413F56E88A531D2068FD23DDBB836B004E80797` |
| SSDEEP | `12288:BJMqwmCjRVzjbMeLtR2i8ILKhDyr+plswibqx:BJMqwmKRVMeD2i8ILKcrglsnqx` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_095_5990121a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5990121aa1cb12cb10cbccf370a337570edcc3c4073babab62bb1648038f52be"
    family = "MassLogger"
    file_name = "ea72a2651983449da93d8858b5c173db.MSG"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:47"
  condition:
    hash.sha256(0, filesize) == "5990121aa1cb12cb10cbccf370a337570edcc3c4073babab62bb1648038f52be"
}
```

### Sample 96: `706e45816f8430a4`

| Field | Value |
|---|---|
| SHA-256 | `706e45816f8430a495f0cf2163c1e7cfb4ade51a46b01ffd8c9d50e6b537c2dd` |
| Family label | `PureLogsStealer` |
| File name | `pd158065316.att` |
| File type | `exe` |
| First seen | `2026-11-26 05:30:44` |
| Reporter | `ni_fi_70` |
| Tags | `exe, PureLogsStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc74a8eb6c986c7626ebef90229dfd41` |
| SHA-1 | `e81ac4587c83a33dbeefd7e1c4b4673ce9e24513` |
| SHA-256 | `706e45816f8430a495f0cf2163c1e7cfb4ade51a46b01ffd8c9d50e6b537c2dd` |
| SHA3-384 | `117fddd867e10207658f6d38b53c436996ca84552dc96caf89d3e974b319d7d852e89d7daba6a2b9402ea6ae34125d26` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B65512602239CF06E4771BF459B0E2F813F56D85A636C2469ED63CEF7836B005A857A3` |
| SSDEEP | `24576:0JVqwmrZ+2Kmt32PboOTZsu905Xpe3mWWi+kI7Fygoeqs5Ik42FZb:WuZ+ZmFuPTIJpD3FygVH/H` |

#### Technical Assessment

- The sample is tracked as `PureLogsStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureLogsStealer_096_706e4581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "706e45816f8430a495f0cf2163c1e7cfb4ade51a46b01ffd8c9d50e6b537c2dd"
    family = "PureLogsStealer"
    file_name = "pd158065316.att"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:44"
  condition:
    hash.sha256(0, filesize) == "706e45816f8430a495f0cf2163c1e7cfb4ade51a46b01ffd8c9d50e6b537c2dd"
}
```

### Sample 97: `cd8536fe243401c8`

| Field | Value |
|---|---|
| SHA-256 | `cd8536fe243401c8d2f11bd6292bd79184d4a1a988de2beb9b819db06c423823` |
| Family label | `Formbook` |
| File name | `md5001000308758.tmp` |
| File type | `exe` |
| First seen | `2026-11-26 05:30:41` |
| Reporter | `ni_fi_70` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8da183ef3a592d61715dc9879665f8e` |
| SHA-1 | `b8eb24840d398e64b48b4780c7cedf203086544b` |
| SHA-256 | `cd8536fe243401c8d2f11bd6292bd79184d4a1a988de2beb9b819db06c423823` |
| SHA3-384 | `4ca14dc065f37ababa74d8add0bb7bfe554232e58ebdfad0df8a51271096905c353be87516b56e7a6fc6a8b3ca1b203b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T14115DF572E2ABA02D4B61BB72561D2BC03B55D8DBDE5C2034EDE7DEBF836B000940A57` |
| SSDEEP | `12288:3JXqwmc1Wn4X4OPh2kniRcgi6ZjF2vfZFrHP4oWar5Cf4JGscfv:3JXqwmFnYZtgi6hmfZlHQoWarcf4ssc` |
| ICON-DHASH | `4c33d8d4d4d8324c` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_097_cd8536fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd8536fe243401c8d2f11bd6292bd79184d4a1a988de2beb9b819db06c423823"
    family = "Formbook"
    file_name = "md5001000308758.tmp"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:41"
  condition:
    hash.sha256(0, filesize) == "cd8536fe243401c8d2f11bd6292bd79184d4a1a988de2beb9b819db06c423823"
}
```

### Sample 98: `a61aeafbc93dac02`

| Field | Value |
|---|---|
| SHA-256 | `a61aeafbc93dac025daabf33521f7d7f0bd6d5ade363000263ee6e6314de505e` |
| Family label | `AgentTesla` |
| File name | `5f937617b8d44533b42d7fabef5597e8.MSG` |
| File type | `exe` |
| First seen | `2026-11-26 05:30:38` |
| Reporter | `ni_fi_70` |
| Tags | `AgentTesla, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9844aca79ff242069b1ae8ca17e7351` |
| SHA-1 | `858b1aaaab11af6d1134df0184f553a69abac098` |
| SHA-256 | `a61aeafbc93dac025daabf33521f7d7f0bd6d5ade363000263ee6e6314de505e` |
| SHA3-384 | `e3f72b80eb26c500624e73c33a3a2d472fa36cae2717ec50517216f1c0f3ebda9063b380f6a4aa317e2ba59383ab0c40` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T189F4E0543329CF07E8B71BF469A1E2B453F66D89A531C2064FE23DEBB936B401A44763` |
| SSDEEP | `12288:nJ0qwmiKnO1dxQXRASMwZV/DHk5w9OZp5M3jp80xdB97FYA:nJ0qwmiKOmXRAdcbE5wUpiTxdPy` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_098_a61aeafb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a61aeafbc93dac025daabf33521f7d7f0bd6d5ade363000263ee6e6314de505e"
    family = "AgentTesla"
    file_name = "5f937617b8d44533b42d7fabef5597e8.MSG"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:38"
  condition:
    hash.sha256(0, filesize) == "a61aeafbc93dac025daabf33521f7d7f0bd6d5ade363000263ee6e6314de505e"
}
```

### Sample 99: `27fec664e3ec2520`

| Field | Value |
|---|---|
| SHA-256 | `27fec664e3ec2520f2ffc3e37f8d950527f9e88aec2e1d53f315f4852f24c617` |
| Family label | `unknown` |
| File name | `1fb664a4_horse_nine_x1.dat` |
| File type | `exe` |
| First seen | `2026-11-26 05:30:35` |
| Reporter | `ni_fi_70` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a1b3dba794bc8db8b6aa52e4414465a2` |
| SHA-1 | `16f7e68e147a005a41529eeee9601b205d91390a` |
| SHA-256 | `27fec664e3ec2520f2ffc3e37f8d950527f9e88aec2e1d53f315f4852f24c617` |
| SHA3-384 | `c3310a15006ce8ce6ab9e7c2b2ae657dd126d50708e06df6dcaa2b80e5d5ea90260f2931b52d5c67c5db319db8c98451` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T10625F11A771DE0EEC656E832AF3A4DD8B69D49C58203939556FB124B2CCCF0B8B531D2` |
| SSDEEP | `24576:fuCYvbnSHD52VkleZm5KE6kCZm/PGyaQ/A:mzvbng5h6kCZmGyXA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_27fec664
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27fec664e3ec2520f2ffc3e37f8d950527f9e88aec2e1d53f315f4852f24c617"
    family = "unknown"
    file_name = "1fb664a4_horse_nine_x1.dat"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:35"
  condition:
    hash.sha256(0, filesize) == "27fec664e3ec2520f2ffc3e37f8d950527f9e88aec2e1d53f315f4852f24c617"
}
```

### Sample 100: `7f4db1fd15d33618`

| Field | Value |
|---|---|
| SHA-256 | `7f4db1fd15d336185099b1509937fd92ebc0afdc9a95cdf88108aaaf3b588601` |
| Family label | `MassLogger` |
| File name | `_00019` |
| File type | `exe` |
| First seen | `2026-11-26 05:30:32` |
| Reporter | `ni_fi_70` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `91632d6e31f6c5d318465fd0e30d3c89` |
| SHA-1 | `b7e286683efba1177672b7a6434d7d48b54c6461` |
| SHA-256 | `7f4db1fd15d336185099b1509937fd92ebc0afdc9a95cdf88108aaaf3b588601` |
| SHA3-384 | `2631a7525bb63f154fd46e6a15ee5f1df576d31d63d71f55697410cdac183cfd41458e23dc953d37c4b29dede4157a9e` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1813501A42229CF17E4BA1FF499B1E1B403F59E88A535D2064FD63CEBB936B401E50763` |
| SSDEEP | `24576:GJbqwmT+aTCT0sJ0PAF+jNbIOZlMqRSp87lTFUmYqI+3KfVx:2n+sJ0PAF+hZW6RFUZqId` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_100_7f4db1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f4db1fd15d336185099b1509937fd92ebc0afdc9a95cdf88108aaaf3b588601"
    family = "MassLogger"
    file_name = "_00019"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:32"
  condition:
    hash.sha256(0, filesize) == "7f4db1fd15d336185099b1509937fd92ebc0afdc9a95cdf88108aaaf3b588601"
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
 * Generated: 2026-11-26T08:35:03.922760+00:00
 */

rule MalwareBazaar_unknown_001_3cc8eaa4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cc8eaa41525dceabd9d34a39298fc8e54bbb3e422530375d4c45aae6d6078ea"
    family = "unknown"
    file_name = "09790-PR-26-14927-PO-14928-14930.scr"
    file_type = "exe"
    first_seen = "2026-11-26 08:34:28"
  condition:
    hash.sha256(0, filesize) == "3cc8eaa41525dceabd9d34a39298fc8e54bbb3e422530375d4c45aae6d6078ea"
}

rule MalwareBazaar_Prometei_002_81f34962
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81f34962e5ee4ebfc1699e525a129faca9816f0fea40a0a255d160555c3dfbdd"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 08:23:03"
  condition:
    hash.sha256(0, filesize) == "81f34962e5ee4ebfc1699e525a129faca9816f0fea40a0a255d160555c3dfbdd"
}

rule MalwareBazaar_AgentTesla_003_8b970e60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b970e600b06d991f1e5dcd6220e9a904cb11b4d008f17b277adc0ef88e0c622"
    family = "AgentTesla"
    file_name = "Payment_Advice-SOA-26_NOV-PDF.JS"
    file_type = "js"
    first_seen = "2026-11-26 08:19:10"
  condition:
    hash.sha256(0, filesize) == "8b970e600b06d991f1e5dcd6220e9a904cb11b4d008f17b277adc0ef88e0c622"
}

rule MalwareBazaar_WannaCry_004_341374dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9"
    family = "WannaCry"
    file_name = "341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9"
    file_type = "exe"
    first_seen = "2026-11-26 08:15:13"
  condition:
    hash.sha256(0, filesize) == "341374dce202a5f5afb014eac547ca965a612672138bee8893c1c298843a39e9"
}

rule MalwareBazaar_unknown_005_77aa7a04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77aa7a04c23669bc478653fd6e0fd90eb5f6b1342105deeebc497e284c8688aa"
    family = "unknown"
    file_name = "GSTR-MT103__ConfirmationPDF.js"
    file_type = "js"
    first_seen = "2026-11-26 08:05:32"
  condition:
    hash.sha256(0, filesize) == "77aa7a04c23669bc478653fd6e0fd90eb5f6b1342105deeebc497e284c8688aa"
}

rule MalwareBazaar_unknown_006_b21a44ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e"
    family = "unknown"
    file_name = "b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e.exe"
    file_type = "exe"
    first_seen = "2026-11-26 07:49:54"
  condition:
    hash.sha256(0, filesize) == "b21a44ab76ee4f999f880d761970069776d1c5b1a1cb6cf14d7da108aa538c6e"
}

rule MalwareBazaar_unknown_007_70c33f33
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659"
    family = "unknown"
    file_name = "70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659"
    file_type = "elf"
    first_seen = "2026-11-26 07:39:52"
  condition:
    hash.sha256(0, filesize) == "70c33f33097d17b717a61abd29732f7fd4bdcc4321a034da5168515fe0314659"
}

rule MalwareBazaar_unknown_008_c6544286
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d"
    family = "unknown"
    file_name = "c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d"
    file_type = "elf"
    first_seen = "2026-11-26 07:32:25"
  condition:
    hash.sha256(0, filesize) == "c6544286dcdf3597dea8a00c04a71d006dc83f89f7313b7be9a9c5a151eb388d"
}

rule MalwareBazaar_unknown_009_511f058e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1"
    family = "unknown"
    file_name = "511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1"
    file_type = "elf"
    first_seen = "2026-11-26 07:25:10"
  condition:
    hash.sha256(0, filesize) == "511f058ee0f47263503412e53dea6ceb318b8c4b64fc6e12d74ec9279c7300b1"
}

rule MalwareBazaar_GuLoader_010_26bbe677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26bbe6772c0f6b8b3d865aba425812faf7df9687891950ca07a9eb3d24c96dd9"
    family = "GuLoader"
    file_name = "IMAGES-REQUEST FOR QUOTAION RO-C-27299,28275.28277,27921,28282,28276 RFQ 730038262 CLOSING DATE 04-12- 2026.jpg.exe"
    file_type = "exe"
    first_seen = "2026-11-26 07:22:35"
  condition:
    hash.sha256(0, filesize) == "26bbe6772c0f6b8b3d865aba425812faf7df9687891950ca07a9eb3d24c96dd9"
}

rule MalwareBazaar_unknown_011_0ace2614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ace26141b9fad0a395a43c0b208e5e943d6de25bdd0bbd1d37bf991b4fa1053"
    family = "unknown"
    file_name = "자금출처 소명서CaryPact 동적 수익 참고표 V1-V10..zip"
    file_type = "zip"
    first_seen = "2026-11-26 07:15:48"
  condition:
    hash.sha256(0, filesize) == "0ace26141b9fad0a395a43c0b208e5e943d6de25bdd0bbd1d37bf991b4fa1053"
}

rule MalwareBazaar_Mirai_012_f9b27045
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc"
    family = "Mirai"
    file_name = "f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc"
    file_type = "elf"
    first_seen = "2026-11-26 07:12:11"
  condition:
    hash.sha256(0, filesize) == "f9b2704547ee9f79dc7f604b7d5b067d355105d6ab167f9a0aae4b86bf510dcc"
}

rule MalwareBazaar_RemcosRAT_013_3fe5c3f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3fe5c3f6e949ca1d08a421a9bf08ed3b5cadcaeeeae4cd427a40eb938a1931b3"
    family = "RemcosRAT"
    file_name = "asc.hta"
    file_type = "hta"
    first_seen = "2026-11-26 07:00:04"
  condition:
    hash.sha256(0, filesize) == "3fe5c3f6e949ca1d08a421a9bf08ed3b5cadcaeeeae4cd427a40eb938a1931b3"
}

rule MalwareBazaar_unknown_014_994bcf81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994bcf81a9faaf1ec96be49c99d68cde37ed9981aaf01aa76271c1e02851991e"
    family = "unknown"
    file_name = "goodwords.hta"
    file_type = "hta"
    first_seen = "2026-11-26 06:57:07"
  condition:
    hash.sha256(0, filesize) == "994bcf81a9faaf1ec96be49c99d68cde37ed9981aaf01aa76271c1e02851991e"
}

rule MalwareBazaar_unknown_015_70dc1383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301"
    family = "unknown"
    file_name = "70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301"
    file_type = "elf"
    first_seen = "2026-11-26 06:55:24"
  condition:
    hash.sha256(0, filesize) == "70dc1383b66ae641c1c5d3c4435f92b86d15000c8a1e603f0989e42124bd5301"
}

rule MalwareBazaar_RemcosRAT_016_d3160d81
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3160d819505de05b40bf4afeec50743bd6941433f0458e3cb74273fe3d700cc"
    family = "RemcosRAT"
    file_name = "SO.0421-FZY3220STX0421-宝柚-TXG to SHIHU-要保險 CLS11302026 SO#0421.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:52:06"
  condition:
    hash.sha256(0, filesize) == "d3160d819505de05b40bf4afeec50743bd6941433f0458e3cb74273fe3d700cc"
}

rule MalwareBazaar_WARDENStealer_017_35d34ec0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d34ec00a6610b3a90a4c2b6df568c119fe320899f698bff65632e023e34f69"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:23"
  condition:
    hash.sha256(0, filesize) == "35d34ec00a6610b3a90a4c2b6df568c119fe320899f698bff65632e023e34f69"
}

rule MalwareBazaar_njrat_018_6d09632e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d09632e3a4be09caabadb562ed7eac2a2b99eba1a3745d2ded9e05b251d85fd"
    family = "njrat"
    file_name = "0baf09147567304bbba75d169a6c92cb.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:18"
  condition:
    hash.sha256(0, filesize) == "6d09632e3a4be09caabadb562ed7eac2a2b99eba1a3745d2ded9e05b251d85fd"
}

rule MalwareBazaar_njrat_019_95c9eca5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95c9eca51d1099d7f4eab495222961b2bad03ea64c08175822b72d4141a3cae6"
    family = "njrat"
    file_name = "1f3f689669e10696eaca535dec865bcc.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:12"
  condition:
    hash.sha256(0, filesize) == "95c9eca51d1099d7f4eab495222961b2bad03ea64c08175822b72d4141a3cae6"
}

rule MalwareBazaar_njrat_020_473fac24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "473fac24fd67ef5c596d9b46b6db74b2ea2eb7931aed0a19a960d6a294730fe8"
    family = "njrat"
    file_name = "0a1542f4c9f53aa1937648d22e46be78.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:07"
  condition:
    hash.sha256(0, filesize) == "473fac24fd67ef5c596d9b46b6db74b2ea2eb7931aed0a19a960d6a294730fe8"
}

rule MalwareBazaar_unknown_021_a1eb7ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1eb7ac383f39dd26c0e9a4b0536df58384dda3710ea6643fb19620b8e046cbd"
    family = "unknown"
    file_name = "bot.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:50:05"
  condition:
    hash.sha256(0, filesize) == "a1eb7ac383f39dd26c0e9a4b0536df58384dda3710ea6643fb19620b8e046cbd"
}

rule MalwareBazaar_WARDENStealer_022_59c31510
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59c315105c6dd7b1cca56a767974b53297cd4a8b043752e45cb19408401656bf"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:49:58"
  condition:
    hash.sha256(0, filesize) == "59c315105c6dd7b1cca56a767974b53297cd4a8b043752e45cb19408401656bf"
}

rule MalwareBazaar_unknown_023_df712eff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df712eff0fb0bc9e37926002e1aad70edb1e03a7eb64403a82415cd461674f30"
    family = "unknown"
    file_name = "sysd"
    file_type = "exe"
    first_seen = "2026-11-26 06:49:55"
  condition:
    hash.sha256(0, filesize) == "df712eff0fb0bc9e37926002e1aad70edb1e03a7eb64403a82415cd461674f30"
}

rule MalwareBazaar_WARDENStealer_024_95ecf420
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95ecf420c6c9650f7080eca8860b577990a8284ff2f4613a6b44056e15127fad"
    family = "WARDENStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:49:38"
  condition:
    hash.sha256(0, filesize) == "95ecf420c6c9650f7080eca8860b577990a8284ff2f4613a6b44056e15127fad"
}

rule MalwareBazaar_unknown_025_128ac403
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "128ac40378b231c03ec490ee2628cc0b02e1a113314beff6f0b1d71f1723a7b1"
    family = "unknown"
    file_name = "Ikov.jar"
    file_type = "jar"
    first_seen = "2026-11-26 06:49:35"
  condition:
    hash.sha256(0, filesize) == "128ac40378b231c03ec490ee2628cc0b02e1a113314beff6f0b1d71f1723a7b1"
}

rule MalwareBazaar_SnappyClient_026_eb1c3d52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb1c3d52bd01ed52a6d87cdf908fcae036723f7b413360ad09df130368520210"
    family = "SnappyClient"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:48:59"
  condition:
    hash.sha256(0, filesize) == "eb1c3d52bd01ed52a6d87cdf908fcae036723f7b413360ad09df130368520210"
}

rule MalwareBazaar_Formbook_027_0d58852a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d58852a37057c6dcda37c1f956d1463bd78b8bb8f3475bdf8dde1acc7e0bdf9"
    family = "Formbook"
    file_name = "Permintaan Penawaran Harga Nov. 2026.vbe"
    file_type = "vbe"
    first_seen = "2026-11-26 06:48:24"
  condition:
    hash.sha256(0, filesize) == "0d58852a37057c6dcda37c1f956d1463bd78b8bb8f3475bdf8dde1acc7e0bdf9"
}

rule MalwareBazaar_unknown_028_1e46feda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e46feda5f8e095f291ee5f696bbc982db4c5005170423c22a13f3031d8b28ab"
    family = "unknown"
    file_name = "TSSA_0947_262611.vbe"
    file_type = "vbe"
    first_seen = "2026-11-26 06:48:21"
  condition:
    hash.sha256(0, filesize) == "1e46feda5f8e095f291ee5f696bbc982db4c5005170423c22a13f3031d8b28ab"
}

rule MalwareBazaar_AsyncRAT_029_47ae865c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47ae865c1ad1abd1c35bd1b8a02550c7a5410273439eebcace33ab6e7f316fcb"
    family = "AsyncRAT"
    file_name = "PAGO PROVEEDOR _EBERSPAECHER.js"
    file_type = "js"
    first_seen = "2026-11-26 06:48:02"
  condition:
    hash.sha256(0, filesize) == "47ae865c1ad1abd1c35bd1b8a02550c7a5410273439eebcace33ab6e7f316fcb"
}

rule MalwareBazaar_XWorm_030_8228dbfd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa"
    family = "XWorm"
    file_name = "Comprobante PDF - 2026-11-26T164039.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:58"
  condition:
    hash.sha256(0, filesize) == "8228dbfd2117952852474de987b087cefa8dc54de37f0e2414cf7df0a36591fa"
}

rule MalwareBazaar_AgentTesla_031_15e545dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1"
    family = "AgentTesla"
    file_name = "Curriculum vitae.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:55"
  condition:
    hash.sha256(0, filesize) == "15e545dd76205cc6f629cdf9e12e9d11fd082bc6877eeb3e5e06b976d19b53f1"
}

rule MalwareBazaar_Formbook_032_b044838e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b044838e9f77994bae0b9b4a6cd0e07e35c3059988d33a23931e967af52faf82"
    family = "Formbook"
    file_name = "29092684116444.Pdf.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:51"
  condition:
    hash.sha256(0, filesize) == "b044838e9f77994bae0b9b4a6cd0e07e35c3059988d33a23931e967af52faf82"
}

rule MalwareBazaar_Formbook_033_7e7ca987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e7ca98773b9f2ba0b0d5d0a448600c4fb9b981f1e7710f8194b41ee77064e56"
    family = "Formbook"
    file_name = "BBK_Payment Advice-OCT SOA-PDF.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:48"
  condition:
    hash.sha256(0, filesize) == "7e7ca98773b9f2ba0b0d5d0a448600c4fb9b981f1e7710f8194b41ee77064e56"
}

rule MalwareBazaar_unknown_034_3f5428de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f5428de8294f7ee820aa77d092164d02c54cbb1fdd110eb9999ef68de540e31"
    family = "unknown"
    file_name = "New Purchase Order.js"
    file_type = "js"
    first_seen = "2026-11-26 06:47:45"
  condition:
    hash.sha256(0, filesize) == "3f5428de8294f7ee820aa77d092164d02c54cbb1fdd110eb9999ef68de540e31"
}

rule MalwareBazaar_unknown_035_b0a3a6f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0a3a6f22d097483fae5d601ee018a235f5922d62219e01283b2a614165d2eba"
    family = "unknown"
    file_name = "PO-2062060 - HOWYOU.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:42"
  condition:
    hash.sha256(0, filesize) == "b0a3a6f22d097483fae5d601ee018a235f5922d62219e01283b2a614165d2eba"
}

rule MalwareBazaar_unknown_036_c9148ab3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c9148ab32c4ae2fd683384f7d59226bc56c1620f8564cd913a1d47bb3bf1510e"
    family = "unknown"
    file_name = "PIT00027301pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:47:39"
  condition:
    hash.sha256(0, filesize) == "c9148ab32c4ae2fd683384f7d59226bc56c1620f8564cd913a1d47bb3bf1510e"
}

rule MalwareBazaar_AgentTesla_037_eb362791
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa"
    family = "AgentTesla"
    file_name = "RFQ180813.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:36"
  condition:
    hash.sha256(0, filesize) == "eb362791a0f98c39acf8eb0f920d94527cbee1c9c48a3b497e02cfbadecf04aa"
}

rule MalwareBazaar_AgentTesla_038_7965c7bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768"
    family = "AgentTesla"
    file_name = "payment-invoice.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:26"
  condition:
    hash.sha256(0, filesize) == "7965c7bf90e8c255f9794ac4de3f2912e82cea4ff498e1cf141a22b96bf72768"
}

rule MalwareBazaar_Formbook_039_2dd56382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dd56382a3883bd46ec6bbc06e43ac35ae36274e182980d6a5f7cfd8ce4e1abf"
    family = "Formbook"
    file_name = "Invoice.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:20"
  condition:
    hash.sha256(0, filesize) == "2dd56382a3883bd46ec6bbc06e43ac35ae36274e182980d6a5f7cfd8ce4e1abf"
}

rule MalwareBazaar_Formbook_040_dab45baa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dab45baa839f4136fc1beedea78f7a273b363b166b4cd3cbc6c599ed751f1df5"
    family = "Formbook"
    file_name = "Payment-Invoice9765.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:11"
  condition:
    hash.sha256(0, filesize) == "dab45baa839f4136fc1beedea78f7a273b363b166b4cd3cbc6c599ed751f1df5"
}

rule MalwareBazaar_unknown_041_27231f6d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27231f6d7f7d07abbca294874cf8a09ce35a6d987259a2ddbf1c41d3206f2d78"
    family = "unknown"
    file_name = "PURCHASE-RFQ-SC5681.js"
    file_type = "js"
    first_seen = "2026-11-26 06:47:08"
  condition:
    hash.sha256(0, filesize) == "27231f6d7f7d07abbca294874cf8a09ce35a6d987259a2ddbf1c41d3206f2d78"
}

rule MalwareBazaar_unknown_042_eb6187b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb6187b82408366bd31b890db5e81519cf5dd504105b08eb83408b4a0b6ed09e"
    family = "unknown"
    file_name = "PO-0001334282.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:47:05"
  condition:
    hash.sha256(0, filesize) == "eb6187b82408366bd31b890db5e81519cf5dd504105b08eb83408b4a0b6ed09e"
}

rule MalwareBazaar_RemcosRAT_043_922112f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "922112f27b5e470b6e8fe32879cac3f392a796b725c07a46722eb1e2dcd14712"
    family = "RemcosRAT"
    file_name = "Revised PO Order.js"
    file_type = "js"
    first_seen = "2026-11-26 06:46:40"
  condition:
    hash.sha256(0, filesize) == "922112f27b5e470b6e8fe32879cac3f392a796b725c07a46722eb1e2dcd14712"
}

rule MalwareBazaar_unknown_044_ebc2f783
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebc2f783451846183d6c435a952fd8223b1f81154d58e6d749c0ca175cd1c2f9"
    family = "unknown"
    file_name = "PO#2026.1194.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:32"
  condition:
    hash.sha256(0, filesize) == "ebc2f783451846183d6c435a952fd8223b1f81154d58e6d749c0ca175cd1c2f9"
}

rule MalwareBazaar_XWorm_045_27b79c3e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57"
    family = "XWorm"
    file_name = "Reckless Driver Cam 5 Photos 20261126SKM.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:24"
  condition:
    hash.sha256(0, filesize) == "27b79c3e852e0c55b2783bf469b2a146a90395e398dbb24bd05166e586f8ea57"
}

rule MalwareBazaar_Formbook_046_4eced92a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eced92a45627ced182aeff6ad2f5f520eeccb579c35aeb8e8388260b05f8823"
    family = "Formbook"
    file_name = "RFQ-TM262581 MMGENERALTRADING.pdf.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:20"
  condition:
    hash.sha256(0, filesize) == "4eced92a45627ced182aeff6ad2f5f520eeccb579c35aeb8e8388260b05f8823"
}

rule MalwareBazaar_AgentTesla_047_c4e39f47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0"
    family = "AgentTesla"
    file_name = "SOA 610952480.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:17"
  condition:
    hash.sha256(0, filesize) == "c4e39f47a0613d48d7fef4d2bc82c2300238ffbac36e79c0f32dbcbbb6e07fe0"
}

rule MalwareBazaar_unknown_048_abcab64d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abcab64d869df02accdf6b1269cb0d204096ef57cc07580312bf928e58246f55"
    family = "unknown"
    file_name = "ใบสั่งซื้อใหม่_PO24100034.pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:46:04"
  condition:
    hash.sha256(0, filesize) == "abcab64d869df02accdf6b1269cb0d204096ef57cc07580312bf928e58246f55"
}

rule MalwareBazaar_AgentTesla_049_1c505207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09"
    family = "AgentTesla"
    file_name = "DRAFT BL 0001288577.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:46:01"
  condition:
    hash.sha256(0, filesize) == "1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09"
}

rule MalwareBazaar_AgentTesla_050_dc7f6694
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc7f6694ce30cf3d8d79ba01f3c76f402e8c6554b3762d9501f9e548ac64f5b1"
    family = "AgentTesla"
    file_name = "SOA SEPT-OCT 2026.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:58"
  condition:
    hash.sha256(0, filesize) == "dc7f6694ce30cf3d8d79ba01f3c76f402e8c6554b3762d9501f9e548ac64f5b1"
}

rule MalwareBazaar_AveMariaRAT_051_66692977
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66692977bf502809e698ff16b278e14e1fda9289b0b89c6f6266514377e249e7"
    family = "AveMariaRAT"
    file_name = "OOLU2341072700 电放保函.js"
    file_type = "js"
    first_seen = "2026-11-26 06:45:54"
  condition:
    hash.sha256(0, filesize) == "66692977bf502809e698ff16b278e14e1fda9289b0b89c6f6266514377e249e7"
}

rule MalwareBazaar_PureLogsStealer_052_c7fcca61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c7fcca617e6c4f5f28ff49c68f3cd25087690ebe7d0f2e82774f30661b704299"
    family = "PureLogsStealer"
    file_name = "Tender Items List – RFQ_HD-2026-59554.js"
    file_type = "js"
    first_seen = "2026-11-26 06:45:51"
  condition:
    hash.sha256(0, filesize) == "c7fcca617e6c4f5f28ff49c68f3cd25087690ebe7d0f2e82774f30661b704299"
}

rule MalwareBazaar_unknown_053_250950cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "250950cb2698648849e23a5e51698dd4241fda73c87473ddd300ae5edbab5c41"
    family = "unknown"
    file_name = "การชำระเงิน_PO_11.25.2026.pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:45:48"
  condition:
    hash.sha256(0, filesize) == "250950cb2698648849e23a5e51698dd4241fda73c87473ddd300ae5edbab5c41"
}

rule MalwareBazaar_unknown_054_4f136732
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f13673279d8013297fc618c739774895837998c8678c7792cb16664c37cd374"
    family = "unknown"
    file_name = "J-033.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:45"
  condition:
    hash.sha256(0, filesize) == "4f13673279d8013297fc618c739774895837998c8678c7792cb16664c37cd374"
}

rule MalwareBazaar_Formbook_055_ad50059d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad50059d9b34101ee98fcc9dd09a0e81ecf473f932c941562dd829304612c99b"
    family = "Formbook"
    file_name = "University Of Mauritius Tender UOM_11-26.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:41"
  condition:
    hash.sha256(0, filesize) == "ad50059d9b34101ee98fcc9dd09a0e81ecf473f932c941562dd829304612c99b"
}

rule MalwareBazaar_AgentTesla_056_cf2fe09e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d"
    family = "AgentTesla"
    file_name = "PO_4500102673_S.S. Grow_2026.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:38"
  condition:
    hash.sha256(0, filesize) == "cf2fe09e88bb9044e0a718aa7d88d4e6a810395b6ffa579167d4d46805200c8d"
}

rule MalwareBazaar_Formbook_057_c4df5fc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9"
    family = "Formbook"
    file_name = "550MW_에 대한 문의입니다.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:17"
  condition:
    hash.sha256(0, filesize) == "c4df5fc57e9ffcb20022fa8d24b07db5b5851607dfb295e1314cd54d785131f9"
}

rule MalwareBazaar_DarkCoreRAT_058_44ff65bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ff65bdeaae8b235e6d6000f3af6efd54a737f6c9d4722e8bb0ce60db70baea"
    family = "DarkCoreRAT"
    file_name = "Order Confirmation 11-26-2026.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:13"
  condition:
    hash.sha256(0, filesize) == "44ff65bdeaae8b235e6d6000f3af6efd54a737f6c9d4722e8bb0ce60db70baea"
}

rule MalwareBazaar_RemcosRAT_059_a14c9168
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14c9168da21a61d6c85e4ba14583b23c2f3b19eeefef70196b2fdc337ad3515"
    family = "RemcosRAT"
    file_name = "mfvyxskd.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:45:02"
  condition:
    hash.sha256(0, filesize) == "a14c9168da21a61d6c85e4ba14583b23c2f3b19eeefef70196b2fdc337ad3515"
}

rule MalwareBazaar_Formbook_060_4978c249
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3"
    family = "Formbook"
    file_name = "PIT00027301.pdf.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:52"
  condition:
    hash.sha256(0, filesize) == "4978c249869c364f4944e7da41c0a9f1e6dac9e54dbcfbf53e02e162c1246bc3"
}

rule MalwareBazaar_unknown_061_646cada4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "646cada448f89b14e5a403b8bbafca97ce26b9e49fd23ea5d9b77bbc3f041e3e"
    family = "unknown"
    file_name = "Biên lai giao hàng_55.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:49"
  condition:
    hash.sha256(0, filesize) == "646cada448f89b14e5a403b8bbafca97ce26b9e49fd23ea5d9b77bbc3f041e3e"
}

rule MalwareBazaar_unknown_062_cd1d62ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd1d62ce3c34143bc656201f398c67c98a754f9bf6ef5898bd7be83f2e47d67b"
    family = "unknown"
    file_name = "Payment advice.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:46"
  condition:
    hash.sha256(0, filesize) == "cd1d62ce3c34143bc656201f398c67c98a754f9bf6ef5898bd7be83f2e47d67b"
}

rule MalwareBazaar_unknown_063_6eb055b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eb055b39b6a137485334e5435e8f3cefd4a9a1b342efaf396b2d6641baa824b"
    family = "unknown"
    file_name = "Biên lai giao hàng_Ip.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:43"
  condition:
    hash.sha256(0, filesize) == "6eb055b39b6a137485334e5435e8f3cefd4a9a1b342efaf396b2d6641baa824b"
}

rule MalwareBazaar_unknown_064_274ad8e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "274ad8e7e88f48ae03f222161bc052910ee80925d0a46dd79f588e0f9dc4af72"
    family = "unknown"
    file_name = "Biên lai giao hàng0.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:41"
  condition:
    hash.sha256(0, filesize) == "274ad8e7e88f48ae03f222161bc052910ee80925d0a46dd79f588e0f9dc4af72"
}

rule MalwareBazaar_RemcosRAT_065_1b9cd0e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b9cd0e9d64c8bbe16e340e6282429b3b47576449708bf439b3b5ceb2d5e3bd6"
    family = "RemcosRAT"
    file_name = "Tender Bidding details.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:38"
  condition:
    hash.sha256(0, filesize) == "1b9cd0e9d64c8bbe16e340e6282429b3b47576449708bf439b3b5ceb2d5e3bd6"
}

rule MalwareBazaar_RemcosRAT_066_4750e4be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4750e4be0b50d49992a299ebced7a468ebde13e5b238812c9c926bbe2ba25f2e"
    family = "RemcosRAT"
    file_name = "Whatsapp-0931 26-11-2026.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:34"
  condition:
    hash.sha256(0, filesize) == "4750e4be0b50d49992a299ebced7a468ebde13e5b238812c9c926bbe2ba25f2e"
}

rule MalwareBazaar_unknown_067_99a11934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99a1193448e31b2ba7357c5b0cdc307c9c3a574ecafb393042981c6be2f521be"
    family = "unknown"
    file_name = "AWB no 530526.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:31"
  condition:
    hash.sha256(0, filesize) == "99a1193448e31b2ba7357c5b0cdc307c9c3a574ecafb393042981c6be2f521be"
}

rule MalwareBazaar_PhantomStealer_068_d459116d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d459116d0d91316205238b0e457f6a3ecafd5dec7099e1cf35fa6172b213e436"
    family = "PhantomStealer"
    file_name = "rfq20mt HV XLPE 4700020778.js"
    file_type = "js"
    first_seen = "2026-11-26 06:44:26"
  condition:
    hash.sha256(0, filesize) == "d459116d0d91316205238b0e457f6a3ecafd5dec7099e1cf35fa6172b213e436"
}

rule MalwareBazaar_AsyncRAT_069_ecc6e934
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecc6e9348321bf0b5ca399a93791af5d67e719968de70f8dbe37f07eecb95390"
    family = "AsyncRAT"
    file_name = "200ae945e6d154ce322c04d480aba416.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:42:50"
  condition:
    hash.sha256(0, filesize) == "ecc6e9348321bf0b5ca399a93791af5d67e719968de70f8dbe37f07eecb95390"
}

rule MalwareBazaar_unknown_070_2ac2e964
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8"
    family = "unknown"
    file_name = "2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8"
    file_type = "sh"
    first_seen = "2026-11-26 06:40:55"
  condition:
    hash.sha256(0, filesize) == "2ac2e964c4d28cb46f1c219fe8c2a43895cf28c653e5fb236fad0c88911f7fd8"
}

rule MalwareBazaar_RemcosRAT_071_826ce3fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "826ce3fe579833e99adce2ed24a3c7d57cb58289d9a533759e52e2b338b9c709"
    family = "RemcosRAT"
    file_name = "Product_Catalog_2026.xls"
    file_type = "xls"
    first_seen = "2026-11-26 06:40:18"
  condition:
    hash.sha256(0, filesize) == "826ce3fe579833e99adce2ed24a3c7d57cb58289d9a533759e52e2b338b9c709"
}

rule MalwareBazaar_XWorm_072_4b745504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717"
    family = "XWorm"
    file_name = "Reckless Driver Cam 5 Photos 20261126.JS"
    file_type = "js"
    first_seen = "2026-11-26 06:40:16"
  condition:
    hash.sha256(0, filesize) == "4b745504580314e61ad7d10296c31f23ea59316a37cc9397b8ea9242d93c6717"
}

rule MalwareBazaar_unknown_073_d4aa0b3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4aa0b3d25fa124d80b195ebda0d004c0ba468b0c4ab15fa8613103c3fb02272"
    family = "unknown"
    file_name = "Grade certificate..docx"
    file_type = "docx"
    first_seen = "2026-11-26 06:40:12"
  condition:
    hash.sha256(0, filesize) == "d4aa0b3d25fa124d80b195ebda0d004c0ba468b0c4ab15fa8613103c3fb02272"
}

rule MalwareBazaar_RemcosRAT_074_b904cc1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b904cc1ef88171d2b3e3cebde14e92847e858360e02099714dcaeaf6c71ab4a1"
    family = "RemcosRAT"
    file_name = "Quotation 2026.xls"
    file_type = "xls"
    first_seen = "2026-11-26 06:40:07"
  condition:
    hash.sha256(0, filesize) == "b904cc1ef88171d2b3e3cebde14e92847e858360e02099714dcaeaf6c71ab4a1"
}

rule MalwareBazaar_ValleyRAT_075_d8d80c72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8d80c729b59fce3c828d489cd4051d1fe244bd33ecdd5bee9e200a7dee61d96"
    family = "ValleyRAT"
    file_name = "dpinst_x64.in.07.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:36:39"
  condition:
    hash.sha256(0, filesize) == "d8d80c729b59fce3c828d489cd4051d1fe244bd33ecdd5bee9e200a7dee61d96"
}

rule MalwareBazaar_unknown_076_49f2c2a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49f2c2a674ac0eefda886d4d7ff832613f90802a350f8e4576d9af45d6411606"
    family = "unknown"
    file_name = "e512cd279dd50d0e8eb2f8f36f2c3b00"
    file_type = "exe"
    first_seen = "2026-11-26 06:33:00"
  condition:
    hash.sha256(0, filesize) == "49f2c2a674ac0eefda886d4d7ff832613f90802a350f8e4576d9af45d6411606"
}

rule MalwareBazaar_ValleyRAT_077_67d76863
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67d76863b812ef960b44e32a67fd2f3a6eebc857c073a448d8dccf3f18002622"
    family = "ValleyRAT"
    file_name = "dpinst_x64.in.06.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:32:19"
  condition:
    hash.sha256(0, filesize) == "67d76863b812ef960b44e32a67fd2f3a6eebc857c073a448d8dccf3f18002622"
}

rule MalwareBazaar_ValleyRAT_078_7317f68c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7317f68c0a92198d6c7858d3ee96ab9bbebb9acaba11c5871bd93dc1fced7e70"
    family = "ValleyRAT"
    file_name = "dpinst_x64.in.02.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:29:17"
  condition:
    hash.sha256(0, filesize) == "7317f68c0a92198d6c7858d3ee96ab9bbebb9acaba11c5871bd93dc1fced7e70"
}

rule MalwareBazaar_unknown_079_06f27275
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06f272750f81540d8cb1808be0b79c4e963bb67ff035cb96ee4d1568fe70ace6"
    family = "unknown"
    file_name = "145.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:26:42"
  condition:
    hash.sha256(0, filesize) == "06f272750f81540d8cb1808be0b79c4e963bb67ff035cb96ee4d1568fe70ace6"
}

rule MalwareBazaar_Prometei_080_0acbe43a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0acbe43aa884db90122d4596da79a266582c98a478b0a4a4e559480252fd3f28"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:26:03"
  condition:
    hash.sha256(0, filesize) == "0acbe43aa884db90122d4596da79a266582c98a478b0a4a4e559480252fd3f28"
}

rule MalwareBazaar_Prometei_081_93f98155
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93f9815582688e65458050489de1c99f8acc28548b3a957c67a87b734c9c3ba6"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:23:04"
  condition:
    hash.sha256(0, filesize) == "93f9815582688e65458050489de1c99f8acc28548b3a957c67a87b734c9c3ba6"
}

rule MalwareBazaar_unknown_082_aa23c2ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42"
    family = "unknown"
    file_name = "aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42"
    file_type = "sh"
    first_seen = "2026-11-26 06:18:55"
  condition:
    hash.sha256(0, filesize) == "aa23c2caeb41f7612e871b0179b9191caa2e5fde2c963216dc6abdd02d826d42"
}

rule MalwareBazaar_Prometei_083_caa42ce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec"
    family = "Prometei"
    file_name = "caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec"
    file_type = "elf"
    first_seen = "2026-11-26 06:18:44"
  condition:
    hash.sha256(0, filesize) == "caa42ce9f5fc5fe016bf9a6c70962cd1613fbb19573a06bf4a456945b2b039ec"
}

rule MalwareBazaar_Prometei_084_685183ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "685183ff4c8da6f4f3fbf3f485bff80831e512c4c9daf8f13e0736da8a13d15c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:17:06"
  condition:
    hash.sha256(0, filesize) == "685183ff4c8da6f4f3fbf3f485bff80831e512c4c9daf8f13e0736da8a13d15c"
}

rule MalwareBazaar_Prometei_085_1dc1c026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dc1c026505f10be2a4eec854482ffc66bfd37853c0648a31bfc581a2ab695fc"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 06:17:03"
  condition:
    hash.sha256(0, filesize) == "1dc1c026505f10be2a4eec854482ffc66bfd37853c0648a31bfc581a2ab695fc"
}

rule MalwareBazaar_Formbook_086_cfcbccc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfcbccc833f403ea88d41787306e263b7fdbe7f45f00f913378d0cb30c227e9d"
    family = "Formbook"
    file_name = "9F3CC576B5E16BF62F0D55529DF09C8DF91F0A28"
    file_type = "exe"
    first_seen = "2026-11-26 06:00:24"
  condition:
    hash.sha256(0, filesize) == "cfcbccc833f403ea88d41787306e263b7fdbe7f45f00f913378d0cb30c227e9d"
}

rule MalwareBazaar_PureLogsStealer_087_d38a4fd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d38a4fd6039fc8ee36eae3185aac45640165b20c208277ccdb77c6289064abd7"
    family = "PureLogsStealer"
    file_name = "_00168"
    file_type = "exe"
    first_seen = "2026-11-26 06:00:21"
  condition:
    hash.sha256(0, filesize) == "d38a4fd6039fc8ee36eae3185aac45640165b20c208277ccdb77c6289064abd7"
}

rule MalwareBazaar_njrat_088_97cbb90c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97cbb90c2fdb71c84cb302309212ee5be356d1e5d1b1e2162e25b3318924fdaa"
    family = "njrat"
    file_name = "6372875880C71C07EA54681687401B75.exe"
    file_type = "exe"
    first_seen = "2026-11-26 06:00:10"
  condition:
    hash.sha256(0, filesize) == "97cbb90c2fdb71c84cb302309212ee5be356d1e5d1b1e2162e25b3318924fdaa"
}

rule MalwareBazaar_unknown_089_eb65f0d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb65f0d4105d47e7a320798fe70de8da676287e169c090f611652dd06dbb4cbf"
    family = "unknown"
    file_name = "load.sh"
    file_type = "sh"
    first_seen = "2026-11-26 05:59:14"
  condition:
    hash.sha256(0, filesize) == "eb65f0d4105d47e7a320798fe70de8da676287e169c090f611652dd06dbb4cbf"
}

rule MalwareBazaar_Prometei_090_6cc8947e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cc8947eff1f63359f1434fc35004651ee5453f754caf94b703edc8a226dd14c"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 05:57:04"
  condition:
    hash.sha256(0, filesize) == "6cc8947eff1f63359f1434fc35004651ee5453f754caf94b703edc8a226dd14c"
}

rule MalwareBazaar_unknown_091_70a0aa90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68"
    family = "unknown"
    file_name = "70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68.bin"
    file_type = "js"
    first_seen = "2026-11-26 05:55:54"
  condition:
    hash.sha256(0, filesize) == "70a0aa9032eddb4d90085a0cb39041f39b39e15a5c1392167dbb2353caa87c68"
}

rule MalwareBazaar_Prometei_092_23904395
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "239043953b148005c185ecf69d57df64d2a0feca0fcb573e3dd9323df0e17093"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 05:55:03"
  condition:
    hash.sha256(0, filesize) == "239043953b148005c185ecf69d57df64d2a0feca0fcb573e3dd9323df0e17093"
}

rule MalwareBazaar_Prometei_093_486e9010
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "486e90103cb806d3fe94fd91b752684f7de818c80f6f08ea3c3a637a158e7a5d"
    family = "Prometei"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-26 05:53:03"
  condition:
    hash.sha256(0, filesize) == "486e90103cb806d3fe94fd91b752684f7de818c80f6f08ea3c3a637a158e7a5d"
}

rule MalwareBazaar_Mirai_094_e9b07e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b07e9ef6a8feb3999d9cb9142d12b2c1eec90d7cc5229e1df7761a5279acc8"
    family = "Mirai"
    file_name = "iranbot-ultimate.aarch64"
    file_type = "elf"
    first_seen = "2026-11-26 05:51:31"
  condition:
    hash.sha256(0, filesize) == "e9b07e9ef6a8feb3999d9cb9142d12b2c1eec90d7cc5229e1df7761a5279acc8"
}

rule MalwareBazaar_MassLogger_095_5990121a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5990121aa1cb12cb10cbccf370a337570edcc3c4073babab62bb1648038f52be"
    family = "MassLogger"
    file_name = "ea72a2651983449da93d8858b5c173db.MSG"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:47"
  condition:
    hash.sha256(0, filesize) == "5990121aa1cb12cb10cbccf370a337570edcc3c4073babab62bb1648038f52be"
}

rule MalwareBazaar_PureLogsStealer_096_706e4581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "706e45816f8430a495f0cf2163c1e7cfb4ade51a46b01ffd8c9d50e6b537c2dd"
    family = "PureLogsStealer"
    file_name = "pd158065316.att"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:44"
  condition:
    hash.sha256(0, filesize) == "706e45816f8430a495f0cf2163c1e7cfb4ade51a46b01ffd8c9d50e6b537c2dd"
}

rule MalwareBazaar_Formbook_097_cd8536fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd8536fe243401c8d2f11bd6292bd79184d4a1a988de2beb9b819db06c423823"
    family = "Formbook"
    file_name = "md5001000308758.tmp"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:41"
  condition:
    hash.sha256(0, filesize) == "cd8536fe243401c8d2f11bd6292bd79184d4a1a988de2beb9b819db06c423823"
}

rule MalwareBazaar_AgentTesla_098_a61aeafb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a61aeafbc93dac025daabf33521f7d7f0bd6d5ade363000263ee6e6314de505e"
    family = "AgentTesla"
    file_name = "5f937617b8d44533b42d7fabef5597e8.MSG"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:38"
  condition:
    hash.sha256(0, filesize) == "a61aeafbc93dac025daabf33521f7d7f0bd6d5ade363000263ee6e6314de505e"
}

rule MalwareBazaar_unknown_099_27fec664
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27fec664e3ec2520f2ffc3e37f8d950527f9e88aec2e1d53f315f4852f24c617"
    family = "unknown"
    file_name = "1fb664a4_horse_nine_x1.dat"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:35"
  condition:
    hash.sha256(0, filesize) == "27fec664e3ec2520f2ffc3e37f8d950527f9e88aec2e1d53f315f4852f24c617"
}

rule MalwareBazaar_MassLogger_100_7f4db1fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f4db1fd15d336185099b1509937fd92ebc0afdc9a95cdf88108aaaf3b588601"
    family = "MassLogger"
    file_name = "_00019"
    file_type = "exe"
    first_seen = "2026-11-26 05:30:32"
  condition:
    hash.sha256(0, filesize) == "7f4db1fd15d336185099b1509937fd92ebc0afdc9a95cdf88108aaaf3b588601"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

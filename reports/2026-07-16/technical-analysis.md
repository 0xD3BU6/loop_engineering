# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-16

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 625 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 625 |
| Unique family labels | 7 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 48 |
| Mirai | 42 |
| Vidar | 3 |
| AsyncRAT | 2 |
| GuLoader | 2 |
| Prometei | 2 |
| ValleyRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 49 |
| exe | 29 |
| sh | 9 |
| zip | 4 |
| js | 3 |
| unknown | 3 |
| xapk | 2 |
| lnk | 1 |

## Per-Sample Analysis

### Sample 1: `721038816079e39f`

| Field | Value |
|---|---|
| SHA-256 | `721038816079e39f95b41461f20ccbf77af20bd22b8a6c71da228bdfa9675413` |
| Family label | `unknown` |
| File name | `com.messaging.textmessage.messages.sms_29.0.xapk` |
| File type | `xapk` |
| First seen | `2026-07-16 03:08:31` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4878822e858617daeeac73a5d9f9629` |
| SHA-1 | `d82cfbbcd997fca26216ce829bd39c0141a81ec7` |
| SHA-256 | `721038816079e39f95b41461f20ccbf77af20bd22b8a6c71da228bdfa9675413` |
| SHA3-384 | `7772c364ecbf2f71f887e9b7a21c67812cfd228de6bc7251675670d9eadc1ef91b3437b49061cf338bf2e874443f366a` |
| TLSH | `T1DD57F14AF61CD52BD9E5B0BC8D8B17A3B5667D110A10C18B3821B30DF9B37D49B26BE1` |
| SSDEEP | `786432:YZY9dYVrRX3FCDZK3bIDoVR3bcxEki+nJcFv4H:Ycd0VX3aZKrI0XgGk4WH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_72103881
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "721038816079e39f95b41461f20ccbf77af20bd22b8a6c71da228bdfa9675413"
    family = "unknown"
    file_name = "com.messaging.textmessage.messages.sms_29.0.xapk"
    file_type = "xapk"
    first_seen = "2026-07-16 03:08:31"
  condition:
    hash.sha256(0, filesize) == "721038816079e39f95b41461f20ccbf77af20bd22b8a6c71da228bdfa9675413"
}
```

### Sample 2: `58fa325d6a5619e1`

| Field | Value |
|---|---|
| SHA-256 | `58fa325d6a5619e1fba43d6bd8a913632521284306631c8fb7bce7ba8dda3393` |
| Family label | `unknown` |
| File name | `Font+Keyboard_1.8.xapk` |
| File type | `xapk` |
| First seen | `2026-07-16 03:07:57` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5d02939d865d5fc4bce13e6ad6d5d77` |
| SHA-1 | `a365abc4936a89b756c70368a3da472468fb66e4` |
| SHA-256 | `58fa325d6a5619e1fba43d6bd8a913632521284306631c8fb7bce7ba8dda3393` |
| SHA3-384 | `d6ea0bbc9df0a9cea37403ccb159f13157791063ef36527d0f1ced4a7501b694ef194f785e4d80a74f5079fe82602440` |
| TLSH | `T18A671206FB0DAC3BC9DA647C8A574B9131166C854290D3976925F618BFBB7CCCE26BC0` |
| SSDEEP | `393216:tJXgcMrH0gnn81Dm94/W9B4GKtO5+dg/eva91YORrKVFDLv9GW5YNE9qkeRGXj0:7gcwVX94/oB43tOCgVRrKVBFesXA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_58fa325d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58fa325d6a5619e1fba43d6bd8a913632521284306631c8fb7bce7ba8dda3393"
    family = "unknown"
    file_name = "Font+Keyboard_1.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-16 03:07:57"
  condition:
    hash.sha256(0, filesize) == "58fa325d6a5619e1fba43d6bd8a913632521284306631c8fb7bce7ba8dda3393"
}
```

### Sample 3: `c3c9b9054a3bab92`

| Field | Value |
|---|---|
| SHA-256 | `c3c9b9054a3bab92bbd7a0a64ad0b3dccb1908fc9d16cc4e491b1397d8e49ae6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-16 02:55:49` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a28bdd6231ec973de56116e4c50d8af7` |
| SHA-1 | `1ac3bb7cb431aabe284cd3ab15d3b23cbff50ae7` |
| SHA-256 | `c3c9b9054a3bab92bbd7a0a64ad0b3dccb1908fc9d16cc4e491b1397d8e49ae6` |
| SHA3-384 | `a118c2434b44646d4f541627b80c5807d500e883386bac5b1439c551fb78a9f89b34ca143ebe8fceff6b7d0feb62e2e8` |
| IMPHASH | `5a08440e22a99b9fda864d620400de65` |
| TLSH | `T11795128FEAA612F9C83D51B454218212BF94BD024F50CEDB6A687DBA1C739EC2F35705` |
| SSDEEP | `49152:adQSiNxeK5/93iiY7ZqK+QeWu9JKD7xuCgO:aQNxek/9yUKOWu9JKD7gO` |
| ICON-DHASH | `f0f89a9a9adcf830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_c3c9b905
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3c9b9054a3bab92bbd7a0a64ad0b3dccb1908fc9d16cc4e491b1397d8e49ae6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 02:55:49"
  condition:
    hash.sha256(0, filesize) == "c3c9b9054a3bab92bbd7a0a64ad0b3dccb1908fc9d16cc4e491b1397d8e49ae6"
}
```

### Sample 4: `cdecd2bc19737113`

| Field | Value |
|---|---|
| SHA-256 | `cdecd2bc19737113c5c2fa88f9a160127e5dcded32ca07067917cbd138f9a7bf` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-16 02:51:58` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf80db264e8032d72128528b07648d4e` |
| SHA-1 | `c6b074393a28a70eaad69eef8ae8cd7f085e415d` |
| SHA-256 | `cdecd2bc19737113c5c2fa88f9a160127e5dcded32ca07067917cbd138f9a7bf` |
| SHA3-384 | `59dd735e48fd9f0a0eaa93b0b5d7bbf5064668b9b356aa667ae453f493407244de36aacd9c17035dd4c91908db973da8` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T157E6335C65E403FDF6B7543CE9B202A0E56AB46247B1C9EF076887F2ADA32D0583D613` |
| SSDEEP | `393216:IMZkz/u6DoVvDrsZ5t6F3GXMCHWUjXAcuI3/PGTAI:IWCDoV3w6FWXMb8XVH/O7` |
| ICON-DHASH | `70f0e4c4c4e0f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_cdecd2bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdecd2bc19737113c5c2fa88f9a160127e5dcded32ca07067917cbd138f9a7bf"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 02:51:58"
  condition:
    hash.sha256(0, filesize) == "cdecd2bc19737113c5c2fa88f9a160127e5dcded32ca07067917cbd138f9a7bf"
}
```

### Sample 5: `fddee8b3af76449d`

| Field | Value |
|---|---|
| SHA-256 | `fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e` |
| Family label | `unknown` |
| File name | `fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e` |
| File type | `elf` |
| First seen | `2026-07-16 02:41:07` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a5f541addb6f172c797389924d6353b` |
| SHA-1 | `83c717c730245572111eefed5bb347498f5bce87` |
| SHA-256 | `fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e` |
| SHA3-384 | `79f446d6ade1552a55fbf1fed0dd7bd4bcc0aa0bfe4a5fc32fcc964edd2fdd75cca95dcee7e6ebadec62370debb63e8d` |
| TLSH | `T194565B73905514D4D2AED974C6156213BEE8388B673863CBBBC076F11B7ABE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQl:cqYUQuVDt0TZEe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_fddee8b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e"
    family = "unknown"
    file_name = "fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e"
    file_type = "elf"
    first_seen = "2026-07-16 02:41:07"
  condition:
    hash.sha256(0, filesize) == "fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e"
}
```

### Sample 6: `bc2d5313943d2e4a`

| Field | Value |
|---|---|
| SHA-256 | `bc2d5313943d2e4a33cdb0a4708c6ec94c60f26ae402626caf970e283d0ad9d4` |
| Family label | `AsyncRAT` |
| File name | `Purchase Order.js` |
| File type | `js` |
| First seen | `2026-07-16 02:25:06` |
| Reporter | `abuse_ch` |
| Tags | `AsyncRAT, js, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe5ea86baf480aa7bd6f81542a83b9ce` |
| SHA-1 | `e8befc6de16d4809754a296aa842182111f02d64` |
| SHA-256 | `bc2d5313943d2e4a33cdb0a4708c6ec94c60f26ae402626caf970e283d0ad9d4` |
| SHA3-384 | `c24ec8f8b5f1793f96b65d70a2750cfc1ff11ffb1a7512dae928e19769ec72511a150712bfdef0628f17e8d398537fdc` |
| TLSH | `T116C4E0E427C42DBC575A5E3AB23FA0D9F6A109C5298508CBF716BC44EAB9700F5A3D70` |
| SSDEEP | `6144:jYecHF08PeWBOY8ha5KR6on0ELDzAGnt2Hl9iYsKFJj8qHD7XGJRnt7YdNA7u+5O:jYDF08bov7n0asGt2HniYsKXReJ1Bx78` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_006_bc2d5313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2d5313943d2e4a33cdb0a4708c6ec94c60f26ae402626caf970e283d0ad9d4"
    family = "AsyncRAT"
    file_name = "Purchase Order.js"
    file_type = "js"
    first_seen = "2026-07-16 02:25:06"
  condition:
    hash.sha256(0, filesize) == "bc2d5313943d2e4a33cdb0a4708c6ec94c60f26ae402626caf970e283d0ad9d4"
}
```

### Sample 7: `e82f6ae11ddfaf06`

| Field | Value |
|---|---|
| SHA-256 | `e82f6ae11ddfaf06b82738aa2f499d4cb8476ec7914efd9aa16bdf520ef90539` |
| Family label | `unknown` |
| File name | `Realtime Protection.exe` |
| File type | `exe` |
| First seen | `2026-07-16 02:23:46` |
| Reporter | `Kejult` |
| Tags | `exe, loader, python, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4aa2449edd6e5a28fc88f8007144b059` |
| SHA-1 | `efc8c213ea63a6d534def60507fcffa14693b3c6` |
| SHA-256 | `e82f6ae11ddfaf06b82738aa2f499d4cb8476ec7914efd9aa16bdf520ef90539` |
| SHA3-384 | `5e29342a5f6c410d5182464deae222dbad05752baf9bae3a36e8f2e64ce3be03e6968d9599b80a9c932f07d542515c2c` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1CA273388ABC5087BC8D2727D69BBC952E3966C550B2188BF0B90273A3F774D58C3975C` |
| SSDEEP | `393216:AqzlNIZ37UJ32eivEoxy8etBnKurNtZq5Xm86A+7EdZHsxtEDweLEiGRlCo:AqzbS4ce2s7t3rNtZq5W3AO49wt7eL7w` |
| ICON-DHASH | `002b032b2b032b00` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_e82f6ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e82f6ae11ddfaf06b82738aa2f499d4cb8476ec7914efd9aa16bdf520ef90539"
    family = "unknown"
    file_name = "Realtime Protection.exe"
    file_type = "exe"
    first_seen = "2026-07-16 02:23:46"
  condition:
    hash.sha256(0, filesize) == "e82f6ae11ddfaf06b82738aa2f499d4cb8476ec7914efd9aa16bdf520ef90539"
}
```

### Sample 8: `e07e535830825db9`

| Field | Value |
|---|---|
| SHA-256 | `e07e535830825db953ee7b0231139a4eebd8333ac7e36383a196abd4038f757e` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-16 02:16:41` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b11466c37917ed4b0537cfa7d425de6c` |
| SHA-1 | `15c6d129bbd1eb8410321159d0ff1276c9b6b31a` |
| SHA-256 | `e07e535830825db953ee7b0231139a4eebd8333ac7e36383a196abd4038f757e` |
| SHA3-384 | `07d7bada7b2c8c9f48ae6449e809cf7ad69bb11eccf5935860be0301a29a3c3a54b575084e7f4c6c47ebeeade88d9938` |
| TLSH | `T1610148C64A40B910406A9A5E22D762A0B811C3CE459A4F68BFDC9D3EFB98914B027F99` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkan+CosuVCN7Q0FCy/qks11CdTBECM6NauD:kXCKysE2hi0ziQvZoha+Rr0FD811fY7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_e07e5358
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e07e535830825db953ee7b0231139a4eebd8333ac7e36383a196abd4038f757e"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-16 02:16:41"
  condition:
    hash.sha256(0, filesize) == "e07e535830825db953ee7b0231139a4eebd8333ac7e36383a196abd4038f757e"
}
```

### Sample 9: `abca9cfafbc5165e`

| Field | Value |
|---|---|
| SHA-256 | `abca9cfafbc5165e73c2bb0ef24815c23a5f865a4c6a4eca61b2c17ec80c9ca7` |
| Family label | `AsyncRAT` |
| File name | `VIN88APP.exe` |
| File type | `exe` |
| First seen | `2026-07-16 02:12:19` |
| Reporter | `anonymous` |
| Tags | `AsyncRAT, exe, rat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `308ef15b5e8f0662fc5c1c828c6c903a` |
| SHA-1 | `8377396347225864adea430e96e5db8103c7e40f` |
| SHA-256 | `abca9cfafbc5165e73c2bb0ef24815c23a5f865a4c6a4eca61b2c17ec80c9ca7` |
| SHA3-384 | `e4a16fdae320bcc7277fc98fe5928cf512b2fae6a27f5e3548e455cd3ba0d755ade565c0c1209d86ee56f162bc1ff289` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1DFC22B0833E4C576E2FD4ABE8C33D5008B75A55B9923D75A6FC490AD29237CD8A14FE4` |
| SSDEEP | `384:ugSVEEMiNPWmvHtZARPn9jvH9qbuUshybQxnCJfJBndnjJGK3R:ugSVXFdt+zIbIBiBnnh` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_009_abca9cfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abca9cfafbc5165e73c2bb0ef24815c23a5f865a4c6a4eca61b2c17ec80c9ca7"
    family = "AsyncRAT"
    file_name = "VIN88APP.exe"
    file_type = "exe"
    first_seen = "2026-07-16 02:12:19"
  condition:
    hash.sha256(0, filesize) == "abca9cfafbc5165e73c2bb0ef24815c23a5f865a4c6a4eca61b2c17ec80c9ca7"
}
```

### Sample 10: `7bce64f71e61af03`

| Field | Value |
|---|---|
| SHA-256 | `7bce64f71e61af03a0cf9efc56e81c4113e6541f252c368603fa43974523081b` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-16 02:09:28` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fd0105fcffe0aedce225fea31e73f73` |
| SHA-1 | `fcf25271e7a9e7c286dc37d164a584b6b04fdeee` |
| SHA-256 | `7bce64f71e61af03a0cf9efc56e81c4113e6541f252c368603fa43974523081b` |
| SHA3-384 | `66b2bce19c0d67b0bc3e783c3b297a7d88e61ee727374e4b52433f2d0e7aedd72f5d96f1285356e60f92b22145d4faf7` |
| TLSH | `T113B5398ED49203B5F792FB73521AD6625DF6390280328A75CF497D365F06F24A028EED` |
| SSDEEP | `24576:WPzswvn78eG6l8xmM90RwfDCrK4Ylyx/Imf/deBsIA/PPMjjKtygLWSU8hyT8eCi:kAPVQMbiKkzfVgsPVUTTF6ZoV` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_010_7bce64f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bce64f71e61af03a0cf9efc56e81c4113e6541f252c368603fa43974523081b"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 02:09:28"
  condition:
    hash.sha256(0, filesize) == "7bce64f71e61af03a0cf9efc56e81c4113e6541f252c368603fa43974523081b"
}
```

### Sample 11: `f0d3c665335eda74`

| Field | Value |
|---|---|
| SHA-256 | `f0d3c665335eda74c52e36348ca978fd021a08c39836029adfa68adf5a3e32f4` |
| Family label | `unknown` |
| File name | `204_panel_tools.exe` |
| File type | `exe` |
| First seen | `2026-07-16 02:03:03` |
| Reporter | `Kejult` |
| Tags | `discord, exe, loader, python, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e771fdb94ca93f6f2358e1234617fffb` |
| SHA-1 | `cac54f26ddb4e8760aaaa3286bac2c549e3b0007` |
| SHA-256 | `f0d3c665335eda74c52e36348ca978fd021a08c39836029adfa68adf5a3e32f4` |
| SHA3-384 | `bc218a0c0fdf125f58f89a17c4c2d65ed3c772cee5c4616579783604db0f7881d45846abbd07b1d7ac6f85cb926dc5d1` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1AD2733D8729159FBECF395385D7AC912E3B271801F54C1BF07A85E290E3BA944E387A4` |
| SSDEEP | `393216:ulNIZ37UJ32eivEoxy8e6hPdDA54XEAphVtnIUQSg+1/i/zC+OstFLvF7gvpl4:ubS4ce2s7Kpq4RphDto+Ri/zFOsttvFx` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_f0d3c665
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d3c665335eda74c52e36348ca978fd021a08c39836029adfa68adf5a3e32f4"
    family = "unknown"
    file_name = "204_panel_tools.exe"
    file_type = "exe"
    first_seen = "2026-07-16 02:03:03"
  condition:
    hash.sha256(0, filesize) == "f0d3c665335eda74c52e36348ca978fd021a08c39836029adfa68adf5a3e32f4"
}
```

### Sample 12: `52a1f9aebd6d8f42`

| Field | Value |
|---|---|
| SHA-256 | `52a1f9aebd6d8f42ed0fa9a36c8c0cea56dccaa7ab941a62c7d70be02479f6d9` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-16 01:51:57` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00d3c17953afb258440c9eb9e15e30b6` |
| SHA-1 | `23902109c0301caec968660ea08cd5cd165354e2` |
| SHA-256 | `52a1f9aebd6d8f42ed0fa9a36c8c0cea56dccaa7ab941a62c7d70be02479f6d9` |
| SHA3-384 | `fc869b0a0b8d53e6d3bc24b1f449cf054b1a3dc6b958f752c1ad0878b1ac800700b9cd68709bdf78c8ef1b7fea83feb4` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T11CE6335C6EC402EFD9B3003CEEF26699E926B4724731CE9F17AC92622E530D48D3565B` |
| SSDEEP | `393216:Ghd01M3OWld0GIAh6OK9XMCHWUjX6cuI3/PGTAI:G7RdtsO0XMb8X3H/O7` |
| ICON-DHASH | `f0f8dca692c6f4f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_52a1f9ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52a1f9aebd6d8f42ed0fa9a36c8c0cea56dccaa7ab941a62c7d70be02479f6d9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 01:51:57"
  condition:
    hash.sha256(0, filesize) == "52a1f9aebd6d8f42ed0fa9a36c8c0cea56dccaa7ab941a62c7d70be02479f6d9"
}
```

### Sample 13: `4a6d1dfa22c10d10`

| Field | Value |
|---|---|
| SHA-256 | `4a6d1dfa22c10d10030b7d7063abdd31e528c1a152568febcff3f6a6a140fdff` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-16 01:35:30` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `595b149335f82abfc6f0d6c4c9803e69` |
| SHA-1 | `7de31a451844a9630666ea0dd35deda9e0c4a07b` |
| SHA-256 | `4a6d1dfa22c10d10030b7d7063abdd31e528c1a152568febcff3f6a6a140fdff` |
| SHA3-384 | `a4bfa3b9e0462555e989e4b8fee4d41d760169578654ebce75d7e1a8f3df7e1b5353b2e897ba2c76db2eb8c02fe470c0` |
| TLSH | `T18A235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EEBFCB3CF68C4A69DD10971D` |
| SSDEEP | `768:Z+09GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:Z+5cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_4a6d1dfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a6d1dfa22c10d10030b7d7063abdd31e528c1a152568febcff3f6a6a140fdff"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-16 01:35:30"
  condition:
    hash.sha256(0, filesize) == "4a6d1dfa22c10d10030b7d7063abdd31e528c1a152568febcff3f6a6a140fdff"
}
```

### Sample 14: `42d85cf2179b3a10`

| Field | Value |
|---|---|
| SHA-256 | `42d85cf2179b3a10e2ac9dc572bac3fa540b3aea4aa87898740f7b0caeb1809b` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-07-16 01:17:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98f6119c8a099aa2cc3f99bfa3d16f43` |
| SHA-1 | `bf8c90ecfc67c8b2dc6467b88fb0751ae9872337` |
| SHA-256 | `42d85cf2179b3a10e2ac9dc572bac3fa540b3aea4aa87898740f7b0caeb1809b` |
| SHA3-384 | `9977dd57b0ed40b9169b15aba22981a3fb0833a7b62ab6314f28b4a3b6639a8566d32c4389ee23562f691b30d2ec6a10` |
| TLSH | `T18FC37CC2B10D7DADE5977E7CC20A27176A1C9A518C83510150F5FE072AB72E72E36ACB` |
| TELFHASH | `t160e024f2834fa625064dcbdd83ca739c5a2de0480147ef53fe41043c909a94e361498f` |
| SSDEEP | `3072:sLWznSQrERPmhb7ZXrSfhKDarKjWvAuQJNQLLjyol:PzcmhvZrGhKe5vAuwNQXvl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_42d85cf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42d85cf2179b3a10e2ac9dc572bac3fa540b3aea4aa87898740f7b0caeb1809b"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-16 01:17:32"
  condition:
    hash.sha256(0, filesize) == "42d85cf2179b3a10e2ac9dc572bac3fa540b3aea4aa87898740f7b0caeb1809b"
}
```

### Sample 15: `c47a9ca2fce58991`

| Field | Value |
|---|---|
| SHA-256 | `c47a9ca2fce589911fb281bd7d94c53d2697581994031ddd6d62a01a354dcc92` |
| Family label | `unknown` |
| File name | `gothgirls3.exe` |
| File type | `exe` |
| First seen | `2026-07-16 01:17:21` |
| Reporter | `lllll` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b331848237ab89b94829952a78d23a0` |
| SHA-1 | `004600b7d9089142784edd3bd90caf8e81cb3089` |
| SHA-256 | `c47a9ca2fce589911fb281bd7d94c53d2697581994031ddd6d62a01a354dcc92` |
| SHA3-384 | `027086d6cf168ceb5062f3a764f5e63d23cf19d8a77ee97a0fde6139d273ade20595504dc000ddf1867a378725c00bc2` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T172173399B79509EEE4DD123A83C1C22B67B334A24724E1CF1BE41D925E677E8DE35B00` |
| SSDEEP | `393216:JXpW8QL5NLn1+TtIiFlCuARuAr7Yx4rTWdS9QV8ax6i8+41b00JhCoCbYkfXCIoo:bW8Q9xn1QtI0CuA7m4usM8ax624ZDCBJ` |
| ICON-DHASH | `a4c9cc49330dd7f7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_c47a9ca2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c47a9ca2fce589911fb281bd7d94c53d2697581994031ddd6d62a01a354dcc92"
    family = "unknown"
    file_name = "gothgirls3.exe"
    file_type = "exe"
    first_seen = "2026-07-16 01:17:21"
  condition:
    hash.sha256(0, filesize) == "c47a9ca2fce589911fb281bd7d94c53d2697581994031ddd6d62a01a354dcc92"
}
```

### Sample 16: `512adcaea143fa04`

| Field | Value |
|---|---|
| SHA-256 | `512adcaea143fa04941516599aed5e2cdd97d374673bc645d585e3ea63183b8e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-16 01:12:05` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX7.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d7a7df9b22e0b0c05aafca137d0a4ce` |
| SHA-1 | `21c0629df4e7298b5ef39cc2f0ef6ff90963dc64` |
| SHA-256 | `512adcaea143fa04941516599aed5e2cdd97d374673bc645d585e3ea63183b8e` |
| SHA3-384 | `9ac0646f6c43e36da8254d66b8d86713305077641bc02c89958ccc38e663144294acf2a2832e7fecec9e954a58b8deac` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T16E762807FCA918E5C0ADD1318A7696127F71BC490B2123E71BA0F6287F76BD0ADB9714` |
| SSDEEP | `49152:bnqCtdYBOHDfMNlVi0dPwhxrPC150JOyCm9IblP92ajVLhvEa6i8jcE9ky8IwyEJ:bnqy8kz04e6tggr1J9j4+vE/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_512adcae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "512adcaea143fa04941516599aed5e2cdd97d374673bc645d585e3ea63183b8e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 01:12:05"
  condition:
    hash.sha256(0, filesize) == "512adcaea143fa04941516599aed5e2cdd97d374673bc645d585e3ea63183b8e"
}
```

### Sample 17: `99cfa4eb1fc878b6`

| Field | Value |
|---|---|
| SHA-256 | `99cfa4eb1fc878b61eb532ecaea600038f3e789d31625fa413f669ff1ee5b22b` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-16 01:09:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87f29d4d2ef7a747da6e9cace4f1cf0a` |
| SHA-1 | `8ad5fb2dda7bc68f52871f5b43362e0191589688` |
| SHA-256 | `99cfa4eb1fc878b61eb532ecaea600038f3e789d31625fa413f669ff1ee5b22b` |
| SHA3-384 | `8a46ad8f7b9247610c45a1b2418c156dfa2a3c573a8272aba731a11b0b3ca9b1445b86ad4fd81fd1906e2462dde2e66e` |
| TLSH | `T1F6838EC9FA03E0F1EC525AB10837A3175A76E5355538EF81EB912631BD13B00AB07B6E` |
| TELFHASH | `t17f4149fa1e7f0dddb3906840a20e6b212d4e6b7b286036b345739c6522efe815577c38` |
| SSDEEP | `1536:Rx0vpwbUFaujDjyEC0QEUOdyfJ41qz4PjBuLnmKSkJURrdJ89yf7:39b2aEjyECFN+2p4bBGfSpJV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_99cfa4eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99cfa4eb1fc878b61eb532ecaea600038f3e789d31625fa413f669ff1ee5b22b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-16 01:09:16"
  condition:
    hash.sha256(0, filesize) == "99cfa4eb1fc878b61eb532ecaea600038f3e789d31625fa413f669ff1ee5b22b"
}
```

### Sample 18: `8c0f9343f5eeb039`

| Field | Value |
|---|---|
| SHA-256 | `8c0f9343f5eeb0393a7d633cbb5fb819d531e35225496815cff8462e90db864b` |
| Family label | `unknown` |
| File name | `vartmp_1c18d769_085aa012` |
| File type | `elf` |
| First seen | `2026-07-16 01:03:58` |
| Reporter | `sigsec` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70c6c97d699a63a2e556b92d30a86dcc` |
| SHA-256 | `8c0f9343f5eeb0393a7d633cbb5fb819d531e35225496815cff8462e90db864b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_8c0f9343
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0f9343f5eeb0393a7d633cbb5fb819d531e35225496815cff8462e90db864b"
    family = "unknown"
    file_name = "vartmp_1c18d769_085aa012"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:58"
  condition:
    hash.sha256(0, filesize) == "8c0f9343f5eeb0393a7d633cbb5fb819d531e35225496815cff8462e90db864b"
}
```

### Sample 19: `8f225e59f3b892c7`

| Field | Value |
|---|---|
| SHA-256 | `8f225e59f3b892c7ed440db4c913491f825ccd64792cb759b55563c1b1310ece` |
| Family label | `unknown` |
| File name | `kuak` |
| File type | `elf` |
| First seen | `2026-07-16 01:03:56` |
| Reporter | `sigsec` |
| Tags | `Diicot, elf, Linux, Mexals, spreader, sshbruteforce` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `530d0a4764964139bac25ff852a904bf` |
| SHA-256 | `8f225e59f3b892c7ed440db4c913491f825ccd64792cb759b55563c1b1310ece` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_8f225e59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f225e59f3b892c7ed440db4c913491f825ccd64792cb759b55563c1b1310ece"
    family = "unknown"
    file_name = "kuak"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:56"
  condition:
    hash.sha256(0, filesize) == "8f225e59f3b892c7ed440db4c913491f825ccd64792cb759b55563c1b1310ece"
}
```

### Sample 20: `41e3673069a4c07e`

| Field | Value |
|---|---|
| SHA-256 | `41e3673069a4c07ee11f566d6bba1523255b6d9cc0fceabe42da04d7f0d944cb` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-16 01:03:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bf6c523dfa2475d24b13552c57a8789` |
| SHA-1 | `f7e0bc2251ec2616af7e5e1bbb51da71786e53f5` |
| SHA-256 | `41e3673069a4c07ee11f566d6bba1523255b6d9cc0fceabe42da04d7f0d944cb` |
| SHA3-384 | `045a47a7c76d203563afdb51f693cf75059441fa62cb679d6af11f7e04fd0f29aa8dae0499f47daba67e416de0d006df` |
| TLSH | `T115C329A9F880DE52C6D1267AF75E118C33231778D3DE7109CE249E3467EB95E0E3A942` |
| SSDEEP | `3072:3KkAGfJqpUqVL45zcQrT25YcYEEU1aK2x2SPpkh+ip8RNaY7AAf1Dl:3K80qrGYcYEEU1aKM2eCh+/r0A95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_41e36730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41e3673069a4c07ee11f566d6bba1523255b6d9cc0fceabe42da04d7f0d944cb"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:53"
  condition:
    hash.sha256(0, filesize) == "41e3673069a4c07ee11f566d6bba1523255b6d9cc0fceabe42da04d7f0d944cb"
}
```

### Sample 21: `ffe04bc05a56f78b`

| Field | Value |
|---|---|
| SHA-256 | `ffe04bc05a56f78b1273876cf17ded8df1aa3da5a15deb17dce99a3e206eb705` |
| Family label | `unknown` |
| File name | `diicot` |
| File type | `elf` |
| First seen | `2026-07-16 01:03:51` |
| Reporter | `sigsec` |
| Tags | `Diicot, elf, Linux, loader, Mexals` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2aac605dc8f0a94211d699d0d62b5382` |
| SHA-256 | `ffe04bc05a56f78b1273876cf17ded8df1aa3da5a15deb17dce99a3e206eb705` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_ffe04bc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffe04bc05a56f78b1273876cf17ded8df1aa3da5a15deb17dce99a3e206eb705"
    family = "unknown"
    file_name = "diicot"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:51"
  condition:
    hash.sha256(0, filesize) == "ffe04bc05a56f78b1273876cf17ded8df1aa3da5a15deb17dce99a3e206eb705"
}
```

### Sample 22: `07b9702bc859227a`

| Field | Value |
|---|---|
| SHA-256 | `07b9702bc859227a658903d1b4cf85d9daed6e0c24e670332c83020cc0a37166` |
| Family label | `unknown` |
| File name | `IQITtfbr.packed` |
| File type | `elf` |
| First seen | `2026-07-16 01:03:45` |
| Reporter | `sigsec` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `366491c86d462de5b192997e3166ba77` |
| SHA-256 | `07b9702bc859227a658903d1b4cf85d9daed6e0c24e670332c83020cc0a37166` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_07b9702b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07b9702bc859227a658903d1b4cf85d9daed6e0c24e670332c83020cc0a37166"
    family = "unknown"
    file_name = "IQITtfbr.packed"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:45"
  condition:
    hash.sha256(0, filesize) == "07b9702bc859227a658903d1b4cf85d9daed6e0c24e670332c83020cc0a37166"
}
```

### Sample 23: `0e0e3b4128eea1f7`

| Field | Value |
|---|---|
| SHA-256 | `0e0e3b4128eea1f7c9cac8abd8097b6cd9fbb2ecc91979cc985674f6c90d9139` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-07-16 01:03:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afafa2a5ff13f82b3070ee09a39c4936` |
| SHA-1 | `d9073aaad2a41e7ea70ed63fa304585a2ee57d4a` |
| SHA-256 | `0e0e3b4128eea1f7c9cac8abd8097b6cd9fbb2ecc91979cc985674f6c90d9139` |
| SHA3-384 | `1161ae936308d1cae860aadaf4cad318fee7bd620f28901c2b6da6324fe9d77621f1e27fd80f4e78390194c816762d1c` |
| TLSH | `T1CF3301B17905B0BDD4448036FC6E8552FB0319B691B8396F09A1CF99DD42AEB72F7280` |
| SSDEEP | `1536:bvVXlTrlg4AnNzW0EKU+m2eAKhMCask4gNf2:7PZEnFZEKSMKZas+O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_0e0e3b41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e0e3b4128eea1f7c9cac8abd8097b6cd9fbb2ecc91979cc985674f6c90d9139"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:24"
  condition:
    hash.sha256(0, filesize) == "0e0e3b4128eea1f7c9cac8abd8097b6cd9fbb2ecc91979cc985674f6c90d9139"
}
```

### Sample 24: `6b2ccc31a86aba2d`

| Field | Value |
|---|---|
| SHA-256 | `6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348` |
| Family label | `unknown` |
| File name | `6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348` |
| File type | `elf` |
| First seen | `2026-07-16 01:00:31` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a00732bf12114e48b243856ec330d6ee` |
| SHA-1 | `192f86c081311be78825b27223033aba2196bf2c` |
| SHA-256 | `6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348` |
| SHA3-384 | `766be59da883bcb8c5b97ef2f03a38d7d354a061070539322a9cd7a0640e6f24d2242e950ad63783b281b5dae970c7ab` |
| TLSH | `T1E3A67C73945224D8E1A9C9B4D1141652BDBC3C8B5738A3C7BAC471F65BBABE48E38730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQy:cqYUQuVDt0TZEJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_6b2ccc31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348"
    family = "unknown"
    file_name = "6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348"
    file_type = "elf"
    first_seen = "2026-07-16 01:00:31"
  condition:
    hash.sha256(0, filesize) == "6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348"
}
```

### Sample 25: `cb5325281c5ecc29`

| Field | Value |
|---|---|
| SHA-256 | `cb5325281c5ecc2983de4e3d349cfa6fc272d3a9920aef743352386405ea280f` |
| Family label | `GuLoader` |
| File name | `rFACTURAJUNIO.exe` |
| File type | `exe` |
| First seen | `2026-07-16 01:00:19` |
| Reporter | `fabiodemartin` |
| Tags | `exe, GuLoader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd419c013cadaa2100ada7f6f7dd34f4` |
| SHA-1 | `fb7172c40bc110e63f5f3ecb15c5950b13590bb3` |
| SHA-256 | `cb5325281c5ecc2983de4e3d349cfa6fc272d3a9920aef743352386405ea280f` |
| SHA3-384 | `796086f51839d4ea07499755f766b74eba2d8deca563f78033fa7ea03e160a6a457ca970fd6cfeb825075752a5802c8a` |
| IMPHASH | `f4639a0b3116c2cfc71144b88a929cfd` |
| TLSH | `T1B694129662D4C523C7755E78F8A8C6DDABBCBE10E0B44BA753E0764EFC26E81450B321` |
| SSDEEP | `12288:FXuLq+uHdADtab75cdDMUxM9VGe/m/UD4K:FXuLqLKDtCdchR0G86UDJ` |
| ICON-DHASH | `8ceecaccf7d4ccd0` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_025_cb532528
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb5325281c5ecc2983de4e3d349cfa6fc272d3a9920aef743352386405ea280f"
    family = "GuLoader"
    file_name = "rFACTURAJUNIO.exe"
    file_type = "exe"
    first_seen = "2026-07-16 01:00:19"
  condition:
    hash.sha256(0, filesize) == "cb5325281c5ecc2983de4e3d349cfa6fc272d3a9920aef743352386405ea280f"
}
```

### Sample 26: `80bd353bb391fcab`

| Field | Value |
|---|---|
| SHA-256 | `80bd353bb391fcabeeec55d17be1dcb5a1d571f64062b4da6f844ef87e526c28` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-16 01:00:16` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6a482f07d13df47f05dc2e1c3e64b391` |
| SHA-1 | `79f76a7354b585b47ddacfea810bff0f68ad5fb6` |
| SHA-256 | `80bd353bb391fcabeeec55d17be1dcb5a1d571f64062b4da6f844ef87e526c28` |
| SHA3-384 | `a70924848bf84ec56bc9086d96481a49e4a24f9556c01bac6e2236b871cba6b459900c90143264d61b4d12940aed6a02` |
| TLSH | `T193C27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:W8vCB+25j6es8RN9FYpMSUpi+20qUpi+20YQX:W8l25J7d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_80bd353b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80bd353bb391fcabeeec55d17be1dcb5a1d571f64062b4da6f844ef87e526c28"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-16 01:00:16"
  condition:
    hash.sha256(0, filesize) == "80bd353bb391fcabeeec55d17be1dcb5a1d571f64062b4da6f844ef87e526c28"
}
```

### Sample 27: `66a1be3919f3f237`

| Field | Value |
|---|---|
| SHA-256 | `66a1be3919f3f23710ebc6d58daf04e5abd52490f4a95993cea670cfc2314809` |
| Family label | `GuLoader` |
| File name | `rMODELO1112T2026.exe` |
| File type | `exe` |
| First seen | `2026-07-16 01:00:08` |
| Reporter | `fabiodemartin` |
| Tags | `exe, GuLoader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `855a7d9da970dd7004a886c91bfda171` |
| SHA-1 | `d7547ce372b2c0a25439f77ad98e1ddc2d5f1eda` |
| SHA-256 | `66a1be3919f3f23710ebc6d58daf04e5abd52490f4a95993cea670cfc2314809` |
| SHA3-384 | `6a3dab73ec5c46f8ca423238bde3b48d5d78d599eea796704e18662e4d84e6737a5ec504e8b32968ce21359388dcc4d6` |
| IMPHASH | `f4639a0b3116c2cfc71144b88a929cfd` |
| TLSH | `T1FB9412962690D727C3761D76F954D6DDDBACAA10A2B49BA313F03A4FB832EC5440F321` |
| SSDEEP | `6144:lXsKoG8pL7qzqAeYyEM5zVPZI9PZY630ExBGogd6MOjZaM9oQEfj7S/fNM/f6HxZ:lXuLsq/DIVv5cdDO1aM9VGe/m/UDT` |
| ICON-DHASH | `8ceecaccf7d4ccd0` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_027_66a1be39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66a1be3919f3f23710ebc6d58daf04e5abd52490f4a95993cea670cfc2314809"
    family = "GuLoader"
    file_name = "rMODELO1112T2026.exe"
    file_type = "exe"
    first_seen = "2026-07-16 01:00:08"
  condition:
    hash.sha256(0, filesize) == "66a1be3919f3f23710ebc6d58daf04e5abd52490f4a95993cea670cfc2314809"
}
```

### Sample 28: `5421de84ac526266`

| Field | Value |
|---|---|
| SHA-256 | `5421de84ac52626640c8004a94732e2abadace7cb828f2a499901f59df259bb0` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-16 00:55:43` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, PMIX1.file, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5bc84645c88f57a988cfb64f254c937` |
| SHA-1 | `b646bce9d63740a5a1c0f8256a5456478dec8e50` |
| SHA-256 | `5421de84ac52626640c8004a94732e2abadace7cb828f2a499901f59df259bb0` |
| SHA3-384 | `b6fdca49669c64c8dbc891ce7540918c672a61d886b107b19fd6bc6d0fdeda25f23fc028b850cc14bb17974a2075a543` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E5168D07BDA148EAC09AE23188B76156BB64BC0C1B3133D72E60BB782F767D05D79B54` |
| SSDEEP | `49152:GHDgAKoisznVrspN3jn3uULSOeutrI34gRKdyCFbipb5PN:G8wKvqOe0I4giit5V` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_028_5421de84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5421de84ac52626640c8004a94732e2abadace7cb828f2a499901f59df259bb0"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 00:55:43"
  condition:
    hash.sha256(0, filesize) == "5421de84ac52626640c8004a94732e2abadace7cb828f2a499901f59df259bb0"
}
```

### Sample 29: `0699369e414a65f7`

| Field | Value |
|---|---|
| SHA-256 | `0699369e414a65f7ba516fe5ed9c7ef3aec8abdae4409331f209c6a27168c157` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-16 00:51:58` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca31a00cfbd0a65bc11c27e5b91468f0` |
| SHA-1 | `8b02926cbb0da2d2539a97e54df7f2c2f3916ff7` |
| SHA-256 | `0699369e414a65f7ba516fe5ed9c7ef3aec8abdae4409331f209c6a27168c157` |
| SHA3-384 | `14b45d050a99aa6581c2f816804e47218bd4c3c97112e59a22c635f67964053351e5348df7d5384eae3a2d5aa5cc3f9a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1C4E63358B8D001EEF6B2403CEDE16AB1F46A78750B71CADB4BA853A17F270C44D3D666` |
| SSDEEP | `393216:H/8P/BVJt5emAMN5quJIvo3NXMCHWUjX9cuI3/PGTAI:H/8P/B54DMN53mvUXMb8XKH/O7` |
| ICON-DHASH | `f0e0d4d8e8e47130` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_0699369e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0699369e414a65f7ba516fe5ed9c7ef3aec8abdae4409331f209c6a27168c157"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 00:51:58"
  condition:
    hash.sha256(0, filesize) == "0699369e414a65f7ba516fe5ed9c7ef3aec8abdae4409331f209c6a27168c157"
}
```

### Sample 30: `8277d9cdcdd6d214`

| Field | Value |
|---|---|
| SHA-256 | `8277d9cdcdd6d214ea747c4e3c36f2ee26bbef746273de07a7836335685f8ba8` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-16 00:51:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `232f3d2fdb0448d4f0552c34002d7cab` |
| SHA-1 | `41d337d029da6eb08add720270cdbb36b58a3ad3` |
| SHA-256 | `8277d9cdcdd6d214ea747c4e3c36f2ee26bbef746273de07a7836335685f8ba8` |
| SHA3-384 | `bf5742309bcb2cfc0eb7078f1c7e30f7e6b7812556175f7a5fccbc05dd8d5af3d91b0e5fc5a8fe04de1290d4c345df4f` |
| TLSH | `T120236C6516857C14AE98C4375C7E2F0CB9AD43E6314492EE7FCA3CF28C4A6ADA20875D` |
| SSDEEP | `768:v99NyXsZztCN9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:lHusZDcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_8277d9cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8277d9cdcdd6d214ea747c4e3c36f2ee26bbef746273de07a7836335685f8ba8"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-16 00:51:17"
  condition:
    hash.sha256(0, filesize) == "8277d9cdcdd6d214ea747c4e3c36f2ee26bbef746273de07a7836335685f8ba8"
}
```

### Sample 31: `98170b42f23c069e`

| Field | Value |
|---|---|
| SHA-256 | `98170b42f23c069e62fd90e946a5047765c030f608f2cb41f22ff5a19c9d7fa8` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-07-16 00:36:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7000b9fa6f934c949e36b7b70155d1b3` |
| SHA-1 | `1f4ddbe9220928db21276aba24085a638dd45346` |
| SHA-256 | `98170b42f23c069e62fd90e946a5047765c030f608f2cb41f22ff5a19c9d7fa8` |
| SHA3-384 | `21a7142ca1d2bf8d468f34b27696b7233548fe87282de86f64b7d26ccffa14c644f5b38160c8099b7310e66cd09aefb5` |
| TLSH | `T16DE38EA89E0F6D82C2C7E3BDAD453F63312634B445E8C3BA1E00528DE6DBDD58DE5522` |
| SSDEEP | `3072:XwSwA+ST8S06MbN+mIiVf3aqdJaiopzl2TdDkKhRYZA:XpQo8r6+Ii/dDop0Td4Kp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_98170b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98170b42f23c069e62fd90e946a5047765c030f608f2cb41f22ff5a19c9d7fa8"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-16 00:36:34"
  condition:
    hash.sha256(0, filesize) == "98170b42f23c069e62fd90e946a5047765c030f608f2cb41f22ff5a19c9d7fa8"
}
```

### Sample 32: `ea5ba796713da558`

| Field | Value |
|---|---|
| SHA-256 | `ea5ba796713da55899f9cc3dc8daae7b4425f2a73058b9abff60e9922af60924` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-16 00:35:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1712b2e36a627bce50ad80a96d4c7e3d` |
| SHA-1 | `e9c525a80ffd3ad877bdc7e6db707803c34b7e86` |
| SHA-256 | `ea5ba796713da55899f9cc3dc8daae7b4425f2a73058b9abff60e9922af60924` |
| SHA3-384 | `0d1e96e8ffe1edfe04aa2d1b3e5cd7f25c79ac32d974deae9614ed5182f6da1d4697d32089372853651d51c813ebf424` |
| TLSH | `T1F0C31995B8929A22C6D216BBFA0EB2CD772633E4E3DE7117CE145F21338755B0E2B141` |
| TELFHASH | `t1d0d02e226b2a0ae48b430406480e100283aab07cb80858b8a3d82f2b0a83947b80a803` |
| SSDEEP | `3072:kHZ1GBF71ofGPWT5w+CKiE3Ecg0EAFnbA:kHZ1GBp1yl5EKL3E5ABA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_ea5ba796
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5ba796713da55899f9cc3dc8daae7b4425f2a73058b9abff60e9922af60924"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-16 00:35:16"
  condition:
    hash.sha256(0, filesize) == "ea5ba796713da55899f9cc3dc8daae7b4425f2a73058b9abff60e9922af60924"
}
```

### Sample 33: `c19a9ccea95a758d`

| Field | Value |
|---|---|
| SHA-256 | `c19a9ccea95a758dccbd692cbd469e9a2d373fe6e63cbf4009d8c76fd073e288` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-16 00:29:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48d6f7d6f94e437cd8b6c98870ef8c87` |
| SHA-1 | `a9547efe5e9a7e2b9a0b6d08bef7e0a6358b187d` |
| SHA-256 | `c19a9ccea95a758dccbd692cbd469e9a2d373fe6e63cbf4009d8c76fd073e288` |
| SHA3-384 | `8d92d1af4c6df22faa1e8c0092d0706a74812d1f3d84950e8dd18a89ed03e113cc0594332c559aa422bddbe1f6df9610` |
| TLSH | `T119147E01BF181953D1931DB45B3F0766D379D88318B8F109190BBB961733EB7AA87B8A` |
| SSDEEP | `3072:t/njlJBseKbpY0EUoGIy4yS010AEvQH/JGaRp1DrojG9uJ:t/njtse6Y0EUtI/F5AEvQH/JGOvQIuJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_c19a9cce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c19a9ccea95a758dccbd692cbd469e9a2d373fe6e63cbf4009d8c76fd073e288"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-16 00:29:46"
  condition:
    hash.sha256(0, filesize) == "c19a9ccea95a758dccbd692cbd469e9a2d373fe6e63cbf4009d8c76fd073e288"
}
```

### Sample 34: `fc6a37d766e2c13e`

| Field | Value |
|---|---|
| SHA-256 | `fc6a37d766e2c13eb68da8efa734978ae6dead2a8ec536b99793c422b1caa836` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-07-16 00:29:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `baaf6b65cac35f0f6f17ce658710725c` |
| SHA-1 | `a8a7b1145aed8c212cca6e7a2f63c1250eeffa43` |
| SHA-256 | `fc6a37d766e2c13eb68da8efa734978ae6dead2a8ec536b99793c422b1caa836` |
| SHA3-384 | `14a3409b0937ad04120c9413c3cf67e9bd7dfe256011693b41ead5f59d00f17f7fddb4b25fb66475665afa8503051069` |
| TLSH | `T18D43025647B8EC16EAFF1D72D89942A223CB271B3055C4C1678CEA91881D42EE679F50` |
| SSDEEP | `1536:rSfYEx2WqGKbQISxfA1p5gJ82ekm3LWt+xXjSn4u+qgw0rl:MYnWfmoxcEJ8Im3qtqXj44u+qgwC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_fc6a37d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc6a37d766e2c13eb68da8efa734978ae6dead2a8ec536b99793c422b1caa836"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-16 00:29:23"
  condition:
    hash.sha256(0, filesize) == "fc6a37d766e2c13eb68da8efa734978ae6dead2a8ec536b99793c422b1caa836"
}
```

### Sample 35: `780e56445f2e5521`

| Field | Value |
|---|---|
| SHA-256 | `780e56445f2e5521791c8802b93afa0c8efa4b44d528b1a18e8ed0a1c5e2858e` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-16 00:24:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ca441406c590855be373850655b09ac` |
| SHA-1 | `b1dd71cbbc9c28cc23fffdc1526a7b9c8271807d` |
| SHA-256 | `780e56445f2e5521791c8802b93afa0c8efa4b44d528b1a18e8ed0a1c5e2858e` |
| SHA3-384 | `0bca042361712178e2f28b038473da9bd8e53a0ebeee3857ccb2d0a9e4dec88829ad0d86cb8c0d41706b21b461ff2d6a` |
| TLSH | `T195C329A9F880DE52C6D1267AF75E118C33231778D3DE7109CE249E3467EB95E0E3A942` |
| SSDEEP | `3072:3KkAGfJqpUqVL45zcQrT25YcYEEU1aK2x2SPpkh+ip8RNaY7A2f1Dl:3K80qrGYcYEEU1aKM2eCh+/r0295` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_780e5644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "780e56445f2e5521791c8802b93afa0c8efa4b44d528b1a18e8ed0a1c5e2858e"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 00:24:44"
  condition:
    hash.sha256(0, filesize) == "780e56445f2e5521791c8802b93afa0c8efa4b44d528b1a18e8ed0a1c5e2858e"
}
```

### Sample 36: `5060058f19b22719`

| Field | Value |
|---|---|
| SHA-256 | `5060058f19b2271985ffc751dfe35b9b107f051a368de01358e6be85335ab1ed` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-07-16 00:24:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e42645af1ddbd3dec6f2a2823249d8a` |
| SHA-1 | `eeb13183798f502356436685d7335b829693c103` |
| SHA-256 | `5060058f19b2271985ffc751dfe35b9b107f051a368de01358e6be85335ab1ed` |
| SHA3-384 | `9c4716d192a4d03ef70a355fe46abc7eb14a1082d565f77d46f4bdf389b35058f395c28d3d315525a88e055fe5558df7` |
| TLSH | `T1693301707005B17ED580C134FCBD8642FB5329A5D1B43A6F0AA1D7A9AD42AE773FB280` |
| SSDEEP | `1536:bvVXlTrlg4AnNzW0EKU+m2eAKhMCa6m0uNfx:7PZEnFZEKSMKZa6YZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_5060058f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5060058f19b2271985ffc751dfe35b9b107f051a368de01358e6be85335ab1ed"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 00:24:19"
  condition:
    hash.sha256(0, filesize) == "5060058f19b2271985ffc751dfe35b9b107f051a368de01358e6be85335ab1ed"
}
```

### Sample 37: `6f1daa323ecda925`

| Field | Value |
|---|---|
| SHA-256 | `6f1daa323ecda925f11f3eea0dc4839057dfff2317f5fa1bfc6176c62b951deb` |
| Family label | `unknown` |
| File name | `sh` |
| File type | `sh` |
| First seen | `2026-07-16 00:24:17` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39d0ae50e3220750fc7ef4e99a8dfc5f` |
| SHA-1 | `58c0c06a59a298176cdb302f97091ef3ed736154` |
| SHA-256 | `6f1daa323ecda925f11f3eea0dc4839057dfff2317f5fa1bfc6176c62b951deb` |
| SHA3-384 | `ff700cbd30589d6107895c00256612fc054358de445a2203ba762a7ee92b10cdd7fcb94f52f0355511f868fd825ceb96` |
| TLSH | `T1C04114BBB4B28E30335DC4B9B486294CB7579A6F44266E74B087743C36BC364B178265` |
| SSDEEP | `48:vkwvpihneZZn1oBydX0P21j/EmfthmmzEvJGU6+gtIIqNTMTCki:vkwYheZZK8gujnFhmmzIl6K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_6f1daa32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f1daa323ecda925f11f3eea0dc4839057dfff2317f5fa1bfc6176c62b951deb"
    family = "unknown"
    file_name = "sh"
    file_type = "sh"
    first_seen = "2026-07-16 00:24:17"
  condition:
    hash.sha256(0, filesize) == "6f1daa323ecda925f11f3eea0dc4839057dfff2317f5fa1bfc6176c62b951deb"
}
```

### Sample 38: `dc28e187522f7376`

| Field | Value |
|---|---|
| SHA-256 | `dc28e187522f7376ae4414ac017bb317f88545b602c657d5c7c4eb028248dda0` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-16 00:14:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6ebab8f38de2b781f1d91bd766beac9` |
| SHA-1 | `d45f1bbeb826f2f0d2a10c1f0bb2da6b103814f1` |
| SHA-256 | `dc28e187522f7376ae4414ac017bb317f88545b602c657d5c7c4eb028248dda0` |
| SHA3-384 | `7e003d9e925fc85acf6a950b60ce31a45034fec58584a48f503cc740540ac9ce16785f79f2e8d9ab8764ec7b361d9ba8` |
| TLSH | `T137D3E60E6F258F2DF3B9C73487F74E21A79873C626E0C649D1ACE5111E6028D641FBA9` |
| TELFHASH | `t15621a44c497422e46b365c992badff77e19530df6b226c378e10e8bdabad8419d00c0c` |
| SSDEEP | `3072:TpBaETS2ZtcwSlE4bMdcGmikUvbxoeEf+gg4Q0neZOm3kRGm+n5vq:TpBc+gyV1UFYvq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_dc28e187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc28e187522f7376ae4414ac017bb317f88545b602c657d5c7c4eb028248dda0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-16 00:14:34"
  condition:
    hash.sha256(0, filesize) == "dc28e187522f7376ae4414ac017bb317f88545b602c657d5c7c4eb028248dda0"
}
```

### Sample 39: `473f4b5e2d22a4fb`

| Field | Value |
|---|---|
| SHA-256 | `473f4b5e2d22a4fb4790813e18073f96c1a2f450d51259ab463b924e7f40244c` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-16 00:13:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bddaa779ac692193fc8fcb0c1be47a4` |
| SHA-1 | `a72e76214d3b4f0a457d39386d6428aae3f32e18` |
| SHA-256 | `473f4b5e2d22a4fb4790813e18073f96c1a2f450d51259ab463b924e7f40244c` |
| SHA3-384 | `eec1cb6def438d44eaad67e95536300298c4430411d2c5b532f38566fe5096949634c0b9aaa5fb9fb7d95df3dee171c2` |
| TLSH | `T12AC329A9F880DE52C6D1267AF75E118C33231778D3DE7109CE249E3467EB95E0E3A942` |
| SSDEEP | `3072:3KkAGfJqpUqVL45zcQrT25YcYEEU1aK2x2SPpkh+ip8RNaY7Adf1Dl:3K80qrGYcYEEU1aKM2eCh+/r0d95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_473f4b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "473f4b5e2d22a4fb4790813e18073f96c1a2f450d51259ab463b924e7f40244c"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:13:46"
  condition:
    hash.sha256(0, filesize) == "473f4b5e2d22a4fb4790813e18073f96c1a2f450d51259ab463b924e7f40244c"
}
```

### Sample 40: `615dffa88641da57`

| Field | Value |
|---|---|
| SHA-256 | `615dffa88641da5740583203114e92507d18b96ca510b9533fb154209b036988` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-07-16 00:13:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63ab625dea9a3feb81a25b2735b74d38` |
| SHA-1 | `d6072683fc892fcb65446bdfbadc554d9f476525` |
| SHA-256 | `615dffa88641da5740583203114e92507d18b96ca510b9533fb154209b036988` |
| SHA3-384 | `1a91f9d3e532180999e4a8b63cd74a34e62e7da34d1aa7c88804f1bfdf656b18c9e8a83c715234b9d61a822a5d468339` |
| TLSH | `T17133F171A006B5BDD140C534FD2E8A53FB432DA5D1683A6F05A1CB9ADE03AE722E72C1` |
| SSDEEP | `1536:bvVXlTrlg4AnNzW0EKU+m2eAKhMCaK1H5I+Nfi:7PZEnFZEKSMKZaK1ZpK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_615dffa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "615dffa88641da5740583203114e92507d18b96ca510b9533fb154209b036988"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:13:16"
  condition:
    hash.sha256(0, filesize) == "615dffa88641da5740583203114e92507d18b96ca510b9533fb154209b036988"
}
```

### Sample 41: `20d9bf470d993f17`

| Field | Value |
|---|---|
| SHA-256 | `20d9bf470d993f176a6a13ae2794bded557e1a4fd1ed50b2bb02838cc6f43189` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-16 00:10:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d630312ce785215e8097b0efff09a8b` |
| SHA-1 | `b470780fbb82a7d1b8fd11b69e9ab0be228591d1` |
| SHA-256 | `20d9bf470d993f176a6a13ae2794bded557e1a4fd1ed50b2bb02838cc6f43189` |
| SHA3-384 | `ffb937f1b42076cf8a971f92ae8c3bc3e5136b229e3f1b6dce25082c3f2f53fc79e1c25315e40bcb35c201306074e9f6` |
| TLSH | `T1DEB30895B8D29A22C6C216BBFA0EB2CD772633A4E3DE7117CD145F21378751B0E6B241` |
| TELFHASH | `t1d0d02e226b2a0ae48b430406480e100283aab07cb80858b8a3d82f2b0a83947b80a803` |
| SSDEEP | `3072:AF6rGHk7VbhwW65K+eIrdRO/z0X2Unbh:AF6rGHY9i5OI5ROu2Yh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_20d9bf47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20d9bf470d993f176a6a13ae2794bded557e1a4fd1ed50b2bb02838cc6f43189"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:10:15"
  condition:
    hash.sha256(0, filesize) == "20d9bf470d993f176a6a13ae2794bded557e1a4fd1ed50b2bb02838cc6f43189"
}
```

### Sample 42: `fab7ef5a1a6c3f5a`

| Field | Value |
|---|---|
| SHA-256 | `fab7ef5a1a6c3f5aafa3e6f4bb1fd2907275cd440159ddb6f29e607c54869e0d` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-16 00:02:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ddc78ada035159895b0b63c589fb5a69` |
| SHA-1 | `c8a3687a600a69f1e6a78dc52f8dd0a3e413eaec` |
| SHA-256 | `fab7ef5a1a6c3f5aafa3e6f4bb1fd2907275cd440159ddb6f29e607c54869e0d` |
| SHA3-384 | `78bcbda81b7502d89f6fd5a8fca8c0206edbb004128914fe7417f09ffc0ead5ffd3696ca9183849d1211da5772901672` |
| TLSH | `T118E3C50E6E218F3DF779833587F7BE25A75873C626D0C645D2ACE9111E2028D641FBA8` |
| TELFHASH | `t14a21925c497423f067714c9d2adeeb77d1a030df1b256d378e11e969aabd9825e00c1c` |
| SSDEEP | `3072:W38FV1TvZS4RzM5u2PP2K0xXY3udpwDcu5xJTBwAYuRj/BFAvSPjYFInbxdsU:q8i4Rz+8YG0xyU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_fab7ef5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fab7ef5a1a6c3f5aafa3e6f4bb1fd2907275cd440159ddb6f29e607c54869e0d"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-16 00:02:29"
  condition:
    hash.sha256(0, filesize) == "fab7ef5a1a6c3f5aafa3e6f4bb1fd2907275cd440159ddb6f29e607c54869e0d"
}
```

### Sample 43: `0af1e1824def0944`

| Field | Value |
|---|---|
| SHA-256 | `0af1e1824def0944d69e44c3ca76bc52163ee20dda7e978ead06134f550fbdc5` |
| Family label | `unknown` |
| File name | `sh` |
| File type | `sh` |
| First seen | `2026-07-16 00:02:27` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8f9ddfe88e5b7ace384cb96a141de23` |
| SHA-1 | `a98350c39ae23755ecef3eddc3ce2d2f86e3654c` |
| SHA-256 | `0af1e1824def0944d69e44c3ca76bc52163ee20dda7e978ead06134f550fbdc5` |
| SHA3-384 | `0765d26ed3363c416d0cbb5bcfdef47074783c7b104fbae01dfe2afa2576df692f499db11a998982eb82540ea24e398b` |
| TLSH | `T14541E2BBB8A28E30335DC4B9B486694CB7579A6F442A6F74F047743C36BC324B1742A5` |
| SSDEEP | `48:vkwvpihneZZn1oBydX5G21j/EmfthmmzEvJGU6+gtIIqNTMTCki:vkwYheZZK8EujnFhmmzIl6K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_0af1e182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0af1e1824def0944d69e44c3ca76bc52163ee20dda7e978ead06134f550fbdc5"
    family = "unknown"
    file_name = "sh"
    file_type = "sh"
    first_seen = "2026-07-16 00:02:27"
  condition:
    hash.sha256(0, filesize) == "0af1e1824def0944d69e44c3ca76bc52163ee20dda7e978ead06134f550fbdc5"
}
```

### Sample 44: `efcf0e27b47bfd41`

| Field | Value |
|---|---|
| SHA-256 | `efcf0e27b47bfd418d6ea526fbf7c2a7d4a0edaa6523b99b93f04e42a91ec9d7` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-16 00:00:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c642753744083d1f4cc54769140d7b22` |
| SHA-1 | `3615e260cf3798d5f0e1566b5027af56eaca07fc` |
| SHA-256 | `efcf0e27b47bfd418d6ea526fbf7c2a7d4a0edaa6523b99b93f04e42a91ec9d7` |
| SHA3-384 | `713f65c962b1595fe67a9ef25a3ae9c68dd8d226752f83444fb0c662320b0466a83c64bdfb12e87bc622dc68ba75d61e` |
| TLSH | `T1F9A31955F8919A26C6C116BFFA4F82CD372663A8E2EF3117CD19AF20378746B0D6B141` |
| TELFHASH | `t154d05b96932d4bd913815141a18d5c0b07e9726e97056868f2d93f1775431d3f01ac51` |
| SSDEEP | `3072:5icoQtNYGZUbQ50ruKxlAryJsQE8zIn55:5icoQtSyx5olAuJsWzG5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_efcf0e27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efcf0e27b47bfd418d6ea526fbf7c2a7d4a0edaa6523b99b93f04e42a91ec9d7"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:00:46"
  condition:
    hash.sha256(0, filesize) == "efcf0e27b47bfd418d6ea526fbf7c2a7d4a0edaa6523b99b93f04e42a91ec9d7"
}
```

### Sample 45: `2549da80202be546`

| Field | Value |
|---|---|
| SHA-256 | `2549da80202be54685dbd427543a75a227e4f59d5c4ceb2c4c67d179e03b76a8` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-15 23:59:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17bc21be84788d04bb160b60b43bfbcb` |
| SHA-1 | `e81b581dd563e194c227549e090d563e0ca200b0` |
| SHA-256 | `2549da80202be54685dbd427543a75a227e4f59d5c4ceb2c4c67d179e03b76a8` |
| SHA3-384 | `04995b76056e6992eed28aae51dbad6fa454b7a06bf0ad1957f9870ba906bb8fbb1c29fe28a0524fbf42f1e65f582967` |
| TLSH | `T1E7C3194AF8819F12D5D625BEFA4E518D331327ACE3EE7112DD245B2437CAA1B0E7B501` |
| TELFHASH | `t1c9d02e5fcb214ae827c35212800f010acbecb0cf2808048b7a443b648083002b033c47` |
| SSDEEP | `3072:iFhpXVb+N8tlgawqIlTiZR5mU6q4t4faRh0VjDcFYvoXKcIyQKofVan5r:ehpXN+N8tlSrlnU8GfaRh0VjDnvoCyZT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_2549da80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2549da80202be54685dbd427543a75a227e4f59d5c4ceb2c4c67d179e03b76a8"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-15 23:59:21"
  condition:
    hash.sha256(0, filesize) == "2549da80202be54685dbd427543a75a227e4f59d5c4ceb2c4c67d179e03b76a8"
}
```

### Sample 46: `73d869ad60ac8af7`

| Field | Value |
|---|---|
| SHA-256 | `73d869ad60ac8af7f82c200488d764f246b6b34426198d4e7d06c72be0c29930` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-15 23:53:10` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fc80d04d5a8393a2b421fb39a0bbfa4` |
| SHA-1 | `932303f7968af0add62cc6e41da5d1864909629c` |
| SHA-256 | `73d869ad60ac8af7f82c200488d764f246b6b34426198d4e7d06c72be0c29930` |
| SHA3-384 | `c725364021115e119e7ed4f33fbe393a1f792455d354c6c66e2d448ef77015a1c38ad789a4dc81c371091a4dd585ca3e` |
| TLSH | `T159C28D956A967C44BDC98A3E4CBE2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:1D8vCB+25j6es8RT9FYpMSUpi+20qUpi+20YQX:F8l25JVd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_73d869ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73d869ad60ac8af7f82c200488d764f246b6b34426198d4e7d06c72be0c29930"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-15 23:53:10"
  condition:
    hash.sha256(0, filesize) == "73d869ad60ac8af7f82c200488d764f246b6b34426198d4e7d06c72be0c29930"
}
```

### Sample 47: `313c89438182321b`

| Field | Value |
|---|---|
| SHA-256 | `313c89438182321b239cc6bef5a7b3b0bdfb0e648e1c4fd3073e8bd02343c867` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 23:51:57` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce9d9848b4144992a3d73221be09f0d3` |
| SHA-1 | `bd26df2c6ca3476c9e9495b11f754110b5851d4b` |
| SHA-256 | `313c89438182321b239cc6bef5a7b3b0bdfb0e648e1c4fd3073e8bd02343c867` |
| SHA3-384 | `27d743afd6e56854e8a9c0c59ea393d7343d0a3061aa2307e8f10bd98f8f41c7cbf1ef4b978ae137709dcc64100f9695` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1E9E6330CA5C006EEE233803EEDA36646E5A1B8361771D7CF5B9886B12D131E58D7CE67` |
| SSDEEP | `393216:sa5smDkouG4dO5E2iXMCHWUjXmcuI3/PGTAI:saayH4pbXMb8XbH/O7` |
| ICON-DHASH | `70f8f8dccce4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_313c8943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "313c89438182321b239cc6bef5a7b3b0bdfb0e648e1c4fd3073e8bd02343c867"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 23:51:57"
  condition:
    hash.sha256(0, filesize) == "313c89438182321b239cc6bef5a7b3b0bdfb0e648e1c4fd3073e8bd02343c867"
}
```

### Sample 48: `f5706e76823530a1`

| Field | Value |
|---|---|
| SHA-256 | `f5706e76823530a1278626c227ffe53f95df9e63e420f9b3f518ad8f696a8abf` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-15 23:50:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cac4ffed385f909f73ac9dc1d2c8210` |
| SHA-1 | `8432ed1acba27ba12b6db64bf8f40f7b44657e16` |
| SHA-256 | `f5706e76823530a1278626c227ffe53f95df9e63e420f9b3f518ad8f696a8abf` |
| SHA3-384 | `fc0a547035848bd6cd07d9366fca2d5ef5b84db2d5076c4c4c0748e7dd602b974c438ca2ef42b265f38981a07d2e21f9` |
| TLSH | `T14D735B13798180FDD88AC1780B2FE236F572B56C13317A6A7BD4EE21AE2AF511D3D644` |
| TELFHASH | `t1902144b1799a2c91b0fbf7267354e1910db02e7610f171e2e637a8f6ea60b800476836` |
| SSDEEP | `768:3BDLX7YyMB8z8hCCl+PIgBu7Wh38zDAcSeZTvGL92ZQQiHoLR1P3NiRCI23LkpLE:X8hCK8IgqpDyeZTvGZLkR1QRCGpYdi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_f5706e76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5706e76823530a1278626c227ffe53f95df9e63e420f9b3f518ad8f696a8abf"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:50:27"
  condition:
    hash.sha256(0, filesize) == "f5706e76823530a1278626c227ffe53f95df9e63e420f9b3f518ad8f696a8abf"
}
```

### Sample 49: `2af6bc32acb2fe10`

| Field | Value |
|---|---|
| SHA-256 | `2af6bc32acb2fe107f11927e849a1343794cc031ac1455fa98f90620ccdd3357` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-15 23:50:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7fcb9b82729ce326ed3b128b9775a16` |
| SHA-1 | `9c07946d12c0817ed9234508e3abf60eaf1a2691` |
| SHA-256 | `2af6bc32acb2fe107f11927e849a1343794cc031ac1455fa98f90620ccdd3357` |
| SHA3-384 | `97204e06ed3a8800572489dab2f2eb58131d536301e4712f80ee7c435e6a0fb064b8c3432e5c5063e7336a8da788e8da` |
| TLSH | `T1E7D3090ABF601EFBE8ABCC3701B94B4A24CC555722A43B757978D828B94B54F4AD3C74` |
| SSDEEP | `3072:LC7+Q7f0OKvosXNjI0yYyinOqPKHZxMrJqn5M5:u3bUvu0RyinOqyHZxXM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_2af6bc32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2af6bc32acb2fe107f11927e849a1343794cc031ac1455fa98f90620ccdd3357"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 23:50:26"
  condition:
    hash.sha256(0, filesize) == "2af6bc32acb2fe107f11927e849a1343794cc031ac1455fa98f90620ccdd3357"
}
```

### Sample 50: `c679320728557b65`

| Field | Value |
|---|---|
| SHA-256 | `c679320728557b65b99b8c25843cff3db038951383abe4b74dfc32aa968e2c4c` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-15 23:49:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ccbd4259eb918e02664fde7f414da30` |
| SHA-1 | `87a9032357b87625e5d6a6eadf3b228257cb8d0e` |
| SHA-256 | `c679320728557b65b99b8c25843cff3db038951383abe4b74dfc32aa968e2c4c` |
| SHA3-384 | `a276d305ee577f4c1a7a165a560b21a88672ae57377ad927a4060e05cd76b0f242d84166e6cad2acf877b898888b0164` |
| TLSH | `T10E041A4F7721CF21C759C53149B38B9A56B926A22BE28845F31CDE083E2134DA91FFE5` |
| TELFHASH | `t15831dff08b3b55219a89cbec88edb75a4a1e9115470adf33fe2180bc50160ede325d4f` |
| SSDEEP | `3072:obx29reuGFMhrfOcyKVbU7SHxCyXn7Sfp1DZjRF:y29reumUrfOfKZZX32fvJRF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_c6793207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c679320728557b65b99b8c25843cff3db038951383abe4b74dfc32aa968e2c4c"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 23:49:50"
  condition:
    hash.sha256(0, filesize) == "c679320728557b65b99b8c25843cff3db038951383abe4b74dfc32aa968e2c4c"
}
```

### Sample 51: `aab106cab1b75132`

| Field | Value |
|---|---|
| SHA-256 | `aab106cab1b75132ce6ac9cb3ab4d3f23a4814186a862858905c6b96ec4f1105` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-15 23:49:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c40b632b07059f2929a29b4a16e25e0c` |
| SHA-1 | `c241d4a92799d593a4e92cbf7a96af31df90549f` |
| SHA-256 | `aab106cab1b75132ce6ac9cb3ab4d3f23a4814186a862858905c6b96ec4f1105` |
| SHA3-384 | `327211875be8f678f500747dd4adcd031d6be1f2f230106b1e2b2277ae9c8e421ea5aa11490136201c1f2479ad766d76` |
| TLSH | `T1597302E2C97003EAFD4B02F2BE5A994A71C141391634B747BBB2732C1DA557B4028B97` |
| SSDEEP | `1536:3YHxrVegz0GJEaZLOhIwGs16mpu9rTsGMdOAv/5CYD8IoZ0eQZ68:3YHxhePGJEaYNNvMldAn5CYD8Iogn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_aab106ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aab106cab1b75132ce6ac9cb3ab4d3f23a4814186a862858905c6b96ec4f1105"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 23:49:17"
  condition:
    hash.sha256(0, filesize) == "aab106cab1b75132ce6ac9cb3ab4d3f23a4814186a862858905c6b96ec4f1105"
}
```

### Sample 52: `149d241e0902e6b1`

| Field | Value |
|---|---|
| SHA-256 | `149d241e0902e6b10a97e3890b10ccacc99d9a481304373ea52da2ce29ab9947` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-15 23:49:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e55a50e0b5c68fa46803854143c37624` |
| SHA-1 | `88568440060b5d2c5bd16a78e435e09994a5dbd6` |
| SHA-256 | `149d241e0902e6b10a97e3890b10ccacc99d9a481304373ea52da2ce29ab9947` |
| SHA3-384 | `c7aeae86c94db6bff75a516e2249286f2ff46c110a444caa7fac9e4789d49627bce208f24c8389a9f331741f56d2c2f2` |
| TLSH | `T193A35CC5EA83D0B0E8525A74043BB32ACF76F43651F5EE86E7952D32AC22711DA0B75C` |
| TELFHASH | `t1e241fcf5ae6708ecb7d06802d60d5b713d4eeb7b246071f105f32c7532aa90641b6c39` |
| SSDEEP | `1536:+kIzpTBgqpGgCN8IR8t1FkClLkra5WVc3nrjnSC1TpjiiOmrw869yjy6a:7Ih2tgCN8IR8rjT5WojS8TVRg8g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_149d241e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149d241e0902e6b10a97e3890b10ccacc99d9a481304373ea52da2ce29ab9947"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:49:16"
  condition:
    hash.sha256(0, filesize) == "149d241e0902e6b10a97e3890b10ccacc99d9a481304373ea52da2ce29ab9947"
}
```

### Sample 53: `4337290c0f38bd81`

| Field | Value |
|---|---|
| SHA-256 | `4337290c0f38bd812f247315283f3981301b4e9687b9301a5b6ebc640e5c777a` |
| Family label | `unknown` |
| File name | `Payment Invoices and bank documents.exe` |
| File type | `exe` |
| First seen | `2026-07-15 23:49:01` |
| Reporter | `threatcat_ch` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a15ab51656f70702676510eaf207f117` |
| SHA-1 | `71d244af6b9d8ece471a7d879ebb66176a937a04` |
| SHA-256 | `4337290c0f38bd812f247315283f3981301b4e9687b9301a5b6ebc640e5c777a` |
| SHA3-384 | `fc6746df233f12136b16cb4013e776b24a537445bbed1cc84e8a2b37e10d578b638f5e92d85e251f5a722987ff8b311d` |
| IMPHASH | `9be4f90f50c714bc00cc8beb2e137299` |
| TLSH | `T12CB40201FF9A58E9E866C07599BBC62315317E4C0A65B62F1718BF2FBE31C80D93A744` |
| SSDEEP | `12288:MBQEiPvu2LeiRsz8eq3AAwP1mPgTqekfri:MBeP9LrsweqFwPCCqS` |
| ICON-DHASH | `f96c6c7064ccbcbc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_4337290c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4337290c0f38bd812f247315283f3981301b4e9687b9301a5b6ebc640e5c777a"
    family = "unknown"
    file_name = "Payment Invoices and bank documents.exe"
    file_type = "exe"
    first_seen = "2026-07-15 23:49:01"
  condition:
    hash.sha256(0, filesize) == "4337290c0f38bd812f247315283f3981301b4e9687b9301a5b6ebc640e5c777a"
}
```

### Sample 54: `a1522fcc06148485`

| Field | Value |
|---|---|
| SHA-256 | `a1522fcc06148485082b82f1e774c286ee98139150a948be54eec8f5f20e3945` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-15 23:48:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e850de83c2328cf6ead7169bcc479cb9` |
| SHA-1 | `b79182b279e45e8bbacb15b2effc887029973dab` |
| SHA-256 | `a1522fcc06148485082b82f1e774c286ee98139150a948be54eec8f5f20e3945` |
| SHA3-384 | `f246b8d0b17cde69d9361a687920f2455099ae7aa7a83c18fc48c44b49c21927735d212c44c154cae0e9535aa6170fb9` |
| TLSH | `T1E9C33A06746158FCC167C434C77FE837EA21B85D12243A6F27C4BA722E22E755F0AB96` |
| SSDEEP | `1536:Ygi3/CDtnYQ1QKcGPd2ktO0T08vZSotkUQvK1Zuo6a44EjzseG44UorH8w:Ygiv2tnYQyzGFonGPea4nseG46HF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_a1522fcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1522fcc06148485082b82f1e774c286ee98139150a948be54eec8f5f20e3945"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:48:45"
  condition:
    hash.sha256(0, filesize) == "a1522fcc06148485082b82f1e774c286ee98139150a948be54eec8f5f20e3945"
}
```

### Sample 55: `d4a4f43c6efee41d`

| Field | Value |
|---|---|
| SHA-256 | `d4a4f43c6efee41dbd3d761503bc5cc5ab7cf1c20a6065971edefe42408fc361` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-07-15 23:48:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dce8f1e3c36c972c8d2baa8488cb4202` |
| SHA-1 | `e60c2018d7b273dda0ecac503fcf6b9ecd9758c4` |
| SHA-256 | `d4a4f43c6efee41dbd3d761503bc5cc5ab7cf1c20a6065971edefe42408fc361` |
| SHA3-384 | `b54960953ec258e9c927bb15054f77d567d432f8a5f54aa0563ddbe3035e133acf217eecf0c7c7cc56265bf10c3b0c9a` |
| TLSH | `T1A043F1FE5D9256FBD67892B2AF4930F8B3D2255420520B77A445307EC8EE7641890FB2` |
| SSDEEP | `768:EQEzbLA8R6vfMqeDZL88KoSN2LAIgghAmcTw9W5uz5Kwtd/syFPHOwqEJwndNK:v4R6HMqep85NMAInhL6wmudayFPHUAJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_d4a4f43c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4a4f43c6efee41dbd3d761503bc5cc5ab7cf1c20a6065971edefe42408fc361"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:48:09"
  condition:
    hash.sha256(0, filesize) == "d4a4f43c6efee41dbd3d761503bc5cc5ab7cf1c20a6065971edefe42408fc361"
}
```

### Sample 56: `5b3958cd6dbbb9e2`

| Field | Value |
|---|---|
| SHA-256 | `5b3958cd6dbbb9e2195de1e88988b7a5ce289bd84a122020ba9c62088bc221a2` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-15 23:46:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6233126161eb655654591a480900d0ee` |
| SHA-1 | `2e9e80717943450580577e85a2e58acf2c64fcd2` |
| SHA-256 | `5b3958cd6dbbb9e2195de1e88988b7a5ce289bd84a122020ba9c62088bc221a2` |
| SHA3-384 | `49f9df9c31b7379406f33d104da2856dabde48d39716718c5f75274622abc560cb5984095495574b27d013be3f206948` |
| TLSH | `T1EDD3F64AF8819F11D5D625BEFA0E728D332337A8E3EE71129D245B2137CA95B0E7B501` |
| TELFHASH | `t145d0a75b73392ae851d741d580de860d669c71536e012431728f2e1fcdc9893f622842` |
| SSDEEP | `3072:umOl36/IWJwQCTxGY1MOVZON5ijx4mEfxskabvNKYUOuhJ6Eu2i8/8Lnbz:umOl3CIWJwQqxGzOkiloCkabvNKYUlJ4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_5b3958cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b3958cd6dbbb9e2195de1e88988b7a5ce289bd84a122020ba9c62088bc221a2"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-15 23:46:40"
  condition:
    hash.sha256(0, filesize) == "5b3958cd6dbbb9e2195de1e88988b7a5ce289bd84a122020ba9c62088bc221a2"
}
```

### Sample 57: `7210622578575fd6`

| Field | Value |
|---|---|
| SHA-256 | `7210622578575fd6bb66077e752fef26aea3dfc790499d35ffb8a2aa11c6cdf5` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-15 23:39:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa83ccb64ac9c806ae41a1b790e2d9f2` |
| SHA-1 | `5956ceac800509d3f8dfc9c9f4d8096c9253fba8` |
| SHA-256 | `7210622578575fd6bb66077e752fef26aea3dfc790499d35ffb8a2aa11c6cdf5` |
| SHA3-384 | `2009a282eaddd095a7391efbf5b52fed571121740029a4aa9219aa8e11c58bf7500d048cdf198717c5fc7adfb4224f51` |
| TLSH | `T1D6042B49AE752BEBC06FCE30152D830721DE944FA2F6A73DE678CD4C399A24859F3854` |
| TELFHASH | `t15831dff08b3b55219a89cbec88edb75a4a1e9115470adf33fe2180bc50160ede325d4f` |
| SSDEEP | `3072:Fex3ZJGNCkyXOvnJDDRdDGSGVW9t23YvAJJ5TZ9/1DvO:4pJGNCkyXOnJzCSGVW9vvAJJ5bdTO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_72106225
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7210622578575fd6bb66077e752fef26aea3dfc790499d35ffb8a2aa11c6cdf5"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 23:39:51"
  condition:
    hash.sha256(0, filesize) == "7210622578575fd6bb66077e752fef26aea3dfc790499d35ffb8a2aa11c6cdf5"
}
```

### Sample 58: `6b697aac4b61f7af`

| Field | Value |
|---|---|
| SHA-256 | `6b697aac4b61f7afa4bbaa6702ccb5950816fa2d78cbbb0824fd313233ba0dc8` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-07-15 23:39:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1df6a681b1211d63121536c7362f4ed4` |
| SHA-1 | `a09c0093bbbdeeca901f7e04ab822aa0d723e2d6` |
| SHA-256 | `6b697aac4b61f7afa4bbaa6702ccb5950816fa2d78cbbb0824fd313233ba0dc8` |
| SHA3-384 | `bd462ba449ae9e37d46592c67aa7096eb4a1f9833c693c2982208d11d3fe0b71ad33e1fa3e214f4df7f040277ad8ef17` |
| TLSH | `T139731257CEED5F76D182F6FEA607A943C2AD2602BFC8031832041E74699A5F1B21F434` |
| SSDEEP | `1536:X/AVZCeJxnFemJxeYhq3uUho7gHsG6Y8DNOTOmPElt4cmb8n02iWd:XN2n5Jxeqq+bmsGU5Onit4cmbs02v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_6b697aac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b697aac4b61f7afa4bbaa6702ccb5950816fa2d78cbbb0824fd313233ba0dc8"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 23:39:28"
  condition:
    hash.sha256(0, filesize) == "6b697aac4b61f7afa4bbaa6702ccb5950816fa2d78cbbb0824fd313233ba0dc8"
}
```

### Sample 59: `b9c73d31536c5a29`

| Field | Value |
|---|---|
| SHA-256 | `b9c73d31536c5a29aa261ebaff72de025440f30a6168c428e6de28a7bbc6ad3f` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-15 23:38:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ec8f08a3f62e7020dd3f9e53bce0cd28` |
| SHA-1 | `83f25fc8828d41e84ba673220b764832859b81f2` |
| SHA-256 | `b9c73d31536c5a29aa261ebaff72de025440f30a6168c428e6de28a7bbc6ad3f` |
| SHA3-384 | `d0fd5dca9e5c0ffe3c4b6170d5254cea62f790ccde906b395266a544c090ab9230f38d4fe7a23e3c9f9c4d0585aab7b7` |
| TLSH | `T10AE35C4CFA57C0F0E1D345F1067BA7AA563A99126237F1E2FF5A3762F871302588926C` |
| SSDEEP | `3072:k9vsY79WInXeu8sG1APbN1yYa3rbKWI9+RhhRc8:k9vR1nuuzGYNEPHKP+fh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_b9c73d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c73d31536c5a29aa261ebaff72de025440f30a6168c428e6de28a7bbc6ad3f"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:38:46"
  condition:
    hash.sha256(0, filesize) == "b9c73d31536c5a29aa261ebaff72de025440f30a6168c428e6de28a7bbc6ad3f"
}
```

### Sample 60: `4a55129d6c014c2b`

| Field | Value |
|---|---|
| SHA-256 | `4a55129d6c014c2b57190dbf17324c36ed3d929b09998d86c6200c8ac75609c4` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-07-15 23:38:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0630a31ef0108c180181c68c3185f697` |
| SHA-1 | `b6015d4bcde0897144a7947f9875b4654afb2ddd` |
| SHA-256 | `4a55129d6c014c2b57190dbf17324c36ed3d929b09998d86c6200c8ac75609c4` |
| SHA3-384 | `2ba4ec9bbf39b8c3c8a8697a653b3a137efdd6446f92b853a9034f637944f7eb0cb769c30757592d3fa69cffd5cc0591` |
| TLSH | `T1764312D497FF4AE1C7EB257A52AA3CA0904EB152E312C750F17F18FFE412D24260698A` |
| SSDEEP | `1536:1ZGKjK4rXUcWMGX5P64ua+pn4JSPQxVtu+Bjxalnouy8DM2:7fG0UcWMGJS4d+6MQv8+Bjxa9outDM2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_4a55129d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a55129d6c014c2b57190dbf17324c36ed3d929b09998d86c6200c8ac75609c4"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:38:23"
  condition:
    hash.sha256(0, filesize) == "4a55129d6c014c2b57190dbf17324c36ed3d929b09998d86c6200c8ac75609c4"
}
```

### Sample 61: `a8f59963739a04b3`

| Field | Value |
|---|---|
| SHA-256 | `a8f59963739a04b38f85872f37de5c6eda7dc00c4adc46002f0a3f6fecb2233e` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 23:30:46` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX10.file, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a187b3d253918a662900349c6bc72a0d` |
| SHA-1 | `c8c5df4c7c46dfea8e538bcbf33edfffcf22c19c` |
| SHA-256 | `a8f59963739a04b38f85872f37de5c6eda7dc00c4adc46002f0a3f6fecb2233e` |
| SHA3-384 | `e5e7e05fe8cc28e6f6819e14ce3bde7fd4fad8aaa59c6e5992c8d17f92981e9f280d5ad266f91ff0c55d67373e2759ac` |
| IMPHASH | `00c93460e3f61240a5442d381fae7ce7` |
| TLSH | `T13BD59D87A3641167D3F310BAE41A2AB1A7766CAA231709F7109DC19C27436DCC7B73E6` |
| SSDEEP | `24576:fzXp3Bwl2QA+nh6yFnM+1nDoUc8MGcl1PAM6FhLFlh8FkuGVdEgxs/e:fzzVQD6aMeFU1j6PvmFNGL5K` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_061_a8f59963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8f59963739a04b38f85872f37de5c6eda7dc00c4adc46002f0a3f6fecb2233e"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 23:30:46"
  condition:
    hash.sha256(0, filesize) == "a8f59963739a04b38f85872f37de5c6eda7dc00c4adc46002f0a3f6fecb2233e"
}
```

### Sample 62: `9c3d18dac0e9364b`

| Field | Value |
|---|---|
| SHA-256 | `9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1aaa81d06b5f955edfda76e01b34bddb` |
| SHA-1 | `a91d46e018b43e1842b6bd758ab6ceb38462da47` |
| SHA-256 | `9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb` |
| SHA3-384 | `23bf7f61e2f88ea8abf6d88a17d201179688ca8c81d9fe57c16eff14cc659c5088fc3a84fafd21cd59839160fc8b22ed` |
| TLSH | `T12B336A77E85A5E94C086817075249F351F23B1C893932EBB16EAC2B55483DACF509FF8` |
| SSDEEP | `1536:0aeLe/MfGsTj5mYcKwlKzwUJGCVHdhnc:0RLeGGsHPDwNUJGehnc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_9c3d18da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:22"
  condition:
    hash.sha256(0, filesize) == "9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb"
}
```

### Sample 63: `72b352a3c0a6763a`

| Field | Value |
|---|---|
| SHA-256 | `72b352a3c0a6763a425912736b369697387aa12f25f297d078511480e8b2306b` |
| Family label | `Mirai` |
| File name | `debug.dbg` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60a807c70d90ce3d10385b7874121a0c` |
| SHA-1 | `9404f71db224c85623e34959a33fb2bf5e8a2c97` |
| SHA-256 | `72b352a3c0a6763a425912736b369697387aa12f25f297d078511480e8b2306b` |
| SHA3-384 | `9009508d98e1d0c2a14302c032f9c9e00630c81d09a743a3b33574490009a3ba7a5b295892e2dfbe8a6009ba4687f609` |
| TLSH | `T118436DC6D143D8F6E80B0570603BE72BAE71E8EA2219FF47C7689631FC86641A5179DC` |
| TELFHASH | `t1ee21b3fb1eaa58e877e46c54c39aaa911935c5371a9037a941f1cdd813d2ec140a9c3d` |
| SSDEEP | `1536:DIqD1xfYqyDgZtmYX38pJspYUz2jMY5ts0Aj+ISeWYeeu:DIqDXfYqykZ4YX3IJsplsMytzG+MWYeR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_72b352a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b352a3c0a6763a425912736b369697387aa12f25f297d078511480e8b2306b"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:20"
  condition:
    hash.sha256(0, filesize) == "72b352a3c0a6763a425912736b369697387aa12f25f297d078511480e8b2306b"
}
```

### Sample 64: `b76e9c4be46dd696`

| Field | Value |
|---|---|
| SHA-256 | `b76e9c4be46dd696a998d2eef5a0a5228c713d7b659358ef08cc647ab98845db` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `397908f4112c7efe54def36d90c6f053` |
| SHA-1 | `b6cc6225c2aad0760ae1c77725b46c2401fd6f21` |
| SHA-256 | `b76e9c4be46dd696a998d2eef5a0a5228c713d7b659358ef08cc647ab98845db` |
| SHA3-384 | `12a734d283e61dc2281a2f100c2bbbacf279edeb32e7ab7ef40d2a3cc8de76243cf34ff81baaea6fc18cfa4b7e2a3af5` |
| TLSH | `T13863B61A6E628FBDFB59833447B78E21AB5823D527D1D641E25CD6002F6034E681FFE8` |
| TELFHASH | `t1fb112948883813f4d7650c9d6bedff76d05160ea07164e378d40f99e9b69e429a00c2c` |
| SSDEEP | `768:bPWek0n4CjdGQKKWxmg0EhFkFkeYA+QoQZXyApGqFDjOZ2uyyQ5NeNTP4wncIZ:bj/hSmmjAoQBym2Uu6eBPZncq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_b76e9c4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b76e9c4be46dd696a998d2eef5a0a5228c713d7b659358ef08cc647ab98845db"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:19"
  condition:
    hash.sha256(0, filesize) == "b76e9c4be46dd696a998d2eef5a0a5228c713d7b659358ef08cc647ab98845db"
}
```

### Sample 65: `717956c13e9a4ae5`

| Field | Value |
|---|---|
| SHA-256 | `717956c13e9a4ae5e18a66dad4b4aba9e20824382663344a3352e1fd1f9c9663` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `04073c84c72055cea56d27f97bbdb48f` |
| SHA-1 | `bccb3af1ec7172f4f6b53504f763a23c1dce5b46` |
| SHA-256 | `717956c13e9a4ae5e18a66dad4b4aba9e20824382663344a3352e1fd1f9c9663` |
| SHA3-384 | `0b267b43d64170ba896009ee7cb76cc80735ebd38c50f69e8d544202b221c7ea6cdabb5c72ad3314dc958dc9487c5ae9` |
| TLSH | `T125434A02B31C0E47C0A31A70263F1BD1D7BFA9D022E4F689255E9B9A9671E375486FCD` |
| SSDEEP | `768:cbXAxLERfyECRZuRlgQ0cq1eg9X+UdUtO9Cm54C+Jjc8Adtbcg12sFRxtAS+wnw1:SX+iDqXXJ2+Cu+q8gbcgIQx6WnwXF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_717956c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "717956c13e9a4ae5e18a66dad4b4aba9e20824382663344a3352e1fd1f9c9663"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:18"
  condition:
    hash.sha256(0, filesize) == "717956c13e9a4ae5e18a66dad4b4aba9e20824382663344a3352e1fd1f9c9663"
}
```

### Sample 66: `0dde7f3ddfe8924a`

| Field | Value |
|---|---|
| SHA-256 | `0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `802cc986ba84ec015701c72f5f4a80c6` |
| SHA-1 | `392d8f5a50b29acd7df0bc484cd107069e35efb0` |
| SHA-256 | `0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204` |
| SHA3-384 | `cb52a79a04e100b3aa0d23ec870fb4ed79243847da3b573f63b74331ab3aec8dae4b0ec6081ff17879d492be59585b1d` |
| TLSH | `T13C330907F681C0FDC49AC174476BBA3AD93771ED0238F2A67BE4EA223D96E611D19C44` |
| TELFHASH | `t1931133f8bc215990f2ebf52ab70bd1188cbc2aa500c031f1c5b6b4f6bb52b460931c27` |
| SSDEEP | `1536:Ru31CxXVpHlCrxsNnVfvj56+Hu2r4DaEXzd0OCUjCYi:Y1sXV5lCKNVfvj51O0GaEDOVUjCYi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_0dde7f3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:17"
  condition:
    hash.sha256(0, filesize) == "0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204"
}
```

### Sample 67: `1fe41e8a4f1dfe02`

| Field | Value |
|---|---|
| SHA-256 | `1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35449891d146dba26c0b0d791a7a9e8b` |
| SHA-1 | `62b1bb32008463c2504f5fec7fa2ac65aee702d2` |
| SHA-256 | `1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566` |
| SHA3-384 | `62354703c9e97278c17b6a1af0f54555590fd1452965bf1b5d82642586cd0ccc62ad9f52f6b0840be5725606440ea35c` |
| TLSH | `T125334AC4F643DAF9EC4705701177FB339A32F5E51229E743C3A99A32AC52602A906EDD` |
| TELFHASH | `t1702129b2ada606fcf3d0a449d72f43d36b35d5372531797804b2298137f25c59079835` |
| SSDEEP | `1536:GWa2d5sf1Gg+ya+nlQ5F0XXbzbfwVsp3MSfCY6:Gt2d5sf1GCammr0nX7MW3dCY6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_1fe41e8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:16"
  condition:
    hash.sha256(0, filesize) == "1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566"
}
```

### Sample 68: `30021ebe609908ad`

| Field | Value |
|---|---|
| SHA-256 | `30021ebe609908ad9b5a42a38b9be1e83225a86f2b7c15b77dc7ec91e016dff2` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcebf93cccb55701d6162b48c0e55390` |
| SHA-1 | `7b24c73414c8cfcefd6afbcf6cb28456e7f3452d` |
| SHA-256 | `30021ebe609908ad9b5a42a38b9be1e83225a86f2b7c15b77dc7ec91e016dff2` |
| SHA3-384 | `ca31a40989abb08b4a843af85454b3868fcdcf647b3dc527c1797af5da21ef4a21b07f0390a9ab03782dbb8761a53988` |
| TLSH | `T13AD31A56E7408B13C4D61779B6EF42453323ABA4A3DB73069528AFF43F8279B0E63905` |
| TELFHASH | `t1cd21f0255765a1199ea1dd54d8ed87b2162887232344af33de36c4cc68060daea3bc4f` |
| SSDEEP | `3072:9S6VGvQ5uazAFEsHY8jNCB4wxGnAE+SQkM/9w4H:9S6VzuazAFEs46NugnAE+SDM/9nH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_30021ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30021ebe609908ad9b5a42a38b9be1e83225a86f2b7c15b77dc7ec91e016dff2"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:15"
  condition:
    hash.sha256(0, filesize) == "30021ebe609908ad9b5a42a38b9be1e83225a86f2b7c15b77dc7ec91e016dff2"
}
```

### Sample 69: `fdefb11a39dd2318`

| Field | Value |
|---|---|
| SHA-256 | `fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65d67878bfb82946f885dbf781a5a702` |
| SHA-1 | `e6df691ebf11af166f35cfe30b47130631f25d6e` |
| SHA-256 | `fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae` |
| SHA3-384 | `28b1f171ea967d74730f6549bdc7055d969dd4de5d5b69fd4386d5f0c127d74b11f0adfe40b8750f60685454d62ec884` |
| TLSH | `T150433A31BA760E27C0D1A8B661E74B25B6F543DE26E8CA0B3DB10D9EBF715406503AF4` |
| SSDEEP | `1536:fvf20dYmgHg1We/mrYF6+QW+75MUtydNKA:f20KKL+VM1NKA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_fdefb11a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:13"
  condition:
    hash.sha256(0, filesize) == "fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae"
}
```

### Sample 70: `3c5228311e436604`

| Field | Value |
|---|---|
| SHA-256 | `3c5228311e4366042fc1fef9f9e960fa94b30267052cf7818d039ce4d256c15e` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-15 23:28:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e11dd3a61ea20cce3a49ca4aedc00b8` |
| SHA-1 | `554459e7e82f6e086c8fe5d1414f50ab9549403c` |
| SHA-256 | `3c5228311e4366042fc1fef9f9e960fa94b30267052cf7818d039ce4d256c15e` |
| SHA3-384 | `26fbef0c5d13d1a2bde6831edec9108d9b730ea7d5424de7fc553bf2dd453c42b22e583ab438bbf518f453d485befd8f` |
| TLSH | `T133F2E891B8854727C2E41379B6AE5A8E377073EC92CBB627D8224B207BC591F1D63F41` |
| TELFHASH | `t195e02600fc748a1888e65ab4dcdc0764a501121360575b20cf51daf0cc3f844a708e5e` |
| SSDEEP | `768:xxt8XqqoG5M1IaBHGa1wS3ittiV5Ha9F2FT93Riz3pocWthEwn:xuqRG5MVxGaSZCWsBB+3cln` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_3c522831
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c5228311e4366042fc1fef9f9e960fa94b30267052cf7818d039ce4d256c15e"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:12"
  condition:
    hash.sha256(0, filesize) == "3c5228311e4366042fc1fef9f9e960fa94b30267052cf7818d039ce4d256c15e"
}
```

### Sample 71: `9fe5f01662010999`

| Field | Value |
|---|---|
| SHA-256 | `9fe5f01662010999236f92b351ef36a759a58421fa4bca630c17e35e8cf8e0d9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 23:27:16` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cccd8763f4ba3fe171732a7777b06421` |
| SHA-1 | `6380aa2979532a8a102ada32c98441d2f677aa07` |
| SHA-256 | `9fe5f01662010999236f92b351ef36a759a58421fa4bca630c17e35e8cf8e0d9` |
| SHA3-384 | `44fb29fe1ec90d9bcf4111260b769776d413a4b28138013a457fb682fc3be815f9eab2f3e66838bc5a8d5f49f770d2b6` |
| IMPHASH | `cd702dbfbd74cf5a80f59195b2460134` |
| TLSH | `T14CD4C013B9A19076E1724635CD78AB149B7DBC700F20A7CB67C005AA6EB16C0AF37767` |
| SSDEEP | `12288:SUoVNdZJ9HO5ov7LJb7B4abh/RuyxBlDetAqxSvwiA:SUIvcojLJqa1/Ruyb4i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_9fe5f016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fe5f01662010999236f92b351ef36a759a58421fa4bca630c17e35e8cf8e0d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 23:27:16"
  condition:
    hash.sha256(0, filesize) == "9fe5f01662010999236f92b351ef36a759a58421fa4bca630c17e35e8cf8e0d9"
}
```

### Sample 72: `02e6fbf7319629a3`

| Field | Value |
|---|---|
| SHA-256 | `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` |
| Family label | `unknown` |
| File name | `stage5_ldb.bin` |
| File type | `unknown` |
| First seen | `2026-07-15 22:52:17` |
| Reporter | `anonymous` |
| Tags | `beacon, ContagiousInterview, DPRK, Lazarus, nodejs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7ba679bf126238f605c9a3ae2a95706` |
| SHA-256 | `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_02e6fbf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5"
    family = "unknown"
    file_name = "stage5_ldb.bin"
    file_type = "unknown"
    first_seen = "2026-07-15 22:52:17"
  condition:
    hash.sha256(0, filesize) == "02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5"
}
```

### Sample 73: `b34aa84e8b4ad57d`

| Field | Value |
|---|---|
| SHA-256 | `b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1` |
| Family label | `unknown` |
| File name | `stage5_brow_final.py` |
| File type | `unknown` |
| First seen | `2026-07-15 22:52:11` |
| Reporter | `anonymous` |
| Tags | `ContagiousInterview, DPRK, Lazarus, python, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26fcfaa9ac36025ca6774a2bb483ebdf` |
| SHA-256 | `b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_b34aa84e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1"
    family = "unknown"
    file_name = "stage5_brow_final.py"
    file_type = "unknown"
    first_seen = "2026-07-15 22:52:11"
  condition:
    hash.sha256(0, filesize) == "b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1"
}
```

### Sample 74: `cd3b606d31c9d3c2`

| Field | Value |
|---|---|
| SHA-256 | `cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6` |
| Family label | `unknown` |
| File name | `stage5_payload_final.py` |
| File type | `unknown` |
| First seen | `2026-07-15 22:52:05` |
| Reporter | `anonymous` |
| Tags | `ContagiousInterview, DPRK, InvisibleFerret, Lazarus, python, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a8db6a56bd1dc37b25daadb4de7764d` |
| SHA-256 | `cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_cd3b606d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6"
    family = "unknown"
    file_name = "stage5_payload_final.py"
    file_type = "unknown"
    first_seen = "2026-07-15 22:52:05"
  condition:
    hash.sha256(0, filesize) == "cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6"
}
```

### Sample 75: `683a1607808f4944`

| Field | Value |
|---|---|
| SHA-256 | `683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630` |
| Family label | `unknown` |
| File name | `stage3_load.js` |
| File type | `js` |
| First seen | `2026-07-15 22:51:59` |
| Reporter | `anonymous` |
| Tags | `ContagiousInterview, DPRK, javascript, js, Lazarus, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4866e472593328cb872fe2d68239b79f` |
| SHA-256 | `683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_683a1607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630"
    family = "unknown"
    file_name = "stage3_load.js"
    file_type = "js"
    first_seen = "2026-07-15 22:51:59"
  condition:
    hash.sha256(0, filesize) == "683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630"
}
```

### Sample 76: `fc874323bea20a98`

| Field | Value |
|---|---|
| SHA-256 | `fc874323bea20a985ee9248ea2eb140a60ee716aeed709cd1e48c528d6b11afc` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 22:51:57` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89979d4fcc0cd658e4429bbd166a9ccf` |
| SHA-1 | `2ba009d47e1d2ee69e1b4f943e9931943daff152` |
| SHA-256 | `fc874323bea20a985ee9248ea2eb140a60ee716aeed709cd1e48c528d6b11afc` |
| SHA3-384 | `fa0564acc8687ba86385ea246b5e0ab7686f6b8df46535fb1e67a9a89c078d7da6dd97b6d90ca8977b7f5b9598e1741e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T188E633089AD021EEE6A7503CFDA255E5F5B178760731DAEF1B9097613DBB0A0883E713` |
| SSDEEP | `393216:xjzwNmLNriOTZ9ahvbJxLqXMCHWUjXWcuI3/PGTAI:xjAmLNrNahvbJVqXMb8XrH/O7` |
| ICON-DHASH | `5471d4d8c8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_fc874323
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc874323bea20a985ee9248ea2eb140a60ee716aeed709cd1e48c528d6b11afc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 22:51:57"
  condition:
    hash.sha256(0, filesize) == "fc874323bea20a985ee9248ea2eb140a60ee716aeed709cd1e48c528d6b11afc"
}
```

### Sample 77: `a3f413338c28c464`

| Field | Value |
|---|---|
| SHA-256 | `a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27` |
| Family label | `unknown` |
| File name | `stage2_payload.js` |
| File type | `js` |
| First seen | `2026-07-15 22:51:53` |
| Reporter | `anonymous` |
| Tags | `ContagiousInterview, DPRK, javascript, js, Lazarus, loader` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab169946d5ba542c305f6b398c49d81d` |
| SHA-256 | `a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_a3f41333
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27"
    family = "unknown"
    file_name = "stage2_payload.js"
    file_type = "js"
    first_seen = "2026-07-15 22:51:53"
  condition:
    hash.sha256(0, filesize) == "a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27"
}
```

### Sample 78: `a129de4fd4f1374a`

| Field | Value |
|---|---|
| SHA-256 | `a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c` |
| Family label | `unknown` |
| File name | `malicious_post-checkout.sh` |
| File type | `sh` |
| First seen | `2026-07-15 22:51:47` |
| Reporter | `anonymous` |
| Tags | `ContagiousInterview, DPRK, githook, Lazarus, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6222cb450999628bb61a4b3cbcd5f460` |
| SHA-256 | `a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_a129de4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c"
    family = "unknown"
    file_name = "malicious_post-checkout.sh"
    file_type = "sh"
    first_seen = "2026-07-15 22:51:47"
  condition:
    hash.sha256(0, filesize) == "a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c"
}
```

### Sample 79: `6673c0852fbf8372`

| Field | Value |
|---|---|
| SHA-256 | `6673c0852fbf8372d4bc146806b2ea1b1e23bc807b792338204e227098789bae` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 22:46:48` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09036bc10ae26bd022aed2951cb53b04` |
| SHA-1 | `74cf9eeb8158ab653c69d4aa171c45947ac51a01` |
| SHA-256 | `6673c0852fbf8372d4bc146806b2ea1b1e23bc807b792338204e227098789bae` |
| SHA3-384 | `3a6e4f923f714b3887c9133bd10f680142f86a751d27d9fea5de9477081e2a87cd68604544bd55045581df7a34a8cc0c` |
| IMPHASH | `fd886131a5124aa5c5627ebb2febfbd1` |
| TLSH | `T14D652311B26818F8D167C438D7052B639BB2348A0B529DFF13E942E92F369E16F3DB15` |
| SSDEEP | `24576:meP6jC43mQTP91oOxooOTW0XxWdmBCo9W81fmko61HajwCusri9jn7m7E7ExiDWW:mePcCIoOUXkmBCKo61HajfusripnS7Qf` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_6673c085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6673c0852fbf8372d4bc146806b2ea1b1e23bc807b792338204e227098789bae"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 22:46:48"
  condition:
    hash.sha256(0, filesize) == "6673c0852fbf8372d4bc146806b2ea1b1e23bc807b792338204e227098789bae"
}
```

### Sample 80: `880ba21b3e58f130`

| Field | Value |
|---|---|
| SHA-256 | `880ba21b3e58f130386afdb060ecc030848f8bd8de5c642705555f89a438c793` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 22:23:15` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f75f1bc5c9da99a704f2f78ed3a79c1d` |
| SHA-1 | `a6558043707a13485e4072791db5b95d53009dc3` |
| SHA-256 | `880ba21b3e58f130386afdb060ecc030848f8bd8de5c642705555f89a438c793` |
| SHA3-384 | `e0bcbfe71fa387e44323399d59cfc4a280bfdaa345e570494791e099350c40b22ef4a55e66ecee1a8abe5458b34263bd` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T146D61233B24B653EE06E4A355AB69110583B6E60AD134D5AB6F038ACFF351E03D3E647` |
| SSDEEP | `196608:ket6WywWJ27HrcUxwRWMR/yPZDfYThuzKPUEb7x:kTWqJ27rcSwdVopN2Hb` |
| ICON-DHASH | `b871c0ccccccc00f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_880ba21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "880ba21b3e58f130386afdb060ecc030848f8bd8de5c642705555f89a438c793"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 22:23:15"
  condition:
    hash.sha256(0, filesize) == "880ba21b3e58f130386afdb060ecc030848f8bd8de5c642705555f89a438c793"
}
```

### Sample 81: `9f16e0d8c5fed47b`

| Field | Value |
|---|---|
| SHA-256 | `9f16e0d8c5fed47bd9a77a9f45332481f320c5916e6efb92f03c3ab035af1a3c` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-15 22:19:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73f7cbc81df3f335f56cf49370dbea0c` |
| SHA-1 | `bed29ce73c6b7ed6f1e87fd136f400329e02ea6a` |
| SHA-256 | `9f16e0d8c5fed47bd9a77a9f45332481f320c5916e6efb92f03c3ab035af1a3c` |
| SHA3-384 | `33bb56ca463d73835778f10907f19dbae120ae5df9205032e6ceadb58d6163d708565726321b822cf518c188b86ec676` |
| TLSH | `T1C604194F7B10CF61C759C53145B3CB9A56B926622AE2C845F31CDE083E21349A92FFE9` |
| TELFHASH | `t13731c1f08b3b55219a89cbec89edb75e491e95054706df33fe2180bc50160ede225d4f` |
| SSDEEP | `3072:bTSx/CGMJMwArSQ/IMWWmMEAcBcFaJ1DwjjTw:3KXMJAW2j/MKaPyw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_9f16e0d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f16e0d8c5fed47bd9a77a9f45332481f320c5916e6efb92f03c3ab035af1a3c"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 22:19:37"
  condition:
    hash.sha256(0, filesize) == "9f16e0d8c5fed47bd9a77a9f45332481f320c5916e6efb92f03c3ab035af1a3c"
}
```

### Sample 82: `5defde36dc21b44a`

| Field | Value |
|---|---|
| SHA-256 | `5defde36dc21b44a1cea847af473d4bfd27926976134e583e0ee7b37f3cdd0b5` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-07-15 22:19:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffff48a82a35bdbe9370e51ea3903289` |
| SHA-1 | `94aa42e09da2b406203d4049afb21d424c92cff4` |
| SHA-256 | `5defde36dc21b44a1cea847af473d4bfd27926976134e583e0ee7b37f3cdd0b5` |
| SHA3-384 | `a90a9625c9ba5751145370841ab8cc183c3af9ad90ee3abeed0a4aac30d169f03b3e857c7901ccda953c862e5572845c` |
| TLSH | `T10F7312F181BE2D79CA57C6BC5B69CB7372D1588C320CFF4E067E726217E49AD2019192` |
| SSDEEP | `1536:A1X23N/QD03qAivQwb+yoOhu2CVVGWic9uuEbykSxFLFIHmjgzqzU8JF4vYeQtn:Awd/Whth3yBiRsV/ZQm8qzU8JF4vun` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_5defde36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5defde36dc21b44a1cea847af473d4bfd27926976134e583e0ee7b37f3cdd0b5"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 22:19:20"
  condition:
    hash.sha256(0, filesize) == "5defde36dc21b44a1cea847af473d4bfd27926976134e583e0ee7b37f3cdd0b5"
}
```

### Sample 83: `8db3d29e73b24d39`

| Field | Value |
|---|---|
| SHA-256 | `8db3d29e73b24d39bc338fa1c9cdc1b7f4cdc60c293759f12985ef1ce0e8f026` |
| Family label | `unknown` |
| File name | `update_flash_player.exe` |
| File type | `exe` |
| First seen | `2026-07-15 21:58:29` |
| Reporter | `skullmug` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ae34591db21bfdf8d666b10cbf0dc01` |
| SHA-1 | `53345b2a8dfa2a964ee703e6bda5e9798de303fd` |
| SHA-256 | `8db3d29e73b24d39bc338fa1c9cdc1b7f4cdc60c293759f12985ef1ce0e8f026` |
| SHA3-384 | `e01a138d274ad842ba65f7c99600c2d8fa4fbd4d1bf501b1ab3c93024c7d62ca61bd2f1853b4997e6f8df35fc2c40451` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1F2473365ABC205B6F9E7403D44748613E1B26A7A0F90D5EF17A9072D3EB73E1053E23A` |
| SSDEEP | `393216:NZqNbiodjs14bMgLc9zGdOu+wgIfUKOcgx/hEWbdXQfM6R4RmhbH00Ij8HsnvDwG:/q82G4TLcNOzf58KPgxZYMc3r00C+gEG` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_8db3d29e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8db3d29e73b24d39bc338fa1c9cdc1b7f4cdc60c293759f12985ef1ce0e8f026"
    family = "unknown"
    file_name = "update_flash_player.exe"
    file_type = "exe"
    first_seen = "2026-07-15 21:58:29"
  condition:
    hash.sha256(0, filesize) == "8db3d29e73b24d39bc338fa1c9cdc1b7f4cdc60c293759f12985ef1ce0e8f026"
}
```

### Sample 84: `d8ba1cd36e31e89b`

| Field | Value |
|---|---|
| SHA-256 | `d8ba1cd36e31e89bb03aa7ac811e81290fa1f6d5cd334005d5f91fafbf0a28ab` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 21:51:57` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c620f44c8fae8fe27ee0e22a1a946cc0` |
| SHA-1 | `80433d5810e047c0cfa881ee2e12b877c76e7b7b` |
| SHA-256 | `d8ba1cd36e31e89bb03aa7ac811e81290fa1f6d5cd334005d5f91fafbf0a28ab` |
| SHA3-384 | `37bb1d61f3345d4cc9bcc1b46d182ffef982f5898454fd6749a4a6591e99f5a88e1d01c62abee90ca03c2af989ebc35a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T10DE6335467E041DEDAB7003CEEE296A8E4A1B4718373C9EF0BE493936D135D18C39667` |
| SSDEEP | `393216:H+g0tBInya3IZcep67NEz3EsLXMCHWUjXRcuI3/PGTAI:egFya3IaC67Wz3XXMb8XGH/O7` |
| ICON-DHASH | `e86864e1d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_d8ba1cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8ba1cd36e31e89bb03aa7ac811e81290fa1f6d5cd334005d5f91fafbf0a28ab"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 21:51:57"
  condition:
    hash.sha256(0, filesize) == "d8ba1cd36e31e89bb03aa7ac811e81290fa1f6d5cd334005d5f91fafbf0a28ab"
}
```

### Sample 85: `8f5b6ce166f923af`

| Field | Value |
|---|---|
| SHA-256 | `8f5b6ce166f923af955e109e5218989c66145596fd3f329077fd0489d2299906` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-15 21:42:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b79bf2cfb89e2f8c605d1b71e025b678` |
| SHA-1 | `b1ff0ed23488271daa07572d11c0b1ce60ed0e23` |
| SHA-256 | `8f5b6ce166f923af955e109e5218989c66145596fd3f329077fd0489d2299906` |
| SHA3-384 | `12a1591e0cd6d3ea7f5ec6193af70ec5ec9e3daa55285a376b6158ce0591361bf54432c3d05e94dabd3edbe3633f9130` |
| TLSH | `T125F3E60AAF611EF7E86BCC3701A87706248C751622E83BB67634D928F64B54F4AD3D74` |
| SSDEEP | `3072:i19vwg71MHRdYNT7baUPUHtV1dqL4nbH:CBpmdobaU0L1XH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_8f5b6ce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f5b6ce166f923af955e109e5218989c66145596fd3f329077fd0489d2299906"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 21:42:12"
  condition:
    hash.sha256(0, filesize) == "8f5b6ce166f923af955e109e5218989c66145596fd3f329077fd0489d2299906"
}
```

### Sample 86: `55fcc0e3e94fdebb`

| Field | Value |
|---|---|
| SHA-256 | `55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087` |
| Family label | `unknown` |
| File name | `55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087` |
| File type | `exe` |
| First seen | `2026-07-15 21:36:18` |
| Reporter | `johnk3r` |
| Tags | `banker, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dee7d75b1dc62df9e1ff1a30817bca97` |
| SHA-1 | `3149e98dc916582416aca83f664bcb4da8134835` |
| SHA-256 | `55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087` |
| SHA3-384 | `857ee9f3c61232ab1e4256c522e09694a6cf0bab0f49eea53b82cc8d27a4493861717511a84d66f32aa1f0d77368eb46` |
| TLSH | `T1F2274C36B244A73EE5BA0B354673A5F0547FB76265128C9E57F048C8CE672C02E3A64F` |
| SSDEEP | `12288:fs7r4veWmVinMygyRjoCY7jGjeC4W7nwUBmBvOlkI02ARWHTD/76HfFwFnbZVU4:fErUQViMygQohUYRgARuTD/QSnjF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_55fcc0e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087"
    family = "unknown"
    file_name = "55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087"
    file_type = "exe"
    first_seen = "2026-07-15 21:36:18"
  condition:
    hash.sha256(0, filesize) == "55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087"
}
```

### Sample 87: `e9b4ae70532e8cc0`

| Field | Value |
|---|---|
| SHA-256 | `e9b4ae70532e8cc060a90ea3c1f520b9355b94bd79ad3fcb363a4b5c0f6b2912` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 21:23:20` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `375673cdb5879e331d36455909e61dbc` |
| SHA-1 | `7d299966d385c607df9dacc792c0f81d24ebabf4` |
| SHA-256 | `e9b4ae70532e8cc060a90ea3c1f520b9355b94bd79ad3fcb363a4b5c0f6b2912` |
| SHA3-384 | `65c5c2d9dbe29fc6d8e683d739c0ff4bd8d70936482e58042ec2d055f581991d80e570a524ec286278e7f181848d6696` |
| IMPHASH | `5c1441a528b617db90f4965375b85533` |
| TLSH | `T11D567D2ABED578329BFED3839B92DCBD8517500052633C9F298E17C88445B68BF6325D` |
| SSDEEP | `12288:aKr+joNa7LL+VVNxQa+1hoPpbDiXJ4XLzcPvMwLTXEo:ahoNALLsN+ODiXJ4bYPvMwL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_e9b4ae70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b4ae70532e8cc060a90ea3c1f520b9355b94bd79ad3fcb363a4b5c0f6b2912"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 21:23:20"
  condition:
    hash.sha256(0, filesize) == "e9b4ae70532e8cc060a90ea3c1f520b9355b94bd79ad3fcb363a4b5c0f6b2912"
}
```

### Sample 88: `8e2a474f0babce15`

| Field | Value |
|---|---|
| SHA-256 | `8e2a474f0babce15d70670b29ea3c68fbe5c9c1f93b82232676ef0b617148b9f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-15 21:10:20` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5b230ca1b8059dd0ff34daa7e98fbc8` |
| SHA-1 | `3eb8a2d087d7b021fefebd792d5c24e989e5fb30` |
| SHA-256 | `8e2a474f0babce15d70670b29ea3c68fbe5c9c1f93b82232676ef0b617148b9f` |
| SHA3-384 | `5c0c7382f8612865c3b6123afd32c974e6bc079801488b92bd9a97896f15761a7bec3291cfff1a77b8807ac57f4a9088` |
| TLSH | `T1BF236C6516857C25EA99C4361C7E2F0CBDAD43E6320452DE7FCE3CF28C4AA9DA20971D` |
| SSDEEP | `768:W1csr0a1ldg9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:ihdcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_8e2a474f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e2a474f0babce15d70670b29ea3c68fbe5c9c1f93b82232676ef0b617148b9f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-15 21:10:20"
  condition:
    hash.sha256(0, filesize) == "8e2a474f0babce15d70670b29ea3c68fbe5c9c1f93b82232676ef0b617148b9f"
}
```

### Sample 89: `292b7cc2fcd484e4`

| Field | Value |
|---|---|
| SHA-256 | `292b7cc2fcd484e4536c593c70ed3cf46fb284976693412fa5d542bcf0be17fe` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-15 21:10:08` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3999ff2c63da5041db4d6a3a0ab1f2bf` |
| SHA-1 | `f692da03a15ef418ceb8d4a5858a177bc2053df3` |
| SHA-256 | `292b7cc2fcd484e4536c593c70ed3cf46fb284976693412fa5d542bcf0be17fe` |
| SHA3-384 | `b61f36be758d02cd7af745fc50de2655cdba1e44b4bb0da9da6da3c3038a00bd95a04cbd65915ee1aa36ba3dff822268` |
| IMPHASH | `edd9caae8565fbe43a73e0ad530f325e` |
| TLSH | `T19E825C0FB9424726C0E110B49676873BD979687233C854DBF7944AED0A686D2FC3355F` |
| SSDEEP | `192:LaISCngTBvqQ1jV6lXwIXZ5qh4le6qo/fKUSiu9zw+gj5tBOgbOBqmEdBTFWEo/Q:3IqQlV6lOh40uu9JgFtfUqXav8U9czF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_292b7cc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "292b7cc2fcd484e4536c593c70ed3cf46fb284976693412fa5d542bcf0be17fe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 21:10:08"
  condition:
    hash.sha256(0, filesize) == "292b7cc2fcd484e4536c593c70ed3cf46fb284976693412fa5d542bcf0be17fe"
}
```

### Sample 90: `c0b2ad27cbc88b9f`

| Field | Value |
|---|---|
| SHA-256 | `c0b2ad27cbc88b9f9879923572ef88eefc509d69170fba16589ff382da463933` |
| Family label | `unknown` |
| File name | `IT-Job-Interview-Preparation-Guide.pdf.lnk` |
| File type | `lnk` |
| First seen | `2026-07-15 20:59:07` |
| Reporter | `smica83` |
| Tags | `lnk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac38e6fa23c08368dbaff751d425476f` |
| SHA-1 | `c0b4bd4f55f2e34e75100436344252694c1e6c05` |
| SHA-256 | `c0b2ad27cbc88b9f9879923572ef88eefc509d69170fba16589ff382da463933` |
| SHA3-384 | `5852a81f233709f987ea6ae336ed3b92efd4bdac1a7d4eca3569f61ce974c9bf0d1cfab7e78593d268c7c97167f5f989` |
| TLSH | `T1CF418E003AED0324F3F79E7A94BA6312447BB896ED658F1D0091468C2826711E8B4F3B` |
| SSDEEP | `24:8pfJtnyURef5+pAwhhsN4qML4Cdd79ds5sq:8RAUAchpqMjdJ9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_c0b2ad27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0b2ad27cbc88b9f9879923572ef88eefc509d69170fba16589ff382da463933"
    family = "unknown"
    file_name = "IT-Job-Interview-Preparation-Guide.pdf.lnk"
    file_type = "lnk"
    first_seen = "2026-07-15 20:59:07"
  condition:
    hash.sha256(0, filesize) == "c0b2ad27cbc88b9f9879923572ef88eefc509d69170fba16589ff382da463933"
}
```

### Sample 91: `b83e8f14960e6b0a`

| Field | Value |
|---|---|
| SHA-256 | `b83e8f14960e6b0a1983e9fcdc484dac1523e7b32614198d9492e1d2922c67cc` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-15 20:58:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f04d1bd205c8bf5412b7e3710df09486` |
| SHA-1 | `57adf02c3edc9a1fe3f4e12b00c0218e2eb1b670` |
| SHA-256 | `b83e8f14960e6b0a1983e9fcdc484dac1523e7b32614198d9492e1d2922c67cc` |
| SHA3-384 | `8a2ad35b5d732808d77bec17eacb68e96060722595d91853d52e901f1dc9255cddc2d65863d7c3615e381f265f2b2cef` |
| TLSH | `T176F3E60AAF601EF7D8ABCC3705E87B0524CC755722E82BB57634D928B60A54F4AE3D74` |
| SSDEEP | `3072:c7O8OBaYeldlowFsg6DtyUjFcN3WbJ/JcVR9Gi4nbr:opn3ts/jFcNG9CVRCr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b83e8f14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83e8f14960e6b0a1983e9fcdc484dac1523e7b32614198d9492e1d2922c67cc"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-15 20:58:05"
  condition:
    hash.sha256(0, filesize) == "b83e8f14960e6b0a1983e9fcdc484dac1523e7b32614198d9492e1d2922c67cc"
}
```

### Sample 92: `1d01f60c35554655`

| Field | Value |
|---|---|
| SHA-256 | `1d01f60c355546557e038ded43fb27f0bfc6559bba9abedcb96a08556e311d2a` |
| Family label | `unknown` |
| File name | `Mohamad,SY.zip` |
| File type | `zip` |
| First seen | `2026-07-15 20:54:43` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07080b179d7019f5e0f783a269c3b5a2` |
| SHA-1 | `28116b6f9bef575d66e0c5be1beb7eebdb5ffd05` |
| SHA-256 | `1d01f60c355546557e038ded43fb27f0bfc6559bba9abedcb96a08556e311d2a` |
| SHA3-384 | `76558a158e4a9715383247105ae54070b1e0da7031efd8abf4cfc363e1a16917010b565f5957fc512347657ca5232704` |
| TLSH | `T11244003431EA1149F1F3EE717DE4B7D59E6BF272A936128D5881060D0A12E90FE21B3B` |
| SSDEEP | `96:ZA68yUn3ucUbAkkrMcyUn3+njPQxLMaQyUnwG+njZ2Nm0c0uLA:KfucIAkkI0cb0LMMGcdqmFLA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_1d01f60c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d01f60c355546557e038ded43fb27f0bfc6559bba9abedcb96a08556e311d2a"
    family = "unknown"
    file_name = "Mohamad,SY.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:54:43"
  condition:
    hash.sha256(0, filesize) == "1d01f60c355546557e038ded43fb27f0bfc6559bba9abedcb96a08556e311d2a"
}
```

### Sample 93: `95a849ce7c11590e`

| Field | Value |
|---|---|
| SHA-256 | `95a849ce7c11590e05cfdeaeb07a8bf232b4a8131f955fdce13189c3d17cbf14` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-15 20:51:57` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da94315c520bc9c2ae8a29ec959b4888` |
| SHA-1 | `93889df51b41e415bf4edd2032e7d7a66605e14f` |
| SHA-256 | `95a849ce7c11590e05cfdeaeb07a8bf232b4a8131f955fdce13189c3d17cbf14` |
| SHA3-384 | `a0c7f670ac3fa6fcb145b0f86ffd015733b15299c1770d7651fd685b1e4c6491a71aaa645b07c9dd198aa9e1d4e5b6ff` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T125E6335899E113EDEA73523DFCA19561F465B07A2F32C8CB4B5493B92E071E08D3D683` |
| SSDEEP | `393216:0g7RtRakVICqbfgc977cS3/BXMCHWUjXqcuI3/PGTAI:0glnakNiIs7ckZXMb8XHH/O7` |
| ICON-DHASH | `71f0e4d4e4e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_95a849ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a849ce7c11590e05cfdeaeb07a8bf232b4a8131f955fdce13189c3d17cbf14"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 20:51:57"
  condition:
    hash.sha256(0, filesize) == "95a849ce7c11590e05cfdeaeb07a8bf232b4a8131f955fdce13189c3d17cbf14"
}
```

### Sample 94: `842d49501e065060`

| Field | Value |
|---|---|
| SHA-256 | `842d49501e0650601458936ade269902a6182c5ba10e731be7f8a87b1d206818` |
| Family label | `unknown` |
| File name | `Complete bill - NAGA.zip` |
| File type | `zip` |
| First seen | `2026-07-15 20:49:47` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3d489c1423f52c23257b4f647039d29` |
| SHA-1 | `2e06c3db2d476bb62f8f423f56de567efd86816b` |
| SHA-256 | `842d49501e0650601458936ade269902a6182c5ba10e731be7f8a87b1d206818` |
| SHA3-384 | `b551987fabd7a9965bff5244eabf80177a35122c2e735bf89f1e006b456b3b57eef8836469fbd9e10f3e1893a1582055` |
| TLSH | `T1FE21C61E02603C13CA1D20F4093BA8AC6069C3E172B8275EC95D6F85CD052017A8C383` |
| SSDEEP | `24:91uzwgg37zazfmLws293Bh5oZvVJBqvRqzYIlhHE0oI4bObKLg/tl:9kz1gDLwf9xhKZjgvRFwhjo1Kqg/X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_842d4950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "842d49501e0650601458936ade269902a6182c5ba10e731be7f8a87b1d206818"
    family = "unknown"
    file_name = "Complete bill - NAGA.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:49:47"
  condition:
    hash.sha256(0, filesize) == "842d49501e0650601458936ade269902a6182c5ba10e731be7f8a87b1d206818"
}
```

### Sample 95: `2d5dfbf29d474f2f`

| Field | Value |
|---|---|
| SHA-256 | `2d5dfbf29d474f2fa504a9e5d625169ab3b09ecec719d5b5ecb0cdd893d2080f` |
| Family label | `unknown` |
| File name | `Dohovir.zip` |
| File type | `zip` |
| First seen | `2026-07-15 20:45:45` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c8df8248b248f2be53b525fd695750b` |
| SHA-1 | `ce4cc6d321c9ed471a1cf792c850e6f8796160ea` |
| SHA-256 | `2d5dfbf29d474f2fa504a9e5d625169ab3b09ecec719d5b5ecb0cdd893d2080f` |
| SHA3-384 | `2e581d4eec1c0ec1895fb09191df53ab5f78319e28aa09d4d53b3af1a7039d3c47189d9fb3157fb657e7d68f4045c487` |
| TLSH | `T1FD83DF3431E90118E1F3FE716DF477D6AD5BB9B7EAB11688594102060D22B80FE26B3B` |
| SSDEEP | `96:smLHyO+nj58g2VcL1ynH+njlCpCNys+njPkSS19QXkR5:BHcy06HcRkkcIvXvv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_2d5dfbf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d5dfbf29d474f2fa504a9e5d625169ab3b09ecec719d5b5ecb0cdd893d2080f"
    family = "unknown"
    file_name = "Dohovir.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:45:45"
  condition:
    hash.sha256(0, filesize) == "2d5dfbf29d474f2fa504a9e5d625169ab3b09ecec719d5b5ecb0cdd893d2080f"
}
```

### Sample 96: `7f6ec55f45b3ad00`

| Field | Value |
|---|---|
| SHA-256 | `7f6ec55f45b3ad0019453151db766882a84d714e2db3a6f607a1e97ed4ce977e` |
| Family label | `unknown` |
| File name | `IMG-145388.zip` |
| File type | `zip` |
| First seen | `2026-07-15 20:42:13` |
| Reporter | `smica83` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ee4452ee9b141af4e624180ed1628c9` |
| SHA-1 | `0990aaeecb290eceea4b34ef3dde70a786728ca7` |
| SHA-256 | `7f6ec55f45b3ad0019453151db766882a84d714e2db3a6f607a1e97ed4ce977e` |
| SHA3-384 | `a686a9765d638f76ecab22488d0d1c0c53d1e40c82158dfdcf8f57b5c66dbabe00bee9f250548eca57cd64511c9b1ba1` |
| TLSH | `T13341FAE9145DC0D0C8F5C4BAE5151A0F1D0E5A37FB9F152FD0287C32B87674D2C5A554` |
| SSDEEP | `48:9kDrk1F8OU8BKCfTW4NaaGO2BM3rUuUo1+:MF88aCuTs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_7f6ec55f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f6ec55f45b3ad0019453151db766882a84d714e2db3a6f607a1e97ed4ce977e"
    family = "unknown"
    file_name = "IMG-145388.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:42:13"
  condition:
    hash.sha256(0, filesize) == "7f6ec55f45b3ad0019453151db766882a84d714e2db3a6f607a1e97ed4ce977e"
}
```

### Sample 97: `12b920865bc8bd9b`

| Field | Value |
|---|---|
| SHA-256 | `12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2` |
| Family label | `ValleyRAT` |
| File name | `Mai Giang's passport.exe` |
| File type | `exe` |
| First seen | `2026-07-15 20:38:02` |
| Reporter | `smica83` |
| Tags | `exe, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84b890deb66302932195d9a28965f9dd` |
| SHA-1 | `35360c9261aa285094e7c75a393c2a6966cd34c8` |
| SHA-256 | `12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2` |
| SHA3-384 | `f7d6027172447645e0fb30137587a7cfa8587aea9b3f27fc409a3022d235e9e7ee027ae80f17b30b38463fd09c1a1381` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T1D816023BF28B653EE06A1A367A72E110583B7A60A4164C1796ECF48CCF255711E3F787` |
| SSDEEP | `98304:R5OKzgrwE36tsCAp3TuU6uisGkX/gL7kBO5WIw0XDR6Pkt0:LQwdtsC6/5isGkXI3kG9t6Pkt0` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_097_12b92086
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2"
    family = "ValleyRAT"
    file_name = "Mai Giang's passport.exe"
    file_type = "exe"
    first_seen = "2026-07-15 20:38:02"
  condition:
    hash.sha256(0, filesize) == "12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2"
}
```

### Sample 98: `a80cb6452a37a6ba`

| Field | Value |
|---|---|
| SHA-256 | `a80cb6452a37a6baf1c86bd83739acea385b4639301a68a96db8e68b3965bc3c` |
| Family label | `unknown` |
| File name | `学术浏览器安装.exe` |
| File type | `exe` |
| First seen | `2026-07-15 20:35:17` |
| Reporter | `smica83` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6035fa62a66e88cc93efab92acd5a116` |
| SHA-1 | `c88492ba75b0f4f74f765f0dcebffb59901ae673` |
| SHA-256 | `a80cb6452a37a6baf1c86bd83739acea385b4639301a68a96db8e68b3965bc3c` |
| SHA3-384 | `4d877db83ca3843cc9d3e7edd72869dc80412226dc71d124afbd4b7319ed2f63bb139ab2188be27da78bc59a6d5a2196` |
| IMPHASH | `474be6c9d2442bf16c35218c835ccdc3` |
| TLSH | `T1F99393E57AD84C9AFA14423C41EAD332253DB9E0D7534B43263076321F12F917ADB66E` |
| SSDEEP | `1536:2tc7dZ4m+V8BvdmMYDo85Wkb9pkIYoL9NXbe:+iH4m+h5Wokzc9NXa` |
| ICON-DHASH | `f0cc8e17178eccf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_a80cb645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a80cb6452a37a6baf1c86bd83739acea385b4639301a68a96db8e68b3965bc3c"
    family = "unknown"
    file_name = "学术浏览器安装.exe"
    file_type = "exe"
    first_seen = "2026-07-15 20:35:17"
  condition:
    hash.sha256(0, filesize) == "a80cb6452a37a6baf1c86bd83739acea385b4639301a68a96db8e68b3965bc3c"
}
```

### Sample 99: `451341ba176d9403`

| Field | Value |
|---|---|
| SHA-256 | `451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15` |
| Family label | `Prometei` |
| File name | `451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15` |
| File type | `elf` |
| First seen | `2026-07-15 20:29:56` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d623118a8b434ca360574790c4bfb83` |
| SHA-1 | `87fa526b1f2a70df7b337694b3be3c7e4ef4c18c` |
| SHA-256 | `451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15` |
| SHA3-384 | `2645e80297a18815a3c970870fd018960852f46ab63b2c1f16e52382fce3b0770ffe80207fd8920e4cf6960e8a051d5b` |
| TLSH | `T1349423FBD6C0430FCF16117C277A6E22D2C6553539AD6AB0C62CF8AE0E792075944EA7` |
| SSDEEP | `12288:4h/taqLkdfH8ytYiflIw0BEmWVeygFurhCg:4YdkVLwKvyaJg` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_099_451341ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15"
    family = "Prometei"
    file_name = "451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15"
    file_type = "elf"
    first_seen = "2026-07-15 20:29:56"
  condition:
    hash.sha256(0, filesize) == "451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15"
}
```

### Sample 100: `7812d8f5ad47a32e`

| Field | Value |
|---|---|
| SHA-256 | `7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2` |
| Family label | `Prometei` |
| File name | `7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2` |
| File type | `exe` |
| First seen | `2026-07-15 20:29:16` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3049d05841052aff1ebd8abfab4dcc6c` |
| SHA-1 | `3bfbb296c6c43ed5a8d00e4c8bfe8fdb8c3e8324` |
| SHA-256 | `7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2` |
| SHA3-384 | `31a72889a70c925ad54bd264bf7731919b9213865a4d623fd8588c0f11906a0fd3c0fd3945db07dd91327a27dd201da1` |
| IMPHASH | `551920a564f0da077e7c568c1940defb` |
| TLSH | `T15774C07775B8F15EC88517328F62C7C293993F908993806F7EB4530F29278A91A35B72` |
| SSDEEP | `6144:9RzeTJQJfChxxTnECpq9XkCnNNCoo/iSq9opz5Pv5Pi12dwyz:9JZJfChLjE4q9X7HGqZ9opzvi1yz` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_100_7812d8f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2"
    family = "Prometei"
    file_name = "7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2"
    file_type = "exe"
    first_seen = "2026-07-15 20:29:16"
  condition:
    hash.sha256(0, filesize) == "7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2"
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
 * Generated: 2026-07-16T03:42:38.791545+00:00
 */

rule MalwareBazaar_unknown_001_72103881
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "721038816079e39f95b41461f20ccbf77af20bd22b8a6c71da228bdfa9675413"
    family = "unknown"
    file_name = "com.messaging.textmessage.messages.sms_29.0.xapk"
    file_type = "xapk"
    first_seen = "2026-07-16 03:08:31"
  condition:
    hash.sha256(0, filesize) == "721038816079e39f95b41461f20ccbf77af20bd22b8a6c71da228bdfa9675413"
}

rule MalwareBazaar_unknown_002_58fa325d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58fa325d6a5619e1fba43d6bd8a913632521284306631c8fb7bce7ba8dda3393"
    family = "unknown"
    file_name = "Font+Keyboard_1.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-16 03:07:57"
  condition:
    hash.sha256(0, filesize) == "58fa325d6a5619e1fba43d6bd8a913632521284306631c8fb7bce7ba8dda3393"
}

rule MalwareBazaar_unknown_003_c3c9b905
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3c9b9054a3bab92bbd7a0a64ad0b3dccb1908fc9d16cc4e491b1397d8e49ae6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 02:55:49"
  condition:
    hash.sha256(0, filesize) == "c3c9b9054a3bab92bbd7a0a64ad0b3dccb1908fc9d16cc4e491b1397d8e49ae6"
}

rule MalwareBazaar_unknown_004_cdecd2bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdecd2bc19737113c5c2fa88f9a160127e5dcded32ca07067917cbd138f9a7bf"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 02:51:58"
  condition:
    hash.sha256(0, filesize) == "cdecd2bc19737113c5c2fa88f9a160127e5dcded32ca07067917cbd138f9a7bf"
}

rule MalwareBazaar_unknown_005_fddee8b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e"
    family = "unknown"
    file_name = "fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e"
    file_type = "elf"
    first_seen = "2026-07-16 02:41:07"
  condition:
    hash.sha256(0, filesize) == "fddee8b3af76449d51c9d3dd5974055b2402a91d4fe3641b415cd4a2140ad57e"
}

rule MalwareBazaar_AsyncRAT_006_bc2d5313
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc2d5313943d2e4a33cdb0a4708c6ec94c60f26ae402626caf970e283d0ad9d4"
    family = "AsyncRAT"
    file_name = "Purchase Order.js"
    file_type = "js"
    first_seen = "2026-07-16 02:25:06"
  condition:
    hash.sha256(0, filesize) == "bc2d5313943d2e4a33cdb0a4708c6ec94c60f26ae402626caf970e283d0ad9d4"
}

rule MalwareBazaar_unknown_007_e82f6ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e82f6ae11ddfaf06b82738aa2f499d4cb8476ec7914efd9aa16bdf520ef90539"
    family = "unknown"
    file_name = "Realtime Protection.exe"
    file_type = "exe"
    first_seen = "2026-07-16 02:23:46"
  condition:
    hash.sha256(0, filesize) == "e82f6ae11ddfaf06b82738aa2f499d4cb8476ec7914efd9aa16bdf520ef90539"
}

rule MalwareBazaar_unknown_008_e07e5358
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e07e535830825db953ee7b0231139a4eebd8333ac7e36383a196abd4038f757e"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-16 02:16:41"
  condition:
    hash.sha256(0, filesize) == "e07e535830825db953ee7b0231139a4eebd8333ac7e36383a196abd4038f757e"
}

rule MalwareBazaar_AsyncRAT_009_abca9cfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "abca9cfafbc5165e73c2bb0ef24815c23a5f865a4c6a4eca61b2c17ec80c9ca7"
    family = "AsyncRAT"
    file_name = "VIN88APP.exe"
    file_type = "exe"
    first_seen = "2026-07-16 02:12:19"
  condition:
    hash.sha256(0, filesize) == "abca9cfafbc5165e73c2bb0ef24815c23a5f865a4c6a4eca61b2c17ec80c9ca7"
}

rule MalwareBazaar_Vidar_010_7bce64f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bce64f71e61af03a0cf9efc56e81c4113e6541f252c368603fa43974523081b"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 02:09:28"
  condition:
    hash.sha256(0, filesize) == "7bce64f71e61af03a0cf9efc56e81c4113e6541f252c368603fa43974523081b"
}

rule MalwareBazaar_unknown_011_f0d3c665
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0d3c665335eda74c52e36348ca978fd021a08c39836029adfa68adf5a3e32f4"
    family = "unknown"
    file_name = "204_panel_tools.exe"
    file_type = "exe"
    first_seen = "2026-07-16 02:03:03"
  condition:
    hash.sha256(0, filesize) == "f0d3c665335eda74c52e36348ca978fd021a08c39836029adfa68adf5a3e32f4"
}

rule MalwareBazaar_unknown_012_52a1f9ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52a1f9aebd6d8f42ed0fa9a36c8c0cea56dccaa7ab941a62c7d70be02479f6d9"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 01:51:57"
  condition:
    hash.sha256(0, filesize) == "52a1f9aebd6d8f42ed0fa9a36c8c0cea56dccaa7ab941a62c7d70be02479f6d9"
}

rule MalwareBazaar_unknown_013_4a6d1dfa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a6d1dfa22c10d10030b7d7063abdd31e528c1a152568febcff3f6a6a140fdff"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-16 01:35:30"
  condition:
    hash.sha256(0, filesize) == "4a6d1dfa22c10d10030b7d7063abdd31e528c1a152568febcff3f6a6a140fdff"
}

rule MalwareBazaar_Mirai_014_42d85cf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42d85cf2179b3a10e2ac9dc572bac3fa540b3aea4aa87898740f7b0caeb1809b"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-07-16 01:17:32"
  condition:
    hash.sha256(0, filesize) == "42d85cf2179b3a10e2ac9dc572bac3fa540b3aea4aa87898740f7b0caeb1809b"
}

rule MalwareBazaar_unknown_015_c47a9ca2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c47a9ca2fce589911fb281bd7d94c53d2697581994031ddd6d62a01a354dcc92"
    family = "unknown"
    file_name = "gothgirls3.exe"
    file_type = "exe"
    first_seen = "2026-07-16 01:17:21"
  condition:
    hash.sha256(0, filesize) == "c47a9ca2fce589911fb281bd7d94c53d2697581994031ddd6d62a01a354dcc92"
}

rule MalwareBazaar_unknown_016_512adcae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "512adcaea143fa04941516599aed5e2cdd97d374673bc645d585e3ea63183b8e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 01:12:05"
  condition:
    hash.sha256(0, filesize) == "512adcaea143fa04941516599aed5e2cdd97d374673bc645d585e3ea63183b8e"
}

rule MalwareBazaar_Mirai_017_99cfa4eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99cfa4eb1fc878b61eb532ecaea600038f3e789d31625fa413f669ff1ee5b22b"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-16 01:09:16"
  condition:
    hash.sha256(0, filesize) == "99cfa4eb1fc878b61eb532ecaea600038f3e789d31625fa413f669ff1ee5b22b"
}

rule MalwareBazaar_unknown_018_8c0f9343
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c0f9343f5eeb0393a7d633cbb5fb819d531e35225496815cff8462e90db864b"
    family = "unknown"
    file_name = "vartmp_1c18d769_085aa012"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:58"
  condition:
    hash.sha256(0, filesize) == "8c0f9343f5eeb0393a7d633cbb5fb819d531e35225496815cff8462e90db864b"
}

rule MalwareBazaar_unknown_019_8f225e59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f225e59f3b892c7ed440db4c913491f825ccd64792cb759b55563c1b1310ece"
    family = "unknown"
    file_name = "kuak"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:56"
  condition:
    hash.sha256(0, filesize) == "8f225e59f3b892c7ed440db4c913491f825ccd64792cb759b55563c1b1310ece"
}

rule MalwareBazaar_Mirai_020_41e36730
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41e3673069a4c07ee11f566d6bba1523255b6d9cc0fceabe42da04d7f0d944cb"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:53"
  condition:
    hash.sha256(0, filesize) == "41e3673069a4c07ee11f566d6bba1523255b6d9cc0fceabe42da04d7f0d944cb"
}

rule MalwareBazaar_unknown_021_ffe04bc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffe04bc05a56f78b1273876cf17ded8df1aa3da5a15deb17dce99a3e206eb705"
    family = "unknown"
    file_name = "diicot"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:51"
  condition:
    hash.sha256(0, filesize) == "ffe04bc05a56f78b1273876cf17ded8df1aa3da5a15deb17dce99a3e206eb705"
}

rule MalwareBazaar_unknown_022_07b9702b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07b9702bc859227a658903d1b4cf85d9daed6e0c24e670332c83020cc0a37166"
    family = "unknown"
    file_name = "IQITtfbr.packed"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:45"
  condition:
    hash.sha256(0, filesize) == "07b9702bc859227a658903d1b4cf85d9daed6e0c24e670332c83020cc0a37166"
}

rule MalwareBazaar_Mirai_023_0e0e3b41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e0e3b4128eea1f7c9cac8abd8097b6cd9fbb2ecc91979cc985674f6c90d9139"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-07-16 01:03:24"
  condition:
    hash.sha256(0, filesize) == "0e0e3b4128eea1f7c9cac8abd8097b6cd9fbb2ecc91979cc985674f6c90d9139"
}

rule MalwareBazaar_unknown_024_6b2ccc31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348"
    family = "unknown"
    file_name = "6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348"
    file_type = "elf"
    first_seen = "2026-07-16 01:00:31"
  condition:
    hash.sha256(0, filesize) == "6b2ccc31a86aba2dc917bda60e4baaaaa918292e4c322b3af08c6f4e99604348"
}

rule MalwareBazaar_GuLoader_025_cb532528
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb5325281c5ecc2983de4e3d349cfa6fc272d3a9920aef743352386405ea280f"
    family = "GuLoader"
    file_name = "rFACTURAJUNIO.exe"
    file_type = "exe"
    first_seen = "2026-07-16 01:00:19"
  condition:
    hash.sha256(0, filesize) == "cb5325281c5ecc2983de4e3d349cfa6fc272d3a9920aef743352386405ea280f"
}

rule MalwareBazaar_unknown_026_80bd353b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80bd353bb391fcabeeec55d17be1dcb5a1d571f64062b4da6f844ef87e526c28"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-16 01:00:16"
  condition:
    hash.sha256(0, filesize) == "80bd353bb391fcabeeec55d17be1dcb5a1d571f64062b4da6f844ef87e526c28"
}

rule MalwareBazaar_GuLoader_027_66a1be39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66a1be3919f3f23710ebc6d58daf04e5abd52490f4a95993cea670cfc2314809"
    family = "GuLoader"
    file_name = "rMODELO1112T2026.exe"
    file_type = "exe"
    first_seen = "2026-07-16 01:00:08"
  condition:
    hash.sha256(0, filesize) == "66a1be3919f3f23710ebc6d58daf04e5abd52490f4a95993cea670cfc2314809"
}

rule MalwareBazaar_Vidar_028_5421de84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5421de84ac52626640c8004a94732e2abadace7cb828f2a499901f59df259bb0"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-16 00:55:43"
  condition:
    hash.sha256(0, filesize) == "5421de84ac52626640c8004a94732e2abadace7cb828f2a499901f59df259bb0"
}

rule MalwareBazaar_unknown_029_0699369e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0699369e414a65f7ba516fe5ed9c7ef3aec8abdae4409331f209c6a27168c157"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-16 00:51:58"
  condition:
    hash.sha256(0, filesize) == "0699369e414a65f7ba516fe5ed9c7ef3aec8abdae4409331f209c6a27168c157"
}

rule MalwareBazaar_unknown_030_8277d9cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8277d9cdcdd6d214ea747c4e3c36f2ee26bbef746273de07a7836335685f8ba8"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-16 00:51:17"
  condition:
    hash.sha256(0, filesize) == "8277d9cdcdd6d214ea747c4e3c36f2ee26bbef746273de07a7836335685f8ba8"
}

rule MalwareBazaar_Mirai_031_98170b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98170b42f23c069e62fd90e946a5047765c030f608f2cb41f22ff5a19c9d7fa8"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-07-16 00:36:34"
  condition:
    hash.sha256(0, filesize) == "98170b42f23c069e62fd90e946a5047765c030f608f2cb41f22ff5a19c9d7fa8"
}

rule MalwareBazaar_Mirai_032_ea5ba796
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea5ba796713da55899f9cc3dc8daae7b4425f2a73058b9abff60e9922af60924"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-16 00:35:16"
  condition:
    hash.sha256(0, filesize) == "ea5ba796713da55899f9cc3dc8daae7b4425f2a73058b9abff60e9922af60924"
}

rule MalwareBazaar_Mirai_033_c19a9cce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c19a9ccea95a758dccbd692cbd469e9a2d373fe6e63cbf4009d8c76fd073e288"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-16 00:29:46"
  condition:
    hash.sha256(0, filesize) == "c19a9ccea95a758dccbd692cbd469e9a2d373fe6e63cbf4009d8c76fd073e288"
}

rule MalwareBazaar_Mirai_034_fc6a37d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc6a37d766e2c13eb68da8efa734978ae6dead2a8ec536b99793c422b1caa836"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-07-16 00:29:23"
  condition:
    hash.sha256(0, filesize) == "fc6a37d766e2c13eb68da8efa734978ae6dead2a8ec536b99793c422b1caa836"
}

rule MalwareBazaar_Mirai_035_780e5644
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "780e56445f2e5521791c8802b93afa0c8efa4b44d528b1a18e8ed0a1c5e2858e"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 00:24:44"
  condition:
    hash.sha256(0, filesize) == "780e56445f2e5521791c8802b93afa0c8efa4b44d528b1a18e8ed0a1c5e2858e"
}

rule MalwareBazaar_Mirai_036_5060058f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5060058f19b2271985ffc751dfe35b9b107f051a368de01358e6be85335ab1ed"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-07-16 00:24:19"
  condition:
    hash.sha256(0, filesize) == "5060058f19b2271985ffc751dfe35b9b107f051a368de01358e6be85335ab1ed"
}

rule MalwareBazaar_unknown_037_6f1daa32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6f1daa323ecda925f11f3eea0dc4839057dfff2317f5fa1bfc6176c62b951deb"
    family = "unknown"
    file_name = "sh"
    file_type = "sh"
    first_seen = "2026-07-16 00:24:17"
  condition:
    hash.sha256(0, filesize) == "6f1daa323ecda925f11f3eea0dc4839057dfff2317f5fa1bfc6176c62b951deb"
}

rule MalwareBazaar_Mirai_038_dc28e187
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc28e187522f7376ae4414ac017bb317f88545b602c657d5c7c4eb028248dda0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-16 00:14:34"
  condition:
    hash.sha256(0, filesize) == "dc28e187522f7376ae4414ac017bb317f88545b602c657d5c7c4eb028248dda0"
}

rule MalwareBazaar_Mirai_039_473f4b5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "473f4b5e2d22a4fb4790813e18073f96c1a2f450d51259ab463b924e7f40244c"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:13:46"
  condition:
    hash.sha256(0, filesize) == "473f4b5e2d22a4fb4790813e18073f96c1a2f450d51259ab463b924e7f40244c"
}

rule MalwareBazaar_Mirai_040_615dffa8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "615dffa88641da5740583203114e92507d18b96ca510b9533fb154209b036988"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:13:16"
  condition:
    hash.sha256(0, filesize) == "615dffa88641da5740583203114e92507d18b96ca510b9533fb154209b036988"
}

rule MalwareBazaar_Mirai_041_20d9bf47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20d9bf470d993f176a6a13ae2794bded557e1a4fd1ed50b2bb02838cc6f43189"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:10:15"
  condition:
    hash.sha256(0, filesize) == "20d9bf470d993f176a6a13ae2794bded557e1a4fd1ed50b2bb02838cc6f43189"
}

rule MalwareBazaar_Mirai_042_fab7ef5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fab7ef5a1a6c3f5aafa3e6f4bb1fd2907275cd440159ddb6f29e607c54869e0d"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-16 00:02:29"
  condition:
    hash.sha256(0, filesize) == "fab7ef5a1a6c3f5aafa3e6f4bb1fd2907275cd440159ddb6f29e607c54869e0d"
}

rule MalwareBazaar_unknown_043_0af1e182
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0af1e1824def0944d69e44c3ca76bc52163ee20dda7e978ead06134f550fbdc5"
    family = "unknown"
    file_name = "sh"
    file_type = "sh"
    first_seen = "2026-07-16 00:02:27"
  condition:
    hash.sha256(0, filesize) == "0af1e1824def0944d69e44c3ca76bc52163ee20dda7e978ead06134f550fbdc5"
}

rule MalwareBazaar_Mirai_044_efcf0e27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efcf0e27b47bfd418d6ea526fbf7c2a7d4a0edaa6523b99b93f04e42a91ec9d7"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-16 00:00:46"
  condition:
    hash.sha256(0, filesize) == "efcf0e27b47bfd418d6ea526fbf7c2a7d4a0edaa6523b99b93f04e42a91ec9d7"
}

rule MalwareBazaar_Mirai_045_2549da80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2549da80202be54685dbd427543a75a227e4f59d5c4ceb2c4c67d179e03b76a8"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-15 23:59:21"
  condition:
    hash.sha256(0, filesize) == "2549da80202be54685dbd427543a75a227e4f59d5c4ceb2c4c67d179e03b76a8"
}

rule MalwareBazaar_unknown_046_73d869ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73d869ad60ac8af7f82c200488d764f246b6b34426198d4e7d06c72be0c29930"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-15 23:53:10"
  condition:
    hash.sha256(0, filesize) == "73d869ad60ac8af7f82c200488d764f246b6b34426198d4e7d06c72be0c29930"
}

rule MalwareBazaar_unknown_047_313c8943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "313c89438182321b239cc6bef5a7b3b0bdfb0e648e1c4fd3073e8bd02343c867"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 23:51:57"
  condition:
    hash.sha256(0, filesize) == "313c89438182321b239cc6bef5a7b3b0bdfb0e648e1c4fd3073e8bd02343c867"
}

rule MalwareBazaar_Mirai_048_f5706e76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5706e76823530a1278626c227ffe53f95df9e63e420f9b3f518ad8f696a8abf"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:50:27"
  condition:
    hash.sha256(0, filesize) == "f5706e76823530a1278626c227ffe53f95df9e63e420f9b3f518ad8f696a8abf"
}

rule MalwareBazaar_Mirai_049_2af6bc32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2af6bc32acb2fe107f11927e849a1343794cc031ac1455fa98f90620ccdd3357"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 23:50:26"
  condition:
    hash.sha256(0, filesize) == "2af6bc32acb2fe107f11927e849a1343794cc031ac1455fa98f90620ccdd3357"
}

rule MalwareBazaar_Mirai_050_c6793207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c679320728557b65b99b8c25843cff3db038951383abe4b74dfc32aa968e2c4c"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 23:49:50"
  condition:
    hash.sha256(0, filesize) == "c679320728557b65b99b8c25843cff3db038951383abe4b74dfc32aa968e2c4c"
}

rule MalwareBazaar_Mirai_051_aab106ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aab106cab1b75132ce6ac9cb3ab4d3f23a4814186a862858905c6b96ec4f1105"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 23:49:17"
  condition:
    hash.sha256(0, filesize) == "aab106cab1b75132ce6ac9cb3ab4d3f23a4814186a862858905c6b96ec4f1105"
}

rule MalwareBazaar_Mirai_052_149d241e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "149d241e0902e6b10a97e3890b10ccacc99d9a481304373ea52da2ce29ab9947"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:49:16"
  condition:
    hash.sha256(0, filesize) == "149d241e0902e6b10a97e3890b10ccacc99d9a481304373ea52da2ce29ab9947"
}

rule MalwareBazaar_unknown_053_4337290c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4337290c0f38bd812f247315283f3981301b4e9687b9301a5b6ebc640e5c777a"
    family = "unknown"
    file_name = "Payment Invoices and bank documents.exe"
    file_type = "exe"
    first_seen = "2026-07-15 23:49:01"
  condition:
    hash.sha256(0, filesize) == "4337290c0f38bd812f247315283f3981301b4e9687b9301a5b6ebc640e5c777a"
}

rule MalwareBazaar_Mirai_054_a1522fcc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1522fcc06148485082b82f1e774c286ee98139150a948be54eec8f5f20e3945"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:48:45"
  condition:
    hash.sha256(0, filesize) == "a1522fcc06148485082b82f1e774c286ee98139150a948be54eec8f5f20e3945"
}

rule MalwareBazaar_Mirai_055_d4a4f43c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4a4f43c6efee41dbd3d761503bc5cc5ab7cf1c20a6065971edefe42408fc361"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:48:09"
  condition:
    hash.sha256(0, filesize) == "d4a4f43c6efee41dbd3d761503bc5cc5ab7cf1c20a6065971edefe42408fc361"
}

rule MalwareBazaar_Mirai_056_5b3958cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b3958cd6dbbb9e2195de1e88988b7a5ce289bd84a122020ba9c62088bc221a2"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-15 23:46:40"
  condition:
    hash.sha256(0, filesize) == "5b3958cd6dbbb9e2195de1e88988b7a5ce289bd84a122020ba9c62088bc221a2"
}

rule MalwareBazaar_Mirai_057_72106225
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7210622578575fd6bb66077e752fef26aea3dfc790499d35ffb8a2aa11c6cdf5"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 23:39:51"
  condition:
    hash.sha256(0, filesize) == "7210622578575fd6bb66077e752fef26aea3dfc790499d35ffb8a2aa11c6cdf5"
}

rule MalwareBazaar_Mirai_058_6b697aac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b697aac4b61f7afa4bbaa6702ccb5950816fa2d78cbbb0824fd313233ba0dc8"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 23:39:28"
  condition:
    hash.sha256(0, filesize) == "6b697aac4b61f7afa4bbaa6702ccb5950816fa2d78cbbb0824fd313233ba0dc8"
}

rule MalwareBazaar_Mirai_059_b9c73d31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9c73d31536c5a29aa261ebaff72de025440f30a6168c428e6de28a7bbc6ad3f"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:38:46"
  condition:
    hash.sha256(0, filesize) == "b9c73d31536c5a29aa261ebaff72de025440f30a6168c428e6de28a7bbc6ad3f"
}

rule MalwareBazaar_Mirai_060_4a55129d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a55129d6c014c2b57190dbf17324c36ed3d929b09998d86c6200c8ac75609c4"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:38:23"
  condition:
    hash.sha256(0, filesize) == "4a55129d6c014c2b57190dbf17324c36ed3d929b09998d86c6200c8ac75609c4"
}

rule MalwareBazaar_Vidar_061_a8f59963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8f59963739a04b38f85872f37de5c6eda7dc00c4adc46002f0a3f6fecb2233e"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 23:30:46"
  condition:
    hash.sha256(0, filesize) == "a8f59963739a04b38f85872f37de5c6eda7dc00c4adc46002f0a3f6fecb2233e"
}

rule MalwareBazaar_Mirai_062_9c3d18da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:22"
  condition:
    hash.sha256(0, filesize) == "9c3d18dac0e9364bbb11423f3f1c1f58535d1ede52751b078a1c5e73b653c4bb"
}

rule MalwareBazaar_Mirai_063_72b352a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72b352a3c0a6763a425912736b369697387aa12f25f297d078511480e8b2306b"
    family = "Mirai"
    file_name = "debug.dbg"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:20"
  condition:
    hash.sha256(0, filesize) == "72b352a3c0a6763a425912736b369697387aa12f25f297d078511480e8b2306b"
}

rule MalwareBazaar_Mirai_064_b76e9c4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b76e9c4be46dd696a998d2eef5a0a5228c713d7b659358ef08cc647ab98845db"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:19"
  condition:
    hash.sha256(0, filesize) == "b76e9c4be46dd696a998d2eef5a0a5228c713d7b659358ef08cc647ab98845db"
}

rule MalwareBazaar_Mirai_065_717956c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "717956c13e9a4ae5e18a66dad4b4aba9e20824382663344a3352e1fd1f9c9663"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:18"
  condition:
    hash.sha256(0, filesize) == "717956c13e9a4ae5e18a66dad4b4aba9e20824382663344a3352e1fd1f9c9663"
}

rule MalwareBazaar_Mirai_066_0dde7f3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:17"
  condition:
    hash.sha256(0, filesize) == "0dde7f3ddfe8924aa019bc2f8204aa6205aa8c04fec5b7c3284e6424b0aab204"
}

rule MalwareBazaar_Mirai_067_1fe41e8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:16"
  condition:
    hash.sha256(0, filesize) == "1fe41e8a4f1dfe024f2b184c5108f38af1199fbce4875fc979de4451681af566"
}

rule MalwareBazaar_Mirai_068_30021ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30021ebe609908ad9b5a42a38b9be1e83225a86f2b7c15b77dc7ec91e016dff2"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:15"
  condition:
    hash.sha256(0, filesize) == "30021ebe609908ad9b5a42a38b9be1e83225a86f2b7c15b77dc7ec91e016dff2"
}

rule MalwareBazaar_Mirai_069_fdefb11a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:13"
  condition:
    hash.sha256(0, filesize) == "fdefb11a39dd231810addbb1e5d210bf7c1fc6ea52466614abbc2e15c7b3fdae"
}

rule MalwareBazaar_Mirai_070_3c522831
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c5228311e4366042fc1fef9f9e960fa94b30267052cf7818d039ce4d256c15e"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-15 23:28:12"
  condition:
    hash.sha256(0, filesize) == "3c5228311e4366042fc1fef9f9e960fa94b30267052cf7818d039ce4d256c15e"
}

rule MalwareBazaar_unknown_071_9fe5f016
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fe5f01662010999236f92b351ef36a759a58421fa4bca630c17e35e8cf8e0d9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 23:27:16"
  condition:
    hash.sha256(0, filesize) == "9fe5f01662010999236f92b351ef36a759a58421fa4bca630c17e35e8cf8e0d9"
}

rule MalwareBazaar_unknown_072_02e6fbf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5"
    family = "unknown"
    file_name = "stage5_ldb.bin"
    file_type = "unknown"
    first_seen = "2026-07-15 22:52:17"
  condition:
    hash.sha256(0, filesize) == "02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5"
}

rule MalwareBazaar_unknown_073_b34aa84e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1"
    family = "unknown"
    file_name = "stage5_brow_final.py"
    file_type = "unknown"
    first_seen = "2026-07-15 22:52:11"
  condition:
    hash.sha256(0, filesize) == "b34aa84e8b4ad57d773fab6cbd7c40cda65f5f17c566cbd726ce3edcd04255b1"
}

rule MalwareBazaar_unknown_074_cd3b606d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6"
    family = "unknown"
    file_name = "stage5_payload_final.py"
    file_type = "unknown"
    first_seen = "2026-07-15 22:52:05"
  condition:
    hash.sha256(0, filesize) == "cd3b606d31c9d3c2ee972916f8de9a403caf00f00698fd6b9acece6ff30647c6"
}

rule MalwareBazaar_unknown_075_683a1607
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630"
    family = "unknown"
    file_name = "stage3_load.js"
    file_type = "js"
    first_seen = "2026-07-15 22:51:59"
  condition:
    hash.sha256(0, filesize) == "683a1607808f49446191d775d181ec9cccd1d629fba76e4d416fa54d1cf42630"
}

rule MalwareBazaar_unknown_076_fc874323
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc874323bea20a985ee9248ea2eb140a60ee716aeed709cd1e48c528d6b11afc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 22:51:57"
  condition:
    hash.sha256(0, filesize) == "fc874323bea20a985ee9248ea2eb140a60ee716aeed709cd1e48c528d6b11afc"
}

rule MalwareBazaar_unknown_077_a3f41333
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27"
    family = "unknown"
    file_name = "stage2_payload.js"
    file_type = "js"
    first_seen = "2026-07-15 22:51:53"
  condition:
    hash.sha256(0, filesize) == "a3f413338c28c464f0c2b2369f1bc1b203261fae68c808b73c2df782dc4b1c27"
}

rule MalwareBazaar_unknown_078_a129de4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c"
    family = "unknown"
    file_name = "malicious_post-checkout.sh"
    file_type = "sh"
    first_seen = "2026-07-15 22:51:47"
  condition:
    hash.sha256(0, filesize) == "a129de4fd4f1374a292bd8964df30c9e82c99bac680c4d36d6890fbf30ffac1c"
}

rule MalwareBazaar_unknown_079_6673c085
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6673c0852fbf8372d4bc146806b2ea1b1e23bc807b792338204e227098789bae"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 22:46:48"
  condition:
    hash.sha256(0, filesize) == "6673c0852fbf8372d4bc146806b2ea1b1e23bc807b792338204e227098789bae"
}

rule MalwareBazaar_unknown_080_880ba21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "880ba21b3e58f130386afdb060ecc030848f8bd8de5c642705555f89a438c793"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 22:23:15"
  condition:
    hash.sha256(0, filesize) == "880ba21b3e58f130386afdb060ecc030848f8bd8de5c642705555f89a438c793"
}

rule MalwareBazaar_Mirai_081_9f16e0d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f16e0d8c5fed47bd9a77a9f45332481f320c5916e6efb92f03c3ab035af1a3c"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 22:19:37"
  condition:
    hash.sha256(0, filesize) == "9f16e0d8c5fed47bd9a77a9f45332481f320c5916e6efb92f03c3ab035af1a3c"
}

rule MalwareBazaar_Mirai_082_5defde36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5defde36dc21b44a1cea847af473d4bfd27926976134e583e0ee7b37f3cdd0b5"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-07-15 22:19:20"
  condition:
    hash.sha256(0, filesize) == "5defde36dc21b44a1cea847af473d4bfd27926976134e583e0ee7b37f3cdd0b5"
}

rule MalwareBazaar_unknown_083_8db3d29e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8db3d29e73b24d39bc338fa1c9cdc1b7f4cdc60c293759f12985ef1ce0e8f026"
    family = "unknown"
    file_name = "update_flash_player.exe"
    file_type = "exe"
    first_seen = "2026-07-15 21:58:29"
  condition:
    hash.sha256(0, filesize) == "8db3d29e73b24d39bc338fa1c9cdc1b7f4cdc60c293759f12985ef1ce0e8f026"
}

rule MalwareBazaar_unknown_084_d8ba1cd3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d8ba1cd36e31e89bb03aa7ac811e81290fa1f6d5cd334005d5f91fafbf0a28ab"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 21:51:57"
  condition:
    hash.sha256(0, filesize) == "d8ba1cd36e31e89bb03aa7ac811e81290fa1f6d5cd334005d5f91fafbf0a28ab"
}

rule MalwareBazaar_Mirai_085_8f5b6ce1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f5b6ce166f923af955e109e5218989c66145596fd3f329077fd0489d2299906"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-15 21:42:12"
  condition:
    hash.sha256(0, filesize) == "8f5b6ce166f923af955e109e5218989c66145596fd3f329077fd0489d2299906"
}

rule MalwareBazaar_unknown_086_55fcc0e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087"
    family = "unknown"
    file_name = "55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087"
    file_type = "exe"
    first_seen = "2026-07-15 21:36:18"
  condition:
    hash.sha256(0, filesize) == "55fcc0e3e94fdebb2a5344f43e6b8650d8184bf0b46e365ed475f1316088b087"
}

rule MalwareBazaar_unknown_087_e9b4ae70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9b4ae70532e8cc060a90ea3c1f520b9355b94bd79ad3fcb363a4b5c0f6b2912"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 21:23:20"
  condition:
    hash.sha256(0, filesize) == "e9b4ae70532e8cc060a90ea3c1f520b9355b94bd79ad3fcb363a4b5c0f6b2912"
}

rule MalwareBazaar_unknown_088_8e2a474f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e2a474f0babce15d70670b29ea3c68fbe5c9c1f93b82232676ef0b617148b9f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-15 21:10:20"
  condition:
    hash.sha256(0, filesize) == "8e2a474f0babce15d70670b29ea3c68fbe5c9c1f93b82232676ef0b617148b9f"
}

rule MalwareBazaar_unknown_089_292b7cc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "292b7cc2fcd484e4536c593c70ed3cf46fb284976693412fa5d542bcf0be17fe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-15 21:10:08"
  condition:
    hash.sha256(0, filesize) == "292b7cc2fcd484e4536c593c70ed3cf46fb284976693412fa5d542bcf0be17fe"
}

rule MalwareBazaar_unknown_090_c0b2ad27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0b2ad27cbc88b9f9879923572ef88eefc509d69170fba16589ff382da463933"
    family = "unknown"
    file_name = "IT-Job-Interview-Preparation-Guide.pdf.lnk"
    file_type = "lnk"
    first_seen = "2026-07-15 20:59:07"
  condition:
    hash.sha256(0, filesize) == "c0b2ad27cbc88b9f9879923572ef88eefc509d69170fba16589ff382da463933"
}

rule MalwareBazaar_Mirai_091_b83e8f14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b83e8f14960e6b0a1983e9fcdc484dac1523e7b32614198d9492e1d2922c67cc"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-15 20:58:05"
  condition:
    hash.sha256(0, filesize) == "b83e8f14960e6b0a1983e9fcdc484dac1523e7b32614198d9492e1d2922c67cc"
}

rule MalwareBazaar_unknown_092_1d01f60c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d01f60c355546557e038ded43fb27f0bfc6559bba9abedcb96a08556e311d2a"
    family = "unknown"
    file_name = "Mohamad,SY.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:54:43"
  condition:
    hash.sha256(0, filesize) == "1d01f60c355546557e038ded43fb27f0bfc6559bba9abedcb96a08556e311d2a"
}

rule MalwareBazaar_unknown_093_95a849ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95a849ce7c11590e05cfdeaeb07a8bf232b4a8131f955fdce13189c3d17cbf14"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-15 20:51:57"
  condition:
    hash.sha256(0, filesize) == "95a849ce7c11590e05cfdeaeb07a8bf232b4a8131f955fdce13189c3d17cbf14"
}

rule MalwareBazaar_unknown_094_842d4950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "842d49501e0650601458936ade269902a6182c5ba10e731be7f8a87b1d206818"
    family = "unknown"
    file_name = "Complete bill - NAGA.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:49:47"
  condition:
    hash.sha256(0, filesize) == "842d49501e0650601458936ade269902a6182c5ba10e731be7f8a87b1d206818"
}

rule MalwareBazaar_unknown_095_2d5dfbf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d5dfbf29d474f2fa504a9e5d625169ab3b09ecec719d5b5ecb0cdd893d2080f"
    family = "unknown"
    file_name = "Dohovir.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:45:45"
  condition:
    hash.sha256(0, filesize) == "2d5dfbf29d474f2fa504a9e5d625169ab3b09ecec719d5b5ecb0cdd893d2080f"
}

rule MalwareBazaar_unknown_096_7f6ec55f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f6ec55f45b3ad0019453151db766882a84d714e2db3a6f607a1e97ed4ce977e"
    family = "unknown"
    file_name = "IMG-145388.zip"
    file_type = "zip"
    first_seen = "2026-07-15 20:42:13"
  condition:
    hash.sha256(0, filesize) == "7f6ec55f45b3ad0019453151db766882a84d714e2db3a6f607a1e97ed4ce977e"
}

rule MalwareBazaar_ValleyRAT_097_12b92086
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2"
    family = "ValleyRAT"
    file_name = "Mai Giang's passport.exe"
    file_type = "exe"
    first_seen = "2026-07-15 20:38:02"
  condition:
    hash.sha256(0, filesize) == "12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2"
}

rule MalwareBazaar_unknown_098_a80cb645
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a80cb6452a37a6baf1c86bd83739acea385b4639301a68a96db8e68b3965bc3c"
    family = "unknown"
    file_name = "学术浏览器安装.exe"
    file_type = "exe"
    first_seen = "2026-07-15 20:35:17"
  condition:
    hash.sha256(0, filesize) == "a80cb6452a37a6baf1c86bd83739acea385b4639301a68a96db8e68b3965bc3c"
}

rule MalwareBazaar_Prometei_099_451341ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15"
    family = "Prometei"
    file_name = "451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15"
    file_type = "elf"
    first_seen = "2026-07-15 20:29:56"
  condition:
    hash.sha256(0, filesize) == "451341ba176d94035d89bde4ba2aac87fafa80d70195c07f978c8753d3a42d15"
}

rule MalwareBazaar_Prometei_100_7812d8f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2"
    family = "Prometei"
    file_name = "7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2"
    file_type = "exe"
    first_seen = "2026-07-15 20:29:16"
  condition:
    hash.sha256(0, filesize) == "7812d8f5ad47a32e71540391771c796802193a36b325c09c3ff4d5f03c321eb2"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

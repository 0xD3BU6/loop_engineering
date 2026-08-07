# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-07

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 651 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 651 |
| Unique family labels | 6 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 66 |
| unknown | 19 |
| ConnectWise | 10 |
| NanoCore | 3 |
| RemusStealer | 1 |
| Stealc | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 68 |
| exe | 26 |
| sh | 4 |
| js | 1 |
| macho | 1 |

## Per-Sample Analysis

### Sample 1: `6e383213ab698d95`

| Field | Value |
|---|---|
| SHA-256 | `6e383213ab698d95c19ba53e6fac6388883139934a91e4c816ee86ff33c0de33` |
| Family label | `unknown` |
| File name | `New_Shipment_0285_Detail_Specificationpdf.js` |
| File type | `js` |
| First seen | `2026-08-07 03:16:34` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a302cbeb7321e30c866cea3d47fd664f` |
| SHA-1 | `ba1f81bc47ed9029a8e6d047dd343ed046e2017b` |
| SHA-256 | `6e383213ab698d95c19ba53e6fac6388883139934a91e4c816ee86ff33c0de33` |
| SHA3-384 | `574e6bed10ac096bf65198079e9512093049ca009f0e6d5b1b2cf51241458d61b26a1c62252ef6216775f2e7a941c003` |
| TLSH | `T13CE5C6B12BCDAA160C0A726FE90D3D980E5A94712ED2D49879EF42D0B24F45D6FD087F` |
| SSDEEP | `24576:bl+YXwu1a146N9EwghlvRB8EbCc9d1CeuFB0TKRtAI8VOauR+uqvjxpoPwzCAZG9:bU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_6e383213
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e383213ab698d95c19ba53e6fac6388883139934a91e4c816ee86ff33c0de33"
    family = "unknown"
    file_name = "New_Shipment_0285_Detail_Specificationpdf.js"
    file_type = "js"
    first_seen = "2026-08-07 03:16:34"
  condition:
    hash.sha256(0, filesize) == "6e383213ab698d95c19ba53e6fac6388883139934a91e4c816ee86ff33c0de33"
}
```

### Sample 2: `e3e213066272b32a`

| Field | Value |
|---|---|
| SHA-256 | `e3e213066272b32a6b4aeaed3f12eebb814cdd3047605d1381a1972ed0809134` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-07 03:00:47` |
| Reporter | `Bitsight` |
| Tags | `BB4.file, dropped-by-GCleaner, exe, F, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cc12f501c6f17f55b17053ac177b9b5` |
| SHA-1 | `84171c04ba6810d3f77cdc0c4ab597894ded1892` |
| SHA-256 | `e3e213066272b32a6b4aeaed3f12eebb814cdd3047605d1381a1972ed0809134` |
| SHA3-384 | `70577e7495bcec483ac64fd360a992f761ee118c3a3f4f7a704f631aaed3fb87a0cccb98f3eb63cd6b89168272bb2119` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T12D166C07ACA148F5C0E6A73188B75292B775B8085B3533DB2EA0AFB82F763C15E35754` |
| SSDEEP | `49152:SOJrS/7bIsrTDXYD+7LN+jxhrBQe1TW72JGLZ6xeqR:SUyvXa+HN2JBTYAGFiR` |
| ICON-DHASH | `e4b3ccd46c36935a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_e3e21306
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3e213066272b32a6b4aeaed3f12eebb814cdd3047605d1381a1972ed0809134"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 03:00:47"
  condition:
    hash.sha256(0, filesize) == "e3e213066272b32a6b4aeaed3f12eebb814cdd3047605d1381a1972ed0809134"
}
```

### Sample 3: `cf29935a19b0f6f8`

| Field | Value |
|---|---|
| SHA-256 | `cf29935a19b0f6f894971c107e8ffdefe122dc44ffd643f1fe0dbf23207d7083` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-07 02:43:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8223e45f76be0234ff5043dfa0eb56c3` |
| SHA-1 | `14908827f9fc3942f2a3df30509e46cbdd9873b1` |
| SHA-256 | `cf29935a19b0f6f894971c107e8ffdefe122dc44ffd643f1fe0dbf23207d7083` |
| SHA3-384 | `716e04373a00be86248664675a5487613a16f283b8f68eda304a63d684607f73f96052d69403380bd74bc6107791ce21` |
| TLSH | `T10714975E6E228F7EF268C73447B74A34976D23D627E1D684D2ACC1101F6039E641FBA8` |
| TELFHASH | `t1e941c518097813b0a6396c5e45ddfb37d6a330de7e166c238f11e86aa769e838d11c0c` |
| SSDEEP | `3072:lcytmq5JQDxGJztOk8klG0n5bCXfuy3Rs8Ge5RPfeWg3KR7X9uHl9i:lcytmq560hOk8ibUfuIOofMaR7ts9i` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_cf29935a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf29935a19b0f6f894971c107e8ffdefe122dc44ffd643f1fe0dbf23207d7083"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-07 02:43:53"
  condition:
    hash.sha256(0, filesize) == "cf29935a19b0f6f894971c107e8ffdefe122dc44ffd643f1fe0dbf23207d7083"
}
```

### Sample 4: `22a7183a59a6dc42`

| Field | Value |
|---|---|
| SHA-256 | `22a7183a59a6dc4203686d5482928fc587c5fd4db20949d599c09e75d01d790b` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-08-07 02:35:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52b08acc9b2be0c6ecf821c65a271a26` |
| SHA-1 | `fe675193c9ece1cf520ff4322773ebd2ce34674a` |
| SHA-256 | `22a7183a59a6dc4203686d5482928fc587c5fd4db20949d599c09e75d01d790b` |
| SHA3-384 | `9a89253af72d9770ea3e98f6a0a001ab076e208414205a38991d44e80ef3041829dd643d75c687060bdacad2c051117c` |
| TLSH | `T101E3AFA7B70F2450C42606F81BCB57AC2A3361114E6F9BE76C6E763E1A375DB28063D1` |
| SSDEEP | `3072:8Cj/bseNZu8cAUrj8Vry0uSHjqgWCWtQuy51dFIHvxq:8Cnhb5U8VmDAjiCWDy5kxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_22a7183a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22a7183a59a6dc4203686d5482928fc587c5fd4db20949d599c09e75d01d790b"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-07 02:35:16"
  condition:
    hash.sha256(0, filesize) == "22a7183a59a6dc4203686d5482928fc587c5fd4db20949d599c09e75d01d790b"
}
```

### Sample 5: `555d862a10163c0d`

| Field | Value |
|---|---|
| SHA-256 | `555d862a10163c0da85fa24a58ec2caf5cf76d9ec0a4cb21983cec216fddedbf` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-07 02:35:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6dd1518b5abf4ba5f46d2bb31f87ef3` |
| SHA-1 | `aadc374b7c088aff4a53de3347f32fb1a3cb9186` |
| SHA-256 | `555d862a10163c0da85fa24a58ec2caf5cf76d9ec0a4cb21983cec216fddedbf` |
| SHA3-384 | `0b44cfa8ebcb72cbd028c826d02ceb17ee73947c5601892209d8e054355874bb3c8ae21d2cc2e62e5603a332050cda54` |
| TLSH | `T12CF318C7F900DAB6F80AE3374853040AB130B7A208925A777257357FED7E199157BE8A` |
| SSDEEP | `3072:4uNV09jAc97rorU9MyFa/v8yFLTPnbhJwqwX2VzjbifLhFHIVP6P:NNV0txf43yFcv8yFHPvNwXpLX86P` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_555d862a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "555d862a10163c0da85fa24a58ec2caf5cf76d9ec0a4cb21983cec216fddedbf"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-07 02:35:14"
  condition:
    hash.sha256(0, filesize) == "555d862a10163c0da85fa24a58ec2caf5cf76d9ec0a4cb21983cec216fddedbf"
}
```

### Sample 6: `3427810ea86c988a`

| Field | Value |
|---|---|
| SHA-256 | `3427810ea86c988af3702d5b43dcfde93205232f5d5a567580f739b26b0fd4d2` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-07 02:29:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2919a523bb69bed68e3575ea4980a661` |
| SHA-1 | `7b2d001b80b3f20f522a7d48ce648864101547d8` |
| SHA-256 | `3427810ea86c988af3702d5b43dcfde93205232f5d5a567580f739b26b0fd4d2` |
| SHA3-384 | `10a3eede109628dc729f847f192d0a601e6e04e06f4e1bf89cba243f08e62fdf30484979cadb1539b725aaa14975a86b` |
| TLSH | `T1FA936C89FB83E0F4DD4A05B0116BF77E8734DE125034DE5ADB98BE729C72602A51A72C` |
| TELFHASH | `t1ed41fafb0eed09f8b3d05400d35e2b62b969667b161036a303b3646533e7bc1916ec35` |
| SSDEEP | `1536:IK6iz+N31yWu8ay/5uYArV7Ub310KtoIyvXT99CGaAVeNSr1:IK7zQu8z/5uYXuTIyPjVeo1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_3427810e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3427810ea86c988af3702d5b43dcfde93205232f5d5a567580f739b26b0fd4d2"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-07 02:29:17"
  condition:
    hash.sha256(0, filesize) == "3427810ea86c988af3702d5b43dcfde93205232f5d5a567580f739b26b0fd4d2"
}
```

### Sample 7: `b7f2e9185472e01b`

| Field | Value |
|---|---|
| SHA-256 | `b7f2e9185472e01b3b636cd48417239456b9a9318b7a9b1a920cdb6b2d9420ed` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-07 02:26:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9266ebb5e4e8120481e83ae16c6d1d95` |
| SHA-1 | `cdb615d027451931df35603b624398e40f7c8556` |
| SHA-256 | `b7f2e9185472e01b3b636cd48417239456b9a9318b7a9b1a920cdb6b2d9420ed` |
| SHA3-384 | `b8664567bdad3f913d73306853ef275defbadad83d1844ad7c9fc9bee98177574034bf52b5a91b69c4e3a2dbab4b9549` |
| TLSH | `T1F6D30845FD458F17CAC225BBFF4E428C7B2A1768D3EE720399255F20379B85A0E3A146` |
| TELFHASH | `t185210579ee981a9cb3d5952dd1cf6137465432fe37252820675d4f4e93339d2b011437` |
| SSDEEP | `3072:LSSTtBs5VOdsQx3NW5wOeMcd31Ubbgu7K4Q6HA:LSScIaM3NW5wSc51wb/7VQt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_b7f2e918
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f2e9185472e01b3b636cd48417239456b9a9318b7a9b1a920cdb6b2d9420ed"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-07 02:26:12"
  condition:
    hash.sha256(0, filesize) == "b7f2e9185472e01b3b636cd48417239456b9a9318b7a9b1a920cdb6b2d9420ed"
}
```

### Sample 8: `17a7ad87346b0119`

| Field | Value |
|---|---|
| SHA-256 | `17a7ad87346b0119caa7f638b3bea08aa14459b25e5150a8c9a0ef70bef719bd` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-08-07 02:26:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70a541fe0683dee9e80979a2879fe366` |
| SHA-1 | `b883ee19ddc1d3303951224562b1c381716050b8` |
| SHA-256 | `17a7ad87346b0119caa7f638b3bea08aa14459b25e5150a8c9a0ef70bef719bd` |
| SHA3-384 | `5bdd218ccd9b66a07ba8ca8a1ea75547c4d1a847650bcf661ceff3696ea39e9a78767d1a62010109ea9a64ee88fa1395` |
| TLSH | `T174334C22C9BD9D86CAE0797E03E703E3C1CB4B1443A4DA1EEDD01EA9DF467505C66B58` |
| TELFHASH | `t1f6f08b44ed3cce1e46e35930cc7d9b519163893342a0c725df44cac0493e109f219e1f` |
| SSDEEP | `1536:4sr9n4n/W03r9n4nB9D20ei+I4RBZWBg3zLThiixiwf3N:4sr94/R3r94T9ei+I4R5Mw3N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_17a7ad87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17a7ad87346b0119caa7f638b3bea08aa14459b25e5150a8c9a0ef70bef719bd"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-07 02:26:11"
  condition:
    hash.sha256(0, filesize) == "17a7ad87346b0119caa7f638b3bea08aa14459b25e5150a8c9a0ef70bef719bd"
}
```

### Sample 9: `89c3ba702d5c424a`

| Field | Value |
|---|---|
| SHA-256 | `89c3ba702d5c424a14c58c3809897b9fc0a66a84c9e4becd4363972e4077756b` |
| Family label | `NanoCore` |
| File name | `09683b2cb19f16818d0a60264663cac2.exe` |
| File type | `exe` |
| First seen | `2026-08-07 02:20:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09683b2cb19f16818d0a60264663cac2` |
| SHA-1 | `0b77288fca4555e501c9cb4474cd689bee669c98` |
| SHA-256 | `89c3ba702d5c424a14c58c3809897b9fc0a66a84c9e4becd4363972e4077756b` |
| SHA3-384 | `c2b10186c476f96807c19f8f58f58541a363a817fb0041b876ce8c2ed7c675968d19b7fd218d46c782d63e5210f2b063` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11814CF5677A84A2FE2DE867D611212169379C2E39CC3F3EE28D455B78F267E00A071D3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5o6V2qhLyNPYTbEjP:MLV6BtpmkbM2uL4YTi` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_009_89c3ba70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89c3ba702d5c424a14c58c3809897b9fc0a66a84c9e4becd4363972e4077756b"
    family = "NanoCore"
    file_name = "09683b2cb19f16818d0a60264663cac2.exe"
    file_type = "exe"
    first_seen = "2026-08-07 02:20:06"
  condition:
    hash.sha256(0, filesize) == "89c3ba702d5c424a14c58c3809897b9fc0a66a84c9e4becd4363972e4077756b"
}
```

### Sample 10: `9b96004da936de55`

| Field | Value |
|---|---|
| SHA-256 | `9b96004da936de55cbd9a2dd86f0f1670a6807a6009a8ae1087684d8527b8af1` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-08-07 02:19:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3407d84a0294de2555d3fd77d2014dcf` |
| SHA-1 | `258443c498cb3fb39619e46e3664d4daf9ab9e1c` |
| SHA-256 | `9b96004da936de55cbd9a2dd86f0f1670a6807a6009a8ae1087684d8527b8af1` |
| SHA3-384 | `84fe36887a8509b4337adfd806ba52064cb8b2e17d547720051564e387ecc9b94bf2a19b7baa18017a4e29c8841acdb6` |
| TLSH | `T1C8D30659FD41AB11E5D635FEFE4E028973530B6CE3FE7101AA245B2123CAA6B0F7A105` |
| TELFHASH | `t17621cb519be41e8c73e44355f2aca2164ff431b972222c22e9fd965b40030d3343ba26` |
| SSDEEP | `3072:H8X2fWwy/OAK1cNLASZclani8XIqBJRf4WKUaKWUJjpCmuHY:HOrJ84LDalaicIqBJRwQaKrJjpCm5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_9b96004d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b96004da936de55cbd9a2dd86f0f1670a6807a6009a8ae1087684d8527b8af1"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-07 02:19:42"
  condition:
    hash.sha256(0, filesize) == "9b96004da936de55cbd9a2dd86f0f1670a6807a6009a8ae1087684d8527b8af1"
}
```

### Sample 11: `b21a6903bc670f9e`

| Field | Value |
|---|---|
| SHA-256 | `b21a6903bc670f9ecbcf74aae1fe4bf479b8ee7430a24d96921e806b13ac1602` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-07 02:13:18` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c21c375b5dd2f9d2a95a4be6f2a1be94` |
| SHA-1 | `dc265c6155a7e410844e387d129465b49d45d803` |
| SHA-256 | `b21a6903bc670f9ecbcf74aae1fe4bf479b8ee7430a24d96921e806b13ac1602` |
| SHA3-384 | `e3096c39d082ffdc5af069cd03b62148063348268daa498e03aa3e8300edfd9a46f0c02afde44721ddbf389f2d7f0f7a` |
| TLSH | `T12A235C552A857C14AA98C8371D7F2F0CB9A943E6320452DE7FCF3CF68C4AA9DA10961D` |
| SSDEEP | `768:76FWzZx529GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:GkzNcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_b21a6903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b21a6903bc670f9ecbcf74aae1fe4bf479b8ee7430a24d96921e806b13ac1602"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-07 02:13:18"
  condition:
    hash.sha256(0, filesize) == "b21a6903bc670f9ecbcf74aae1fe4bf479b8ee7430a24d96921e806b13ac1602"
}
```

### Sample 12: `ea607ebe34ee5a06`

| Field | Value |
|---|---|
| SHA-256 | `ea607ebe34ee5a06f5ed85805e0cf9175eaeb390fc39cb19bd31a7add8a4edf5` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-07 02:01:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3bfa05e5d583e362b5ea1893b54f4166` |
| SHA-1 | `a14409f5a799150184ce27400fcf6ed6699e7647` |
| SHA-256 | `ea607ebe34ee5a06f5ed85805e0cf9175eaeb390fc39cb19bd31a7add8a4edf5` |
| SHA3-384 | `689eb9e8b8620548c01ef7fe40cd975359d43ceaaad2d3c53660aad9707eb3b9131359046e62c55c9c4d74fa97eaa10b` |
| TLSH | `T14824188ADEA50FDFC46FCE30062E431719EE599B93E4733A457CCC54B68A2494AE3858` |
| TELFHASH | `t14d417604c939cb2a99e203e8cbec5e55ca85d16a9a610f13cf32c75c41b5049911befe` |
| SSDEEP | `6144:s7vwfwq/uBbXxFTd7Lji38h5d+ylyuEPvMao07:+vKebXTd3jVTylxo07` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_ea607ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea607ebe34ee5a06f5ed85805e0cf9175eaeb390fc39cb19bd31a7add8a4edf5"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 02:01:00"
  condition:
    hash.sha256(0, filesize) == "ea607ebe34ee5a06f5ed85805e0cf9175eaeb390fc39cb19bd31a7add8a4edf5"
}
```

### Sample 13: `a9a08daf07f1b3b6`

| Field | Value |
|---|---|
| SHA-256 | `a9a08daf07f1b3b65aefe346cece1f53a82d2dd69cd7f73a3827ae6f20c0d1bc` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-07 02:00:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1583f3613d50ece6d6c113de77b7ae5` |
| SHA-1 | `1d2815bd5c54f60b97edd4626e5ced2bc5698256` |
| SHA-256 | `a9a08daf07f1b3b65aefe346cece1f53a82d2dd69cd7f73a3827ae6f20c0d1bc` |
| SHA3-384 | `6705091d7190039bccd918e9cbb2879f4810aa5bb0a91174ab90d7f9f4dd7f656fe954fde3a818a97eed59aa67d94fa5` |
| TLSH | `T1B393026CE0D43A91659CAD78622F15F1FD20D844D7AA329A33DE4E8C0F4706B5E9E0DD` |
| SSDEEP | `1536:w845eht382rIQPVTzOHPqJLJIotui9BzF7+4hOlbzVS7wCovw0vWfNKzdqiPKZBO:QehtDJz1JItW7JOlbzU7wrluwzdR2mBd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_a9a08daf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a08daf07f1b3b65aefe346cece1f53a82d2dd69cd7f73a3827ae6f20c0d1bc"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 02:00:12"
  condition:
    hash.sha256(0, filesize) == "a9a08daf07f1b3b65aefe346cece1f53a82d2dd69cd7f73a3827ae6f20c0d1bc"
}
```

### Sample 14: `84b8ec2f3b29a10f`

| Field | Value |
|---|---|
| SHA-256 | `84b8ec2f3b29a10f88d21fc7617cdfecac1c2c76303086b41471beb5f563f65c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-07 01:56:20` |
| Reporter | `Bitsight` |
| Tags | `37412fcd9a39df7667b49f4bab671219, dropped-by-Vidar, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `066dab36fbf44cfa930929d002a07cb3` |
| SHA-1 | `9ba5a8bf9564e71f333406b3e4962cac35e33a38` |
| SHA-256 | `84b8ec2f3b29a10f88d21fc7617cdfecac1c2c76303086b41471beb5f563f65c` |
| SHA3-384 | `d962943afadfbf3b4819cae11afb6e44a505c60bf1fa2a7bc567be60fc37b4c02a479ca8f67699e18ff503736e32b3da` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T1F064C005BB6710ECE1778978C8581662FB773E614350AB6F0360B676BF336A17C29B21` |
| SSDEEP | `6144:rQxVrl4fkcCYDHElcLjm+WgUqeIw5mMVDMbEwV19ohTNwyEtSo4V:UVrl4fk9YjhLjWgPw0ADMh/SkX4V` |
| ICON-DHASH | `f1f4e8e8b288c8c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_84b8ec2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b8ec2f3b29a10f88d21fc7617cdfecac1c2c76303086b41471beb5f563f65c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 01:56:20"
  condition:
    hash.sha256(0, filesize) == "84b8ec2f3b29a10f88d21fc7617cdfecac1c2c76303086b41471beb5f563f65c"
}
```

### Sample 15: `996cab13bc21cff4`

| Field | Value |
|---|---|
| SHA-256 | `996cab13bc21cff4f38ba7cbbcadd4cd31b6fe8b1fb45251d3923ca3498b3df7` |
| Family label | `Mirai` |
| File name | `Mddos.arm5` |
| File type | `elf` |
| First seen | `2026-08-07 01:54:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dca56af4e9d5780b89bbc8fa2c06f7e0` |
| SHA-1 | `2d935c39061ddb2efbf106517e8447516303f93a` |
| SHA-256 | `996cab13bc21cff4f38ba7cbbcadd4cd31b6fe8b1fb45251d3923ca3498b3df7` |
| SHA3-384 | `e54034c192dc9f20f46c9850fc938c550f3e899311c8fa244bb8c28ca2b947699c12c1823ddcecd4790683d3e800f8e8` |
| TLSH | `T1D4E42955F8809F61C6C529B6F65D42AC73074BB9D3EB72069A144B343BEB86B0F3A701` |
| TELFHASH | `t187f020346c4c65acb5d2c820c782f81a29f8269547047c9e6a58ae8e0e82fc138b40b7` |
| SSDEEP | `12288:6kWAxr4qaC5aKIjQIH86MzJyRWEmdkaRK3vFD9qC6rd8S8pqP8qbt:6k/EC5SDHTMFyRWLd/w/l6rbbx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_996cab13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "996cab13bc21cff4f38ba7cbbcadd4cd31b6fe8b1fb45251d3923ca3498b3df7"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-07 01:54:21"
  condition:
    hash.sha256(0, filesize) == "996cab13bc21cff4f38ba7cbbcadd4cd31b6fe8b1fb45251d3923ca3498b3df7"
}
```

### Sample 16: `924194012db5ee87`

| Field | Value |
|---|---|
| SHA-256 | `924194012db5ee8721227fa456bff10954996a7c519bac33babd4236e987c941` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-08-07 01:54:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b61b9a10e78a527e1760f8f487675baa` |
| SHA-1 | `6f2434b6d4d3b9f088977eefed68975272b4a707` |
| SHA-256 | `924194012db5ee8721227fa456bff10954996a7c519bac33babd4236e987c941` |
| SHA3-384 | `022e1b58a5a0caaee74e794a0af8f2843b28017a203fcbd0af71d35b51f3ef5487d93b5ce41daa0af3ffd2d7f378593b` |
| TLSH | `T1BDE30855F980DF22CAC1267ABB9E428D33131778D3EA7102CD205F3577EE95A4B3A942` |
| SSDEEP | `3072:yTWMcfdhPDLEgXiWfDKeOoL8Znx3rqXRMEGB19CR0Q0pZarR:yTWMoPDLEgXiWfDKvJZnBqXRMEGB1oKq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_92419401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "924194012db5ee8721227fa456bff10954996a7c519bac33babd4236e987c941"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-07 01:54:20"
  condition:
    hash.sha256(0, filesize) == "924194012db5ee8721227fa456bff10954996a7c519bac33babd4236e987c941"
}
```

### Sample 17: `cb2ffb986351e2ee`

| Field | Value |
|---|---|
| SHA-256 | `cb2ffb986351e2eea68c323dffd000bf0b8af4b41e4ce5afd024bbd0f4dfd599` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-07 01:51:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e394f9ac8a393f4deea581598441ea6` |
| SHA-1 | `6566bcf6104aeda0407fb1f27c66aa2c76263da5` |
| SHA-256 | `cb2ffb986351e2eea68c323dffd000bf0b8af4b41e4ce5afd024bbd0f4dfd599` |
| SHA3-384 | `ec85ba0781193df9b8551af90a63aaf88215b286e1910a16ef17e5d52a95776840e257366323e68f4e35ee258e5e2776` |
| TLSH | `T10BD34C13E98080FDC49AD274879FD137EB32F89A12347B0F2B946E611D36F616B5A781` |
| SSDEEP | `3072:ByrYwOWHo64Cqm4NgI9bjjYqUA0ndiTLUbkt:ByRH7E7YDfcwbkt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_cb2ffb98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb2ffb986351e2eea68c323dffd000bf0b8af4b41e4ce5afd024bbd0f4dfd599"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:51:41"
  condition:
    hash.sha256(0, filesize) == "cb2ffb986351e2eea68c323dffd000bf0b8af4b41e4ce5afd024bbd0f4dfd599"
}
```

### Sample 18: `88b5109d8eb8b053`

| Field | Value |
|---|---|
| SHA-256 | `88b5109d8eb8b053819ea7b488ff317c7ec584b4e1223398b8a500bd8a04bd5d` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-07 01:51:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4019ba627e220caabbe0e84f19fc8d4` |
| SHA-1 | `3e964a61b9d721edbf40dc8d9c9fe9459439f1f8` |
| SHA-256 | `88b5109d8eb8b053819ea7b488ff317c7ec584b4e1223398b8a500bd8a04bd5d` |
| SHA3-384 | `fb1a2e59990a81c5905d9c86859ad810ed3eedba539b13f2e2c46abdef8aee37c6db0d9b1d90a929e512bdfab16d56da` |
| TLSH | `T134E30845FD459F57CAC255BBFB4E428C7B2A0768D3EE720389256F30379B85A0E3A142` |
| TELFHASH | `t1ff21e070cb990a9c7fd9c159c1dfa12a4b1a39b927193025a74eab1e8533cd0ec64927` |
| SSDEEP | `3072:OKMO5X40Dt23/8ur/BcLiwDrjnbWMpHh4CBf+hHQ:OKM+0v80/BcLiwDrXWCH6Qf+6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_88b5109d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88b5109d8eb8b053819ea7b488ff317c7ec584b4e1223398b8a500bd8a04bd5d"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-07 01:51:26"
  condition:
    hash.sha256(0, filesize) == "88b5109d8eb8b053819ea7b488ff317c7ec584b4e1223398b8a500bd8a04bd5d"
}
```

### Sample 19: `d031735c3f1885f1`

| Field | Value |
|---|---|
| SHA-256 | `d031735c3f1885f132d422c246cf99fa8c7dd6ec10f78d4397fe50621ac84576` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-07 01:51:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a4e5fb9867616d104e17853809d0f64` |
| SHA-1 | `ee74a5517084f3d5a39551606696df581c15e2a2` |
| SHA-256 | `d031735c3f1885f132d422c246cf99fa8c7dd6ec10f78d4397fe50621ac84576` |
| SHA3-384 | `84d7235d96ee57abdc520f5c88dd7279406c182de8090009599d7c2e2ee114e2498d8cbbaa24d8bbf36c3f57c51b7aa4` |
| TLSH | `T1476301BF815AFEB5C7D059365A3E07C93390582B1076E71EA4E2769AC8D76FC8F05202` |
| SSDEEP | `1536:35qDgMsi2HRMhrf4pgCxG5C12aC+nnLumY50IINQBP5k1ZVyDa:JEsDRMhzqnxG5CVFnimY5nVPGZVyO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_d031735c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d031735c3f1885f132d422c246cf99fa8c7dd6ec10f78d4397fe50621ac84576"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:51:24"
  condition:
    hash.sha256(0, filesize) == "d031735c3f1885f132d422c246cf99fa8c7dd6ec10f78d4397fe50621ac84576"
}
```

### Sample 20: `c2258509124d2f09`

| Field | Value |
|---|---|
| SHA-256 | `c2258509124d2f096ddfe68e16e2e6f75772048bf0fd3eb2bbdd7898004b5585` |
| Family label | `Mirai` |
| File name | `disconnectraw.aarch64` |
| File type | `elf` |
| First seen | `2026-08-07 01:45:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4a9d25339f177f151f8f2ac943b1b5b` |
| SHA-1 | `5ee88f7b80ffaf3611a5eb039667c058057bb2be` |
| SHA-256 | `c2258509124d2f096ddfe68e16e2e6f75772048bf0fd3eb2bbdd7898004b5585` |
| SHA3-384 | `bcec4452136243ea4e5cbaffc51885de5e15b831035009bd779909653ffab650253bc56549ca76a2a02dd03d5860dae3` |
| TLSH | `T186F37ED49A1F6D81D6C7F7BCAD5E4FB230373CB40664C1B31A00626DD4EEDE688A2562` |
| SSDEEP | `3072:u2r6Rq+KHwlxdBeCTFxcROtLtMHJvvKR:VuRQwl3BeCTkRmLqJnKR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_c2258509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2258509124d2f096ddfe68e16e2e6f75772048bf0fd3eb2bbdd7898004b5585"
    family = "Mirai"
    file_name = "disconnectraw.aarch64"
    file_type = "elf"
    first_seen = "2026-08-07 01:45:56"
  condition:
    hash.sha256(0, filesize) == "c2258509124d2f096ddfe68e16e2e6f75772048bf0fd3eb2bbdd7898004b5585"
}
```

### Sample 21: `3e54bd672c62b542`

| Field | Value |
|---|---|
| SHA-256 | `3e54bd672c62b54255400308df61b30f508d92ccd80c097b73281bf92c04c58f` |
| Family label | `Mirai` |
| File name | `disconnectraw.aarch64` |
| File type | `elf` |
| First seen | `2026-08-07 01:45:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f390863fc6d3fe71a4311afcfd0b8926` |
| SHA-1 | `007023ed69e4997b368e21a1f299509b5e6d46b8` |
| SHA-256 | `3e54bd672c62b54255400308df61b30f508d92ccd80c097b73281bf92c04c58f` |
| SHA3-384 | `3b19bc7bc4b2ab1492a7c9cdf2f73a59b496af97f1876d8c3595db79059528b4f70dc8c708f0ad651561d932b00ed208` |
| TLSH | `T1C963029396B23C43E9D870FBE03687514A84F63501BACD743A74A5DA9F0D86EB0B849D` |
| SSDEEP | `768:JJ1ELbD1VyJjw3raqEYkv3MKGhfBjJfpfXIGdpaK+Yu/H/9hVupQguhWRJxf7ev+:JvELFVtdnkvKhBjJEK+z/JzguwSOQK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_3e54bd67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e54bd672c62b54255400308df61b30f508d92ccd80c097b73281bf92c04c58f"
    family = "Mirai"
    file_name = "disconnectraw.aarch64"
    file_type = "elf"
    first_seen = "2026-08-07 01:45:28"
  condition:
    hash.sha256(0, filesize) == "3e54bd672c62b54255400308df61b30f508d92ccd80c097b73281bf92c04c58f"
}
```

### Sample 22: `2759b171a3a9b245`

| Field | Value |
|---|---|
| SHA-256 | `2759b171a3a9b245bb0559d8a9aaa2ad753a140a072d6ca0c26235139fdc2a7c` |
| Family label | `unknown` |
| File name | `cat.sh` |
| File type | `sh` |
| First seen | `2026-08-07 01:45:25` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6887af6cb9a62c67ff55ce9fc74c4bba` |
| SHA-1 | `0d22bdff94de2a302d098487493d578407474e6b` |
| SHA-256 | `2759b171a3a9b245bb0559d8a9aaa2ad753a140a072d6ca0c26235139fdc2a7c` |
| SHA3-384 | `f70fc0435921820e10ac5924134e27404c3eded0b8432d7e02d0144df41fc3615ec34d0c34c360544c10e53cb0831b54` |
| TLSH | `T156117FA925707E20428EDF4D71E587E45206F5C3B1935BF2E5835D25A8CAE40B816F33` |
| SSDEEP | `12:7kft0dt6hbNaKjT6dODOqaDU8fGMGTK1zk1ZhVbcVb1LBqhN0m:4fCc3FHDwjYKxkpCe2m` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_2759b171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2759b171a3a9b245bb0559d8a9aaa2ad753a140a072d6ca0c26235139fdc2a7c"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-08-07 01:45:25"
  condition:
    hash.sha256(0, filesize) == "2759b171a3a9b245bb0559d8a9aaa2ad753a140a072d6ca0c26235139fdc2a7c"
}
```

### Sample 23: `192ab4c313bdd769`

| Field | Value |
|---|---|
| SHA-256 | `192ab4c313bdd769956ada60e82dbcb7d2f6c41efb520e213a647dcdf1077ce9` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-07 01:42:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `867fbf5656b93ed7da17a6a224b887e4` |
| SHA-1 | `bca9c05c79ba5cc824c1ff90661c73f19e9ca1e8` |
| SHA-256 | `192ab4c313bdd769956ada60e82dbcb7d2f6c41efb520e213a647dcdf1077ce9` |
| SHA3-384 | `c04a8239187df6cb93187b16a13abe3be7b7c3afbcdffc94bcd0fc00e4f0a2f1564924c21479831e72e1c0a3868ac053` |
| TLSH | `T1CC145BA5BA0F6C42F1C6D3F8DE8C83F17E1735E3C67689B1781213ACCAA39D95990502` |
| SSDEEP | `6144:ti0Se0J/AAtLJbfO5EZn4o71E6awYnoq:tELhf+E5Yno` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_192ab4c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "192ab4c313bdd769956ada60e82dbcb7d2f6c41efb520e213a647dcdf1077ce9"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-07 01:42:27"
  condition:
    hash.sha256(0, filesize) == "192ab4c313bdd769956ada60e82dbcb7d2f6c41efb520e213a647dcdf1077ce9"
}
```

### Sample 24: `1ae01ac29110a83c`

| Field | Value |
|---|---|
| SHA-256 | `1ae01ac29110a83c78af2f046599bffd4212b5653d949074374a4f27a6d6aaef` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-07 01:39:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e81757b8c89cdc3233c0c8d9a73f0ce6` |
| SHA-1 | `e6f85a57c68aaffff0d6ffaeb43d46f41937e14f` |
| SHA-256 | `1ae01ac29110a83c78af2f046599bffd4212b5653d949074374a4f27a6d6aaef` |
| SHA3-384 | `26c7c31d5f073f1e9d72d7541b547f3c28004a9a2b5cecb995c142db3c7d9399bc2d55f8ce6084d1269b648d649086cc` |
| TLSH | `T13AE35B1775C1C0FDC8D9C2B84BAAE226DD72B4695138B25F37C4AE261E5DE206F6C710` |
| TELFHASH | `t1a151ce703a9539a4f1d7f566b30be965ac3a0e6108e034d9cb727cda8f163c44d75827` |
| SSDEEP | `3072:y/SK3B33rTQ5YVs4P1jgEFbVcQ4h1V3Ki1qtJvV9b8:Z60DJHUb8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_1ae01ac2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae01ac29110a83c78af2f046599bffd4212b5653d949074374a4f27a6d6aaef"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:39:46"
  condition:
    hash.sha256(0, filesize) == "1ae01ac29110a83c78af2f046599bffd4212b5653d949074374a4f27a6d6aaef"
}
```

### Sample 25: `9fb7734eff92e718`

| Field | Value |
|---|---|
| SHA-256 | `9fb7734eff92e7186fc51250c305b087df7c7c0698ab6a987a5027c0507b38e8` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-07 01:39:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5da82555ba64dd2870f01adc8d2f48f` |
| SHA-1 | `2e167353d07227079b50454603875d30f1953db1` |
| SHA-256 | `9fb7734eff92e7186fc51250c305b087df7c7c0698ab6a987a5027c0507b38e8` |
| SHA3-384 | `2bbded1946c6b69470d9915a7ed950c2fa2a7eb65a74f8d01bef80316b7b23ede9bdf1b6c869d16e19650421b0d7080a` |
| TLSH | `T10914D70AAF910FFBD86FDE3706E90A0235CCA55722A43F353674D524F54A64B4AE3C68` |
| SSDEEP | `3072:QNqm236VBWbOAvwoFhA6EdAAy/LZdOgdkQHUjX:qly6V8d7hA6qyFoIkPj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_9fb7734e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb7734eff92e7186fc51250c305b087df7c7c0698ab6a987a5027c0507b38e8"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 01:39:27"
  condition:
    hash.sha256(0, filesize) == "9fb7734eff92e7186fc51250c305b087df7c7c0698ab6a987a5027c0507b38e8"
}
```

### Sample 26: `4b7c709aba3af9f7`

| Field | Value |
|---|---|
| SHA-256 | `4b7c709aba3af9f79945f21998b06e73ec951ec5a523bc038fd21d0bdecfe326` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-07 01:39:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef9e282b9917c11798dc99b9298beca7` |
| SHA-1 | `c0216d9bc7cd0e7f7da8a75de3baf3817676b338` |
| SHA-256 | `4b7c709aba3af9f79945f21998b06e73ec951ec5a523bc038fd21d0bdecfe326` |
| SHA3-384 | `9a59a172b2b74857269849e58c67fb063abc074d501d758f7f754d9eda37c2f42bda0908064930e55a9937fb8804323c` |
| TLSH | `T17D43026B9359D1FBCA35E8B6B443638DF4B17C037602470FB53922752B5AC227F60682` |
| SSDEEP | `768:oJOy7sp/RfJScbFon8/huyCxykcOQUvxDvnnhmuwxlfnSfshmjL0VUm3aLEDKJ8k:kOy74pfrm8/Xz1wDvnErfGYm0VUmGZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_4b7c709a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b7c709aba3af9f79945f21998b06e73ec951ec5a523bc038fd21d0bdecfe326"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:39:26"
  condition:
    hash.sha256(0, filesize) == "4b7c709aba3af9f79945f21998b06e73ec951ec5a523bc038fd21d0bdecfe326"
}
```

### Sample 27: `27f5a48e661bf28d`

| Field | Value |
|---|---|
| SHA-256 | `27f5a48e661bf28d1f2498c31e692411ecc8891a13da9f76458c0197dd3c7079` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-07 01:36:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `568010db2d21df503755125aee81e5ed` |
| SHA-1 | `5562f5947d78a29326760390d7fcee5ad9a6102e` |
| SHA-256 | `27f5a48e661bf28d1f2498c31e692411ecc8891a13da9f76458c0197dd3c7079` |
| SHA3-384 | `fa79ebfdb0fc4aeedb093d9d247da8dc9e7d6f4934978ca76d95c4ce4e80a19f13ca71eca128589e2b0f3e8f715dc3b9` |
| TLSH | `T1DDC36A77C8256FACC524E9B0B0719FB86B63A911854B5FBE1967C2758083DCCF6093B8` |
| SSDEEP | `3072:+l1pDga/5yuZcqnRe24m1+AguAWz/RW4DVHj:+lHcw5MqnRem9Jz/vDh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_27f5a48e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27f5a48e661bf28d1f2498c31e692411ecc8891a13da9f76458c0197dd3c7079"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-07 01:36:29"
  condition:
    hash.sha256(0, filesize) == "27f5a48e661bf28d1f2498c31e692411ecc8891a13da9f76458c0197dd3c7079"
}
```

### Sample 28: `bfd4a1275626d0b8`

| Field | Value |
|---|---|
| SHA-256 | `bfd4a1275626d0b82bc22a41aa65fb39b3936c895ce885d248195860fd07345b` |
| Family label | `Mirai` |
| File name | `disconnectraw.x86` |
| File type | `elf` |
| First seen | `2026-08-07 01:36:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7681e606ed7f3d0caf532bd35715f3d0` |
| SHA-1 | `11fcefb771aa40a0af5abff86f0f3a813a1831e0` |
| SHA-256 | `bfd4a1275626d0b82bc22a41aa65fb39b3936c895ce885d248195860fd07345b` |
| SHA3-384 | `cde8bbaf33d6c1ef85d7ee42e89826d6482ab71da482b457ec75212eda02afc8594a33e8425048f65a7ed14ed5f18e83` |
| TLSH | `T1C4E35B81FB87D2F1E99345B0012BB71F8B349D358124DE0AEBA92E31EC75706855BB6C` |
| SSDEEP | `3072:TtDPwtUC1l3oH0SLjgWaH44nxkpB8WNWSer7OtgvTareTR/CU:pD2P4HPEWaY4nKs7OsGa//` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_bfd4a127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfd4a1275626d0b82bc22a41aa65fb39b3936c895ce885d248195860fd07345b"
    family = "Mirai"
    file_name = "disconnectraw.x86"
    file_type = "elf"
    first_seen = "2026-08-07 01:36:27"
  condition:
    hash.sha256(0, filesize) == "bfd4a1275626d0b82bc22a41aa65fb39b3936c895ce885d248195860fd07345b"
}
```

### Sample 29: `e8c0a568e792becd`

| Field | Value |
|---|---|
| SHA-256 | `e8c0a568e792becdf2986764d2485c797d9af3de4402bd2a5f1064e732a451a5` |
| Family label | `Mirai` |
| File name | `disconnectraw.mips` |
| File type | `elf` |
| First seen | `2026-08-07 01:33:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e67414131e1073b627cfc84b2e616845` |
| SHA-1 | `fdb89a8a38f489d55617b7b0a3d8e4829856ff31` |
| SHA-256 | `e8c0a568e792becdf2986764d2485c797d9af3de4402bd2a5f1064e732a451a5` |
| SHA3-384 | `e0aed32048e0a5d00166fb49328ecd5e85adbbe264dd4de4ab0e1b15f3ab0c2562b038fb076ef97fc33561912bcc4d98` |
| TLSH | `T13C243A4B77118FA0E379D63006F34BA7ABA9228616D39545E36DDE107F6034C682FFA4` |
| TELFHASH | `t14d417604c939cb2a99e203e8cbec5e55ca85d16a9a610f13cf32c75c41b5049911befe` |
| SSDEEP | `3072:wcWRQRKgLXF539VsavywVi5C0Ucms9HEUlQKBxKYZfv3GTkQES9w7IKotjbu:lhIgLVVFzVC49sB/JiyPQEGEIhpK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_e8c0a568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c0a568e792becdf2986764d2485c797d9af3de4402bd2a5f1064e732a451a5"
    family = "Mirai"
    file_name = "disconnectraw.mips"
    file_type = "elf"
    first_seen = "2026-08-07 01:33:37"
  condition:
    hash.sha256(0, filesize) == "e8c0a568e792becdf2986764d2485c797d9af3de4402bd2a5f1064e732a451a5"
}
```

### Sample 30: `2313008eb3ed7c58`

| Field | Value |
|---|---|
| SHA-256 | `2313008eb3ed7c5874283b577f6614bd0eddd471014d3b6b23a8d1218c2f4ae7` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-07 01:33:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4538b25c31206119dbbe7056c7423a76` |
| SHA-1 | `c5e6b9568a6fc3a57d5514e6f80ea8cd2864270d` |
| SHA-256 | `2313008eb3ed7c5874283b577f6614bd0eddd471014d3b6b23a8d1218c2f4ae7` |
| SHA3-384 | `06849daf7a55f8ce8b0506df0791503a49389bbe9146d7b3d3888dd8aafd7d80226399d3d4af03d22b6c76e896c3982a` |
| TLSH | `T1F9E35B06B30D0A47E1632EF43F3B27E1D3DFDA9124E4E640251FAA8A9271D32558ADDD` |
| SSDEEP | `1536:g3Ex7Y865aRP3xzaesgHfbU+pERU+MF5uMuRkpEFtTi49Nd/MG2q3vA16ogbpK0U:pxcM3xGeXy2ATiuNZc12iotHY7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_2313008e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2313008eb3ed7c5874283b577f6614bd0eddd471014d3b6b23a8d1218c2f4ae7"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-07 01:33:29"
  condition:
    hash.sha256(0, filesize) == "2313008eb3ed7c5874283b577f6614bd0eddd471014d3b6b23a8d1218c2f4ae7"
}
```

### Sample 31: `59361ef6ce368657`

| Field | Value |
|---|---|
| SHA-256 | `59361ef6ce36865765e3f07506b99dd55373a8b31e2011b0f77c0d0ad9439126` |
| Family label | `Mirai` |
| File name | `disconnectraw.mips` |
| File type | `elf` |
| First seen | `2026-08-07 01:33:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9090b20001e218c9537d60618fad407` |
| SHA-1 | `802b14d268938cd9dcff28545861bf717a62781e` |
| SHA-256 | `59361ef6ce36865765e3f07506b99dd55373a8b31e2011b0f77c0d0ad9439126` |
| SHA3-384 | `f798099ff91b27eda647a27c925aba57f6af4b4d013fed06ad9f49d14eff367fb4f75bcc0e51ce784c6a1ae3c608117f` |
| TLSH | `T1349302229303B96BD63ECCBB97F517E16DF508351A747A113AF6DFB51A90EE49C00980` |
| SSDEEP | `1536:VB357QiG505OB1sJt24fmRX3OhCJqBNIC5/vyM1zTqYPhi+dOKpAFSbTIZHVEWf:jxus6XH3qBOCPzT/P0qmwPkHVE4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_59361ef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59361ef6ce36865765e3f07506b99dd55373a8b31e2011b0f77c0d0ad9439126"
    family = "Mirai"
    file_name = "disconnectraw.mips"
    file_type = "elf"
    first_seen = "2026-08-07 01:33:28"
  condition:
    hash.sha256(0, filesize) == "59361ef6ce36865765e3f07506b99dd55373a8b31e2011b0f77c0d0ad9439126"
}
```

### Sample 32: `f26e0468626e39ac`

| Field | Value |
|---|---|
| SHA-256 | `f26e0468626e39ac1940aba366021ce782221d505888d15bf95519bc0340c1c9` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-08-07 01:17:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a23c74da92168efe64b1f4d04ea66504` |
| SHA-1 | `5df90d17beb48db6cd3dba88463b066aa2e69c6a` |
| SHA-256 | `f26e0468626e39ac1940aba366021ce782221d505888d15bf95519bc0340c1c9` |
| SHA3-384 | `74e94e824e955d7788f172102c4aea2609c070036345234cb523b639cba0d9585dd5852a1024f825774cc9176ac25d66` |
| TLSH | `T182E31856F8819F11D5C151BAFF0E128E73131B7CE2DE72129D24AB707B8A8BB0E3A515` |
| TELFHASH | `t131213331de3419fc62c1c30a90dfa335569d30b92a142021f2fdbe4f0912bd2f42d922` |
| SSDEEP | `3072:PdgDabQu6uoXtQFzQaNRYZtbEK+Ifg7/D82mUnbPUHp76:POkp6ztQF0azYvoIY7/DoUnbS7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_f26e0468
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f26e0468626e39ac1940aba366021ce782221d505888d15bf95519bc0340c1c9"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-07 01:17:14"
  condition:
    hash.sha256(0, filesize) == "f26e0468626e39ac1940aba366021ce782221d505888d15bf95519bc0340c1c9"
}
```

### Sample 33: `b28df0a1e9e330e2`

| Field | Value |
|---|---|
| SHA-256 | `b28df0a1e9e330e23c3ce483935e9d5f2fd164679806013f10e40e7123aeec4f` |
| Family label | `unknown` |
| File name | `riscv64` |
| File type | `elf` |
| First seen | `2026-08-07 01:17:13` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6b651fd9e10ed7e8f5688793dd8fb38` |
| SHA-1 | `ea530060d196d0e96e884de37c7cf81beb3aead0` |
| SHA-256 | `b28df0a1e9e330e23c3ce483935e9d5f2fd164679806013f10e40e7123aeec4f` |
| SHA3-384 | `1bccbf0a6cf64207ea2ec6ebb98ad421ac5b668fb4280290f04dcc8b99eea38622a4efea82fb9a80280a36a17d325d3e` |
| TLSH | `T19604CF58D9D1BF39C84FA27C51B8C8A4A21290CF1369F30B459DAD3DB28A4D4DF6E8D1` |
| SSDEEP | `3072:o+WD5Ud5TTCa8U2cn+xaSpkLgzNUZE+gYOyfFR7aPGDkEs43Iu:o+OiPl8R6+xXogL+eyPaQkE7z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_b28df0a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b28df0a1e9e330e23c3ce483935e9d5f2fd164679806013f10e40e7123aeec4f"
    family = "unknown"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-08-07 01:17:13"
  condition:
    hash.sha256(0, filesize) == "b28df0a1e9e330e23c3ce483935e9d5f2fd164679806013f10e40e7123aeec4f"
}
```

### Sample 34: `d4cfab5e052df4c0`

| Field | Value |
|---|---|
| SHA-256 | `d4cfab5e052df4c049f258e226d11825cb37b0359be454b83241edd59b295f08` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-07 01:12:19` |
| Reporter | `Bitsight` |
| Tags | `197b1ec4b9644da7b43669fd4f0ed73f, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8fcb7a4ef513ffff9cd2b3448c2b0e0` |
| SHA-1 | `56b6322ec04bb397dcdcab70d50275e689312c4e` |
| SHA-256 | `d4cfab5e052df4c049f258e226d11825cb37b0359be454b83241edd59b295f08` |
| SHA3-384 | `67acb78b4612a99f2f093b26a64402e8ec4ad0b7ab224b10bf4190a9f6952bc276a923654e3767da9535ffd364bd7562` |
| IMPHASH | `8c0ed5311e0eeba51b4c1a13e4263081` |
| TLSH | `T11145BF15A3A411F8E62BC274CA9A5233EBF174811B64EACB1755D65D3F33AD06F3A320` |
| SSDEEP | `24576:F69ePqpqfpP1y2LxKG0+m1gFZ3VttK5O1+MEcCxlnAlQrA:F69ePX110+HFlVts5aCxCM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_d4cfab5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4cfab5e052df4c049f258e226d11825cb37b0359be454b83241edd59b295f08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 01:12:19"
  condition:
    hash.sha256(0, filesize) == "d4cfab5e052df4c049f258e226d11825cb37b0359be454b83241edd59b295f08"
}
```

### Sample 35: `94c78e0d80e3364e`

| Field | Value |
|---|---|
| SHA-256 | `94c78e0d80e3364e1c90d6f5311e6e4104bfa8e831d3351ba8cb875620d0dc64` |
| Family label | `NanoCore` |
| File name | `F32F66F210C25EA6DD97348034BB698B.exe` |
| File type | `exe` |
| First seen | `2026-08-07 00:25:05` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f32f66f210c25ea6dd97348034bb698b` |
| SHA-1 | `717d84b07335ef125dd27c00ef3341933ae2a508` |
| SHA-256 | `94c78e0d80e3364e1c90d6f5311e6e4104bfa8e831d3351ba8cb875620d0dc64` |
| SHA3-384 | `48c0950e9a6676f1db449ff51c107f22fd8bf841a2de4254ce59016d8003df59e740b8b60d978531b5f03ef90a52205b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19114CF267BF98A2FE2DE86B9611212028379C2E399C3F3DE18D455B34F267E506071D3` |
| SSDEEP | `3072:MzEqV6B1jHa6dtJ10jgvzcgi+oG/j9iaMP2s/HIJuP+1Nda82N+xdkv9iRLGeQLe:MLV6Bta6dtJmakIM5zkAgNp/z` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_035_94c78e0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94c78e0d80e3364e1c90d6f5311e6e4104bfa8e831d3351ba8cb875620d0dc64"
    family = "NanoCore"
    file_name = "F32F66F210C25EA6DD97348034BB698B.exe"
    file_type = "exe"
    first_seen = "2026-08-07 00:25:05"
  condition:
    hash.sha256(0, filesize) == "94c78e0d80e3364e1c90d6f5311e6e4104bfa8e831d3351ba8cb875620d0dc64"
}
```

### Sample 36: `f4dc07d863c39fac`

| Field | Value |
|---|---|
| SHA-256 | `f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693` |
| Family label | `unknown` |
| File name | `f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693` |
| File type | `sh` |
| First seen | `2026-08-06 23:55:40` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e2b116f12129f0c5a384ae24d34f061` |
| SHA-1 | `77679188e742cc7f89dcc58de189d3c40b824aa0` |
| SHA-256 | `f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693` |
| SHA3-384 | `ff705de9704c52a9dae43685fb0b80130930fd33a87c867d6d0d6320e1ee58f21a2863bb5ce923f88dc06039d7da79c7` |
| TLSH | `T172F142A53C6594712ACC853C5BDC5A1828EA017F79062D2C340F7D3D2F79664B7FC2AA` |
| SSDEEP | `192:JmtAk1Lr8XgoH9r1PKZihEo8jYtIuCyDA:JmeUSHzPKYhEoeyDA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_f4dc07d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693"
    family = "unknown"
    file_name = "f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693"
    file_type = "sh"
    first_seen = "2026-08-06 23:55:40"
  condition:
    hash.sha256(0, filesize) == "f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693"
}
```

### Sample 37: `7661b8408aa96773`

| Field | Value |
|---|---|
| SHA-256 | `7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd` |
| Family label | `Mirai` |
| File name | `sample` |
| File type | `elf` |
| First seen | `2026-08-06 23:39:38` |
| Reporter | `abuserobot66609` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b39a9cd00020264a81ff64b2e24a8435` |
| SHA-1 | `534a81992d45adbb17d306edde1bce502a3dc21d` |
| SHA-256 | `7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd` |
| SHA3-384 | `d2eb1bf9473888b7c73d6e40608b57cd9a9c3186a35ac4c193bf8648b41acf9a801142b5dd0750bd0d6cdb5bf75f5cf6` |
| TLSH | `T149042945EA404B13C4D627B9F6DF42453333AB9493EB73069528AFB43F8679E4F22A05` |
| TELFHASH | `t178310071567851269aa1ec64d9ed97b2652ac7171340ff32df26c0cc281a449f62ac0f` |
| SSDEEP | `3072:8Le6vh5G1QIruCee+asuTuRebU7IVILUZQe38YhTfYo+M/RzApthLn:0e6vfRIr1r+asuTuReAvLU/38+x+M/R+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_7661b840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-06 23:39:38"
  condition:
    hash.sha256(0, filesize) == "7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd"
}
```

### Sample 38: `f949ba49ba8db0c4`

| Field | Value |
|---|---|
| SHA-256 | `f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f` |
| Family label | `Mirai` |
| File name | `f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:39:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fafe93899795acaecaa8ba1835ddab9` |
| SHA-1 | `ce31ab6cf1ca508fd8f1b54262b14a94094340dc` |
| SHA-256 | `f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f` |
| SHA3-384 | `2592cecd27e65967090fb2f228564c9f66b0d0b3ad3f893cb2245f1ae7d7dd7b75761ec64d27dd4d900402e091509e04` |
| TLSH | `T154C36CC1B10C7EADD5933D7DC20613176E1C9A55DC83810190A6FA53EAB76E32E36ACB` |
| TELFHASH | `t1c7d0c9f1878fa206468ccbcd83c9779c0a0de145004bff13fd22993c80a091cb92998f` |
| SSDEEP | `3072:YfEkkWHEPZ2QHKFZOKSP6X1ypvMctaTQLLjyoBrnQ:QE0OZcCKSP8wvMcgTQXvBDQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_f949ba49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f"
    family = "Mirai"
    file_name = "f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:39:10"
  condition:
    hash.sha256(0, filesize) == "f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f"
}
```

### Sample 39: `032f7dd5999ef636`

| Field | Value |
|---|---|
| SHA-256 | `032f7dd5999ef63685afcf7040a3cde9fbf010efa507fdfe3f17d7630ce128de` |
| Family label | `Mirai` |
| File name | `b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:34:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ffd140909c5ca6c7f14d86f79ce0911` |
| SHA-1 | `91c1de174e5c968a0e009e09f605f97f888e6a8c` |
| SHA-256 | `032f7dd5999ef63685afcf7040a3cde9fbf010efa507fdfe3f17d7630ce128de` |
| SHA3-384 | `0c74b4a6eff2f6b2853577991793bfb07b1d0bf7bc6f631fa9dd89a95def850d6d747db3a93bfe4bab8c3b9d4c9a48e8` |
| TLSH | `T176148D01FB081913D0935EB45B3B0766E379D88318B9E019190E7F569733AFB9AC7B89` |
| SSDEEP | `6144:/hyVd80rgY0BpUrmIQGAIOiYqQdn8l6uN1S:5N0GUyViok1S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_032f7dd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032f7dd5999ef63685afcf7040a3cde9fbf010efa507fdfe3f17d7630ce128de"
    family = "Mirai"
    file_name = "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:37"
  condition:
    hash.sha256(0, filesize) == "032f7dd5999ef63685afcf7040a3cde9fbf010efa507fdfe3f17d7630ce128de"
}
```

### Sample 40: `611c02afa2bc7256`

| Field | Value |
|---|---|
| SHA-256 | `611c02afa2bc725622b7c5154f69b4d5b4f409a46f93ba67dbddcb224d90efc6` |
| Family label | `Mirai` |
| File name | `5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:34:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ee58d073a67f2e1837006815a43a0e0` |
| SHA-1 | `7d34bc32c19d3be303df71e3f5bf007a0326e8bd` |
| SHA-256 | `611c02afa2bc725622b7c5154f69b4d5b4f409a46f93ba67dbddcb224d90efc6` |
| SHA3-384 | `e2db7e8126b8e04ae9984c6f40832695510d679713f686bd3485713c6e72d48d1b5bf82a4d10c1719bdb87ba027ef6fe` |
| TLSH | `T19A042A4F7721CF61C72CC93009B3CB4656E522522AE18889F31DDE08BE65349A96FFD9` |
| TELFHASH | `t1ca31d3b08b7b55119ac5c7ec88ec7756591e8515470adf33fe3180bc50260ece22ad4f` |
| SSDEEP | `3072:+2vvDpgOZfcLfjZaiNxX/iU8hOjQDhd8r570qxGKdSPnlf1DgjjF7:16PivhO681Z7U/l9qjF7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_611c02af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "611c02afa2bc725622b7c5154f69b4d5b4f409a46f93ba67dbddcb224d90efc6"
    family = "Mirai"
    file_name = "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:35"
  condition:
    hash.sha256(0, filesize) == "611c02afa2bc725622b7c5154f69b4d5b4f409a46f93ba67dbddcb224d90efc6"
}
```

### Sample 41: `b82828da08e4b971`

| Field | Value |
|---|---|
| SHA-256 | `b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4` |
| Family label | `Mirai` |
| File name | `b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:34:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `077b850a4ce4ed02c910dbc592cd77ff` |
| SHA-1 | `24fdf07e42d5fd926c2233ca21b21e1222fbde26` |
| SHA-256 | `b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4` |
| SHA3-384 | `42eeb9cf10723e9daa5a9f59356baf2f5bdbe542b91f29eb941530ebc1409cf63b919a73064e2742ab50801fb4e9a4a0` |
| TLSH | `T138530274D4600D62F86215FCBAEAC1C6C396967E383D4FC25F98EEA43E706D992C14E4` |
| SSDEEP | `1536:ACNyK0exfAxE1zTEbMOic4Wpeu+s40mqeC/nmjgxehqM4u+qgw0rG:Ay0yoimbMOb5LmYf8z4u+qgwd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_b82828da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4"
    family = "Mirai"
    file_name = "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:14"
  condition:
    hash.sha256(0, filesize) == "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4"
}
```

### Sample 42: `5b7ce7dd4dae44f7`

| Field | Value |
|---|---|
| SHA-256 | `5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3` |
| Family label | `Mirai` |
| File name | `5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:34:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b53626b25238a22e73e57eb5956bd2d6` |
| SHA-1 | `047bfab761e1a2d47818f94408a80d118e67c192` |
| SHA-256 | `5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3` |
| SHA3-384 | `22e823953578634201cb8ae0daee9ec5258925d98bc1db0c0123ee7dea2bb3a25db13c19950cbcd46686dc76b062efa1` |
| TLSH | `T1C78312D9DC6756B1F657BAD3082C6FE12A42C0AE5E0C51831F4873A14E86DDC9D36D23` |
| SSDEEP | `1536:p2r7eCANVC3phe+ThBwhPhomPMjoQD0QrxUI2dJvmQNvYiZDt9L8uojWxUXGuIjN:p2HeCEC5nLW50MQFrx4JvmmYiB9oYOGL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_5b7ce7dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3"
    family = "Mirai"
    file_name = "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:10"
  condition:
    hash.sha256(0, filesize) == "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3"
}
```

### Sample 43: `2bcd14ad3499be6f`

| Field | Value |
|---|---|
| SHA-256 | `2bcd14ad3499be6f1bc2b4b569df53ee9b70f6dc7eb3865bd6229650a3d634f3` |
| Family label | `Mirai` |
| File name | `fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:29:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfc169d27ea0d2962b6adade5eb268f1` |
| SHA-1 | `bc262fee9560a49489e6dd55a28da255319ede46` |
| SHA-256 | `2bcd14ad3499be6f1bc2b4b569df53ee9b70f6dc7eb3865bd6229650a3d634f3` |
| SHA3-384 | `374cb2e9542f3f04d9dc128979864d65c6a827c8e6ef572bc29c2e090c521b6ae263aef591c5645c23facb168fbd140f` |
| TLSH | `T141C33B06756144FCC156C074C77FA927EA31B85D13343AAF7B84BA31AE22E365F0AB52` |
| SSDEEP | `3072:VLV0Pzv5f3EIPNG2uAKA/C5Sl01PSxDkG4Mh1B:VLVk5fZPNGKC5V1cDky1B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_2bcd14ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bcd14ad3499be6f1bc2b4b569df53ee9b70f6dc7eb3865bd6229650a3d634f3"
    family = "Mirai"
    file_name = "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:39"
  condition:
    hash.sha256(0, filesize) == "2bcd14ad3499be6f1bc2b4b569df53ee9b70f6dc7eb3865bd6229650a3d634f3"
}
```

### Sample 44: `dd2f2a49b031dab6`

| Field | Value |
|---|---|
| SHA-256 | `dd2f2a49b031dab67adaf17071779965ca4d79eb3e1f81be633716493a54d95b` |
| Family label | `Mirai` |
| File name | `c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:29:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56610f03670af192bdc3014d5407ea71` |
| SHA-1 | `b9e070caf435b3686b6ab69e513d4a0d74f97e5b` |
| SHA-256 | `dd2f2a49b031dab67adaf17071779965ca4d79eb3e1f81be633716493a54d95b` |
| SHA3-384 | `95b389c2ee529d599949d9a15732787a0532168cad4120c369e671c20ab15afcef758b47443cb9be5d68978df4a6941b` |
| TLSH | `T12CC329A9F890DE52C6C52676F74E418C33231778D3DA7106CE249E34F7EB95A0E3A942` |
| SSDEEP | `3072:8E/eDOpvJF41gFIXbcYEEU5ajMWxNwhUhGw2P7KNyF3j+uyf1Dl:8wEuFCbcYEEU5ajMW3wst2PnT5y95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_dd2f2a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd2f2a49b031dab67adaf17071779965ca4d79eb3e1f81be633716493a54d95b"
    family = "Mirai"
    file_name = "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:37"
  condition:
    hash.sha256(0, filesize) == "dd2f2a49b031dab67adaf17071779965ca4d79eb3e1f81be633716493a54d95b"
}
```

### Sample 45: `fc09cf6556d51f47`

| Field | Value |
|---|---|
| SHA-256 | `fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585` |
| Family label | `Mirai` |
| File name | `fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:29:14` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e219b47e1417a0a965b98adaf69e812` |
| SHA-1 | `29aec684f3603d2a0de11a0f681c60d5dd009e21` |
| SHA-256 | `fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585` |
| SHA3-384 | `2901fe528c5dd8fc4e6129c1aa985f7c76aaa1e7dd06014e8606cbcecb304e875826b167759725a4a61256f31e73a891` |
| TLSH | `T1DF53026AC147C2B1C1799A322F0C43F4DD71E5C217A79F8BA689F1BD48A7F906444399` |
| SSDEEP | `1536:/lWnNvVkpdSUxQ4gXxoeoO0CVNF5n5lO5t:UTuxQZo2D545t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_fc09cf65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585"
    family = "Mirai"
    file_name = "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:14"
  condition:
    hash.sha256(0, filesize) == "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585"
}
```

### Sample 46: `c0e6f1d6af634fab`

| Field | Value |
|---|---|
| SHA-256 | `c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8` |
| Family label | `Mirai` |
| File name | `c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:29:10` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c008831ee8d964466cf890457726841c` |
| SHA-1 | `c5004f26a06d228ac87810942878bb892cc49708` |
| SHA-256 | `c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8` |
| SHA3-384 | `5a4c7b36223baac4eb2b0b409ece039c2316a5e5db56b26662b3e950c7b8ea988276134e93a9b1db1048cfc06ee8032f` |
| TLSH | `T1E843026E4E5AE936E9BE0836E73A47002522EE22D075733B650C8144DFA61CDD4FD6AC` |
| SSDEEP | `768:bTckj2H6CqS8jo9M3sVj3bUzl7L3YXMtVaQsGfNsf3uSHY/rhPC3Gq3U03wfSl:bwM2aCv19M3k3Uz1iMDaQsGfC3uSyf+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_c0e6f1d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8"
    family = "Mirai"
    file_name = "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:10"
  condition:
    hash.sha256(0, filesize) == "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8"
}
```

### Sample 47: `2055a6d22f882f79`

| Field | Value |
|---|---|
| SHA-256 | `2055a6d22f882f79211a9209556b9d2e14498da87a112007e5fe0d3bf5cbd2fb` |
| Family label | `NanoCore` |
| File name | `A0EBE1250B23CB60D919AA4E7DBD7E40.exe` |
| File type | `exe` |
| First seen | `2026-08-06 23:25:04` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0ebe1250b23cb60d919aa4e7dbd7e40` |
| SHA-1 | `0465401a1bc1b5efbf9d8bd8c3db20a3cc571111` |
| SHA-256 | `2055a6d22f882f79211a9209556b9d2e14498da87a112007e5fe0d3bf5cbd2fb` |
| SHA3-384 | `1fce72747a39ca1388cbdb6cc62c6847ae523b3a3d96965ba415df239ba3f3b98a55f086bcc20a166e0fab926de14e26` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16014CF2677A84A2FE2DE86B9701212039778C2E2A8D3F3DF58D454B75F263E4060B1D7` |
| SSDEEP | `6144:sLV6Bta6dtJmakIM5titzMM3/mpjxE7pzpTVv:sLV6BtpmkGitoxizpZv` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_047_2055a6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2055a6d22f882f79211a9209556b9d2e14498da87a112007e5fe0d3bf5cbd2fb"
    family = "NanoCore"
    file_name = "A0EBE1250B23CB60D919AA4E7DBD7E40.exe"
    file_type = "exe"
    first_seen = "2026-08-06 23:25:04"
  condition:
    hash.sha256(0, filesize) == "2055a6d22f882f79211a9209556b9d2e14498da87a112007e5fe0d3bf5cbd2fb"
}
```

### Sample 48: `94ff3c3a94cf9778`

| Field | Value |
|---|---|
| SHA-256 | `94ff3c3a94cf977890206e7592239387083dfbe2aaa27a2f6f74d7b39d68c8e8` |
| Family label | `Mirai` |
| File name | `f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:24:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cdd3997d23e81d2d8888985e77d2124` |
| SHA-1 | `cf723562e98d21aed0c1d52fcdbe47fffec79ab4` |
| SHA-256 | `94ff3c3a94cf977890206e7592239387083dfbe2aaa27a2f6f74d7b39d68c8e8` |
| SHA3-384 | `4ca58c5094237e000ef5f675517acbcbeaa0f9458f3ff2a0d841c95a6c64b646d2d739dd564b769598f92b746cf4d9bb` |
| TLSH | `T10FC329A9F890DE52C6C52676F74E418C33231778D3DA7106CE249E34F7EB95A0E3A942` |
| SSDEEP | `3072:8E/eDOpvJF41gFIXbcYEEU5ajMWxNwhUhGw2P7KNyF3j+uFf1Dl:8wEuFCbcYEEU5ajMW3wst2PnT5F95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_94ff3c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94ff3c3a94cf977890206e7592239387083dfbe2aaa27a2f6f74d7b39d68c8e8"
    family = "Mirai"
    file_name = "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:40"
  condition:
    hash.sha256(0, filesize) == "94ff3c3a94cf977890206e7592239387083dfbe2aaa27a2f6f74d7b39d68c8e8"
}
```

### Sample 49: `ff75859841364fa7`

| Field | Value |
|---|---|
| SHA-256 | `ff75859841364fa791b47c073bd4a4f37d32be48ce349749a98537b0d0926996` |
| Family label | `Mirai` |
| File name | `eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:24:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `559ec197356fa29937dc96073285b140` |
| SHA-1 | `969014c57e3e4a83a7abfb6fe9543272b96975c6` |
| SHA-256 | `ff75859841364fa791b47c073bd4a4f37d32be48ce349749a98537b0d0926996` |
| SHA3-384 | `1e2397ea414b51c49067bb61d6b347e162f6f5425b6107cba27c30910e4dd42977a16eff410438fd39ba08e7c878ad4b` |
| TLSH | `T16EC329A9F890DE52C6C52676F74E418C33231778D3DA7106CE249E34F7EB95A0E3A942` |
| SSDEEP | `3072:8E/eDOpvJF41gFIXbcYEEU5ajMWxNwhUhGw2P7KNyF3j+uzf1Dl:8wEuFCbcYEEU5ajMW3wst2PnT5z95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_ff758598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff75859841364fa791b47c073bd4a4f37d32be48ce349749a98537b0d0926996"
    family = "Mirai"
    file_name = "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:37"
  condition:
    hash.sha256(0, filesize) == "ff75859841364fa791b47c073bd4a4f37d32be48ce349749a98537b0d0926996"
}
```

### Sample 50: `f52824d120c097cb`

| Field | Value |
|---|---|
| SHA-256 | `f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea` |
| Family label | `Mirai` |
| File name | `f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:24:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7eba7e1c4fb80786d3c400dd6c8ac5f` |
| SHA-1 | `457a1d49a2a1e968db3e1cc9d054b9ff6f27b601` |
| SHA-256 | `f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea` |
| SHA3-384 | `ebf269b5709ca44960b39bb5eb283fc81d9753cb980d3b816bae7f5a2111bd4950db6b19160f8cdf17983e9f33875c6a` |
| TLSH | `T10743F259892BF576EDBF0836E63A47011432AE21C075B33B3D084244EE962DDD9FD968` |
| SSDEEP | `768:bTckj2H6CqS8jo9M3sVj3bUzl7L3YXMtVaQsGfNsf3uSHY/rhP0BWUJScfa43U0u:bwM2aCv19M3k3Uz1iMDaQsGfC3uSc5fp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_f52824d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea"
    family = "Mirai"
    file_name = "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:11"
  condition:
    hash.sha256(0, filesize) == "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea"
}
```

### Sample 51: `eb2ee7f82fbb97e2`

| Field | Value |
|---|---|
| SHA-256 | `eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635` |
| Family label | `Mirai` |
| File name | `eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:24:08` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5afbe6bab9993c484b0480f66e053b50` |
| SHA-1 | `3df6a908813542fa52a8d1bde9eeeb30ffc8973a` |
| SHA-256 | `eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635` |
| SHA3-384 | `3606cb0d62df2e13ad6e666aa559f42dbe02928923aa8d53d79846b7474fd154c5f2f280801fd0da6cd36a2a67390b60` |
| TLSH | `T1B043026E4D27E532E96F1C3EE73B47001922EF11D0AAB33B69084144DA961CED4FC5AC` |
| SSDEEP | `768:bTckj2H6CqS8jo9M3sVj3bUzl7L3YXMtVaQsGfNsf3uSHY/rhPssZ3U03wfSY:bwM2aCv19M3k3Uz1iMDaQsGfC3uSLfv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_eb2ee7f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635"
    family = "Mirai"
    file_name = "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:08"
  condition:
    hash.sha256(0, filesize) == "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635"
}
```

### Sample 52: `9a89598b0696c5ec`

| Field | Value |
|---|---|
| SHA-256 | `9a89598b0696c5ecade5ff4af16042e57fb5c88c4fdbbef94d8c03230a9fb6f2` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-06 23:20:48` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f49c2c9aa9d52ba001569913a47a1f13` |
| SHA-1 | `5e495b95b36062cdf188e5595f1b215a5fef69a2` |
| SHA-256 | `9a89598b0696c5ecade5ff4af16042e57fb5c88c4fdbbef94d8c03230a9fb6f2` |
| SHA3-384 | `01796f7c04f37bc2c8f55de2502eb495bde421e79d1999266dcce1de73c100d619ec7115ae09a1cc60d59c9527930d98` |
| TLSH | `T1A9237D552A817C14AA99C4371D7E2F0CB9AD43E6320492EDBFCF3CF68C4A69DA11871D` |
| SSDEEP | `768:tXOGVvO9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:5Lzcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_9a89598b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a89598b0696c5ecade5ff4af16042e57fb5c88c4fdbbef94d8c03230a9fb6f2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-06 23:20:48"
  condition:
    hash.sha256(0, filesize) == "9a89598b0696c5ecade5ff4af16042e57fb5c88c4fdbbef94d8c03230a9fb6f2"
}
```

### Sample 53: `460e297dfef977c8`

| Field | Value |
|---|---|
| SHA-256 | `460e297dfef977c8054c1ef871cfe6a9102839411308555c1d49480e217e70fb` |
| Family label | `Mirai` |
| File name | `c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:11:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `360803549f1b77a31f368a267796bdd3` |
| SHA-1 | `aaf465228c74bddb9bc510c01133bf85fa77a0bb` |
| SHA-256 | `460e297dfef977c8054c1ef871cfe6a9102839411308555c1d49480e217e70fb` |
| SHA3-384 | `793bdc60cd0af5fcf9e3e5c4fa63d62a6d36c0e02693d9dbc671e345da2ff4950f46e244848ca132d099990cb553c1db` |
| TLSH | `T151E35B59F99BC0F0D6D340F5062BEBAA963B99116173F1B1FF5A3761FCB1201288626C` |
| SSDEEP | `1536:5AVyiyX7cA7e2F3M9x/GXZXSsQAvrnXB1yKFsuNvuDZkUeCsYeaVByo5WIkorKYW:h7AsQAvbysTNvuD+msXaVB15WI1KYW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_460e297d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "460e297dfef977c8054c1ef871cfe6a9102839411308555c1d49480e217e70fb"
    family = "Mirai"
    file_name = "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:11:12"
  condition:
    hash.sha256(0, filesize) == "460e297dfef977c8054c1ef871cfe6a9102839411308555c1d49480e217e70fb"
}
```

### Sample 54: `c151368e6297fcd3`

| Field | Value |
|---|---|
| SHA-256 | `c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c` |
| Family label | `Mirai` |
| File name | `c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:09:56` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8caa0a244ae61d98cd412a7e6e0bcdc` |
| SHA-1 | `2ab569b71e8285dbf74060d4bd4374000bed38b5` |
| SHA-256 | `c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c` |
| SHA3-384 | `01085256ba327997e2562eabc3261cd116b23d35ae0b24c1cd169eca3dd826cf29001b7e785fb582535973559146c8b8` |
| TLSH | `T1CA5301599DF28F9AC747047A14FCFC590416F58DEA9CAF8F8418B25759132E0B88CE62` |
| SSDEEP | `1536:KwWzIeB8WvAIdPPrTt5JCI+CEgJ2LuxYvKMxmIO+5iWQtwnouy8DMw:1W8eBVvA0PPrFCmEOCuCJ3OF4outDMw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_c151368e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c"
    family = "Mirai"
    file_name = "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:09:56"
  condition:
    hash.sha256(0, filesize) == "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c"
}
```

### Sample 55: `e2affa0d6d98ca6c`

| Field | Value |
|---|---|
| SHA-256 | `e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6` |
| Family label | `RemusStealer` |
| File name | `e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6.exe` |
| File type | `exe` |
| First seen | `2026-08-06 23:09:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, RemusStealer, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05c80e5463a628b7c823595f3b1f4bbf` |
| SHA-1 | `cbe184ae6fff5254b172b160e127de27dee3409e` |
| SHA-256 | `e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6` |
| SHA3-384 | `4db2dcf2d48f2f92e2dba81bc2c97f2d41995f42f22ab2af305c29ded499999b2bb0391fcc17b2d7eb259475dbf4b4f6` |
| IMPHASH | `905d6e2fd95bb9d68bb959ec7e8cfb12` |
| TLSH | `T112F4CD04A25924E8D46645F388D1771DA63AFE0432C05EDA7ECEB6716E327D0EDEBE10` |
| SSDEEP | `12288:sVrlAVcbE1nhpWGA8S1DlJdJs2uzjemyXybS9b0KqRYw7OoFHF0eCc:PVcY1nS11ZLC2aimzwb0OoFHieCc` |
| ICON-DHASH | `78f8bcf2b2b0f059` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_055_e2affa0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6"
    family = "RemusStealer"
    file_name = "e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6.exe"
    file_type = "exe"
    first_seen = "2026-08-06 23:09:08"
  condition:
    hash.sha256(0, filesize) == "e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6"
}
```

### Sample 56: `29be0f56275f0511`

| Field | Value |
|---|---|
| SHA-256 | `29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40` |
| Family label | `unknown` |
| File name | `sample_dante.bin` |
| File type | `macho` |
| First seen | `2026-08-06 23:09:06` |
| Reporter | `novumanalytica` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab477021780e553be4271cb34bb8394b` |
| SHA-256 | `29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_29be0f56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40"
    family = "unknown"
    file_name = "sample_dante.bin"
    file_type = "macho"
    first_seen = "2026-08-06 23:09:06"
  condition:
    hash.sha256(0, filesize) == "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40"
}
```

### Sample 57: `148cf20cd5436453`

| Field | Value |
|---|---|
| SHA-256 | `148cf20cd54364532ab66886d91149757827727145fcb4abf8569c14ad3775e8` |
| Family label | `Mirai` |
| File name | `fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:04:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d0f00b10d08b71a845b397ab3bcafca` |
| SHA-1 | `f3994d4b195901d06719eda12975768057037b36` |
| SHA-256 | `148cf20cd54364532ab66886d91149757827727145fcb4abf8569c14ad3775e8` |
| SHA3-384 | `a208bd6ff2050ab224b876d0ae882c945dd98c0a474107ac1664b362ac635e67325b32265b9a72fdb92f74284b504040` |
| TLSH | `T1F8044B49BE746AFBC06FCE30052E930612DD945FE2F6B3796278CD4CB99A20859F3854` |
| TELFHASH | `t1ca31d3b08b7b55119ac5c7ec88ec7756591e8515470adf33fe3180bc50260ece22ad4f` |
| SSDEEP | `3072:1v8J3LK+PiaM1k6XWntKSG11lRm5WFvJv7nmQVq30UK7n4fVYYOev1DG7n:h8J3e2iaM1k6XytKSG11lRm5WFvNJVq2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_148cf20c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "148cf20cd54364532ab66886d91149757827727145fcb4abf8569c14ad3775e8"
    family = "Mirai"
    file_name = "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:41"
  condition:
    hash.sha256(0, filesize) == "148cf20cd54364532ab66886d91149757827727145fcb4abf8569c14ad3775e8"
}
```

### Sample 58: `ce97470535478594`

| Field | Value |
|---|---|
| SHA-256 | `ce974705354785948578000ff6a139dffd8bdda4cd24a1b18bc04df2a71733b4` |
| Family label | `Mirai` |
| File name | `02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:04:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d76a7edf7955021acebf24768c1c080` |
| SHA-1 | `176efc6e98a6dcbd66d1e161865fb934d1f600b1` |
| SHA-256 | `ce974705354785948578000ff6a139dffd8bdda4cd24a1b18bc04df2a71733b4` |
| SHA3-384 | `6fe4ff73ea40b79e5ae290d64c8cad2f4d434b3cbafb54b9ac695d33b49067ff3cabebe315367fa3e9f48262d76746af` |
| TLSH | `T1CBC32B99F890DE52C6D52675FA5E018C332357B8C3EA7206CD209F34B7E7D5A0E3A942` |
| SSDEEP | `3072:ZVJW0PobiEUGHtUQ4g8ObC+qE5HqvfDh6dso4f1Dlu:ZXWHJHtUQ4g8O2+qEIDh6N495` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_ce974705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce974705354785948578000ff6a139dffd8bdda4cd24a1b18bc04df2a71733b4"
    family = "Mirai"
    file_name = "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:39"
  condition:
    hash.sha256(0, filesize) == "ce974705354785948578000ff6a139dffd8bdda4cd24a1b18bc04df2a71733b4"
}
```

### Sample 59: `fd720b19a62efa97`

| Field | Value |
|---|---|
| SHA-256 | `fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a` |
| Family label | `Mirai` |
| File name | `fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:04:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `735890fa4a6428dfa85a29c0c918a4a2` |
| SHA-1 | `179a54adf77861a534b583069ef6b96f23eabdde` |
| SHA-256 | `fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a` |
| SHA3-384 | `452f0d7d7902494da8f1c9ab0994064785d315cbd176c38f83ed0029e45b892c997f58343242c5db7a901e3f0ad44e42` |
| TLSH | `T112831229111913FDDFA34D7052B7B8F7B8A4A079A2C4E2D67540CEB86B490A1F7051E7` |
| SSDEEP | `1536:MlZCNQKJT+1n0Rdiaz3Koqbnede8zucQHeqLYH6RnfaoHzBZQqI2j+NsNP/ej0HD:uwJalJ0yer4HeqLYH6F71ZnCNsNPC0HD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_fd720b19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a"
    family = "Mirai"
    file_name = "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:16"
  condition:
    hash.sha256(0, filesize) == "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a"
}
```

### Sample 60: `02cafc015e53bcb9`

| Field | Value |
|---|---|
| SHA-256 | `02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b` |
| Family label | `Mirai` |
| File name | `02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b.elf` |
| File type | `elf` |
| First seen | `2026-08-06 23:04:11` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, upx, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89baf2d890053bca95badcf9dd11be7c` |
| SHA-1 | `544037e43ac570cc596b28b8fbef19c3af70e154` |
| SHA-256 | `02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b` |
| SHA3-384 | `c8f313d22fb887ae921788bb0150374d7845cc55cbd10a0aa654ea83b84de3d15d4d0ed05aa7cc33919d736bc6105caa` |
| TLSH | `T1A54301DD9712EC48F53419F7DB318093C71BA7798EAB94743560122EEA800E56EF48DB` |
| SSDEEP | `1536:1ULjqNXTXZwRjSoSPBuiq/8qdqalRH+5OZQAiyfc:AjqBD9aq5Ogyk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_02cafc01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b"
    family = "Mirai"
    file_name = "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:11"
  condition:
    hash.sha256(0, filesize) == "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b"
}
```

### Sample 61: `b87b3b60b7350747`

| Field | Value |
|---|---|
| SHA-256 | `b87b3b60b7350747ba6998f50204c78ef0a6fb11281a35c9d15b52ea4765a75c` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.W32.FlyStudio.W.gen.Eldorado.647.26198` |
| File type | `exe` |
| First seen | `2026-08-06 22:50:43` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81e98b864789ad79176a464a7e1f7676` |
| SHA-1 | `01a9fc496ffab7972d6a1a32adbefa8f9e2cec16` |
| SHA-256 | `b87b3b60b7350747ba6998f50204c78ef0a6fb11281a35c9d15b52ea4765a75c` |
| SHA3-384 | `85737e77d161344d4356da5b45a33140f6b5e2645bc277b807b89d3494a2553d22bde9a031800976cbdd2c15c583f1d0` |
| IMPHASH | `cd44d3dd99f5947904ffa3d6ca7a61a5` |
| TLSH | `T10AB733B3116541ECC99BDCBBE3176DF6B9F603234700787051BDAAC91F4A0A9E36B942` |
| SSDEEP | `786432:3MD2hJ1MX2DpxgQ05RcvyiQjC+JSM2SqPn7BNEzzA7EQBHoJ8pRGa7GmlONBJhp+:cD2j1wcxd05MSjCSqzBNEvA7EQuWz7AU` |
| ICON-DHASH | `c8ac2c9eb65c5ccc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_b87b3b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b87b3b60b7350747ba6998f50204c78ef0a6fb11281a35c9d15b52ea4765a75c"
    family = "unknown"
    file_name = "SecuriteInfo.com.W32.FlyStudio.W.gen.Eldorado.647.26198"
    file_type = "exe"
    first_seen = "2026-08-06 22:50:43"
  condition:
    hash.sha256(0, filesize) == "b87b3b60b7350747ba6998f50204c78ef0a6fb11281a35c9d15b52ea4765a75c"
}
```

### Sample 62: `353c5fe38cd4e5a0`

| Field | Value |
|---|---|
| SHA-256 | `353c5fe38cd4e5a0736da021581f782be3c5f6f73da4a035f11f70a305dc19f4` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Trojan.Linux.Mirai.25962.11260` |
| File type | `elf` |
| First seen | `2026-08-06 22:50:39` |
| Reporter | `SecuriteInfoCom` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e36b5a1aeb323557936b7bc8665a7ad` |
| SHA-1 | `8cc7e5ee18fa96656c4bfe44ad839259a558dcde` |
| SHA-256 | `353c5fe38cd4e5a0736da021581f782be3c5f6f73da4a035f11f70a305dc19f4` |
| SHA3-384 | `bcb4a54fcd6e7da7471777006805fe19504f39a882203d16ac80f832727a694e15439ab95892a474574ca0573870e5b5` |
| TLSH | `T15F33D645FA41AB05D5E232FAFB8E414D3317AFA8E3F9312199305FA013C6ADB0B76525` |
| SSDEEP | `1536:dNnT9qKqvYiSrdwotXAGfflUyGAig4zurEy:T9qhSrdwotXoq4zMEy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_353c5fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "353c5fe38cd4e5a0736da021581f782be3c5f6f73da4a035f11f70a305dc19f4"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.25962.11260"
    file_type = "elf"
    first_seen = "2026-08-06 22:50:39"
  condition:
    hash.sha256(0, filesize) == "353c5fe38cd4e5a0736da021581f782be3c5f6f73da4a035f11f70a305dc19f4"
}
```

### Sample 63: `4d24c9c629ce5e5a`

| Field | Value |
|---|---|
| SHA-256 | `4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc` |
| Family label | `Mirai` |
| File name | `4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc.elf` |
| File type | `elf` |
| First seen | `2026-08-06 22:39:17` |
| Reporter | `Tuxxin` |
| Tags | `elf, exe, Mirai, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bba14867fd9c3158489aa5a3018ac2f7` |
| SHA-1 | `9127a1d21c8d7bc193081048c2cb2f60c993eac8` |
| SHA-256 | `4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc` |
| SHA3-384 | `fd3834961c0ff2f959276c4efd6d84ee9a63f7e5dc17eab706a7b0cfa2b1722591a4803b13520339e842fa1020830d2d` |
| TLSH | `T1C1A48D44B54F7D52D3D6E2BCEE0DCAA1B11B79B8C1A3A0B27E43034CC1669E1CAF5961` |
| SSDEEP | `6144:Pv+3wP4HvjcGSaXRyDUnARC8CrqPdeUpccoMax0MRaR+ASdSHP:OA4P4rDYARMr6rCwRR+E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_4d24c9c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc"
    family = "Mirai"
    file_name = "4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc.elf"
    file_type = "elf"
    first_seen = "2026-08-06 22:39:17"
  condition:
    hash.sha256(0, filesize) == "4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc"
}
```

### Sample 64: `652f91bcf60dc148`

| Field | Value |
|---|---|
| SHA-256 | `652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 22:14:12` |
| Reporter | `Bitsight` |
| Tags | `BB5.file, dropped-by-GCleaner, exe, F, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e79ad54bd794375224a5d76d56f3180b` |
| SHA-1 | `7c43762eb07a44ba9add9301546b77e4e6d5bfa7` |
| SHA-256 | `652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9` |
| SHA3-384 | `ad86786193688aaa5c16e3eec427576f6340620b7efe31a7a62991dc181f639e38b8fd4c43febf4674435c3284489016` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T1F3A533D653E41AADD4B8B3B854E115676F31F8608F36924F13F09A8D6D22BE2D936303` |
| SSDEEP | `49152:MSHHf/Y9l1UAuC6uOknC129b8PiW7kRscXcTmfiY4p:9HYvnuCtC29b3W7kRxXcSH` |
| ICON-DHASH | `d8c4a499a1a9e060` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_064_652f91bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 22:14:12"
  condition:
    hash.sha256(0, filesize) == "652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9"
}
```

### Sample 65: `670e15d21d6ffa4f`

| Field | Value |
|---|---|
| SHA-256 | `670e15d21d6ffa4f89be367e9c0007eab1d123f8f92d1af8ac95de8a935e7332` |
| Family label | `unknown` |
| File name | `2.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:46:10` |
| Reporter | `BlinkzSec` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edb7a959d708d5140203cc3dfffc0e95` |
| SHA-1 | `f21d9785056ad3fc871e62348689465a4d8c80a3` |
| SHA-256 | `670e15d21d6ffa4f89be367e9c0007eab1d123f8f92d1af8ac95de8a935e7332` |
| SHA3-384 | `e1d9e3d1152c4abdb4eb5a206316caee815972e3bab706c195c4bc815f40d35fcf96fe3acad136a08d3055134355137b` |
| IMPHASH | `631f628884033ab8daeff2f8fe3a83c6` |
| TLSH | `T1D2B733AB12715059D25AD83D87373FC93AF2676B8A40BC78D4FDCDC82639DD1A123A06` |
| SSDEEP | `786432:d1nF8hbglPRoPTIRWNZ86LRTqjy80enDTLMjaLHag5BA5UFROCTCuIOZJlkzX:dNFEbaRaIReZDLRTrveDTrLHBzAKBrs` |
| ICON-DHASH | `ccf64a9480f170f0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_670e15d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "670e15d21d6ffa4f89be367e9c0007eab1d123f8f92d1af8ac95de8a935e7332"
    family = "unknown"
    file_name = "2.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:46:10"
  condition:
    hash.sha256(0, filesize) == "670e15d21d6ffa4f89be367e9c0007eab1d123f8f92d1af8ac95de8a935e7332"
}
```

### Sample 66: `89f5e86a2ca62dee`

| Field | Value |
|---|---|
| SHA-256 | `89f5e86a2ca62dee4ea9ea65d2235efb36528f987ba4d136326612f79cfe89a9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 21:46:02` |
| Reporter | `Bitsight` |
| Tags | `BB4.file, dropped-by-GCleaner, exe, F` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bdc5d7419f69b538a77b9397c5db01b6` |
| SHA-1 | `5cf2d0a673a924a77f30080307eefb3735abcf87` |
| SHA-256 | `89f5e86a2ca62dee4ea9ea65d2235efb36528f987ba4d136326612f79cfe89a9` |
| SHA3-384 | `c18e304d750b709be6bddb72533935b01b8d66ceac418029f1aa0bd72ebc1ae2ee3dda3bb541860e1b7bcb1160989cf3` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T15D85235197E54063E8DAC7B4A4F04107BBB87C959F79829F2391A1AD0F67E90B23831F` |
| SSDEEP | `49152:rO5IEUpkrtUiNxC/Wk7yHmNP2vAQUptJ:CaE6q/C/7eGNP8RUptJ` |
| ICON-DHASH | `c9938ca1c9e6c8c8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_89f5e86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89f5e86a2ca62dee4ea9ea65d2235efb36528f987ba4d136326612f79cfe89a9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 21:46:02"
  condition:
    hash.sha256(0, filesize) == "89f5e86a2ca62dee4ea9ea65d2235efb36528f987ba4d136326612f79cfe89a9"
}
```

### Sample 67: `accbe9fca34638de`

| Field | Value |
|---|---|
| SHA-256 | `accbe9fca34638def5aa8a0c9d4cd7a536cc631c00a391d75e5a7b7548bade4b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 21:45:50` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0eac77c609e979069a74923fe5816de` |
| SHA-1 | `a36c2fcdb5895a8ab12f57409b855bb945f11112` |
| SHA-256 | `accbe9fca34638def5aa8a0c9d4cd7a536cc631c00a391d75e5a7b7548bade4b` |
| SHA3-384 | `9b709e0847210be9ae602b67bf9984d2a10ad6e36a5f00ef50a73b5ec3a41efbaf4a71c83136ab56e00b1e8bfc96decf` |
| IMPHASH | `fb40ad72cb65f1767a2e06fa73fcbc83` |
| TLSH | `T1E4C602059E5D5270CED64D76E1AA4B340F3A7711E310B4EBAF88828D46FF192D2E364E` |
| SSDEEP | `98304:64EdCO388idcp7+hHL9XEYiUDeksd3p6ro26pHdOwd83r:64Ed3sTI7OL90YiUDhsK/6pHdL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_accbe9fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "accbe9fca34638def5aa8a0c9d4cd7a536cc631c00a391d75e5a7b7548bade4b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 21:45:50"
  condition:
    hash.sha256(0, filesize) == "accbe9fca34638def5aa8a0c9d4cd7a536cc631c00a391d75e5a7b7548bade4b"
}
```

### Sample 68: `57bdbf20404cb95d`

| Field | Value |
|---|---|
| SHA-256 | `57bdbf20404cb95dbe39e87043159e6caf2a44e1a8881775e465f68210bbe644` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 21:40:10` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX4.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceaebe010931012da100e0f99cf1d4c4` |
| SHA-1 | `33c67444509a6dd48172b06634d8fc313e3a62bd` |
| SHA-256 | `57bdbf20404cb95dbe39e87043159e6caf2a44e1a8881775e465f68210bbe644` |
| SHA3-384 | `8c64d475fa0ae7853167854eaba696125ec7d6185fe2266a8cb722ed196118c593f0f29157883352db3e7e718943db38` |
| IMPHASH | `4e2bd2c481372f7ab13b83b63b424e97` |
| TLSH | `T15C967B03EC9415E9C1AEE23189F69652BB31BC494B3263D31B60F2386E77BD09E79354` |
| SSDEEP | `98304:6tg298ahqVvY0HqlUEo5TWdqZGGq8yC2Pjy1U:650HqXACPCYO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_57bdbf20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57bdbf20404cb95dbe39e87043159e6caf2a44e1a8881775e465f68210bbe644"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 21:40:10"
  condition:
    hash.sha256(0, filesize) == "57bdbf20404cb95dbe39e87043159e6caf2a44e1a8881775e465f68210bbe644"
}
```

### Sample 69: `dede2a29a045c3d1`

| Field | Value |
|---|---|
| SHA-256 | `dede2a29a045c3d12dce4b04347a3a4aeb95936f0117a399eaa15eb7d295881f` |
| Family label | `Mirai` |
| File name | `bin.armv5l` |
| File type | `elf` |
| First seen | `2026-08-06 21:30:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47f2cd037bb9439174574900ee32c421` |
| SHA-1 | `168865ebfed9dc3a009815107122107fce6d9b55` |
| SHA-256 | `dede2a29a045c3d12dce4b04347a3a4aeb95936f0117a399eaa15eb7d295881f` |
| SHA3-384 | `a0167d63182deb986a25ce06739e37a4c56dd6c7d29318f3949db8a98394be5ff9b21351b95d74ee46acc7b16b312ad4` |
| TLSH | `T1A4F3F84AFD919F2686D116BBFB4E428D772A5398D2EE3103DD152F24378B85B0E3B142` |
| SSDEEP | `3072:kJ3PN65WmjekuyLAo8hgVbquQiTGFV3b5ZMLfKlv3ftKYjx:Wc5rGysjGuu5TCV3b5OLWfftKYjx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_dede2a29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dede2a29a045c3d12dce4b04347a3a4aeb95936f0117a399eaa15eb7d295881f"
    family = "Mirai"
    file_name = "bin.armv5l"
    file_type = "elf"
    first_seen = "2026-08-06 21:30:18"
  condition:
    hash.sha256(0, filesize) == "dede2a29a045c3d12dce4b04347a3a4aeb95936f0117a399eaa15eb7d295881f"
}
```

### Sample 70: `2cd24da13a8b8abb`

| Field | Value |
|---|---|
| SHA-256 | `2cd24da13a8b8abbfcf0222b47e31707af04a082cb48d7259ac03494bc5842f1` |
| Family label | `Mirai` |
| File name | `bin.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:50` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f7e88a7c8367adbad7ec2c6261ea108` |
| SHA-1 | `b40d878888996f908a607707feb727cfc658ce3c` |
| SHA-256 | `2cd24da13a8b8abbfcf0222b47e31707af04a082cb48d7259ac03494bc5842f1` |
| SHA3-384 | `0877787c2c9e2a80a9d5ce66963dd1fc39399a8a760e490285e575e5edba90427c9b94d103c381ef17b9633048bb1352` |
| TLSH | `T1C1243B037A81C9FEC496D1F04BEB95319A78F82D1635714B3794FFB12A09EE02B6D618` |
| TELFHASH | `t15f71fdb02ec5395ca0d78b45b31efe6cee7214455ee975e8ae67bd90ce43bc00c51422` |
| SSDEEP | `6144:mBbbTJgbFAd/jFSMZkdGFer/+xENv/4X9:m5RjFSMRFer/3/4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_2cd24da1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cd24da13a8b8abbfcf0222b47e31707af04a082cb48d7259ac03494bc5842f1"
    family = "Mirai"
    file_name = "bin.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:50"
  condition:
    hash.sha256(0, filesize) == "2cd24da13a8b8abbfcf0222b47e31707af04a082cb48d7259ac03494bc5842f1"
}
```

### Sample 71: `6eee92142627b47c`

| Field | Value |
|---|---|
| SHA-256 | `6eee92142627b47cadb3a4833b18fa1f850079a4e643db0ef2a462fb2cdbc6f6` |
| Family label | `Mirai` |
| File name | `bin.sh4` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab946227b2955ca11a9370bdcaa76fb3` |
| SHA-1 | `a75303a50632252a373f0dc26d7e3efe26a81902` |
| SHA-256 | `6eee92142627b47cadb3a4833b18fa1f850079a4e643db0ef2a462fb2cdbc6f6` |
| SHA3-384 | `76d3e518c2c956572a57f299f5af8946e63c1ce2bf7887963e059cb811021f7f0f0459875e9d9f7acdbf32bb72505030` |
| TLSH | `T16C045B22DD25AF8AC516A1F0B1F18E789F12BD2548470FF9A5B6EAF44143DC8F1097B8` |
| SSDEEP | `3072:lRKxvYNGszJHjBYLjuvIH7l8WDJWAv8gVmjG7nGw:lRKxvEGsVHjBYLjXtoAvJmjW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_6eee9214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eee92142627b47cadb3a4833b18fa1f850079a4e643db0ef2a462fb2cdbc6f6"
    family = "Mirai"
    file_name = "bin.sh4"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:46"
  condition:
    hash.sha256(0, filesize) == "6eee92142627b47cadb3a4833b18fa1f850079a4e643db0ef2a462fb2cdbc6f6"
}
```

### Sample 72: `b8fa1f90c3611a5f`

| Field | Value |
|---|---|
| SHA-256 | `b8fa1f90c3611a5f80dd2a16903698e41d2f69e425a70a20a710fccfcdcb4768` |
| Family label | `Mirai` |
| File name | `bin.powerpc-440fp` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:46` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97cb0c84a75619b96727d163c40640a6` |
| SHA-1 | `1b07705d0e78317c6848baedabc5cd763bdafa41` |
| SHA-256 | `b8fa1f90c3611a5f80dd2a16903698e41d2f69e425a70a20a710fccfcdcb4768` |
| SHA3-384 | `3c962e088c1e5f990b6f87975bf86b50ba977ba38df61cd68b9fc0ed448df53a8692445b82466bb3edcb15cae55c80c4` |
| TLSH | `T12D2429027B0D0E07D1432DF4267B0BF14BABAD6138FAE681750AFEC957B1DB16449A8D` |
| SSDEEP | `3072:JUEdJWfWs8a85rJ1dNWZMxB999ixFDNJrMh7X1jSgnGu4:JwW7a8tJoZMx/99izDN1MhZj74` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_b8fa1f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8fa1f90c3611a5f80dd2a16903698e41d2f69e425a70a20a710fccfcdcb4768"
    family = "Mirai"
    file_name = "bin.powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:46"
  condition:
    hash.sha256(0, filesize) == "b8fa1f90c3611a5f80dd2a16903698e41d2f69e425a70a20a710fccfcdcb4768"
}
```

### Sample 73: `70e6321443d11cd3`

| Field | Value |
|---|---|
| SHA-256 | `70e6321443d11cd384022b2bf5e1c7594266070715d1c4f0815a13ee329e2698` |
| Family label | `Mirai` |
| File name | `bin.powerpc` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:44` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c281c4f55cb4dcf010789db84af38cd` |
| SHA-1 | `792e3306dda84d83a2d3a022729ef11a7aeaa268` |
| SHA-256 | `70e6321443d11cd384022b2bf5e1c7594266070715d1c4f0815a13ee329e2698` |
| SHA3-384 | `b232ec71bfbb639a7bf57aa14fdc940021ef80af4a7fffbe3eb8f8ab819a270e4502efccc9f4d6cd5f454f4f0067d75e` |
| TLSH | `T1332439027B0D0E03D1532DF0273B1BE14BEFFDA128B5E681755EBEC59271DB22489A99` |
| SSDEEP | `3072:saQzEan+o5ED6tK8ezqDgc5oAx8mNMAbpnFCnVFS/k1jUMnGIq:S+o5lZezoz5bxZMAbpnwzSWj/q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_70e63214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e6321443d11cd384022b2bf5e1c7594266070715d1c4f0815a13ee329e2698"
    family = "Mirai"
    file_name = "bin.powerpc"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "70e6321443d11cd384022b2bf5e1c7594266070715d1c4f0815a13ee329e2698"
}
```

### Sample 74: `a3b4052307fb2f2a`

| Field | Value |
|---|---|
| SHA-256 | `a3b4052307fb2f2a66477e8640bc0937e3f5c86240b9866559eb52d1a6876f24` |
| Family label | `Mirai` |
| File name | `bin.mips64` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:44` |
| Reporter | `BlinkzSec` |
| Tags | `Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ead803e7bbf1e67b9eaf53a4e91613f6` |
| SHA-1 | `98332c85f48df784d630216e4da88bb624ed0a9f` |
| SHA-256 | `a3b4052307fb2f2a66477e8640bc0937e3f5c86240b9866559eb52d1a6876f24` |
| SHA3-384 | `c88edc8c82326b072774e059ddd44327bafa4784207096eade9ad3e354654f73dd7f7a7557f90f7c3a5b01bf4f8d9d04` |
| TLSH | `T19774F8113B47EC7FFD6A03744AF78E7477D865A225A1858AE26ABF4D0F250D10E0CAC9` |
| SSDEEP | `3072:L9QX4IfoljD6IhEu3tXk48h7CJDVPRTfdX5zF/Bn0/P/BM4on8dDDbIR/PVpyHyg:ZioljD6IhXXAm7IHBsoOVp8q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_a3b40523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3b4052307fb2f2a66477e8640bc0937e3f5c86240b9866559eb52d1a6876f24"
    family = "Mirai"
    file_name = "bin.mips64"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "a3b4052307fb2f2a66477e8640bc0937e3f5c86240b9866559eb52d1a6876f24"
}
```

### Sample 75: `e0a1adc708da1bb9`

| Field | Value |
|---|---|
| SHA-256 | `e0a1adc708da1bb9718b698d137fe065ba54ad47da72f30eaf3839fa5ebee372` |
| Family label | `Mirai` |
| File name | `bin.mipsel` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:44` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c36062f54a8d15231e9222265752c9fa` |
| SHA-1 | `c2573f9163714b0b99676df39e14e0442365dfd9` |
| SHA-256 | `e0a1adc708da1bb9718b698d137fe065ba54ad47da72f30eaf3839fa5ebee372` |
| SHA3-384 | `b234f546bad2a246f14d5f652e773e8a2a89d5f19d258f127f07ab5d00321a0330be273f95177e01f3f630430c4f3c2f` |
| TLSH | `T15654D60A7B518FB7D46FCD3306F98B0128CCB45335652B7A3670E65CB62A58B0AD38B4` |
| SSDEEP | `3072:tr8nUqqlQzmhMfC9oS/Zmt7Miq03ZTC7QKpUoCGtte6jiRnGcLA3J:eHt7MspyQ4jt9jkLo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_e0a1adc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0a1adc708da1bb9718b698d137fe065ba54ad47da72f30eaf3839fa5ebee372"
    family = "Mirai"
    file_name = "bin.mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "e0a1adc708da1bb9718b698d137fe065ba54ad47da72f30eaf3839fa5ebee372"
}
```

### Sample 76: `2f516e833a42b768`

| Field | Value |
|---|---|
| SHA-256 | `2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472` |
| Family label | `Mirai` |
| File name | `bin.mips` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:43` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6f0343531ec9cbce967869559327193` |
| SHA-1 | `46b24d24f39e4d325ee9f8381571d1601cdc9401` |
| SHA-256 | `2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472` |
| SHA3-384 | `61b7968311d8e90cd54003a6f6507f52b5e7c9c5e30dbdfc32ddb960e262d3d561fcd6f5f1faa4e8894f661163890c4e` |
| TLSH | `T124548A1A2E22DF7FF66D867047F389305A9876D62AE1D544F16CE60C1F2028E641F7E8` |
| TELFHASH | `t1825190180d7817f4a6655c9d49acff36d6a330df7e161c378e50e86eab6aa435d00c0d` |
| SSDEEP | `6144:cRR/4cIFT5z7L+gzX24siwzrC6lSqpj2TZKjB/6:F5z7TDrwzrVjBy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_2f516e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472"
    family = "Mirai"
    file_name = "bin.mips"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:43"
  condition:
    hash.sha256(0, filesize) == "2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472"
}
```

### Sample 77: `82d16a631297bdfd`

| Field | Value |
|---|---|
| SHA-256 | `82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb` |
| Family label | `Mirai` |
| File name | `bin.m68k` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:41` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `261b51613dd261926d2ca9a711e3b081` |
| SHA-1 | `6fc8d66cad0590dcca2663676c48e4651f7600d2` |
| SHA-256 | `82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb` |
| SHA3-384 | `dd76e30e4a406c879563f4c8cd5b9d128eb57b4e04dd8c166af973b924bacc11c9da2737ccc6b9a6c7dfa7e607a16130` |
| TLSH | `T1C8342A87F900DF7EFC07A27244A70919B130BF7618620A77F126BDE69E390D5192BE85` |
| SSDEEP | `6144:ogVITOHZW5nU2Yme6WJBvSqSyF2bDs9TLPxE/1LaTIK+:owITM5LPHTIK+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_82d16a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb"
    family = "Mirai"
    file_name = "bin.m68k"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:41"
  condition:
    hash.sha256(0, filesize) == "82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb"
}
```

### Sample 78: `c765ed5690a276fb`

| Field | Value |
|---|---|
| SHA-256 | `c765ed5690a276fba464020b7b87f827ed9315b64822bbcb216b5eb06f1896eb` |
| Family label | `Mirai` |
| File name | `bin.i686` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:41` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `538c2244d87478e7dfcd65a276bb2612` |
| SHA-1 | `6532aaaa6d6f0b13f335caec054dc20614d8da5b` |
| SHA-256 | `c765ed5690a276fba464020b7b87f827ed9315b64822bbcb216b5eb06f1896eb` |
| SHA3-384 | `95cbcff0dced394f7f9fca0d71566b1c79bd74f66d759a72386cbe1be6bfad3868ba5aea98f8763120f2ea5aeac7ce73` |
| TLSH | `T176141A45FA43CEF3E41304F011B7A63E4B30ED394826D599EBA8BEB5D9236C1661636C` |
| TELFHASH | `t1d3915b76a9a61bed7be0d902d6cb5311ce18e17b352035fd06f616c832b2f416366c3a` |
| SSDEEP | `3072:czQv74CdX62aqDXqFbg5HwKeYii+Scgcb7OQ3lpDi1:cskuq2aEP1BVmyQnDi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_c765ed56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c765ed5690a276fba464020b7b87f827ed9315b64822bbcb216b5eb06f1896eb"
    family = "Mirai"
    file_name = "bin.i686"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:41"
  condition:
    hash.sha256(0, filesize) == "c765ed5690a276fba464020b7b87f827ed9315b64822bbcb216b5eb06f1896eb"
}
```

### Sample 79: `958dabdb8ea42dfd`

| Field | Value |
|---|---|
| SHA-256 | `958dabdb8ea42dfd3725bf70d8d8641b794298942269d33a921d2428a9f0bf20` |
| Family label | `Mirai` |
| File name | `bin.i486` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ed1b3d25151c7f45b0e09626ab7eebd` |
| SHA-1 | `54bcec92d22d6caaa2f297f43ac872dc223dcedd` |
| SHA-256 | `958dabdb8ea42dfd3725bf70d8d8641b794298942269d33a921d2428a9f0bf20` |
| SHA3-384 | `c44ee00674fe690b07467348ee6cc26f7a75b64adedd5eb5ceb0b7c9f5accc6a7c2407a9de70807c1a1b258d047bb87c` |
| TLSH | `T1B4043802E603CDB2C01301B212B7DB760E31F9B7AE26D452D3BCFEA5AD616D1654936E` |
| TELFHASH | `t18b912b75fef509dcb7d0c801d24e5361de19e53b34503aba0af2269837b2a42527ac7a` |
| SSDEEP | `3072:svxSRDk8dj118115ccNaCJEb/+BIhbjoHU8gYlpm8X:svKJr7cNaIGjbjo08fm8X` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_958dabdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "958dabdb8ea42dfd3725bf70d8d8641b794298942269d33a921d2428a9f0bf20"
    family = "Mirai"
    file_name = "bin.i486"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:40"
  condition:
    hash.sha256(0, filesize) == "958dabdb8ea42dfd3725bf70d8d8641b794298942269d33a921d2428a9f0bf20"
}
```

### Sample 80: `e2d12341dfc7c12a`

| Field | Value |
|---|---|
| SHA-256 | `e2d12341dfc7c12aefa0bad0610e44723628d84459e3412d745e2dd59f3965e1` |
| Family label | `Mirai` |
| File name | `bin.i586` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:40` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86efef3f38397bfe5158d47ac54332e1` |
| SHA-1 | `6b71b2fa08ac01b062b6ae213019f571d47eeb06` |
| SHA-256 | `e2d12341dfc7c12aefa0bad0610e44723628d84459e3412d745e2dd59f3965e1` |
| SHA3-384 | `99e647d5d509f15a0d610f7951431830da3d4cf3cb299d6669fcd101ffa4e76cb09d239bd00828fab8273909b9243af4` |
| TLSH | `T1E404F856EA43DFB3E51341F202B787310E71ED7A6C26D542E3BCACB49A619C1A60637C` |
| TELFHASH | `t1ec9148b5bfb209dcb7d0d902d24d5721dd1cd53b745079ba0af2269837b2b026276c39` |
| SSDEEP | `3072:ZfiM6+zlDCR5e+CpUFUy+4sOmnLHtXgnhbyEPOx23yi9VO67Fn6fRDlpGe:ZtdCR5e+ULLlgnmc3yibHpYRbGe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_e2d12341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2d12341dfc7c12aefa0bad0610e44723628d84459e3412d745e2dd59f3965e1"
    family = "Mirai"
    file_name = "bin.i586"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:40"
  condition:
    hash.sha256(0, filesize) == "e2d12341dfc7c12aefa0bad0610e44723628d84459e3412d745e2dd59f3965e1"
}
```

### Sample 81: `b435762e4fbe122d`

| Field | Value |
|---|---|
| SHA-256 | `b435762e4fbe122df3b90b006bad194b4293755389be09b3e53e6b87bb0f9c2e` |
| Family label | `Mirai` |
| File name | `bin.armv7l` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:39` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e30eb70b8e1f97d439abd9f09d331bc` |
| SHA-1 | `4a07065a40417425d9f23404a8e35bd319224bf1` |
| SHA-256 | `b435762e4fbe122df3b90b006bad194b4293755389be09b3e53e6b87bb0f9c2e` |
| SHA3-384 | `73d9f4482d81f5faaec0770ddde230d67ea4af49253a0b6391ef190383fcb842f5b50e0cd54308b95001805e8d0d7627` |
| TLSH | `T1ED14F70AB9919F11D5D231FEFA9F419833136BA8D7FA7101DD206F6033C699B0B7A216` |
| SSDEEP | `6144:xQjJUveb5+Ms0zcPXKUCas/MPVztIPJhPt/iO8jj2i:xQjWel+tScPXKJascVztIPvJiO8jj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_b435762e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b435762e4fbe122df3b90b006bad194b4293755389be09b3e53e6b87bb0f9c2e"
    family = "Mirai"
    file_name = "bin.armv7l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:39"
  condition:
    hash.sha256(0, filesize) == "b435762e4fbe122df3b90b006bad194b4293755389be09b3e53e6b87bb0f9c2e"
}
```

### Sample 82: `516c4512ef992282`

| Field | Value |
|---|---|
| SHA-256 | `516c4512ef9922821eed1f2489b5a5243b757b30d2bf018a85b27ecdefee5826` |
| Family label | `Mirai` |
| File name | `bin.armv6l` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:38` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfdb6901df97436fb36d196e6581e8c6` |
| SHA-1 | `ab77a10620ddaf64173d604af3a3a63cf27c4007` |
| SHA-256 | `516c4512ef9922821eed1f2489b5a5243b757b30d2bf018a85b27ecdefee5826` |
| SHA3-384 | `9b39346271182d91294ad6bc1680423fd28c8f72938f17385202b4da2f2ab874f9ae66b514c168ee56546a0718fa6074` |
| TLSH | `T1FB24E947B991CF12C1C111FEFE5E418D37136FB8D2DA72029D24AFA477868EA0E7A116` |
| SSDEEP | `6144:B3GbATqHMcX7qloyeJa3iVf5L56WeFjmhCjsa2:B2b1McXOlYJa3M8We9mYjs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_516c4512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "516c4512ef9922821eed1f2489b5a5243b757b30d2bf018a85b27ecdefee5826"
    family = "Mirai"
    file_name = "bin.armv6l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:38"
  condition:
    hash.sha256(0, filesize) == "516c4512ef9922821eed1f2489b5a5243b757b30d2bf018a85b27ecdefee5826"
}
```

### Sample 83: `9f5372d58342c988`

| Field | Value |
|---|---|
| SHA-256 | `9f5372d58342c98892588edb4c05af2e7d237f79448d51bef2412fed77f0c495` |
| Family label | `Mirai` |
| File name | `bin.armv5l` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:38` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7df50caab0dca9b69b230a9e95cd08e8` |
| SHA-1 | `80f1fc2a1142a40a4ccb717d2f6c14d5f796d657` |
| SHA-256 | `9f5372d58342c98892588edb4c05af2e7d237f79448d51bef2412fed77f0c495` |
| SHA3-384 | `8ebf01187baa9cedd29f75da7cbfbd9d18b7cb33ac0cabbb61b49cd0ed4215a7382726f2f7f1b7183731e8fc97476f48` |
| TLSH | `T1F414E846BD518F23C6C311FAFB9F429C37266BA8D6EB3102DD157FA437864DA093A211` |
| TELFHASH | `t159110002aeb419befad1c0be42dd60172704304aad6438f8dcbdfa6d6353d98703680b` |
| SSDEEP | `3072:kJ3PN65WmjekuyLAo8hgVbquQiTGFV3b5ZMLfKlv3ftKYjI7nG6gk0L:Wc5rGysjGuu5TCV3b5OLWfftKYjXk0L` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_9f5372d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f5372d58342c98892588edb4c05af2e7d237f79448d51bef2412fed77f0c495"
    family = "Mirai"
    file_name = "bin.armv5l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:38"
  condition:
    hash.sha256(0, filesize) == "9f5372d58342c98892588edb4c05af2e7d237f79448d51bef2412fed77f0c495"
}
```

### Sample 84: `5fb744c398342172`

| Field | Value |
|---|---|
| SHA-256 | `5fb744c3983421724443599492d9d5f0667fe1fbcb8a80f0879488983320f06e` |
| Family label | `Mirai` |
| File name | `bin.armv4l` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:37` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acadeed043d9fd1d52ae7af652cafd6a` |
| SHA-1 | `9a3028282e3a2125bdcde270ae90df8839777d20` |
| SHA-256 | `5fb744c3983421724443599492d9d5f0667fe1fbcb8a80f0879488983320f06e` |
| SHA3-384 | `1e3b56fb301b738e16ead321e3bfda3a1dfb9a18cb9c78712527408d4e34c5777a36e261dd49eeb3a17a823fe94bddb7` |
| TLSH | `T15314E946BD519F23C5C311FBFB9F429C3B2667A8D6EA3102DD256FA437864DA093B201` |
| TELFHASH | `t118f0a21ddef91e9d66dc0048c8fb2514d7a470c43750296e9a9e9f3a8c915f1342890a` |
| SSDEEP | `3072:/+ajkQJQMtbE3bDAjg1Yct3TidXTNrkR6CA5584wx1Kjh7nGPdL:xJJJsb081FVedXTNkR6CAP871Kj+dL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_5fb744c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fb744c3983421724443599492d9d5f0667fe1fbcb8a80f0879488983320f06e"
    family = "Mirai"
    file_name = "bin.armv4l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:37"
  condition:
    hash.sha256(0, filesize) == "5fb744c3983421724443599492d9d5f0667fe1fbcb8a80f0879488983320f06e"
}
```

### Sample 85: `d93d9b733dbd17c9`

| Field | Value |
|---|---|
| SHA-256 | `d93d9b733dbd17c9b1d60774e2be07aa06ccfec66425cef2c6bad882854155d5` |
| Family label | `Mirai` |
| File name | `bin.armv4tl` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:37` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c3dfe3f3b318f48e684994d0e83c1b31` |
| SHA-1 | `f991580071d57fee5eec725beb956d7c444bd19e` |
| SHA-256 | `d93d9b733dbd17c9b1d60774e2be07aa06ccfec66425cef2c6bad882854155d5` |
| SHA3-384 | `da9fa8099d583b56885a81e84b4434d0ec6238c613934ec8f68bac18973c5113ed9321dd9d85dfa276f62c063226dd34` |
| TLSH | `T1EB24E947B991CF12C1C111FEFE5E418D37136FB8D2DA72029D24AFA477868EA0E7A116` |
| SSDEEP | `6144:BJGbATqHMcX7qloyeJa3iVf5L56WeFjmhCj6a2:Bkb1McXOlYJa3M8We9mYj6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_d93d9b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d93d9b733dbd17c9b1d60774e2be07aa06ccfec66425cef2c6bad882854155d5"
    family = "Mirai"
    file_name = "bin.armv4tl"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:37"
  condition:
    hash.sha256(0, filesize) == "d93d9b733dbd17c9b1d60774e2be07aa06ccfec66425cef2c6bad882854155d5"
}
```

### Sample 86: `72dd47f7eedc101f`

| Field | Value |
|---|---|
| SHA-256 | `72dd47f7eedc101f63f5f557651a388013319bb73e96a0c821252b75f2217169` |
| Family label | `Mirai` |
| File name | `bin.armv4eb` |
| File type | `elf` |
| First seen | `2026-08-06 21:09:36` |
| Reporter | `BlinkzSec` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de10cf62d704b9e3c05ff05053e0dc63` |
| SHA-1 | `98e1872239863df0e842dbeca0af885911574d57` |
| SHA-256 | `72dd47f7eedc101f63f5f557651a388013319bb73e96a0c821252b75f2217169` |
| SHA3-384 | `aa8cd373de7ae86ba99313464850a8b969eb10b489b80933bfb48b0a4c78fd85c450a36ca50b66f400104045ecdd0319` |
| TLSH | `T1C4241990BA59EC32C05E1D3667FBDB593B4369D14EA39104C460EBCCBB871C0AB6857B` |
| SSDEEP | `3072:nDbfo8kLrr1j5kQts04meSPuBThOdAAVR47WKhSjU7nGGrz22:nfYLX3kQS05Pud4VR4Hwjurz22` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_72dd47f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72dd47f7eedc101f63f5f557651a388013319bb73e96a0c821252b75f2217169"
    family = "Mirai"
    file_name = "bin.armv4eb"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:36"
  condition:
    hash.sha256(0, filesize) == "72dd47f7eedc101f63f5f557651a388013319bb73e96a0c821252b75f2217169"
}
```

### Sample 87: `5b2d48b4ea0599e4`

| Field | Value |
|---|---|
| SHA-256 | `5b2d48b4ea0599e4cfa18fd532be04ce24fcb559d789432a64708feea05bf83f` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:08:32` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe44783ba824629a0e2b909a6a9b80a2` |
| SHA-1 | `1fbd1a082a9ee5c24578e77d913b6461c48f7411` |
| SHA-256 | `5b2d48b4ea0599e4cfa18fd532be04ce24fcb559d789432a64708feea05bf83f` |
| SHA3-384 | `b466c3da9c1e9361a526e3d7c2e3fa0a3aac324a8c0b469cee2abf158e93710785c10742019a1367b40d6ec6b6769171` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T12246E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:qzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:qhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_087_5b2d48b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b2d48b4ea0599e4cfa18fd532be04ce24fcb559d789432a64708feea05bf83f"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:32"
  condition:
    hash.sha256(0, filesize) == "5b2d48b4ea0599e4cfa18fd532be04ce24fcb559d789432a64708feea05bf83f"
}
```

### Sample 88: `1d9a1b096c4ae71f`

| Field | Value |
|---|---|
| SHA-256 | `1d9a1b096c4ae71f9c0403802667ea0b3492de2d57281a6d4145ba5758e74bad` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:08:31` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c3de5d59d0d41f5c593c4ecf152cfc0` |
| SHA-1 | `3d927f1e53fcb9d1873527fd760e6910eccd8b21` |
| SHA-256 | `1d9a1b096c4ae71f9c0403802667ea0b3492de2d57281a6d4145ba5758e74bad` |
| SHA3-384 | `a501998d16bdb02ff0cf6491f814550d5113d4475591afd357fed0bbe73d1cf9f96f5362ab86ad1044f6bbd20d2dfd05` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T198646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:ymlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:R1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_088_1d9a1b09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d9a1b096c4ae71f9c0403802667ea0b3492de2d57281a6d4145ba5758e74bad"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:31"
  condition:
    hash.sha256(0, filesize) == "1d9a1b096c4ae71f9c0403802667ea0b3492de2d57281a6d4145ba5758e74bad"
}
```

### Sample 89: `60df12c872628826`

| Field | Value |
|---|---|
| SHA-256 | `60df12c872628826a9a5289474082ffe1ea55819133219dde1d656bdb0d502fd` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:08:08` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f8c1135c656b7b91f1da74cbfee5ea2` |
| SHA-1 | `e18b8195f4b99f8f4d4b2ab72f52ff479d26b33d` |
| SHA-256 | `60df12c872628826a9a5289474082ffe1ea55819133219dde1d656bdb0d502fd` |
| SHA3-384 | `131d56a52a035419ae4eaa0a5dfe63343a8dd47643f1d07b830e08a5364ee9aed63125c72c429ed8f471dff863347ad9` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T12546E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:XzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:XhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_089_60df12c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60df12c872628826a9a5289474082ffe1ea55819133219dde1d656bdb0d502fd"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:08"
  condition:
    hash.sha256(0, filesize) == "60df12c872628826a9a5289474082ffe1ea55819133219dde1d656bdb0d502fd"
}
```

### Sample 90: `b5f7df56de192f53`

| Field | Value |
|---|---|
| SHA-256 | `b5f7df56de192f53a8122e1e6a7d83c80344d94b401d140004cff8cf04252757` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:08:06` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `455f63ee9d170effdb2305c22977cef8` |
| SHA-1 | `65a8062fbb1555872ba67e696dfc9b67a8a334e4` |
| SHA-256 | `b5f7df56de192f53a8122e1e6a7d83c80344d94b401d140004cff8cf04252757` |
| SHA3-384 | `7e0871edc17e502c04f5392e73d24fb7946ac2f2d6171773966f156f870ca1f74ff090453e74267cb2a6354c756d189a` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T1DA647C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:CmlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9:B1iw7gryNkSV1hy1Z1u2JLu9` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_090_b5f7df56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5f7df56de192f53a8122e1e6a7d83c80344d94b401d140004cff8cf04252757"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:06"
  condition:
    hash.sha256(0, filesize) == "b5f7df56de192f53a8122e1e6a7d83c80344d94b401d140004cff8cf04252757"
}
```

### Sample 91: `cdf1259459502c82`

| Field | Value |
|---|---|
| SHA-256 | `cdf1259459502c82ce1bcb0651d6dba80d6f0bb2c7418e6a4ab75d0c4718536c` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:05:11` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37af0be3dccc41a28468d76454485b4f` |
| SHA-1 | `000c5d3519a58d1c7aa14b63b04cea34d1a39ee1` |
| SHA-256 | `cdf1259459502c82ce1bcb0651d6dba80d6f0bb2c7418e6a4ab75d0c4718536c` |
| SHA3-384 | `6e393862483385bf7d4c3bbb3e1e7b1992f0241b50416d5fbc7a363fff3105dac3ee67afad982b8902453d083315c2a5` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1E846E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:vzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:vhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_091_cdf12594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdf1259459502c82ce1bcb0651d6dba80d6f0bb2c7418e6a4ab75d0c4718536c"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:05:11"
  condition:
    hash.sha256(0, filesize) == "cdf1259459502c82ce1bcb0651d6dba80d6f0bb2c7418e6a4ab75d0c4718536c"
}
```

### Sample 92: `b8bec7b45605da35`

| Field | Value |
|---|---|
| SHA-256 | `b8bec7b45605da355b092c9f3e40bab447928839d4eef5a9290cb5bb1dd50f2d` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-06 21:05:08` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bab937bd0f559a42ebd338416f5ed99f` |
| SHA-1 | `8ffcd01fed2d1735914475f51e33801fd13cceaf` |
| SHA-256 | `b8bec7b45605da355b092c9f3e40bab447928839d4eef5a9290cb5bb1dd50f2d` |
| SHA3-384 | `e5b225bc141a12b71b632c1a3c95bfdd98affd786f11831f166f8cd445ac1e630e445164ee3a3aebcbda2cebb58b2c31` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T184647D11B9C48432C273383147B8E2B28DBDB8301D655B8F57A81D7A9F745D0EA29B6F` |
| SSDEEP | `6144:imlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji98:h1iw7gryNkSV1hy1Z1u2JLu98` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_092_b8bec7b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bec7b45605da355b092c9f3e40bab447928839d4eef5a9290cb5bb1dd50f2d"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:05:08"
  condition:
    hash.sha256(0, filesize) == "b8bec7b45605da355b092c9f3e40bab447928839d4eef5a9290cb5bb1dd50f2d"
}
```

### Sample 93: `3caaa5e8cab6d0ec`

| Field | Value |
|---|---|
| SHA-256 | `3caaa5e8cab6d0ec2932ea20fb71301eeea20ea16ea18d4cde08f8130a59fd25` |
| Family label | `ConnectWise` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:57:49` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `683223a69f91887a6cb4f68b50adefb2` |
| SHA-1 | `1d766b04adda359f3a5b062f6abfc20e1a32e1e4` |
| SHA-256 | `3caaa5e8cab6d0ec2932ea20fb71301eeea20ea16ea18d4cde08f8130a59fd25` |
| SHA3-384 | `1d8d436d03d6b9265fa84bc9bd4541b093396fd1b8afba7009d73d3126fb917b7fff2ebae8dcdd1dc57be66304737b09` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T1A846E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:fzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:fhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_093_3caaa5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3caaa5e8cab6d0ec2932ea20fb71301eeea20ea16ea18d4cde08f8130a59fd25"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:57:49"
  condition:
    hash.sha256(0, filesize) == "3caaa5e8cab6d0ec2932ea20fb71301eeea20ea16ea18d4cde08f8130a59fd25"
}
```

### Sample 94: `4b1f69dcea99ca1e`

| Field | Value |
|---|---|
| SHA-256 | `4b1f69dcea99ca1e1884a377ed2481ee1f0d543e7faade27f6ac3dc850042233` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:57:43` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdb6c03e9d9e120f85e827954d55bd88` |
| SHA-1 | `bee0adee9ff4bd8cce13bef4381c5f6dcee3aa25` |
| SHA-256 | `4b1f69dcea99ca1e1884a377ed2481ee1f0d543e7faade27f6ac3dc850042233` |
| SHA3-384 | `7ff572bb5463016db60274e5562c62bda83af12c8a19a9818af63b5c6bd9f5dd91a78063ffe78a4f04594a005a3f6c02` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T176646D11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:imlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9f:h1iw7gryNkSV1hy1Z1u2JLu9f` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_094_4b1f69dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1f69dcea99ca1e1884a377ed2481ee1f0d543e7faade27f6ac3dc850042233"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:57:43"
  condition:
    hash.sha256(0, filesize) == "4b1f69dcea99ca1e1884a377ed2481ee1f0d543e7faade27f6ac3dc850042233"
}
```

### Sample 95: `73c8b883889a87c6`

| Field | Value |
|---|---|
| SHA-256 | `73c8b883889a87c6844c8eab2f3540141eb078d44b741c843abc7fda2ccf2bed` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-08-06 20:53:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9f5cba4674287afbed72c63c9d6185ba` |
| SHA-1 | `8de7ef98123e999d700c5fd39ec0b845fca9cd92` |
| SHA-256 | `73c8b883889a87c6844c8eab2f3540141eb078d44b741c843abc7fda2ccf2bed` |
| SHA3-384 | `189106b52cf673ce7c4fb9d76417122243a7a61cb2d2cb305e399f00a8a965bf13fcb9bf1125c46c1fe177a9fc2ea189` |
| TLSH | `T1D2C30749ED41AF11E5D636FEFA4F028933531B6CE3FE7201AA245B2123CAA5B0F76505` |
| SSDEEP | `3072:zsJCzu/SEG4z8hMZnda2rbdrodpGQQ8e4t+ox4cvACH:z4CSKC82Rda23drodpYytfx4cvACH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_73c8b883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73c8b883889a87c6844c8eab2f3540141eb078d44b741c843abc7fda2ccf2bed"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-06 20:53:01"
  condition:
    hash.sha256(0, filesize) == "73c8b883889a87c6844c8eab2f3540141eb078d44b741c843abc7fda2ccf2bed"
}
```

### Sample 96: `2f029858b8ecca8f`

| Field | Value |
|---|---|
| SHA-256 | `2f029858b8ecca8fb6c156eb2d046a2463e8b67d356c1003e5567339681a71be` |
| Family label | `unknown` |
| File name | `bhatta.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:52:44` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-OffLoader, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5be302261ca861b71f8b75a21e635618` |
| SHA-1 | `4bd636293f63519b3f1f438fa164a1f5cc10fc53` |
| SHA-256 | `2f029858b8ecca8fb6c156eb2d046a2463e8b67d356c1003e5567339681a71be` |
| SHA3-384 | `5c05c8d15bd2eacc1077d16489547c14bc8a02b53ed14ce921f157a31770b55dad8071eec178421e4eddf4f83ab72760` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1F3F55B07ACA189F5C095B73188B79296B771B8085B3537C32EA1AFB82FB23D05D76744` |
| SSDEEP | `24576:Oebi5XrxIxCv3GiszJcKCDEKboo51CCN0+apQ6OMPZFYKYuumrv/oBele5I92wi7:OebK7mxeGjnWEKcorCCNtsvxumRLVcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_2f029858
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f029858b8ecca8fb6c156eb2d046a2463e8b67d356c1003e5567339681a71be"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:52:44"
  condition:
    hash.sha256(0, filesize) == "2f029858b8ecca8fb6c156eb2d046a2463e8b67d356c1003e5567339681a71be"
}
```

### Sample 97: `a43abf1be5dd450d`

| Field | Value |
|---|---|
| SHA-256 | `a43abf1be5dd450dd88370d503721ea3d1b228d06a3ad4957f57a08a73cad669` |
| Family label | `unknown` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:52:42` |
| Reporter | `BlinkzSec` |
| Tags | `signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5c4a6f40f5bbd19f090c1f95626687a` |
| SHA-1 | `84d492bc761bace055e847f34a410f57cd90f53f` |
| SHA-256 | `a43abf1be5dd450dd88370d503721ea3d1b228d06a3ad4957f57a08a73cad669` |
| SHA3-384 | `3dd0b38707bd7fd42b80a94e9e4a883098ffc6c8228955001d712e56b9ee52f6182f5a063b200420e80c4d6d6c895f9b` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T18C46E101B3D695B6D1BF1638D87A52696734BC049316CBBF5394BD392E32BC04E323A6` |
| SSDEEP | `98304:SzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:ShfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_a43abf1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a43abf1be5dd450dd88370d503721ea3d1b228d06a3ad4957f57a08a73cad669"
    family = "unknown"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:52:42"
  condition:
    hash.sha256(0, filesize) == "a43abf1be5dd450dd88370d503721ea3d1b228d06a3ad4957f57a08a73cad669"
}
```

### Sample 98: `12411713c6d011f8`

| Field | Value |
|---|---|
| SHA-256 | `12411713c6d011f83666bd855708a673e8f3d98e3b9555a3cc10857a74e47a58` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:52:32` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fdc8eb2b0739cdea9e5559342cf9152` |
| SHA-1 | `0f5f0b2d7a359dd8cb35a8dd4abc31fff4ac6d5e` |
| SHA-256 | `12411713c6d011f83666bd855708a673e8f3d98e3b9555a3cc10857a74e47a58` |
| SHA3-384 | `77eb9252b22c35f185379cdfc89f972605dab882d17314ad55f2867a44e990ec19067ebb57636e632af0b0dbc9d981f6` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T122646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:9mlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji9g:41iw7gryNkSV1hy1Z1u2JLu9g` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_098_12411713
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12411713c6d011f83666bd855708a673e8f3d98e3b9555a3cc10857a74e47a58"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:52:32"
  condition:
    hash.sha256(0, filesize) == "12411713c6d011f83666bd855708a673e8f3d98e3b9555a3cc10857a74e47a58"
}
```

### Sample 99: `f6f133e53b98fc3e`

| Field | Value |
|---|---|
| SHA-256 | `f6f133e53b98fc3e0d108357e848f7250ad9fe1b8af75cabe379c03d01e13a81` |
| Family label | `unknown` |
| File name | `ScreenConnect.ClientSetup.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:51:48` |
| Reporter | `BlinkzSec` |
| Tags | `signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1187112573cb0257eeaaddc6e18b36cc` |
| SHA-1 | `14d696393464aa44bc72199105b825d9ea2a96bb` |
| SHA-256 | `f6f133e53b98fc3e0d108357e848f7250ad9fe1b8af75cabe379c03d01e13a81` |
| SHA3-384 | `52f5fc03aa9f48cef7e4cf850c60b8e5f86c1783f19f6b29747e6dbb540a05cbc2f71db872cd182449a422417e819e70` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T11A46E003B3D599B7D07B8778ED7A46656734BC048311EAEB5394B9292F32BC04E32366` |
| SSDEEP | `98304:jzIus6efPUIdoaxcp8wy5c3trGOlkQ5DUOgJ9zl:jhfefPtHxcp9ym3nltDUJV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_f6f133e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6f133e53b98fc3e0d108357e848f7250ad9fe1b8af75cabe379c03d01e13a81"
    family = "unknown"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:51:48"
  condition:
    hash.sha256(0, filesize) == "f6f133e53b98fc3e0d108357e848f7250ad9fe1b8af75cabe379c03d01e13a81"
}
```

### Sample 100: `add0e262bd554841`

| Field | Value |
|---|---|
| SHA-256 | `add0e262bd554841dc12c106294dda4f8c6b73e7f28fca51a6f57e4d52fa16dc` |
| Family label | `ConnectWise` |
| File name | `support.client.exe` |
| File type | `exe` |
| First seen | `2026-08-06 20:51:47` |
| Reporter | `BlinkzSec` |
| Tags | `ConnectWise, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad425d7410a864bf63a61ed811a8e77b` |
| SHA-1 | `5707a2b7c3ce31544b627354182418dafb7307c1` |
| SHA-256 | `add0e262bd554841dc12c106294dda4f8c6b73e7f28fca51a6f57e4d52fa16dc` |
| SHA3-384 | `b849cf925320753048f69d5d0751c4e24548e9f0bd462431e369e4062fe9471ee77486f1d7642aeaccfc644e592e1678` |
| IMPHASH | `c2fe6927e1db8cf00400dbef9e5d35be` |
| TLSH | `T175646C11B9C48432C673383147B4E2B28DBDB8302D655B8F57A81D7A9F741D0EA29B6F` |
| SSDEEP | `6144:KmlfAgiw7Op5ryNkS7Z12wvtGVG3iVt8eZ1u2J/xFji90:51iw7gryNkSV1hy1Z1u2JLu90` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_100_add0e262
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "add0e262bd554841dc12c106294dda4f8c6b73e7f28fca51a6f57e4d52fa16dc"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:51:47"
  condition:
    hash.sha256(0, filesize) == "add0e262bd554841dc12c106294dda4f8c6b73e7f28fca51a6f57e4d52fa16dc"
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
 * Generated: 2026-08-07T03:19:23.771004+00:00
 */

rule MalwareBazaar_unknown_001_6e383213
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e383213ab698d95c19ba53e6fac6388883139934a91e4c816ee86ff33c0de33"
    family = "unknown"
    file_name = "New_Shipment_0285_Detail_Specificationpdf.js"
    file_type = "js"
    first_seen = "2026-08-07 03:16:34"
  condition:
    hash.sha256(0, filesize) == "6e383213ab698d95c19ba53e6fac6388883139934a91e4c816ee86ff33c0de33"
}

rule MalwareBazaar_unknown_002_e3e21306
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3e213066272b32a6b4aeaed3f12eebb814cdd3047605d1381a1972ed0809134"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 03:00:47"
  condition:
    hash.sha256(0, filesize) == "e3e213066272b32a6b4aeaed3f12eebb814cdd3047605d1381a1972ed0809134"
}

rule MalwareBazaar_Mirai_003_cf29935a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf29935a19b0f6f894971c107e8ffdefe122dc44ffd643f1fe0dbf23207d7083"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-07 02:43:53"
  condition:
    hash.sha256(0, filesize) == "cf29935a19b0f6f894971c107e8ffdefe122dc44ffd643f1fe0dbf23207d7083"
}

rule MalwareBazaar_Mirai_004_22a7183a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22a7183a59a6dc4203686d5482928fc587c5fd4db20949d599c09e75d01d790b"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-07 02:35:16"
  condition:
    hash.sha256(0, filesize) == "22a7183a59a6dc4203686d5482928fc587c5fd4db20949d599c09e75d01d790b"
}

rule MalwareBazaar_Mirai_005_555d862a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "555d862a10163c0da85fa24a58ec2caf5cf76d9ec0a4cb21983cec216fddedbf"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-07 02:35:14"
  condition:
    hash.sha256(0, filesize) == "555d862a10163c0da85fa24a58ec2caf5cf76d9ec0a4cb21983cec216fddedbf"
}

rule MalwareBazaar_Mirai_006_3427810e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3427810ea86c988af3702d5b43dcfde93205232f5d5a567580f739b26b0fd4d2"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-07 02:29:17"
  condition:
    hash.sha256(0, filesize) == "3427810ea86c988af3702d5b43dcfde93205232f5d5a567580f739b26b0fd4d2"
}

rule MalwareBazaar_Mirai_007_b7f2e918
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7f2e9185472e01b3b636cd48417239456b9a9318b7a9b1a920cdb6b2d9420ed"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-07 02:26:12"
  condition:
    hash.sha256(0, filesize) == "b7f2e9185472e01b3b636cd48417239456b9a9318b7a9b1a920cdb6b2d9420ed"
}

rule MalwareBazaar_Mirai_008_17a7ad87
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17a7ad87346b0119caa7f638b3bea08aa14459b25e5150a8c9a0ef70bef719bd"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-07 02:26:11"
  condition:
    hash.sha256(0, filesize) == "17a7ad87346b0119caa7f638b3bea08aa14459b25e5150a8c9a0ef70bef719bd"
}

rule MalwareBazaar_NanoCore_009_89c3ba70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89c3ba702d5c424a14c58c3809897b9fc0a66a84c9e4becd4363972e4077756b"
    family = "NanoCore"
    file_name = "09683b2cb19f16818d0a60264663cac2.exe"
    file_type = "exe"
    first_seen = "2026-08-07 02:20:06"
  condition:
    hash.sha256(0, filesize) == "89c3ba702d5c424a14c58c3809897b9fc0a66a84c9e4becd4363972e4077756b"
}

rule MalwareBazaar_Mirai_010_9b96004d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b96004da936de55cbd9a2dd86f0f1670a6807a6009a8ae1087684d8527b8af1"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-07 02:19:42"
  condition:
    hash.sha256(0, filesize) == "9b96004da936de55cbd9a2dd86f0f1670a6807a6009a8ae1087684d8527b8af1"
}

rule MalwareBazaar_unknown_011_b21a6903
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b21a6903bc670f9ecbcf74aae1fe4bf479b8ee7430a24d96921e806b13ac1602"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-07 02:13:18"
  condition:
    hash.sha256(0, filesize) == "b21a6903bc670f9ecbcf74aae1fe4bf479b8ee7430a24d96921e806b13ac1602"
}

rule MalwareBazaar_Mirai_012_ea607ebe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea607ebe34ee5a06f5ed85805e0cf9175eaeb390fc39cb19bd31a7add8a4edf5"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 02:01:00"
  condition:
    hash.sha256(0, filesize) == "ea607ebe34ee5a06f5ed85805e0cf9175eaeb390fc39cb19bd31a7add8a4edf5"
}

rule MalwareBazaar_Mirai_013_a9a08daf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9a08daf07f1b3b65aefe346cece1f53a82d2dd69cd7f73a3827ae6f20c0d1bc"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 02:00:12"
  condition:
    hash.sha256(0, filesize) == "a9a08daf07f1b3b65aefe346cece1f53a82d2dd69cd7f73a3827ae6f20c0d1bc"
}

rule MalwareBazaar_unknown_014_84b8ec2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84b8ec2f3b29a10f88d21fc7617cdfecac1c2c76303086b41471beb5f563f65c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 01:56:20"
  condition:
    hash.sha256(0, filesize) == "84b8ec2f3b29a10f88d21fc7617cdfecac1c2c76303086b41471beb5f563f65c"
}

rule MalwareBazaar_Mirai_015_996cab13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "996cab13bc21cff4f38ba7cbbcadd4cd31b6fe8b1fb45251d3923ca3498b3df7"
    family = "Mirai"
    file_name = "Mddos.arm5"
    file_type = "elf"
    first_seen = "2026-08-07 01:54:21"
  condition:
    hash.sha256(0, filesize) == "996cab13bc21cff4f38ba7cbbcadd4cd31b6fe8b1fb45251d3923ca3498b3df7"
}

rule MalwareBazaar_Mirai_016_92419401
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "924194012db5ee8721227fa456bff10954996a7c519bac33babd4236e987c941"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-07 01:54:20"
  condition:
    hash.sha256(0, filesize) == "924194012db5ee8721227fa456bff10954996a7c519bac33babd4236e987c941"
}

rule MalwareBazaar_Mirai_017_cb2ffb98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb2ffb986351e2eea68c323dffd000bf0b8af4b41e4ce5afd024bbd0f4dfd599"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:51:41"
  condition:
    hash.sha256(0, filesize) == "cb2ffb986351e2eea68c323dffd000bf0b8af4b41e4ce5afd024bbd0f4dfd599"
}

rule MalwareBazaar_Mirai_018_88b5109d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88b5109d8eb8b053819ea7b488ff317c7ec584b4e1223398b8a500bd8a04bd5d"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-07 01:51:26"
  condition:
    hash.sha256(0, filesize) == "88b5109d8eb8b053819ea7b488ff317c7ec584b4e1223398b8a500bd8a04bd5d"
}

rule MalwareBazaar_Mirai_019_d031735c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d031735c3f1885f132d422c246cf99fa8c7dd6ec10f78d4397fe50621ac84576"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:51:24"
  condition:
    hash.sha256(0, filesize) == "d031735c3f1885f132d422c246cf99fa8c7dd6ec10f78d4397fe50621ac84576"
}

rule MalwareBazaar_Mirai_020_c2258509
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2258509124d2f096ddfe68e16e2e6f75772048bf0fd3eb2bbdd7898004b5585"
    family = "Mirai"
    file_name = "disconnectraw.aarch64"
    file_type = "elf"
    first_seen = "2026-08-07 01:45:56"
  condition:
    hash.sha256(0, filesize) == "c2258509124d2f096ddfe68e16e2e6f75772048bf0fd3eb2bbdd7898004b5585"
}

rule MalwareBazaar_Mirai_021_3e54bd67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e54bd672c62b54255400308df61b30f508d92ccd80c097b73281bf92c04c58f"
    family = "Mirai"
    file_name = "disconnectraw.aarch64"
    file_type = "elf"
    first_seen = "2026-08-07 01:45:28"
  condition:
    hash.sha256(0, filesize) == "3e54bd672c62b54255400308df61b30f508d92ccd80c097b73281bf92c04c58f"
}

rule MalwareBazaar_unknown_022_2759b171
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2759b171a3a9b245bb0559d8a9aaa2ad753a140a072d6ca0c26235139fdc2a7c"
    family = "unknown"
    file_name = "cat.sh"
    file_type = "sh"
    first_seen = "2026-08-07 01:45:25"
  condition:
    hash.sha256(0, filesize) == "2759b171a3a9b245bb0559d8a9aaa2ad753a140a072d6ca0c26235139fdc2a7c"
}

rule MalwareBazaar_Mirai_023_192ab4c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "192ab4c313bdd769956ada60e82dbcb7d2f6c41efb520e213a647dcdf1077ce9"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-07 01:42:27"
  condition:
    hash.sha256(0, filesize) == "192ab4c313bdd769956ada60e82dbcb7d2f6c41efb520e213a647dcdf1077ce9"
}

rule MalwareBazaar_Mirai_024_1ae01ac2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae01ac29110a83c78af2f046599bffd4212b5653d949074374a4f27a6d6aaef"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:39:46"
  condition:
    hash.sha256(0, filesize) == "1ae01ac29110a83c78af2f046599bffd4212b5653d949074374a4f27a6d6aaef"
}

rule MalwareBazaar_Mirai_025_9fb7734e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9fb7734eff92e7186fc51250c305b087df7c7c0698ab6a987a5027c0507b38e8"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-07 01:39:27"
  condition:
    hash.sha256(0, filesize) == "9fb7734eff92e7186fc51250c305b087df7c7c0698ab6a987a5027c0507b38e8"
}

rule MalwareBazaar_Mirai_026_4b7c709a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b7c709aba3af9f79945f21998b06e73ec951ec5a523bc038fd21d0bdecfe326"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-07 01:39:26"
  condition:
    hash.sha256(0, filesize) == "4b7c709aba3af9f79945f21998b06e73ec951ec5a523bc038fd21d0bdecfe326"
}

rule MalwareBazaar_Mirai_027_27f5a48e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27f5a48e661bf28d1f2498c31e692411ecc8891a13da9f76458c0197dd3c7079"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-07 01:36:29"
  condition:
    hash.sha256(0, filesize) == "27f5a48e661bf28d1f2498c31e692411ecc8891a13da9f76458c0197dd3c7079"
}

rule MalwareBazaar_Mirai_028_bfd4a127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfd4a1275626d0b82bc22a41aa65fb39b3936c895ce885d248195860fd07345b"
    family = "Mirai"
    file_name = "disconnectraw.x86"
    file_type = "elf"
    first_seen = "2026-08-07 01:36:27"
  condition:
    hash.sha256(0, filesize) == "bfd4a1275626d0b82bc22a41aa65fb39b3936c895ce885d248195860fd07345b"
}

rule MalwareBazaar_Mirai_029_e8c0a568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c0a568e792becdf2986764d2485c797d9af3de4402bd2a5f1064e732a451a5"
    family = "Mirai"
    file_name = "disconnectraw.mips"
    file_type = "elf"
    first_seen = "2026-08-07 01:33:37"
  condition:
    hash.sha256(0, filesize) == "e8c0a568e792becdf2986764d2485c797d9af3de4402bd2a5f1064e732a451a5"
}

rule MalwareBazaar_Mirai_030_2313008e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2313008eb3ed7c5874283b577f6614bd0eddd471014d3b6b23a8d1218c2f4ae7"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-07 01:33:29"
  condition:
    hash.sha256(0, filesize) == "2313008eb3ed7c5874283b577f6614bd0eddd471014d3b6b23a8d1218c2f4ae7"
}

rule MalwareBazaar_Mirai_031_59361ef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59361ef6ce36865765e3f07506b99dd55373a8b31e2011b0f77c0d0ad9439126"
    family = "Mirai"
    file_name = "disconnectraw.mips"
    file_type = "elf"
    first_seen = "2026-08-07 01:33:28"
  condition:
    hash.sha256(0, filesize) == "59361ef6ce36865765e3f07506b99dd55373a8b31e2011b0f77c0d0ad9439126"
}

rule MalwareBazaar_Mirai_032_f26e0468
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f26e0468626e39ac1940aba366021ce782221d505888d15bf95519bc0340c1c9"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-07 01:17:14"
  condition:
    hash.sha256(0, filesize) == "f26e0468626e39ac1940aba366021ce782221d505888d15bf95519bc0340c1c9"
}

rule MalwareBazaar_unknown_033_b28df0a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b28df0a1e9e330e23c3ce483935e9d5f2fd164679806013f10e40e7123aeec4f"
    family = "unknown"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-08-07 01:17:13"
  condition:
    hash.sha256(0, filesize) == "b28df0a1e9e330e23c3ce483935e9d5f2fd164679806013f10e40e7123aeec4f"
}

rule MalwareBazaar_unknown_034_d4cfab5e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4cfab5e052df4c049f258e226d11825cb37b0359be454b83241edd59b295f08"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-07 01:12:19"
  condition:
    hash.sha256(0, filesize) == "d4cfab5e052df4c049f258e226d11825cb37b0359be454b83241edd59b295f08"
}

rule MalwareBazaar_NanoCore_035_94c78e0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94c78e0d80e3364e1c90d6f5311e6e4104bfa8e831d3351ba8cb875620d0dc64"
    family = "NanoCore"
    file_name = "F32F66F210C25EA6DD97348034BB698B.exe"
    file_type = "exe"
    first_seen = "2026-08-07 00:25:05"
  condition:
    hash.sha256(0, filesize) == "94c78e0d80e3364e1c90d6f5311e6e4104bfa8e831d3351ba8cb875620d0dc64"
}

rule MalwareBazaar_unknown_036_f4dc07d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693"
    family = "unknown"
    file_name = "f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693"
    file_type = "sh"
    first_seen = "2026-08-06 23:55:40"
  condition:
    hash.sha256(0, filesize) == "f4dc07d863c39fac212ae9c43b6eb84286a44306e2d26372617bcef641bbc693"
}

rule MalwareBazaar_Mirai_037_7661b840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd"
    family = "Mirai"
    file_name = "sample"
    file_type = "elf"
    first_seen = "2026-08-06 23:39:38"
  condition:
    hash.sha256(0, filesize) == "7661b8408aa9677341bf46a27561c9f6d3967ad2e72ea5eab4b665f283f9b3fd"
}

rule MalwareBazaar_Mirai_038_f949ba49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f"
    family = "Mirai"
    file_name = "f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:39:10"
  condition:
    hash.sha256(0, filesize) == "f949ba49ba8db0c49c0e22fa8c6f84ba7da8530b2bcc00c0df0f9cb17c69486f"
}

rule MalwareBazaar_Mirai_039_032f7dd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "032f7dd5999ef63685afcf7040a3cde9fbf010efa507fdfe3f17d7630ce128de"
    family = "Mirai"
    file_name = "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:37"
  condition:
    hash.sha256(0, filesize) == "032f7dd5999ef63685afcf7040a3cde9fbf010efa507fdfe3f17d7630ce128de"
}

rule MalwareBazaar_Mirai_040_611c02af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "611c02afa2bc725622b7c5154f69b4d5b4f409a46f93ba67dbddcb224d90efc6"
    family = "Mirai"
    file_name = "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:35"
  condition:
    hash.sha256(0, filesize) == "611c02afa2bc725622b7c5154f69b4d5b4f409a46f93ba67dbddcb224d90efc6"
}

rule MalwareBazaar_Mirai_041_b82828da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4"
    family = "Mirai"
    file_name = "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:14"
  condition:
    hash.sha256(0, filesize) == "b82828da08e4b971257f6091161f0dbcbd350e000f99bf40c967b7348e9045d4"
}

rule MalwareBazaar_Mirai_042_5b7ce7dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3"
    family = "Mirai"
    file_name = "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:34:10"
  condition:
    hash.sha256(0, filesize) == "5b7ce7dd4dae44f70ad94a4965d013d9354b062f8ecba93005dd6717b462eae3"
}

rule MalwareBazaar_Mirai_043_2bcd14ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bcd14ad3499be6f1bc2b4b569df53ee9b70f6dc7eb3865bd6229650a3d634f3"
    family = "Mirai"
    file_name = "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:39"
  condition:
    hash.sha256(0, filesize) == "2bcd14ad3499be6f1bc2b4b569df53ee9b70f6dc7eb3865bd6229650a3d634f3"
}

rule MalwareBazaar_Mirai_044_dd2f2a49
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd2f2a49b031dab67adaf17071779965ca4d79eb3e1f81be633716493a54d95b"
    family = "Mirai"
    file_name = "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:37"
  condition:
    hash.sha256(0, filesize) == "dd2f2a49b031dab67adaf17071779965ca4d79eb3e1f81be633716493a54d95b"
}

rule MalwareBazaar_Mirai_045_fc09cf65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585"
    family = "Mirai"
    file_name = "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:14"
  condition:
    hash.sha256(0, filesize) == "fc09cf6556d51f47fac884e51c4eff76d43bf44ab9dba7578123d8aa19dd3585"
}

rule MalwareBazaar_Mirai_046_c0e6f1d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8"
    family = "Mirai"
    file_name = "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:29:10"
  condition:
    hash.sha256(0, filesize) == "c0e6f1d6af634fab562853ba2cd3e20c4b75e5a5a424f9a39bb464fb8ee695e8"
}

rule MalwareBazaar_NanoCore_047_2055a6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2055a6d22f882f79211a9209556b9d2e14498da87a112007e5fe0d3bf5cbd2fb"
    family = "NanoCore"
    file_name = "A0EBE1250B23CB60D919AA4E7DBD7E40.exe"
    file_type = "exe"
    first_seen = "2026-08-06 23:25:04"
  condition:
    hash.sha256(0, filesize) == "2055a6d22f882f79211a9209556b9d2e14498da87a112007e5fe0d3bf5cbd2fb"
}

rule MalwareBazaar_Mirai_048_94ff3c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94ff3c3a94cf977890206e7592239387083dfbe2aaa27a2f6f74d7b39d68c8e8"
    family = "Mirai"
    file_name = "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:40"
  condition:
    hash.sha256(0, filesize) == "94ff3c3a94cf977890206e7592239387083dfbe2aaa27a2f6f74d7b39d68c8e8"
}

rule MalwareBazaar_Mirai_049_ff758598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff75859841364fa791b47c073bd4a4f37d32be48ce349749a98537b0d0926996"
    family = "Mirai"
    file_name = "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:37"
  condition:
    hash.sha256(0, filesize) == "ff75859841364fa791b47c073bd4a4f37d32be48ce349749a98537b0d0926996"
}

rule MalwareBazaar_Mirai_050_f52824d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea"
    family = "Mirai"
    file_name = "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:11"
  condition:
    hash.sha256(0, filesize) == "f52824d120c097cbca20a105bfef128d103b9ee54c9ba9cafe38c8d79a95bfea"
}

rule MalwareBazaar_Mirai_051_eb2ee7f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635"
    family = "Mirai"
    file_name = "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:24:08"
  condition:
    hash.sha256(0, filesize) == "eb2ee7f82fbb97e22c940a837e3544f9d0ebee6ca4e875cd45eb36f546154635"
}

rule MalwareBazaar_unknown_052_9a89598b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a89598b0696c5ecade5ff4af16042e57fb5c88c4fdbbef94d8c03230a9fb6f2"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-06 23:20:48"
  condition:
    hash.sha256(0, filesize) == "9a89598b0696c5ecade5ff4af16042e57fb5c88c4fdbbef94d8c03230a9fb6f2"
}

rule MalwareBazaar_Mirai_053_460e297d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "460e297dfef977c8054c1ef871cfe6a9102839411308555c1d49480e217e70fb"
    family = "Mirai"
    file_name = "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:11:12"
  condition:
    hash.sha256(0, filesize) == "460e297dfef977c8054c1ef871cfe6a9102839411308555c1d49480e217e70fb"
}

rule MalwareBazaar_Mirai_054_c151368e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c"
    family = "Mirai"
    file_name = "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:09:56"
  condition:
    hash.sha256(0, filesize) == "c151368e6297fcd311f548fe124e6e41b7c14986465bc558b8ebc69e9265b26c"
}

rule MalwareBazaar_RemusStealer_055_e2affa0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6"
    family = "RemusStealer"
    file_name = "e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6.exe"
    file_type = "exe"
    first_seen = "2026-08-06 23:09:08"
  condition:
    hash.sha256(0, filesize) == "e2affa0d6d98ca6cd8dbb05f8db955a71127b37c631a9cea4c967bdc992c93e6"
}

rule MalwareBazaar_unknown_056_29be0f56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40"
    family = "unknown"
    file_name = "sample_dante.bin"
    file_type = "macho"
    first_seen = "2026-08-06 23:09:06"
  condition:
    hash.sha256(0, filesize) == "29be0f56275f051181ea3ec37ddc3d3807cde34cb65de855709fae0e13786a40"
}

rule MalwareBazaar_Mirai_057_148cf20c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "148cf20cd54364532ab66886d91149757827727145fcb4abf8569c14ad3775e8"
    family = "Mirai"
    file_name = "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:41"
  condition:
    hash.sha256(0, filesize) == "148cf20cd54364532ab66886d91149757827727145fcb4abf8569c14ad3775e8"
}

rule MalwareBazaar_Mirai_058_ce974705
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce974705354785948578000ff6a139dffd8bdda4cd24a1b18bc04df2a71733b4"
    family = "Mirai"
    file_name = "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:39"
  condition:
    hash.sha256(0, filesize) == "ce974705354785948578000ff6a139dffd8bdda4cd24a1b18bc04df2a71733b4"
}

rule MalwareBazaar_Mirai_059_fd720b19
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a"
    family = "Mirai"
    file_name = "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:16"
  condition:
    hash.sha256(0, filesize) == "fd720b19a62efa97b733d8f816a8a1e49867e50b042d6353d23ef8d8ad54458a"
}

rule MalwareBazaar_Mirai_060_02cafc01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b"
    family = "Mirai"
    file_name = "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b.elf"
    file_type = "elf"
    first_seen = "2026-08-06 23:04:11"
  condition:
    hash.sha256(0, filesize) == "02cafc015e53bcb91415ed85b53728b0da6b07a2900339c50f309e26d0ec281b"
}

rule MalwareBazaar_unknown_061_b87b3b60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b87b3b60b7350747ba6998f50204c78ef0a6fb11281a35c9d15b52ea4765a75c"
    family = "unknown"
    file_name = "SecuriteInfo.com.W32.FlyStudio.W.gen.Eldorado.647.26198"
    file_type = "exe"
    first_seen = "2026-08-06 22:50:43"
  condition:
    hash.sha256(0, filesize) == "b87b3b60b7350747ba6998f50204c78ef0a6fb11281a35c9d15b52ea4765a75c"
}

rule MalwareBazaar_unknown_062_353c5fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "353c5fe38cd4e5a0736da021581f782be3c5f6f73da4a035f11f70a305dc19f4"
    family = "unknown"
    file_name = "SecuriteInfo.com.Trojan.Linux.Mirai.25962.11260"
    file_type = "elf"
    first_seen = "2026-08-06 22:50:39"
  condition:
    hash.sha256(0, filesize) == "353c5fe38cd4e5a0736da021581f782be3c5f6f73da4a035f11f70a305dc19f4"
}

rule MalwareBazaar_Mirai_063_4d24c9c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc"
    family = "Mirai"
    file_name = "4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc.elf"
    file_type = "elf"
    first_seen = "2026-08-06 22:39:17"
  condition:
    hash.sha256(0, filesize) == "4d24c9c629ce5e5a35544d656228de3ea15b8f4c42ac2497df926b3179ce30cc"
}

rule MalwareBazaar_Stealc_064_652f91bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 22:14:12"
  condition:
    hash.sha256(0, filesize) == "652f91bcf60dc148e7af64bf509cd4f7e4ffac685030bc260c59c7b869585ac9"
}

rule MalwareBazaar_unknown_065_670e15d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "670e15d21d6ffa4f89be367e9c0007eab1d123f8f92d1af8ac95de8a935e7332"
    family = "unknown"
    file_name = "2.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:46:10"
  condition:
    hash.sha256(0, filesize) == "670e15d21d6ffa4f89be367e9c0007eab1d123f8f92d1af8ac95de8a935e7332"
}

rule MalwareBazaar_unknown_066_89f5e86a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89f5e86a2ca62dee4ea9ea65d2235efb36528f987ba4d136326612f79cfe89a9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 21:46:02"
  condition:
    hash.sha256(0, filesize) == "89f5e86a2ca62dee4ea9ea65d2235efb36528f987ba4d136326612f79cfe89a9"
}

rule MalwareBazaar_unknown_067_accbe9fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "accbe9fca34638def5aa8a0c9d4cd7a536cc631c00a391d75e5a7b7548bade4b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 21:45:50"
  condition:
    hash.sha256(0, filesize) == "accbe9fca34638def5aa8a0c9d4cd7a536cc631c00a391d75e5a7b7548bade4b"
}

rule MalwareBazaar_unknown_068_57bdbf20
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57bdbf20404cb95dbe39e87043159e6caf2a44e1a8881775e465f68210bbe644"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 21:40:10"
  condition:
    hash.sha256(0, filesize) == "57bdbf20404cb95dbe39e87043159e6caf2a44e1a8881775e465f68210bbe644"
}

rule MalwareBazaar_Mirai_069_dede2a29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dede2a29a045c3d12dce4b04347a3a4aeb95936f0117a399eaa15eb7d295881f"
    family = "Mirai"
    file_name = "bin.armv5l"
    file_type = "elf"
    first_seen = "2026-08-06 21:30:18"
  condition:
    hash.sha256(0, filesize) == "dede2a29a045c3d12dce4b04347a3a4aeb95936f0117a399eaa15eb7d295881f"
}

rule MalwareBazaar_Mirai_070_2cd24da1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cd24da13a8b8abbfcf0222b47e31707af04a082cb48d7259ac03494bc5842f1"
    family = "Mirai"
    file_name = "bin.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:50"
  condition:
    hash.sha256(0, filesize) == "2cd24da13a8b8abbfcf0222b47e31707af04a082cb48d7259ac03494bc5842f1"
}

rule MalwareBazaar_Mirai_071_6eee9214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6eee92142627b47cadb3a4833b18fa1f850079a4e643db0ef2a462fb2cdbc6f6"
    family = "Mirai"
    file_name = "bin.sh4"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:46"
  condition:
    hash.sha256(0, filesize) == "6eee92142627b47cadb3a4833b18fa1f850079a4e643db0ef2a462fb2cdbc6f6"
}

rule MalwareBazaar_Mirai_072_b8fa1f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8fa1f90c3611a5f80dd2a16903698e41d2f69e425a70a20a710fccfcdcb4768"
    family = "Mirai"
    file_name = "bin.powerpc-440fp"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:46"
  condition:
    hash.sha256(0, filesize) == "b8fa1f90c3611a5f80dd2a16903698e41d2f69e425a70a20a710fccfcdcb4768"
}

rule MalwareBazaar_Mirai_073_70e63214
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e6321443d11cd384022b2bf5e1c7594266070715d1c4f0815a13ee329e2698"
    family = "Mirai"
    file_name = "bin.powerpc"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "70e6321443d11cd384022b2bf5e1c7594266070715d1c4f0815a13ee329e2698"
}

rule MalwareBazaar_Mirai_074_a3b40523
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3b4052307fb2f2a66477e8640bc0937e3f5c86240b9866559eb52d1a6876f24"
    family = "Mirai"
    file_name = "bin.mips64"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "a3b4052307fb2f2a66477e8640bc0937e3f5c86240b9866559eb52d1a6876f24"
}

rule MalwareBazaar_Mirai_075_e0a1adc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0a1adc708da1bb9718b698d137fe065ba54ad47da72f30eaf3839fa5ebee372"
    family = "Mirai"
    file_name = "bin.mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:44"
  condition:
    hash.sha256(0, filesize) == "e0a1adc708da1bb9718b698d137fe065ba54ad47da72f30eaf3839fa5ebee372"
}

rule MalwareBazaar_Mirai_076_2f516e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472"
    family = "Mirai"
    file_name = "bin.mips"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:43"
  condition:
    hash.sha256(0, filesize) == "2f516e833a42b768ed8121ab74dd589f5513dd9531eaa8a5432ff49557bd4472"
}

rule MalwareBazaar_Mirai_077_82d16a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb"
    family = "Mirai"
    file_name = "bin.m68k"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:41"
  condition:
    hash.sha256(0, filesize) == "82d16a631297bdfde2b55177d15ca38c742ca677369e92ae4000c4c93350dffb"
}

rule MalwareBazaar_Mirai_078_c765ed56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c765ed5690a276fba464020b7b87f827ed9315b64822bbcb216b5eb06f1896eb"
    family = "Mirai"
    file_name = "bin.i686"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:41"
  condition:
    hash.sha256(0, filesize) == "c765ed5690a276fba464020b7b87f827ed9315b64822bbcb216b5eb06f1896eb"
}

rule MalwareBazaar_Mirai_079_958dabdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "958dabdb8ea42dfd3725bf70d8d8641b794298942269d33a921d2428a9f0bf20"
    family = "Mirai"
    file_name = "bin.i486"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:40"
  condition:
    hash.sha256(0, filesize) == "958dabdb8ea42dfd3725bf70d8d8641b794298942269d33a921d2428a9f0bf20"
}

rule MalwareBazaar_Mirai_080_e2d12341
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2d12341dfc7c12aefa0bad0610e44723628d84459e3412d745e2dd59f3965e1"
    family = "Mirai"
    file_name = "bin.i586"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:40"
  condition:
    hash.sha256(0, filesize) == "e2d12341dfc7c12aefa0bad0610e44723628d84459e3412d745e2dd59f3965e1"
}

rule MalwareBazaar_Mirai_081_b435762e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b435762e4fbe122df3b90b006bad194b4293755389be09b3e53e6b87bb0f9c2e"
    family = "Mirai"
    file_name = "bin.armv7l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:39"
  condition:
    hash.sha256(0, filesize) == "b435762e4fbe122df3b90b006bad194b4293755389be09b3e53e6b87bb0f9c2e"
}

rule MalwareBazaar_Mirai_082_516c4512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "516c4512ef9922821eed1f2489b5a5243b757b30d2bf018a85b27ecdefee5826"
    family = "Mirai"
    file_name = "bin.armv6l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:38"
  condition:
    hash.sha256(0, filesize) == "516c4512ef9922821eed1f2489b5a5243b757b30d2bf018a85b27ecdefee5826"
}

rule MalwareBazaar_Mirai_083_9f5372d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f5372d58342c98892588edb4c05af2e7d237f79448d51bef2412fed77f0c495"
    family = "Mirai"
    file_name = "bin.armv5l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:38"
  condition:
    hash.sha256(0, filesize) == "9f5372d58342c98892588edb4c05af2e7d237f79448d51bef2412fed77f0c495"
}

rule MalwareBazaar_Mirai_084_5fb744c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fb744c3983421724443599492d9d5f0667fe1fbcb8a80f0879488983320f06e"
    family = "Mirai"
    file_name = "bin.armv4l"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:37"
  condition:
    hash.sha256(0, filesize) == "5fb744c3983421724443599492d9d5f0667fe1fbcb8a80f0879488983320f06e"
}

rule MalwareBazaar_Mirai_085_d93d9b73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d93d9b733dbd17c9b1d60774e2be07aa06ccfec66425cef2c6bad882854155d5"
    family = "Mirai"
    file_name = "bin.armv4tl"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:37"
  condition:
    hash.sha256(0, filesize) == "d93d9b733dbd17c9b1d60774e2be07aa06ccfec66425cef2c6bad882854155d5"
}

rule MalwareBazaar_Mirai_086_72dd47f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72dd47f7eedc101f63f5f557651a388013319bb73e96a0c821252b75f2217169"
    family = "Mirai"
    file_name = "bin.armv4eb"
    file_type = "elf"
    first_seen = "2026-08-06 21:09:36"
  condition:
    hash.sha256(0, filesize) == "72dd47f7eedc101f63f5f557651a388013319bb73e96a0c821252b75f2217169"
}

rule MalwareBazaar_ConnectWise_087_5b2d48b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b2d48b4ea0599e4cfa18fd532be04ce24fcb559d789432a64708feea05bf83f"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:32"
  condition:
    hash.sha256(0, filesize) == "5b2d48b4ea0599e4cfa18fd532be04ce24fcb559d789432a64708feea05bf83f"
}

rule MalwareBazaar_ConnectWise_088_1d9a1b09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d9a1b096c4ae71f9c0403802667ea0b3492de2d57281a6d4145ba5758e74bad"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:31"
  condition:
    hash.sha256(0, filesize) == "1d9a1b096c4ae71f9c0403802667ea0b3492de2d57281a6d4145ba5758e74bad"
}

rule MalwareBazaar_ConnectWise_089_60df12c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60df12c872628826a9a5289474082ffe1ea55819133219dde1d656bdb0d502fd"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:08"
  condition:
    hash.sha256(0, filesize) == "60df12c872628826a9a5289474082ffe1ea55819133219dde1d656bdb0d502fd"
}

rule MalwareBazaar_ConnectWise_090_b5f7df56
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5f7df56de192f53a8122e1e6a7d83c80344d94b401d140004cff8cf04252757"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:08:06"
  condition:
    hash.sha256(0, filesize) == "b5f7df56de192f53a8122e1e6a7d83c80344d94b401d140004cff8cf04252757"
}

rule MalwareBazaar_ConnectWise_091_cdf12594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cdf1259459502c82ce1bcb0651d6dba80d6f0bb2c7418e6a4ab75d0c4718536c"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:05:11"
  condition:
    hash.sha256(0, filesize) == "cdf1259459502c82ce1bcb0651d6dba80d6f0bb2c7418e6a4ab75d0c4718536c"
}

rule MalwareBazaar_ConnectWise_092_b8bec7b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bec7b45605da355b092c9f3e40bab447928839d4eef5a9290cb5bb1dd50f2d"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 21:05:08"
  condition:
    hash.sha256(0, filesize) == "b8bec7b45605da355b092c9f3e40bab447928839d4eef5a9290cb5bb1dd50f2d"
}

rule MalwareBazaar_ConnectWise_093_3caaa5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3caaa5e8cab6d0ec2932ea20fb71301eeea20ea16ea18d4cde08f8130a59fd25"
    family = "ConnectWise"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:57:49"
  condition:
    hash.sha256(0, filesize) == "3caaa5e8cab6d0ec2932ea20fb71301eeea20ea16ea18d4cde08f8130a59fd25"
}

rule MalwareBazaar_ConnectWise_094_4b1f69dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b1f69dcea99ca1e1884a377ed2481ee1f0d543e7faade27f6ac3dc850042233"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:57:43"
  condition:
    hash.sha256(0, filesize) == "4b1f69dcea99ca1e1884a377ed2481ee1f0d543e7faade27f6ac3dc850042233"
}

rule MalwareBazaar_Mirai_095_73c8b883
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73c8b883889a87c6844c8eab2f3540141eb078d44b741c843abc7fda2ccf2bed"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-06 20:53:01"
  condition:
    hash.sha256(0, filesize) == "73c8b883889a87c6844c8eab2f3540141eb078d44b741c843abc7fda2ccf2bed"
}

rule MalwareBazaar_unknown_096_2f029858
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f029858b8ecca8fb6c156eb2d046a2463e8b67d356c1003e5567339681a71be"
    family = "unknown"
    file_name = "bhatta.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:52:44"
  condition:
    hash.sha256(0, filesize) == "2f029858b8ecca8fb6c156eb2d046a2463e8b67d356c1003e5567339681a71be"
}

rule MalwareBazaar_unknown_097_a43abf1b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a43abf1be5dd450dd88370d503721ea3d1b228d06a3ad4957f57a08a73cad669"
    family = "unknown"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:52:42"
  condition:
    hash.sha256(0, filesize) == "a43abf1be5dd450dd88370d503721ea3d1b228d06a3ad4957f57a08a73cad669"
}

rule MalwareBazaar_ConnectWise_098_12411713
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12411713c6d011f83666bd855708a673e8f3d98e3b9555a3cc10857a74e47a58"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:52:32"
  condition:
    hash.sha256(0, filesize) == "12411713c6d011f83666bd855708a673e8f3d98e3b9555a3cc10857a74e47a58"
}

rule MalwareBazaar_unknown_099_f6f133e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6f133e53b98fc3e0d108357e848f7250ad9fe1b8af75cabe379c03d01e13a81"
    family = "unknown"
    file_name = "ScreenConnect.ClientSetup.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:51:48"
  condition:
    hash.sha256(0, filesize) == "f6f133e53b98fc3e0d108357e848f7250ad9fe1b8af75cabe379c03d01e13a81"
}

rule MalwareBazaar_ConnectWise_100_add0e262
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "add0e262bd554841dc12c106294dda4f8c6b73e7f28fca51a6f57e4d52fa16dc"
    family = "ConnectWise"
    file_name = "support.client.exe"
    file_type = "exe"
    first_seen = "2026-08-06 20:51:47"
  condition:
    hash.sha256(0, filesize) == "add0e262bd554841dc12c106294dda4f8c6b73e7f28fca51a6f57e4d52fa16dc"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

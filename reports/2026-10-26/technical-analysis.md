# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-26

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 694 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 694 |
| Unique family labels | 4 |
| Unique file types | 5 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| SalatStealer | 88 |
| unknown | 9 |
| RemcosRAT | 2 |
| Mirai | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 92 |
| elf | 3 |
| vbs | 2 |
| js | 2 |
| macho | 1 |

## Per-Sample Analysis

### Sample 1: `bf7a8c0ad143e008`

| Field | Value |
|---|---|
| SHA-256 | `bf7a8c0ad143e00843d4238f6e97b7f8cc533d2c9663afd724663ef7af982ec3` |
| Family label | `unknown` |
| File name | `Bassist.vbs` |
| File type | `vbs` |
| First seen | `2026-10-26 04:45:20` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9795d778176f401ff85c1cd0ef90872` |
| SHA-1 | `d8afe6d000086924c662a138815e18d69b5d5c0b` |
| SHA-256 | `bf7a8c0ad143e00843d4238f6e97b7f8cc533d2c9663afd724663ef7af982ec3` |
| SHA3-384 | `73f8604124e7db8ad39ac4a6ea10dcdd84c7366d8bc60440e8ff055b00a54b346756de5ae4901b4cf3332b11bb41b2d3` |
| TLSH | `T1FB233A60CF291365AD0F33E6DC3A29A4C97C8222141398A37EF5B30DE42665C63FDD5A` |
| SSDEEP | `768:JVUBGBRp0trbphnaXvRYYXkxWf43tLVoS2JySu813z37wRh2YBT6:JVUByX0VPna/z49+Siyk937r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_bf7a8c0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf7a8c0ad143e00843d4238f6e97b7f8cc533d2c9663afd724663ef7af982ec3"
    family = "unknown"
    file_name = "Bassist.vbs"
    file_type = "vbs"
    first_seen = "2026-10-26 04:45:20"
  condition:
    hash.sha256(0, filesize) == "bf7a8c0ad143e00843d4238f6e97b7f8cc533d2c9663afd724663ef7af982ec3"
}
```

### Sample 2: `9cb0006ba80d05ee`

| Field | Value |
|---|---|
| SHA-256 | `9cb0006ba80d05eed418511693eba7bde1d9ef3d6fc4ae4ff877f304758d5cb7` |
| Family label | `RemcosRAT` |
| File name | `4567890766567896765YourQuotation.JS.js` |
| File type | `js` |
| First seen | `2026-10-26 04:40:10` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78d58aed4803540680e7e0a02d7ef630` |
| SHA-1 | `c5a0327752665dfe6e6620fc1585525df4605184` |
| SHA-256 | `9cb0006ba80d05eed418511693eba7bde1d9ef3d6fc4ae4ff877f304758d5cb7` |
| SHA3-384 | `a57e5dd493fbfe86fcf821485d8d50f42bac6626e40e2421bea909e8240b648450d3ca7d4e5d99aeeaa067248f7c2132` |
| TLSH | `T15F463881230695F2B62DBB5CD236DAA0F94A640317C6DF3D30BC9316B758D07A75CAE2` |
| SSDEEP | `98304:jJ1UKVme+kbhY5YpxPSTwdd6YZU3Enz6LPdDU7+EtRom79Pfu20tePD5u3mdoEVl:FUe99Y5YLSwLZy4WPdDUltO6Nfn+KnPL` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_002_9cb0006b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cb0006ba80d05eed418511693eba7bde1d9ef3d6fc4ae4ff877f304758d5cb7"
    family = "RemcosRAT"
    file_name = "4567890766567896765YourQuotation.JS.js"
    file_type = "js"
    first_seen = "2026-10-26 04:40:10"
  condition:
    hash.sha256(0, filesize) == "9cb0006ba80d05eed418511693eba7bde1d9ef3d6fc4ae4ff877f304758d5cb7"
}
```

### Sample 3: `e42de348c01da6a9`

| Field | Value |
|---|---|
| SHA-256 | `e42de348c01da6a95b259804866e362d74fc0ea918f5a83362cb60e483d86afe` |
| Family label | `SalatStealer` |
| File name | `4ffd58dd83a3f89c.bin` |
| File type | `exe` |
| First seen | `2026-10-26 04:26:22` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b914b0ef5c13a8bab22ff4cc555cb36` |
| SHA-1 | `1289785cf9c3c945088b6a82632b05503a5b81d3` |
| SHA-256 | `e42de348c01da6a95b259804866e362d74fc0ea918f5a83362cb60e483d86afe` |
| SHA3-384 | `77e8a3e806aed7cf47f6cca4a2cdcc890459184bd50a270d156adddf8c7407ee29d24d71a689ffa850ccd504309835a3` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T166C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+c:yBkKr5rszpNDy+c` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_003_e42de348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e42de348c01da6a95b259804866e362d74fc0ea918f5a83362cb60e483d86afe"
    family = "SalatStealer"
    file_name = "4ffd58dd83a3f89c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 04:26:22"
  condition:
    hash.sha256(0, filesize) == "e42de348c01da6a95b259804866e362d74fc0ea918f5a83362cb60e483d86afe"
}
```

### Sample 4: `4ffd58dd83a3f89c`

| Field | Value |
|---|---|
| SHA-256 | `4ffd58dd83a3f89cade6d58e13b5919410e0cf1f30afdbf60bad1f716a061ac0` |
| Family label | `SalatStealer` |
| File name | `4ffd58dd83a3f89c.bin` |
| File type | `exe` |
| First seen | `2026-10-26 04:25:50` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95291c58a13eb929ead5750351e85772` |
| SHA-1 | `ccdd4a4218ec06bc360fe533c598c3d57dc3e270` |
| SHA-256 | `4ffd58dd83a3f89cade6d58e13b5919410e0cf1f30afdbf60bad1f716a061ac0` |
| SHA3-384 | `cd16becaede96e2c955719afb4da9072f8d212421ae34334e7b75c99254602c7497d87d6246a00943e4c68f3bc1331a8` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T124F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OQ:iJiafuIO7rhWEES4b` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_004_4ffd58dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ffd58dd83a3f89cade6d58e13b5919410e0cf1f30afdbf60bad1f716a061ac0"
    family = "SalatStealer"
    file_name = "4ffd58dd83a3f89c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 04:25:50"
  condition:
    hash.sha256(0, filesize) == "4ffd58dd83a3f89cade6d58e13b5919410e0cf1f30afdbf60bad1f716a061ac0"
}
```

### Sample 5: `61d1c1ca3ed32698`

| Field | Value |
|---|---|
| SHA-256 | `61d1c1ca3ed32698a440f3815606b23283a41a2c282567bfca2ee904b0932c6b` |
| Family label | `unknown` |
| File name | `macho_61d1c1ca3ed3.bin` |
| File type | `macho` |
| First seen | `2026-10-26 04:24:43` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c4ecc2dad4ac8b6eed0fd2dcb5e441d` |
| SHA-1 | `d94504196658c35a662140a64f8065c43279ae8f` |
| SHA-256 | `61d1c1ca3ed32698a440f3815606b23283a41a2c282567bfca2ee904b0932c6b` |
| SHA3-384 | `8e8129e9ca7e2fe7259af5b423cf074222ef08d9fb518770aab1b5101f38731dc4dd37c19a1154083529a150f484631e` |
| TLSH | `T159A5F110626F1165D1022832DCD10FA6D1F0A989A9CCAEF97765DB26FC37E43B6E3325` |
| SSDEEP | `49152:J6GVxwl7eDeOkLmNi5feZtJiBEeW+HFFcp3:QCXkLQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_61d1c1ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61d1c1ca3ed32698a440f3815606b23283a41a2c282567bfca2ee904b0932c6b"
    family = "unknown"
    file_name = "macho_61d1c1ca3ed3.bin"
    file_type = "macho"
    first_seen = "2026-10-26 04:24:43"
  condition:
    hash.sha256(0, filesize) == "61d1c1ca3ed32698a440f3815606b23283a41a2c282567bfca2ee904b0932c6b"
}
```

### Sample 6: `87c041a4ae659d82`

| Field | Value |
|---|---|
| SHA-256 | `87c041a4ae659d820ea1f586da9324764740cef43f167adefcef6c28d7595152` |
| Family label | `unknown` |
| File name | `RFQ PINACLE OM-JB-DNR AD-36588 - JOB IN HAND.vbs` |
| File type | `vbs` |
| First seen | `2026-10-26 04:15:44` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7bd153cd735d58787f99ff760614c94` |
| SHA-1 | `429e66954607f3690d03b1744a413000b0b5807a` |
| SHA-256 | `87c041a4ae659d820ea1f586da9324764740cef43f167adefcef6c28d7595152` |
| SHA3-384 | `486d7b47bcab79299ac4b5f5e062d78bce014e8dd9090fa9130bde5414bef84c030b28af6cd5897de0822e95ea12dd36` |
| TLSH | `T121736C70EE59021A0E4727EAFC494A65C5BC8215022710F5FEE9270EA107DECF7FE669` |
| SSDEEP | `1536:zo3Y2QGcYbnJsu5XycpI0zgPzqHOlSrsOS7u3xhzgl+Aziuxz:zcYsx1Xy50zgPSOl+sOP3Pzgl+eiux` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_87c041a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87c041a4ae659d820ea1f586da9324764740cef43f167adefcef6c28d7595152"
    family = "unknown"
    file_name = "RFQ PINACLE OM-JB-DNR AD-36588 - JOB IN HAND.vbs"
    file_type = "vbs"
    first_seen = "2026-10-26 04:15:44"
  condition:
    hash.sha256(0, filesize) == "87c041a4ae659d820ea1f586da9324764740cef43f167adefcef6c28d7595152"
}
```

### Sample 7: `34e5887dd33383eb`

| Field | Value |
|---|---|
| SHA-256 | `34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435` |
| Family label | `unknown` |
| File name | `ORDER_QUOTATION_FORM.com` |
| File type | `exe` |
| First seen | `2026-10-26 03:55:31` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aca797c1589207329745b4dfbd073867` |
| SHA-1 | `e7b1c7f0957b9b79c96547bf66d4391c046d04f6` |
| SHA-256 | `34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435` |
| SHA3-384 | `fcbb37a8a7a0d7272c82853d84140489aa3c4b20729037dfac1135bb0d03f2bdd25fcb87c5e6674824313582ea4b2455` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E805011935275013D9B26EF00D71E0B197762D6AB138E1954ECB1DABB9FBB10BE42323` |
| SSDEEP | `24576:CSATMUVYjFxTaq2DeooG3Taws+yPGj+sooB6ZciXy:ycdCDs+yP1PciXy` |
| ICON-DHASH | `71f8febeab80c071` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_34e5887d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435"
    family = "unknown"
    file_name = "ORDER_QUOTATION_FORM.com"
    file_type = "exe"
    first_seen = "2026-10-26 03:55:31"
  condition:
    hash.sha256(0, filesize) == "34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435"
}
```

### Sample 8: `04d9c053e5cff50a`

| Field | Value |
|---|---|
| SHA-256 | `04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4` |
| Family label | `RemcosRAT` |
| File name | `Quotation.JS.js` |
| File type | `js` |
| First seen | `2026-10-26 03:45:10` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `961b06b9ed566ce870840a4b0ed74b87` |
| SHA-1 | `fa2fd7dfd4703f258556b7bc87c8ecf443a3c5f2` |
| SHA-256 | `04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4` |
| SHA3-384 | `fafc5ba00f2e3ddf2371759f28d975a1966133524d8baccf7421e072594f8803b05fc16271b6bbf7b0922dfdf0018f43` |
| TLSH | `T1C036184213D7D532762FEB5CC136E860991A201315D6DF3D31BCA316767AD0BAB8CAE2` |
| SSDEEP | `98304:A5kdDnKLqQYscNmtwplFUTRzxx4X0znx13SzIlvYfS4kAVuXd/m2kgAK7N/V5oRn:a+zX8qMn7S+SLVuXd/nkgL/V5oRRWmL1` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_008_04d9c053
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4"
    family = "RemcosRAT"
    file_name = "Quotation.JS.js"
    file_type = "js"
    first_seen = "2026-10-26 03:45:10"
  condition:
    hash.sha256(0, filesize) == "04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4"
}
```

### Sample 9: `f9829cddd02a0960`

| Field | Value |
|---|---|
| SHA-256 | `f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2` |
| Family label | `unknown` |
| File name | `f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:32:58` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `862073e13dba53db8c27b1c54fb2a19c` |
| SHA-1 | `971b08bbb42c29939e17dfe04880de9e0313d1ad` |
| SHA-256 | `f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2` |
| SHA3-384 | `3558c6720e104ab6fb31de3588c03d9f794ac2b5297dc1b0f10250b36528743bda966b53bbc1d833b62c8d150f7e881e` |
| IMPHASH | `3b1036ee6220db1bbce96f7e017ed708` |
| TLSH | `T1FC45F14EF7910BF9F4658C3F49524512DAD3A80DE6900AEA538C13173E25ED1BAFB6E0` |
| SSDEEP | `24576:iqDQQaijO3bBX1sEUK6r20+LCoD8o6wzK:xkB6Opx` |
| ICON-DHASH | `9671f0d4d4f07196` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_f9829cdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2"
    family = "unknown"
    file_name = "f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:32:58"
  condition:
    hash.sha256(0, filesize) == "f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2"
}
```

### Sample 10: `deb10b2a3c921bb2`

| Field | Value |
|---|---|
| SHA-256 | `deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2` |
| Family label | `SalatStealer` |
| File name | `1fc26715d960f204.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:28:01` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57259bc7c9d8c86369eaf0698644d60d` |
| SHA-1 | `856246ff041038ad79d876744d507fa1a9953410` |
| SHA-256 | `deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2` |
| SHA3-384 | `e60d10758ad0cecc8e32a51cd3f8a7d5d7f9d92767205ab3db82b985e943cd288ef5089a05f5063404855a0e66edad72` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T165C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+7:yBkKr5rszpNDy+7` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_010_deb10b2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2"
    family = "SalatStealer"
    file_name = "1fc26715d960f204.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:28:01"
  condition:
    hash.sha256(0, filesize) == "deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2"
}
```

### Sample 11: `49818c65eaad6ee5`

| Field | Value |
|---|---|
| SHA-256 | `49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d` |
| Family label | `SalatStealer` |
| File name | `380a427f08c55b15.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:27:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b278d50e2ef267e1eca51a949367ef3` |
| SHA-1 | `5c26fed20a08e585ab96d8c366efcc7527ebb27b` |
| SHA-256 | `49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d` |
| SHA3-384 | `98a2b281022b8708729b68dce5da8b20cbefe97917a1b932c5e5b8cb856e171ef40dec0f0c7db7a4ed336ba6bbf91bf0` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T19CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+2:yBkKr5rszpNDy+2` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_011_49818c65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d"
    family = "SalatStealer"
    file_name = "380a427f08c55b15.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:27:51"
  condition:
    hash.sha256(0, filesize) == "49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d"
}
```

### Sample 12: `d98684d84b676fbd`

| Field | Value |
|---|---|
| SHA-256 | `d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842` |
| Family label | `SalatStealer` |
| File name | `ab25adf6f1b4b69b.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:27:44` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac0b7b0b6a9a103909c8c1946191dd1b` |
| SHA-1 | `c1c33d9fd8d9f13383c96d00ca28bf97c7088399` |
| SHA-256 | `d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842` |
| SHA3-384 | `1767356d410a8966c267f94bc8912289fa8836ce9e2e5f686bda86f9a864285abf95e876785c9276b656d58bf0029f71` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T195C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+K:yBkKr5rszpNDy+K` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_012_d98684d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842"
    family = "SalatStealer"
    file_name = "ab25adf6f1b4b69b.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:27:44"
  condition:
    hash.sha256(0, filesize) == "d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842"
}
```

### Sample 13: `965746db162d0483`

| Field | Value |
|---|---|
| SHA-256 | `965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5` |
| Family label | `SalatStealer` |
| File name | `b95779be1565278c.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:52` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f401a4fcf6ea4c330f18e1625dad626d` |
| SHA-1 | `c20f694d32f72115447ac4cf60d0c18ae5cc0cbe` |
| SHA-256 | `965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5` |
| SHA3-384 | `98f28672bacb7d7dabdf6db6e3f554421ceab09da75b60dbe8c1fddc87e99c7f6b5f43521308d220936e267beb7d8d5c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T146C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+H:yBkKr5rszpNDy+H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_013_965746db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5"
    family = "SalatStealer"
    file_name = "b95779be1565278c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:52"
  condition:
    hash.sha256(0, filesize) == "965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5"
}
```

### Sample 14: `56047cbe27a63d0c`

| Field | Value |
|---|---|
| SHA-256 | `56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08` |
| Family label | `SalatStealer` |
| File name | `dbbbbfb98939a25f.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea228be0de1a3540ff4de647e1969a9e` |
| SHA-1 | `8b6534676f149554c824eca498597c97ef3c62a9` |
| SHA-256 | `56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08` |
| SHA3-384 | `a868f212f93c22981129fa633458675b45dce19de39d54a7cde45b6e02b250bd058ad7d9b00ca0144c38d72edcaa0f7e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D5C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+P:yBkKr5rszpNDy+P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_014_56047cbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08"
    family = "SalatStealer"
    file_name = "dbbbbfb98939a25f.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:47"
  condition:
    hash.sha256(0, filesize) == "56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08"
}
```

### Sample 15: `1fc26715d960f204`

| Field | Value |
|---|---|
| SHA-256 | `1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba` |
| Family label | `SalatStealer` |
| File name | `1fc26715d960f204.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:41` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d99b89777a1c888a7d1089fb21d6bf9` |
| SHA-1 | `c6112e2079816e06c22eab24d555db8f88f02310` |
| SHA-256 | `1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba` |
| SHA3-384 | `92accca87e05f36c8ac56e31fabefe817eb323522e7a5dc002fe6c97f543d6368d018337b808b221a15a5c27aeb31819` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14AF5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O3:iJiafuIO7rhWEES44` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_015_1fc26715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba"
    family = "SalatStealer"
    file_name = "1fc26715d960f204.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:41"
  condition:
    hash.sha256(0, filesize) == "1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba"
}
```

### Sample 16: `50b420204ab02f38`

| Field | Value |
|---|---|
| SHA-256 | `50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384` |
| Family label | `SalatStealer` |
| File name | `5fc8200c7584303a.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:41` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c54ee413f379a926808943c7c3bce73` |
| SHA-1 | `a6d4eab09f19123cbd9a079b054f48c0eb3f190c` |
| SHA-256 | `50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384` |
| SHA3-384 | `1dd91c02721bb97335bd1162c735e238d75cebcc83e32ccf3b7fb901501c1a157d46313e476cca54463d23569bf2af18` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15FC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+k:yBkKr5rszpNDy+k` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_016_50b42020
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384"
    family = "SalatStealer"
    file_name = "5fc8200c7584303a.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:41"
  condition:
    hash.sha256(0, filesize) == "50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384"
}
```

### Sample 17: `f960ee2bf8316da0`

| Field | Value |
|---|---|
| SHA-256 | `f960ee2bf8316da09be6a44e024edd609e21f582ad094dc58803c5b93e08c79e` |
| Family label | `SalatStealer` |
| File name | `44901fe5e07cb3a5.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fbaaea7ff73c5bdb9a752c24ae58a22` |
| SHA-1 | `273c7db678e393e19a2be3196c24caa377eb37d3` |
| SHA-256 | `f960ee2bf8316da09be6a44e024edd609e21f582ad094dc58803c5b93e08c79e` |
| SHA3-384 | `a79b06199cb5c5764c2b62d82751453e7fdac3baa466f3dbafafd4b655a7244ad58208a22f6ddf934b829de00db3dd6b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T129C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+C:yBkKr5rszpNDy+C` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_017_f960ee2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f960ee2bf8316da09be6a44e024edd609e21f582ad094dc58803c5b93e08c79e"
    family = "SalatStealer"
    file_name = "44901fe5e07cb3a5.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:35"
  condition:
    hash.sha256(0, filesize) == "f960ee2bf8316da09be6a44e024edd609e21f582ad094dc58803c5b93e08c79e"
}
```

### Sample 18: `380a427f08c55b15`

| Field | Value |
|---|---|
| SHA-256 | `380a427f08c55b158cc0d90c38d3f741ea08a24a2811a2d9ca0c1d2dab5bfc66` |
| Family label | `SalatStealer` |
| File name | `380a427f08c55b15.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cdd2f97116893a4834be9d8ff35e50ef` |
| SHA-1 | `152f47ad6fc5bb19a6c5add9b079109c725adede` |
| SHA-256 | `380a427f08c55b158cc0d90c38d3f741ea08a24a2811a2d9ca0c1d2dab5bfc66` |
| SHA3-384 | `71edd5e930919f4404971ee34462a9ec7e32009aa4eb4c4445de4d776f6d9e97d0a1c58f744376bc3652c44916e647e4` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1EFF5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oy:iJiafuIO7rhWEES4X` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_018_380a427f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "380a427f08c55b158cc0d90c38d3f741ea08a24a2811a2d9ca0c1d2dab5bfc66"
    family = "SalatStealer"
    file_name = "380a427f08c55b15.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:31"
  condition:
    hash.sha256(0, filesize) == "380a427f08c55b158cc0d90c38d3f741ea08a24a2811a2d9ca0c1d2dab5bfc66"
}
```

### Sample 19: `ab25adf6f1b4b69b`

| Field | Value |
|---|---|
| SHA-256 | `ab25adf6f1b4b69b915555f1df2e7c4703b44a28a9aa0377e096b36c4bf406e6` |
| Family label | `SalatStealer` |
| File name | `ab25adf6f1b4b69b.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:21` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `805060e7ca141c6061062343514111fa` |
| SHA-1 | `233dbd99754859947ecda581b01dc85ce4626a4a` |
| SHA-256 | `ab25adf6f1b4b69b915555f1df2e7c4703b44a28a9aa0377e096b36c4bf406e6` |
| SHA3-384 | `3c4adc11fae82f7c8fa9eb054a2aa12483858cc06867b45e626c5cd603db574621be1a12b84a6decfeae1de4b8f63e4a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T13FF5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O2:iJiafuIO7rhWEES4b` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_019_ab25adf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab25adf6f1b4b69b915555f1df2e7c4703b44a28a9aa0377e096b36c4bf406e6"
    family = "SalatStealer"
    file_name = "ab25adf6f1b4b69b.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:21"
  condition:
    hash.sha256(0, filesize) == "ab25adf6f1b4b69b915555f1df2e7c4703b44a28a9aa0377e096b36c4bf406e6"
}
```

### Sample 20: `b95779be1565278c`

| Field | Value |
|---|---|
| SHA-256 | `b95779be1565278c9595423f93d8dc6bbdc4bda8abbed130f4f8924d03300862` |
| Family label | `SalatStealer` |
| File name | `b95779be1565278c.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9191fe58349196800d3bce448af0580c` |
| SHA-1 | `eb949bf21ce94cb4b168aabbcc91dc803746e9d5` |
| SHA-256 | `b95779be1565278c9595423f93d8dc6bbdc4bda8abbed130f4f8924d03300862` |
| SHA3-384 | `24203c7bdc926ad2af09d603b7e2a20ade4ce1e9662dddc817593a413c8316740974d5517007ad293c68df057420ec9a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1F2F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oz:iJiafuIO7rhWEES42` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_020_b95779be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95779be1565278c9595423f93d8dc6bbdc4bda8abbed130f4f8924d03300862"
    family = "SalatStealer"
    file_name = "b95779be1565278c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:11"
  condition:
    hash.sha256(0, filesize) == "b95779be1565278c9595423f93d8dc6bbdc4bda8abbed130f4f8924d03300862"
}
```

### Sample 21: `dbbbbfb98939a25f`

| Field | Value |
|---|---|
| SHA-256 | `dbbbbfb98939a25f1b2ab0e260aa01f7f6b569799aba107daf1cb17d66475295` |
| Family label | `SalatStealer` |
| File name | `dbbbbfb98939a25f.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:26:02` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `476fb20e8e352288e67e50680717b269` |
| SHA-1 | `011a89e3f497ac06c57132867adf24a739b2e66a` |
| SHA-256 | `dbbbbfb98939a25f1b2ab0e260aa01f7f6b569799aba107daf1cb17d66475295` |
| SHA3-384 | `4f4af6edafd08cd2aa54aa2fc6af540c49e0793850a8e6d416fd533918d7d400b4dbf16e122e0610c2d8d22050e33adb` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12DF5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Or:iJiafuIO7rhWEES4M` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_021_dbbbbfb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbbbbfb98939a25f1b2ab0e260aa01f7f6b569799aba107daf1cb17d66475295"
    family = "SalatStealer"
    file_name = "dbbbbfb98939a25f.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:02"
  condition:
    hash.sha256(0, filesize) == "dbbbbfb98939a25f1b2ab0e260aa01f7f6b569799aba107daf1cb17d66475295"
}
```

### Sample 22: `5fc8200c7584303a`

| Field | Value |
|---|---|
| SHA-256 | `5fc8200c7584303a0a9967875ce8050b95a9838b38e24ac0f35b595f79ca6217` |
| Family label | `SalatStealer` |
| File name | `5fc8200c7584303a.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:25:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61f34d207434074fc556705d6770cbf8` |
| SHA-1 | `5d41b36562059520931650a684cce21b9a25c1a6` |
| SHA-256 | `5fc8200c7584303a0a9967875ce8050b95a9838b38e24ac0f35b595f79ca6217` |
| SHA3-384 | `78eb9f3e26b11e2adc041b99b889d667e4e67be507accca49509c7ad2bb680159eb74e09b2b2c36464638cc4916e3a7c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T157F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OY:iJiafuIO7rhWEES4F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_022_5fc8200c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc8200c7584303a0a9967875ce8050b95a9838b38e24ac0f35b595f79ca6217"
    family = "SalatStealer"
    file_name = "5fc8200c7584303a.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:25:52"
  condition:
    hash.sha256(0, filesize) == "5fc8200c7584303a0a9967875ce8050b95a9838b38e24ac0f35b595f79ca6217"
}
```

### Sample 23: `44901fe5e07cb3a5`

| Field | Value |
|---|---|
| SHA-256 | `44901fe5e07cb3a5e0d4e278126e40f491ca8c67eb431bd2fcf764568bc16a65` |
| Family label | `SalatStealer` |
| File name | `44901fe5e07cb3a5.bin` |
| File type | `exe` |
| First seen | `2026-10-26 03:25:42` |
| Reporter | `Tuxxin` |
| Tags | `exe, salatstealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `698c8a75beda1c89b93e9f853e190410` |
| SHA-1 | `97cacda47465e87c1eb2c5297328ebbcbf635d3f` |
| SHA-256 | `44901fe5e07cb3a5e0d4e278126e40f491ca8c67eb431bd2fcf764568bc16a65` |
| SHA3-384 | `9323d541da6dbcd33ef3d61e8eb50e8cefa2d71c417aedf1199c459673ce9ac9dec5b67e650b710c9acbc16162493912` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T11FF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Om:iJiafuIO7rhWEES4P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_023_44901fe5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44901fe5e07cb3a5e0d4e278126e40f491ca8c67eb431bd2fcf764568bc16a65"
    family = "SalatStealer"
    file_name = "44901fe5e07cb3a5.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:25:42"
  condition:
    hash.sha256(0, filesize) == "44901fe5e07cb3a5e0d4e278126e40f491ca8c67eb431bd2fcf764568bc16a65"
}
```

### Sample 24: `18dc14d98be70b0b`

| Field | Value |
|---|---|
| SHA-256 | `18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345` |
| Family label | `Mirai` |
| File name | `titanjr.m68k` |
| File type | `elf` |
| First seen | `2026-10-26 03:20:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96c8ea4082cdc9ad5e1d0820c03e405e` |
| SHA-1 | `160df4343c31c57b860619c661017aa41b737d05` |
| SHA-256 | `18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345` |
| SHA3-384 | `651ace48a48d75bf5d62e86e4b81bacd1b26a937b2b8f34ec15214b35b272ff47032ef98691e59d360220f69aa2d95ca` |
| TLSH | `T1BE145BC3F900DDBDF80BE33B84174919B530A7A214935A33A257B97BED3A1990537E86` |
| SSDEEP | `3072:yFGw5vFUgl7Uqsa/Pdtctk3RRevIEQgbMtbZVijbiZLLzEqiyBOSAld3od:yU6pl1Ck3REv9wtbVLLEyBV01od` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_18dc14d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345"
    family = "Mirai"
    file_name = "titanjr.m68k"
    file_type = "elf"
    first_seen = "2026-10-26 03:20:57"
  condition:
    hash.sha256(0, filesize) == "18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345"
}
```

### Sample 25: `6ca51009e9135f05`

| Field | Value |
|---|---|
| SHA-256 | `6ca51009e9135f05a3ed7772f7fb00c87e973d71cfbb4292f46c369c2e5e27cd` |
| Family label | `SalatStealer` |
| File name | `4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:17:01` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afc7e918789524ff48129bbf1795045f` |
| SHA-1 | `f7ac3b8497ef77b0a0df6f228df305f1e95ea80f` |
| SHA-256 | `6ca51009e9135f05a3ed7772f7fb00c87e973d71cfbb4292f46c369c2e5e27cd` |
| SHA3-384 | `5f4da5cc64134b15fe657de8c2d536cef29dceade3ab4e5b8d007441ccd3195671d147a10f216c76ca197b8606beed07` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13DC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+d:yBkKr5rszpNDy+d` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_025_6ca51009
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ca51009e9135f05a3ed7772f7fb00c87e973d71cfbb4292f46c369c2e5e27cd"
    family = "SalatStealer"
    file_name = "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:17:01"
  condition:
    hash.sha256(0, filesize) == "6ca51009e9135f05a3ed7772f7fb00c87e973d71cfbb4292f46c369c2e5e27cd"
}
```

### Sample 26: `c32adbd683ac24aa`

| Field | Value |
|---|---|
| SHA-256 | `c32adbd683ac24aa6dcf4d8d5bba1457dcdd116446a44cf7dc0f3f4937fc739e` |
| Family label | `SalatStealer` |
| File name | `d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:16:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d9e1fe08cc0b6de6b819bdd9c060a36` |
| SHA-1 | `23a9fd6d2356319a6581cf78dce821ba488ac617` |
| SHA-256 | `c32adbd683ac24aa6dcf4d8d5bba1457dcdd116446a44cf7dc0f3f4937fc739e` |
| SHA3-384 | `ccd79e60162d17b8f6470f363069382fa29041efaf68f624893a1dd606858e5b87acc260832e7ef5dcc6e89af2afe539` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Q:yBkKr5rszpNDy+Q` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_026_c32adbd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c32adbd683ac24aa6dcf4d8d5bba1457dcdd116446a44cf7dc0f3f4937fc739e"
    family = "SalatStealer"
    file_name = "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:16:54"
  condition:
    hash.sha256(0, filesize) == "c32adbd683ac24aa6dcf4d8d5bba1457dcdd116446a44cf7dc0f3f4937fc739e"
}
```

### Sample 27: `f8ed72c81eadb12f`

| Field | Value |
|---|---|
| SHA-256 | `f8ed72c81eadb12f513f2245163ec5cf89b1433199a4c6a8d9aaa44460818486` |
| Family label | `SalatStealer` |
| File name | `ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:16:44` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9c1c7cf82ff620802ebcda9545999c9` |
| SHA-1 | `6569d8052804e86f98af46e59112f264954362eb` |
| SHA-256 | `f8ed72c81eadb12f513f2245163ec5cf89b1433199a4c6a8d9aaa44460818486` |
| SHA3-384 | `5bbdee7483c0cea89b63a6265b133d71e772e7b8be806b1991c9b421b9dca32b455aa24a52003a080076badff0624795` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Z:yBkKr5rszpNDy+Z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_027_f8ed72c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ed72c81eadb12f513f2245163ec5cf89b1433199a4c6a8d9aaa44460818486"
    family = "SalatStealer"
    file_name = "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:16:44"
  condition:
    hash.sha256(0, filesize) == "f8ed72c81eadb12f513f2245163ec5cf89b1433199a4c6a8d9aaa44460818486"
}
```

### Sample 28: `c2ee0b2f58eedd5c`

| Field | Value |
|---|---|
| SHA-256 | `c2ee0b2f58eedd5c3690c5766870f17608e16bff99c2217e902b281d53ca4f85` |
| Family label | `SalatStealer` |
| File name | `599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:15:02` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afc738c0b7ce074d772ad90f764a0cb2` |
| SHA-1 | `343c549e1aedcf0165f4a70adbed84460908ce07` |
| SHA-256 | `c2ee0b2f58eedd5c3690c5766870f17608e16bff99c2217e902b281d53ca4f85` |
| SHA3-384 | `19bb78d1354d69d5db46fe89b94da1f7bec4d12e10f5a6145ece9465761bfdf38e7ede0aa7e0337db591dc105dec7464` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T171C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+Y:yBkKr5rszpNDy+Y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_028_c2ee0b2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ee0b2f58eedd5c3690c5766870f17608e16bff99c2217e902b281d53ca4f85"
    family = "SalatStealer"
    file_name = "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:15:02"
  condition:
    hash.sha256(0, filesize) == "c2ee0b2f58eedd5c3690c5766870f17608e16bff99c2217e902b281d53ca4f85"
}
```

### Sample 29: `4fc7a8e8b3f31afa`

| Field | Value |
|---|---|
| SHA-256 | `4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3` |
| Family label | `SalatStealer` |
| File name | `4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:14:56` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2edfb7f7b0e032ca366b3bec1d222528` |
| SHA-1 | `ad370bc21a14b1be74a8e728be3f82c6a606da38` |
| SHA-256 | `4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3` |
| SHA3-384 | `6696064ae4f88bc42128049a1cf2c2dd727c2a35299dd9cc4932504cec14564944617f87edc7515cada3284b2de51870` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E2F5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oh:iJiafuIO7rhWEES4i` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_029_4fc7a8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3"
    family = "SalatStealer"
    file_name = "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:56"
  condition:
    hash.sha256(0, filesize) == "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3"
}
```

### Sample 30: `c4939596c1549254`

| Field | Value |
|---|---|
| SHA-256 | `c4939596c1549254f379ba7d7ebc85525af699e24011dc7ddf6ffdc37eb0cce1` |
| Family label | `SalatStealer` |
| File name | `6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:14:55` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8500668fa76660605e36207d6208a23b` |
| SHA-1 | `d22d2bf5e489bcb9ec19807e08a1d80566c13836` |
| SHA-256 | `c4939596c1549254f379ba7d7ebc85525af699e24011dc7ddf6ffdc37eb0cce1` |
| SHA3-384 | `78fd6583d734cb6c41d82675af997776342f0e38e41317a6442dcb8b81fc94887f33c9a9cb871f568345e4195e1527e0` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T171C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE++:yBkKr5rszpNDy++` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_030_c4939596
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4939596c1549254f379ba7d7ebc85525af699e24011dc7ddf6ffdc37eb0cce1"
    family = "SalatStealer"
    file_name = "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:55"
  condition:
    hash.sha256(0, filesize) == "c4939596c1549254f379ba7d7ebc85525af699e24011dc7ddf6ffdc37eb0cce1"
}
```

### Sample 31: `d5e40d66ee25be80`

| Field | Value |
|---|---|
| SHA-256 | `d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0` |
| Family label | `SalatStealer` |
| File name | `d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:14:51` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e89f1164303332098ce3326dcf011b0e` |
| SHA-1 | `97132abfa7eb4c14dc1e4114661603d22993c586` |
| SHA-256 | `d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0` |
| SHA3-384 | `879e6b2b8b89f541fbf483ce9e134dc7a56424cc583ddfcdf29659c522b0cb261189acb681cd5e0a4870f6c529014b45` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B5F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OE:iJiafuIO7rhWEES4H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_031_d5e40d66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0"
    family = "SalatStealer"
    file_name = "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:51"
  condition:
    hash.sha256(0, filesize) == "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0"
}
```

### Sample 32: `ba8346394f23db90`

| Field | Value |
|---|---|
| SHA-256 | `ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0` |
| Family label | `SalatStealer` |
| File name | `ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:14:46` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `deac839bf75d78da1655f64a15f9a995` |
| SHA-1 | `0a9022fc8342009daf05c0e3db1a8686532f93f3` |
| SHA-256 | `ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0` |
| SHA3-384 | `94f7b40402c6a3ee489a7c34ea2428eee25853d8c1ea39af83e173014366dc8e83e659ceec3eb237c6f7149205e517c3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T165F5335BF1AB4BB3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0846FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O9:iJiafuIO7rhWEES4u` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_032_ba834639
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0"
    family = "SalatStealer"
    file_name = "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:46"
  condition:
    hash.sha256(0, filesize) == "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0"
}
```

### Sample 33: `db62273ba408eeb6`

| Field | Value |
|---|---|
| SHA-256 | `db62273ba408eeb6246b973f11cfa96313c1e8d5d6831e9b783db5e765544836` |
| Family label | `SalatStealer` |
| File name | `4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:14:07` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c7007050ae3593d95c160d8fcd00bb4a` |
| SHA-1 | `88f18ce3979bc15a3440219dd4f3cca267a5e549` |
| SHA-256 | `db62273ba408eeb6246b973f11cfa96313c1e8d5d6831e9b783db5e765544836` |
| SHA3-384 | `ae2d68f3100515cb1da3cadd94d92abd8e13c3293888baff5d3e7d8ef5b35b11405eb2ec582837898bf02db93d30d9b3` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T181C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+e:yBkKr5rszpNDy+e` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_033_db62273b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db62273ba408eeb6246b973f11cfa96313c1e8d5d6831e9b783db5e765544836"
    family = "SalatStealer"
    file_name = "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:07"
  condition:
    hash.sha256(0, filesize) == "db62273ba408eeb6246b973f11cfa96313c1e8d5d6831e9b783db5e765544836"
}
```

### Sample 34: `f586e25f4fa4fb7e`

| Field | Value |
|---|---|
| SHA-256 | `f586e25f4fa4fb7ef2945dda68d6b18c84ba812f1de761e205cea75686e91f6f` |
| Family label | `unknown` |
| File name | `0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5bfac62891da558181b0e1cc9efb39e9` |
| SHA-1 | `94011dab838298d2985e2d69ca5d91dfbbeea17d` |
| SHA-256 | `f586e25f4fa4fb7ef2945dda68d6b18c84ba812f1de761e205cea75686e91f6f` |
| SHA3-384 | `f4bf80b53e0eebaca8e775cccdd943c13ee6fdbe19531281ec396cb4c6bd14345f1a133c1f122f0cc02edece65d06e46` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T132C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+r:yBkKr5rszpNDy+r` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_f586e25f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f586e25f4fa4fb7ef2945dda68d6b18c84ba812f1de761e205cea75686e91f6f"
    family = "unknown"
    file_name = "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:59"
  condition:
    hash.sha256(0, filesize) == "f586e25f4fa4fb7ef2945dda68d6b18c84ba812f1de761e205cea75686e91f6f"
}
```

### Sample 35: `4dd43a8aea19f785`

| Field | Value |
|---|---|
| SHA-256 | `4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518` |
| Family label | `unknown` |
| File name | `01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:54` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75d8f5385d73d00b439fcf06c44f345d` |
| SHA-1 | `644aeb89dc4ef0cfc7d17fbcea8a0ad08e11d08b` |
| SHA-256 | `4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518` |
| SHA3-384 | `9fc68df4dfa27be4bc7d1a1cd68f29c04d981da77623f0554ddd11b65aa92a21d6a8ba26bc96128e901203705c9bf8eb` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C8C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+f:yBkKr5rszpNDy+f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_4dd43a8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518"
    family = "unknown"
    file_name = "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:54"
  condition:
    hash.sha256(0, filesize) == "4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518"
}
```

### Sample 36: `599cd0608c4f96e7`

| Field | Value |
|---|---|
| SHA-256 | `599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66` |
| Family label | `SalatStealer` |
| File name | `599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e983c803b551268abd87a8c64757828b` |
| SHA-1 | `298ce6af7dee38aaa5c5ccb589ce92b75680e4a8` |
| SHA-256 | `599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66` |
| SHA3-384 | `7f81573d64f2a4e49f5362d65a97fc5a250e9612f6bbdfd45d7a51c7ef67ff22f7d7d2d16d941c05dd11a70c7de61268` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T138F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O8:iJiafuIO7rhWEES4h` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_036_599cd060
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66"
    family = "SalatStealer"
    file_name = "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:39"
  condition:
    hash.sha256(0, filesize) == "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66"
}
```

### Sample 37: `6b1ae5d5a3575a9a`

| Field | Value |
|---|---|
| SHA-256 | `6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a` |
| Family label | `SalatStealer` |
| File name | `6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:34` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0154414bc8fcf7f84bf0ea4e384beff` |
| SHA-1 | `4c35af61f4e38ee6577c1ba46a5ac163cd7b7992` |
| SHA-256 | `6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a` |
| SHA3-384 | `325318ea81177ef1f5afa23a374241ecf53e0f23b72776ba9680666cfb1bd916a7121ef333130e84ac6d325518c4c45a` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T100F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES4n` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_037_6b1ae5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a"
    family = "SalatStealer"
    file_name = "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:34"
  condition:
    hash.sha256(0, filesize) == "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a"
}
```

### Sample 38: `4be7c4355dee7e87`

| Field | Value |
|---|---|
| SHA-256 | `4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26` |
| Family label | `SalatStealer` |
| File name | `4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc95bf11a4843cfa8d784be8515550be` |
| SHA-1 | `a0d989381d395fc83bd73616ea1ae82ae6eb52e8` |
| SHA-256 | `4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26` |
| SHA3-384 | `3ada73c11a93e95bd8284c52eef7c22057b23bb9f6e11663bf837dfc81e27314e313aeb07d4a8db72c7807046a75a9ff` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A5F5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oa:iJiafuIO7rhWEES4j` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_038_4be7c435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26"
    family = "SalatStealer"
    file_name = "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:29"
  condition:
    hash.sha256(0, filesize) == "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26"
}
```

### Sample 39: `be22e2e21368e30c`

| Field | Value |
|---|---|
| SHA-256 | `be22e2e21368e30cc8089edb0543459cfc404c3a1645f3b870a1ad05760a0343` |
| Family label | `SalatStealer` |
| File name | `65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2e1258ab537abfef3f129b3e979cff0` |
| SHA-1 | `4f4d055e9520556480344c9b7b132676a11f193c` |
| SHA-256 | `be22e2e21368e30cc8089edb0543459cfc404c3a1645f3b870a1ad05760a0343` |
| SHA3-384 | `384b2669c1d8ff4fab95dc0af8d196f21c9e72688d2d84f07e22c2d3916ab96fb0cf51f25f79ab04889108daeed1c58b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1AFC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+J:yBkKr5rszpNDy+J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_039_be22e2e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be22e2e21368e30cc8089edb0543459cfc404c3a1645f3b870a1ad05760a0343"
    family = "SalatStealer"
    file_name = "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:26"
  condition:
    hash.sha256(0, filesize) == "be22e2e21368e30cc8089edb0543459cfc404c3a1645f3b870a1ad05760a0343"
}
```

### Sample 40: `0b09b5c8c4e7133e`

| Field | Value |
|---|---|
| SHA-256 | `0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b` |
| Family label | `SalatStealer` |
| File name | `0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:24` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96f180f164b162031f4475d33cd147df` |
| SHA-1 | `303622a1b2e51493c7764895725939a042d2b5db` |
| SHA-256 | `0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b` |
| SHA3-384 | `6540c2824566d2bdaf5f52a88401906bbfc3eafe8c208ca6a308bfe6ad11b217c15dcf4266dc0147441289459b976787` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1ADF5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Of:iJiafuIO7rhWEES4E` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_040_0b09b5c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b"
    family = "SalatStealer"
    file_name = "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:24"
  condition:
    hash.sha256(0, filesize) == "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b"
}
```

### Sample 41: `01b4818ebcd9a88c`

| Field | Value |
|---|---|
| SHA-256 | `01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845` |
| Family label | `SalatStealer` |
| File name | `01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:19` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3a551f171b49685a132f4b32956e069d` |
| SHA-1 | `c644a641f361675bd33521d8626b9e8dac029cf2` |
| SHA-256 | `01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845` |
| SHA3-384 | `2bd833b3a60bd6102ef4742019b3e464dd16fe34c105936330f54293e64c6efb761f93288eb0ff39db7ce979c5732bec` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T123F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O7:iJiafuIO7rhWEES4u` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_041_01b4818e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845"
    family = "SalatStealer"
    file_name = "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:19"
  condition:
    hash.sha256(0, filesize) == "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845"
}
```

### Sample 42: `28c7ddc294a263b8`

| Field | Value |
|---|---|
| SHA-256 | `28c7ddc294a263b8ca8a76fdec743c11cc9553447e66499882d5086d3f44d9bb` |
| Family label | `SalatStealer` |
| File name | `46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:13:02` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b76750c14a667991292126a66384209f` |
| SHA-1 | `7dd97333fcb72d5f6be7cff307f94924fa3c1419` |
| SHA-256 | `28c7ddc294a263b8ca8a76fdec743c11cc9553447e66499882d5086d3f44d9bb` |
| SHA3-384 | `bf90d546aec276e63406e31beef9452e466637df485f63f7e7fd38e29990bea36f3395e1b12bdca9e9160ce62d4e1f27` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T142C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+M:yBkKr5rszpNDy+M` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_042_28c7ddc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c7ddc294a263b8ca8a76fdec743c11cc9553447e66499882d5086d3f44d9bb"
    family = "SalatStealer"
    file_name = "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:02"
  condition:
    hash.sha256(0, filesize) == "28c7ddc294a263b8ca8a76fdec743c11cc9553447e66499882d5086d3f44d9bb"
}
```

### Sample 43: `9c5a43a6c1d5d68e`

| Field | Value |
|---|---|
| SHA-256 | `9c5a43a6c1d5d68e2c67d16b89fab04d838f8fa25daf863df8774d5be24004ff` |
| Family label | `SalatStealer` |
| File name | `de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:12:55` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b0d0c8a4de32ba154af4178c096ff70` |
| SHA-1 | `c5a846f918d73efb9acdbd50baf20da55bab64f3` |
| SHA-256 | `9c5a43a6c1d5d68e2c67d16b89fab04d838f8fa25daf863df8774d5be24004ff` |
| SHA3-384 | `d0374da2d94b8e1ec42a07861a17991881621d01e66e3471dff09c8740b470eb50e92d0b7efaa82fdc65f69c5049dce1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C1C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+6:yBkKr5rszpNDy+6` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_043_9c5a43a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c5a43a6c1d5d68e2c67d16b89fab04d838f8fa25daf863df8774d5be24004ff"
    family = "SalatStealer"
    file_name = "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:55"
  condition:
    hash.sha256(0, filesize) == "9c5a43a6c1d5d68e2c67d16b89fab04d838f8fa25daf863df8774d5be24004ff"
}
```

### Sample 44: `ecfd4196785d5944`

| Field | Value |
|---|---|
| SHA-256 | `ecfd4196785d5944fe1e947fd3e23ed87dfccc246a0553bc6ab5f7a3e6ad4102` |
| Family label | `SalatStealer` |
| File name | `9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:12:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c973001389b8163ee6dcfa2a0cc1cc46` |
| SHA-1 | `10c72faeb7864810c1b666a9e9dc58bad86e3e0a` |
| SHA-256 | `ecfd4196785d5944fe1e947fd3e23ed87dfccc246a0553bc6ab5f7a3e6ad4102` |
| SHA3-384 | `2d64fc817d3c8e23059a173338f38ace3647ced21aa28e12bd36bf737e5f0edbef4d3cc6c2e780cd2c24a77329a69e18` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1A7C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+b:yBkKr5rszpNDy+b` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_044_ecfd4196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecfd4196785d5944fe1e947fd3e23ed87dfccc246a0553bc6ab5f7a3e6ad4102"
    family = "SalatStealer"
    file_name = "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:47"
  condition:
    hash.sha256(0, filesize) == "ecfd4196785d5944fe1e947fd3e23ed87dfccc246a0553bc6ab5f7a3e6ad4102"
}
```

### Sample 45: `f48fd32b4c3c6dc7`

| Field | Value |
|---|---|
| SHA-256 | `f48fd32b4c3c6dc7553630d4c624ab46e4b0458b5362515407ec6e7c2d46c1f1` |
| Family label | `SalatStealer` |
| File name | `f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:12:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c38b9dd376b236c0b2e626c05fc82dc` |
| SHA-1 | `9b64a23ceaf5d59500921ce965d48cb8463abbce` |
| SHA-256 | `f48fd32b4c3c6dc7553630d4c624ab46e4b0458b5362515407ec6e7c2d46c1f1` |
| SHA3-384 | `8cd254dfbdd3b3b1e383e9f8af1bdb73be6bbe98a7c8af5f3db9396a9a0d55a5b75042eb37d8f888203a09a84ef04463` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T123C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+3:yBkKr5rszpNDy+3` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_045_f48fd32b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48fd32b4c3c6dc7553630d4c624ab46e4b0458b5362515407ec6e7c2d46c1f1"
    family = "SalatStealer"
    file_name = "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:40"
  condition:
    hash.sha256(0, filesize) == "f48fd32b4c3c6dc7553630d4c624ab46e4b0458b5362515407ec6e7c2d46c1f1"
}
```

### Sample 46: `b647fada3a64d2da`

| Field | Value |
|---|---|
| SHA-256 | `b647fada3a64d2dad979b8d18c0e2ed34944e2ba4cc60889cc06b093eb3f396e` |
| Family label | `SalatStealer` |
| File name | `1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:12:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c01caeec65219cbd985f8234d722985` |
| SHA-1 | `c86624d7ddc629d64fc36036443e4ce359c7986f` |
| SHA-256 | `b647fada3a64d2dad979b8d18c0e2ed34944e2ba4cc60889cc06b093eb3f396e` |
| SHA3-384 | `8a04fcb505aec80a0bddc12f7dfc9daf1e0481c35d3088ee815d1200a8e19962c327ae946184b84676636917a46296e5` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13BC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+O:yBkKr5rszpNDy+O` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_046_b647fada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b647fada3a64d2dad979b8d18c0e2ed34944e2ba4cc60889cc06b093eb3f396e"
    family = "SalatStealer"
    file_name = "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:31"
  condition:
    hash.sha256(0, filesize) == "b647fada3a64d2dad979b8d18c0e2ed34944e2ba4cc60889cc06b093eb3f396e"
}
```

### Sample 47: `6d2365d521653fef`

| Field | Value |
|---|---|
| SHA-256 | `6d2365d521653fef1c85938fe6e8ec7d67d3fae28515344733ff802a7f74ea18` |
| Family label | `SalatStealer` |
| File name | `30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:11:36` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d97be596936c2129f8a1237a259224b3` |
| SHA-1 | `44d5d09bf6bfacb63ba624f8a2546db22a942700` |
| SHA-256 | `6d2365d521653fef1c85938fe6e8ec7d67d3fae28515344733ff802a7f74ea18` |
| SHA3-384 | `94f88bea912da2cf0500d814a76a4844ad64fc781bfd592b9bfcfb9a322fd115171ba92532f6b809e61e633b8861a218` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T173C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+J:yBkKr5rszpNDy+J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_047_6d2365d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d2365d521653fef1c85938fe6e8ec7d67d3fae28515344733ff802a7f74ea18"
    family = "SalatStealer"
    file_name = "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:36"
  condition:
    hash.sha256(0, filesize) == "6d2365d521653fef1c85938fe6e8ec7d67d3fae28515344733ff802a7f74ea18"
}
```

### Sample 48: `8daad70d021307c2`

| Field | Value |
|---|---|
| SHA-256 | `8daad70d021307c29446df9c72e93b13aaa8b41106c2c87d1b1e46ee16a0c76c` |
| Family label | `SalatStealer` |
| File name | `087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:11:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3274a08f5c61c716a7cdbf3cba506f4c` |
| SHA-1 | `f63335987463da40221486be787317fd4a868ed1` |
| SHA-256 | `8daad70d021307c29446df9c72e93b13aaa8b41106c2c87d1b1e46ee16a0c76c` |
| SHA3-384 | `4fce0bbad7594e972dae510c7fa74b0c34d7fae99fa03a735ec65c0b08d2d2d2511608ae03a1d9f57b513bc51a28db09` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T181C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+2:yBkKr5rszpNDy+2` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_048_8daad70d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8daad70d021307c29446df9c72e93b13aaa8b41106c2c87d1b1e46ee16a0c76c"
    family = "SalatStealer"
    file_name = "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:25"
  condition:
    hash.sha256(0, filesize) == "8daad70d021307c29446df9c72e93b13aaa8b41106c2c87d1b1e46ee16a0c76c"
}
```

### Sample 49: `65490ae0988454e9`

| Field | Value |
|---|---|
| SHA-256 | `65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1` |
| Family label | `SalatStealer` |
| File name | `65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:11:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2106dc24c90b05cde859d4dc238cb6d7` |
| SHA-1 | `06f6afc976d61ea9bd66b8e2230ac07d022ec6c9` |
| SHA-256 | `65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1` |
| SHA3-384 | `f6d114565d42b9065fe49cd94f103f202831c38bad4b6ecc9dfc6812c13b9c8d6a4b78ef775724420d7673c9ca30a92d` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C6F5335BF1AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OV:iJiafuIO7rhWEES4K` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_049_65490ae0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1"
    family = "SalatStealer"
    file_name = "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:03"
  condition:
    hash.sha256(0, filesize) == "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1"
}
```

### Sample 50: `f6c74c5ac49453f0`

| Field | Value |
|---|---|
| SHA-256 | `f6c74c5ac49453f0d43e3c459de39bfaa8bc68db1847b4123600ddb4607d9757` |
| Family label | `SalatStealer` |
| File name | `5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:11:01` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df5e6dab5fe8635b7dcbf46b1d6b4e0e` |
| SHA-1 | `427b068c83e200c7654c1ca13d3ae1dea2097f80` |
| SHA-256 | `f6c74c5ac49453f0d43e3c459de39bfaa8bc68db1847b4123600ddb4607d9757` |
| SHA3-384 | `01019698bd433d45b9a1683cca46d69f630ae80d4b72a1e0866a6e97c7d4576ed8b798b7b1357b0790bddfb6c474b21c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1DBC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+d:yBkKr5rszpNDy+d` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_050_f6c74c5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6c74c5ac49453f0d43e3c459de39bfaa8bc68db1847b4123600ddb4607d9757"
    family = "SalatStealer"
    file_name = "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:01"
  condition:
    hash.sha256(0, filesize) == "f6c74c5ac49453f0d43e3c459de39bfaa8bc68db1847b4123600ddb4607d9757"
}
```

### Sample 51: `46eeb050ee375b52`

| Field | Value |
|---|---|
| SHA-256 | `46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7` |
| Family label | `SalatStealer` |
| File name | `46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:58` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfc220bcae8e1c2264c4646d4eea29a3` |
| SHA-1 | `f9e458bc456a79676034e853ffe22c4ff34a5f76` |
| SHA-256 | `46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7` |
| SHA3-384 | `dd125e1690b1fd9b9b6efb46a614742f34d16561a439add096386987e2bb21bcc92d17389cb1c26d852111982886c5b0` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T192F5335BF5AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0882FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Og:iJiafuIO7rhWEES4D` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_051_46eeb050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7"
    family = "SalatStealer"
    file_name = "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:58"
  condition:
    hash.sha256(0, filesize) == "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7"
}
```

### Sample 52: `81bfade2a8f36b41`

| Field | Value |
|---|---|
| SHA-256 | `81bfade2a8f36b41b76f42088b0171cd98bc691e50161e9d7b15bf9f3a205b31` |
| Family label | `SalatStealer` |
| File name | `4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:55` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86d8478965f359c2c36e9b9e8790aa97` |
| SHA-1 | `a71813dc63bf2e3ba109d87edcd45a40bec7d60e` |
| SHA-256 | `81bfade2a8f36b41b76f42088b0171cd98bc691e50161e9d7b15bf9f3a205b31` |
| SHA3-384 | `84acdc1bfb81a5c7084d8d162b414599333acf50b5d5113b3993ac73091cba1223145d7ec9a9d5b48c2e6f60ae1b62ff` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1BAC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+U:yBkKr5rszpNDy+U` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_052_81bfade2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81bfade2a8f36b41b76f42088b0171cd98bc691e50161e9d7b15bf9f3a205b31"
    family = "SalatStealer"
    file_name = "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:55"
  condition:
    hash.sha256(0, filesize) == "81bfade2a8f36b41b76f42088b0171cd98bc691e50161e9d7b15bf9f3a205b31"
}
```

### Sample 53: `de8566192e11b9fe`

| Field | Value |
|---|---|
| SHA-256 | `de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a` |
| Family label | `SalatStealer` |
| File name | `de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:53` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `428a04d3bc013e9c92c2f4a4af482ce9` |
| SHA-1 | `013369566907a6865f53e494b4c1410067282755` |
| SHA-256 | `de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a` |
| SHA3-384 | `58d00f18ab11c9e1a6b183a8cd203f4f888d8ad9b77179d5afe49b1a0ea5a400603c9fcb6f47d3ab3c1f4ff76c909eb3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T12FF5335BF1AB47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OG:iJiafuIO7rhWEES4J` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_053_de856619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a"
    family = "SalatStealer"
    file_name = "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:53"
  condition:
    hash.sha256(0, filesize) == "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a"
}
```

### Sample 54: `9178eae708a885cd`

| Field | Value |
|---|---|
| SHA-256 | `9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0` |
| Family label | `SalatStealer` |
| File name | `9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a9c0cdbd7adbac266e0ce153e4beac9` |
| SHA-1 | `72b82ccd4db84000f68619f10be4f311e3c7ce61` |
| SHA-256 | `9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0` |
| SHA3-384 | `904673c9caba28c37675ec88330b0d228e0f571593bac3837e7161f30b65bd1cef50ec67fd6124c20f64d1b4d35630d2` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T109F5335BF1AB47B3F7D9A831560FC66458F09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Of:iJiafuIO7rhWEES4I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_054_9178eae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0"
    family = "SalatStealer"
    file_name = "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:49"
  condition:
    hash.sha256(0, filesize) == "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0"
}
```

### Sample 55: `58cafffe8b371b4e`

| Field | Value |
|---|---|
| SHA-256 | `58cafffe8b371b4e89eea07bfe2100bce7f77df31dfb2b9cc2ea08612b09d7c4` |
| Family label | `SalatStealer` |
| File name | `07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `229199674a1d5b6f098bddeab7b0a87d` |
| SHA-1 | `c2994fffb65a5e028504a3c4ccaf9a95c14b5713` |
| SHA-256 | `58cafffe8b371b4e89eea07bfe2100bce7f77df31dfb2b9cc2ea08612b09d7c4` |
| SHA3-384 | `d6d9ed7399c911b6783a9a90e457e9f93bc35b94608071a692801edc93e51488ffaf9043055b23daff4e1be045ec24d7` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T136C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+B:yBkKr5rszpNDy+B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_055_58cafffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58cafffe8b371b4e89eea07bfe2100bce7f77df31dfb2b9cc2ea08612b09d7c4"
    family = "SalatStealer"
    file_name = "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:47"
  condition:
    hash.sha256(0, filesize) == "58cafffe8b371b4e89eea07bfe2100bce7f77df31dfb2b9cc2ea08612b09d7c4"
}
```

### Sample 56: `f585889eea971998`

| Field | Value |
|---|---|
| SHA-256 | `f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2` |
| Family label | `SalatStealer` |
| File name | `f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c98b9d0a502ec9b5d48aab197e8b7255` |
| SHA-1 | `5d8da97e61e063e8281004ff78f44566d4071174` |
| SHA-256 | `f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2` |
| SHA3-384 | `471776fb57c24490c03652e1688665c0bddc02be6ecb1721c6c7f978de96f2307481f38cdfc437a9ea21dd170e50daca` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1F0F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAADF0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OD:iJiafuIO7rhWEES4E` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_056_f585889e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2"
    family = "SalatStealer"
    file_name = "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:44"
  condition:
    hash.sha256(0, filesize) == "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2"
}
```

### Sample 57: `7d09495041b89cb3`

| Field | Value |
|---|---|
| SHA-256 | `7d09495041b89cb3c4e49870c0534b9e9c3910950ce4838756e5daf2b610e25c` |
| Family label | `SalatStealer` |
| File name | `7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98947b961607154acfbc7c20154dcdba` |
| SHA-1 | `df6b3bb6705250e9e923766d67789dfdcba69e7b` |
| SHA-256 | `7d09495041b89cb3c4e49870c0534b9e9c3910950ce4838756e5daf2b610e25c` |
| SHA3-384 | `df8a1a9eefa7dd13cd329b0db0f54b6180c55da012d598014479e2e7e7db13664cb109d84e3397260542eba5ba810029` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T162C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+N:yBkKr5rszpNDy+N` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_057_7d094950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d09495041b89cb3c4e49870c0534b9e9c3910950ce4838756e5daf2b610e25c"
    family = "SalatStealer"
    file_name = "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:39"
  condition:
    hash.sha256(0, filesize) == "7d09495041b89cb3c4e49870c0534b9e9c3910950ce4838756e5daf2b610e25c"
}
```

### Sample 58: `1f2de816dd49ccf3`

| Field | Value |
|---|---|
| SHA-256 | `1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75` |
| Family label | `SalatStealer` |
| File name | `1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a88c49e31f84254d96470dd940f67eb2` |
| SHA-1 | `415a0e355a9836c5f7a2ce9fef7f4b648c7d3985` |
| SHA-256 | `1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75` |
| SHA3-384 | `4c42be081ae9fac2d04d40680aa5a31f6c3492b4ae22367a4db9b081eb4bce106030f358ab8ff22ae83d87d2eefab300` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T106F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OC:iJiafuIO7rhWEES4d` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_058_1f2de816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75"
    family = "SalatStealer"
    file_name = "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:39"
  condition:
    hash.sha256(0, filesize) == "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75"
}
```

### Sample 59: `30b07d7dfc830487`

| Field | Value |
|---|---|
| SHA-256 | `30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96` |
| Family label | `SalatStealer` |
| File name | `30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:10:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1750be26a984ea15da75d84ee5acb127` |
| SHA-1 | `634c0df8a0d337733108fc99a3d3cf3ada5aa5ec` |
| SHA-256 | `30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96` |
| SHA3-384 | `280eced9bf0ff7650aa2a574c5ab5c600d3ad19132539f06e58c6566c9697b860b3864a0e6af9872828dea160b8b9390` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1C8F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ot:iJiafuIO7rhWEES42` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_059_30b07d7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96"
    family = "SalatStealer"
    file_name = "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:04"
  condition:
    hash.sha256(0, filesize) == "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96"
}
```

### Sample 60: `087148ec3f18d6b8`

| Field | Value |
|---|---|
| SHA-256 | `087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9` |
| Family label | `SalatStealer` |
| File name | `087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:59` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `403ce6843c299e3e4823cfb1d7a51807` |
| SHA-1 | `484b662bb6df6efac262385e6f6b1d0f785dbc23` |
| SHA-256 | `087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9` |
| SHA3-384 | `bb71c9eb0611964cf691cf8914af6f7a800bbcee8073f77d9f0dfe4e35269149001a0cc0e6942725c8d28395ef371e17` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T179F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O6:iJiafuIO7rhWEES4n` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_060_087148ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9"
    family = "SalatStealer"
    file_name = "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:59"
  condition:
    hash.sha256(0, filesize) == "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9"
}
```

### Sample 61: `5b951b57c8529a2c`

| Field | Value |
|---|---|
| SHA-256 | `5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5` |
| Family label | `SalatStealer` |
| File name | `5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57bbe7db8a3819a49011539231e7ee3a` |
| SHA-1 | `8ced4c64818bc225820ce3ebc6aa73d933ff469e` |
| SHA-256 | `5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5` |
| SHA3-384 | `9ff5ae5bcd23e4a48d6113320fa423a225db77064d96ed2859840632c1bfdad7c234afbcd8eb6cdc5de52d9fc8218fdf` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1F2F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OR:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_061_5b951b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5"
    family = "SalatStealer"
    file_name = "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:54"
  condition:
    hash.sha256(0, filesize) == "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5"
}
```

### Sample 62: `4e0dfca1772897e7`

| Field | Value |
|---|---|
| SHA-256 | `4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769` |
| Family label | `SalatStealer` |
| File name | `4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da2d89290f6c14f597dd219befab5b7e` |
| SHA-1 | `33c6e82e6c73268596642b4e0074f5497e221b18` |
| SHA-256 | `4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769` |
| SHA3-384 | `f8bfaf45fbb4c44f0426bd626fc9c0aaf0ca39ab94a2ada49f3e8f1ac8640b6d709be6e431bba7ae14b5311abd0b19ef` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T10AF5335BF1AB4BB3F7D9A871560FC66458B09FE40A20D38AD4DBAADF0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OY:iJiafuIO7rhWEES4h` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_062_4e0dfca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769"
    family = "SalatStealer"
    file_name = "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:49"
  condition:
    hash.sha256(0, filesize) == "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769"
}
```

### Sample 63: `07be1a5a5d75c8cf`

| Field | Value |
|---|---|
| SHA-256 | `07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac` |
| Family label | `SalatStealer` |
| File name | `07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `596b2c4feeb789949ebcd7f4dde08c97` |
| SHA-1 | `b73f3af69c4241f4604c68327b09d70e88c80318` |
| SHA-256 | `07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac` |
| SHA3-384 | `f9c1c341a23aba229bb2f65d846297577d9117480f2cdb61e0146e82b76223262e7419625578079ffc3eebe912502e21` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T13FF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O1:iJiafuIO7rhWEES4U` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_063_07be1a5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac"
    family = "SalatStealer"
    file_name = "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:44"
  condition:
    hash.sha256(0, filesize) == "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac"
}
```

### Sample 64: `7688611419ae279d`

| Field | Value |
|---|---|
| SHA-256 | `7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a` |
| Family label | `SalatStealer` |
| File name | `7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:39` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f472572bfb616330d7ca5ee876bf586c` |
| SHA-1 | `ac3c31b8f6ae5a95bc8e2033e68c091097a2e81d` |
| SHA-256 | `7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a` |
| SHA3-384 | `aeb92ad7a1cb8526105891216d170e5e2355d39dd0986eaa5a9c5ca838057453fe39c080c32d71631d31af9d786e5a9b` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T188F5335BF1AB47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ox:iJiafuIO7rhWEES4G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_064_76886114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a"
    family = "SalatStealer"
    file_name = "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:39"
  condition:
    hash.sha256(0, filesize) == "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a"
}
```

### Sample 65: `6295455b0e17a381`

| Field | Value |
|---|---|
| SHA-256 | `6295455b0e17a38176a0c45681d0c13b6266fe0b465816a594e7e23af82ec23c` |
| Family label | `SalatStealer` |
| File name | `9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:31` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `34c3b7f21647115495af4e7603125a04` |
| SHA-1 | `ad1732022755816c508aa6bb4caaf3baa8c14826` |
| SHA-256 | `6295455b0e17a38176a0c45681d0c13b6266fe0b465816a594e7e23af82ec23c` |
| SHA3-384 | `93e31f960e7c1d704866c932602eb8e40d3bb36161e57439ead49f9308dc868d1e5bcef3b33b57f6b20440aba5d3961e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T173C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+8:yBkKr5rszpNDy+8` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_065_6295455b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6295455b0e17a38176a0c45681d0c13b6266fe0b465816a594e7e23af82ec23c"
    family = "SalatStealer"
    file_name = "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:31"
  condition:
    hash.sha256(0, filesize) == "6295455b0e17a38176a0c45681d0c13b6266fe0b465816a594e7e23af82ec23c"
}
```

### Sample 66: `7e4c129f5bd09bef`

| Field | Value |
|---|---|
| SHA-256 | `7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31` |
| Family label | `SalatStealer` |
| File name | `47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:09:25` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e7be912ac3c259347db7d4c43295ab2` |
| SHA-1 | `29c482b602d7a08d1db06b9a5468990da0401202` |
| SHA-256 | `7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31` |
| SHA3-384 | `1bfb396209323fb899e380778bc1b05c8326fcc2b917b70b5627879ff31b979e17452605e1194f37b019cddd1f154240` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CEC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+y:yBkKr5rszpNDy+y` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_066_7e4c129f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31"
    family = "SalatStealer"
    file_name = "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:25"
  condition:
    hash.sha256(0, filesize) == "7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31"
}
```

### Sample 67: `0fce7fe633685a0b`

| Field | Value |
|---|---|
| SHA-256 | `0fce7fe633685a0b907f2b26ed26604ac04fc1496f570ff10e50019c28eb1a17` |
| Family label | `SalatStealer` |
| File name | `38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:08:32` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `662f4faed4cb6d026cab3ab5de757b20` |
| SHA-1 | `4cf6c5416e53ed769f8b9a85359b1a0eb638dde1` |
| SHA-256 | `0fce7fe633685a0b907f2b26ed26604ac04fc1496f570ff10e50019c28eb1a17` |
| SHA3-384 | `f9ee2a38608eabd97fc67e53670924ac8f11a412c75e9809b44b4bad206f090b73449fa99562a611bcce986859849662` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1CFC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+L:yBkKr5rszpNDy+L` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_067_0fce7fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fce7fe633685a0b907f2b26ed26604ac04fc1496f570ff10e50019c28eb1a17"
    family = "SalatStealer"
    file_name = "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:32"
  condition:
    hash.sha256(0, filesize) == "0fce7fe633685a0b907f2b26ed26604ac04fc1496f570ff10e50019c28eb1a17"
}
```

### Sample 68: `1768dae488b76147`

| Field | Value |
|---|---|
| SHA-256 | `1768dae488b76147fb0bd76dc4aaa498fe7ecc5b8e3e3a802381b9d7c365f483` |
| Family label | `SalatStealer` |
| File name | `501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:08:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07b8cb2a68dc830c7855ab9a6aef17b3` |
| SHA-1 | `8701eaa9502bc60172a9ebeaf5b356b73cfcd783` |
| SHA-256 | `1768dae488b76147fb0bd76dc4aaa498fe7ecc5b8e3e3a802381b9d7c365f483` |
| SHA3-384 | `ca379ad36de42bd6b916b0215e97715e258b007b0d4f4c46eea11ab741538966f4bd7bec94dac7357ae64217678715fd` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1BEC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+5:yBkKr5rszpNDy+5` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_068_1768dae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1768dae488b76147fb0bd76dc4aaa498fe7ecc5b8e3e3a802381b9d7c365f483"
    family = "SalatStealer"
    file_name = "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:26"
  condition:
    hash.sha256(0, filesize) == "1768dae488b76147fb0bd76dc4aaa498fe7ecc5b8e3e3a802381b9d7c365f483"
}
```

### Sample 69: `9aeae30a3e6d49b4`

| Field | Value |
|---|---|
| SHA-256 | `9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4` |
| Family label | `SalatStealer` |
| File name | `9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:08:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b6fd01a98ea144c70b04220dc79ea08` |
| SHA-1 | `68f67ace4658ac93cb74f2dc0847020a82e67960` |
| SHA-256 | `9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4` |
| SHA3-384 | `e3064a2a2b5a3bb2fcf8f54a9900b4f4dc2c987bfbf6e86d89f9d3bd882accf776033116633f626f7fc61b87253eb564` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E8F5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ow:iJiafuIO7rhWEES43` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_069_9aeae30a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4"
    family = "SalatStealer"
    file_name = "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:22"
  condition:
    hash.sha256(0, filesize) == "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4"
}
```

### Sample 70: `47958f939631f1ad`

| Field | Value |
|---|---|
| SHA-256 | `47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b` |
| Family label | `SalatStealer` |
| File name | `47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:08:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1eb268549e6887b48580f1e0b0efa1a4` |
| SHA-1 | `0c0d8edb566d9c4f979a3130dbb29ab04447e8e5` |
| SHA-256 | `47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b` |
| SHA3-384 | `3e03493d690d3ece8faa8b708212072977723045eac81134f92db7575136d0d8ec23f72647ad4b31f7791cd66f214a92` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T114F5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OO:iJiafuIO7rhWEES4L` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_070_47958f93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b"
    family = "SalatStealer"
    file_name = "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:18"
  condition:
    hash.sha256(0, filesize) == "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b"
}
```

### Sample 71: `38602089a296b989`

| Field | Value |
|---|---|
| SHA-256 | `38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305` |
| Family label | `SalatStealer` |
| File name | `38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:08:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd392ea0848cec344bd1e34e4a5af459` |
| SHA-1 | `2670e4cb6b54f7296393eb8096234a57aabdb898` |
| SHA-256 | `38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305` |
| SHA3-384 | `c468f8bd23575ea8d17554316dc8e66211e4267c3c4125ac0657d113a6ff8adb8a6a4297fa5e0fdf7ab8e15082aeeb4e` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1F0F5335BF1AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OX:iJiafuIO7rhWEES4s` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_071_38602089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305"
    family = "SalatStealer"
    file_name = "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:13"
  condition:
    hash.sha256(0, filesize) == "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305"
}
```

### Sample 72: `501e191da3be2d08`

| Field | Value |
|---|---|
| SHA-256 | `501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402` |
| Family label | `SalatStealer` |
| File name | `501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:08:08` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e13e7f913ebc52dd5b845c16319b103` |
| SHA-1 | `7642026d8805109bd2e3a685212f023f93e3fdc5` |
| SHA-256 | `501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402` |
| SHA3-384 | `74400dfb041a7f0146458f18349f7b6b81674ed9bafbec89e676ad3e59819a1396e2e799d5a2ebd022b6f1c6a1b36096` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1EEF5335BF1AF47B3F7D9A831561FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Od:iJiafuIO7rhWEES4S` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_072_501e191d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402"
    family = "SalatStealer"
    file_name = "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:08"
  condition:
    hash.sha256(0, filesize) == "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402"
}
```

### Sample 73: `b6a075d0ccd0b63e`

| Field | Value |
|---|---|
| SHA-256 | `b6a075d0ccd0b63e057244a64cd672074cc8a5f5579bb07d6291a1c648bad6bf` |
| Family label | `SalatStealer` |
| File name | `e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:06:45` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73df29527f94b09f6f0bf634067c04b3` |
| SHA-1 | `60367c077eb7c4079580c458de69048f678310d4` |
| SHA-256 | `b6a075d0ccd0b63e057244a64cd672074cc8a5f5579bb07d6291a1c648bad6bf` |
| SHA3-384 | `7c51da0c43c175f4eeceaeaada56f7731d18e4df2735555fb7822a38f356202c2cba0a6309757d99c94ba30a89b29d0e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T155C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+e:yBkKr5rszpNDy+e` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_073_b6a075d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a075d0ccd0b63e057244a64cd672074cc8a5f5579bb07d6291a1c648bad6bf"
    family = "SalatStealer"
    file_name = "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:45"
  condition:
    hash.sha256(0, filesize) == "b6a075d0ccd0b63e057244a64cd672074cc8a5f5579bb07d6291a1c648bad6bf"
}
```

### Sample 74: `4327169987154a2a`

| Field | Value |
|---|---|
| SHA-256 | `4327169987154a2a6770742919b916aff0c958f649145336a555c290c0d858ca` |
| Family label | `SalatStealer` |
| File name | `51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:06:39` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c68b5e311c5cbf5e525fab07cc1c928a` |
| SHA-1 | `acc6ce98133e015a92f8dc47bce5768bfdd6cdea` |
| SHA-256 | `4327169987154a2a6770742919b916aff0c958f649145336a555c290c0d858ca` |
| SHA3-384 | `44711a62b16158006d1585ac0c9f21ae9d6be4e70b24178e0ca92956e7b826a402111c137565e748fc09c64556bb4020` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T187C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+4:yBkKr5rszpNDy+4` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_074_43271699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4327169987154a2a6770742919b916aff0c958f649145336a555c290c0d858ca"
    family = "SalatStealer"
    file_name = "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:39"
  condition:
    hash.sha256(0, filesize) == "4327169987154a2a6770742919b916aff0c958f649145336a555c290c0d858ca"
}
```

### Sample 75: `ef3fafc754d4aa55`

| Field | Value |
|---|---|
| SHA-256 | `ef3fafc754d4aa5597378fac2c27582dc974ab53077137f0c234638f42a5c009` |
| Family label | `SalatStealer` |
| File name | `1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:06:30` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de5331d7df774b1170eb5726e6d592f9` |
| SHA-1 | `1044bab7dff0b44d2708e7a22274d8a3ccbf2520` |
| SHA-256 | `ef3fafc754d4aa5597378fac2c27582dc974ab53077137f0c234638f42a5c009` |
| SHA3-384 | `def328537021e7a74e6e1aa1f289528e6445f92968dfc285008c63b074244aa634ea3f5036c34431552d1dfd454924bc` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T176C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+G:yBkKr5rszpNDy+G` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_075_ef3fafc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef3fafc754d4aa5597378fac2c27582dc974ab53077137f0c234638f42a5c009"
    family = "SalatStealer"
    file_name = "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:30"
  condition:
    hash.sha256(0, filesize) == "ef3fafc754d4aa5597378fac2c27582dc974ab53077137f0c234638f42a5c009"
}
```

### Sample 76: `7f002f5d4cd461e2`

| Field | Value |
|---|---|
| SHA-256 | `7f002f5d4cd461e27bec8016fcf981bba7b78dfd6386f3a9807a024f953dfbde` |
| Family label | `SalatStealer` |
| File name | `f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:06:23` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f61265c8c1df36e803134e7e36e088d0` |
| SHA-1 | `d198f6d1aea8d0b824765ac2548680cf933d0c19` |
| SHA-256 | `7f002f5d4cd461e27bec8016fcf981bba7b78dfd6386f3a9807a024f953dfbde` |
| SHA3-384 | `a3c38b348bb3cc79a56a9e8e213166ceae9022745d4ec452707352974ad6825ab2184b5aebff10bf110c8ce1ebe81e82` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T168C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_076_7f002f5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f002f5d4cd461e27bec8016fcf981bba7b78dfd6386f3a9807a024f953dfbde"
    family = "SalatStealer"
    file_name = "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:23"
  condition:
    hash.sha256(0, filesize) == "7f002f5d4cd461e27bec8016fcf981bba7b78dfd6386f3a9807a024f953dfbde"
}
```

### Sample 77: `e1bc1d85b1e60ccf`

| Field | Value |
|---|---|
| SHA-256 | `e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1` |
| Family label | `SalatStealer` |
| File name | `e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:05:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9fbe6ff89a8315b75036e3345b32d625` |
| SHA-1 | `5edb4b2d663645a5918e611036517a206c861495` |
| SHA-256 | `e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1` |
| SHA3-384 | `6067742ccca2b1b2eeaa3b0a13820d46906334849a15feced9a723d9dae5f1da769cacdc529283c30d1de1db58bc4ade` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T114F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oi:iJiafuIO7rhWEES4l` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_077_e1bc1d85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1"
    family = "SalatStealer"
    file_name = "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:54"
  condition:
    hash.sha256(0, filesize) == "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1"
}
```

### Sample 78: `51cda73c920806c6`

| Field | Value |
|---|---|
| SHA-256 | `51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f` |
| Family label | `SalatStealer` |
| File name | `51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:05:49` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `267f9f33b72a578f111ee89f7bf65a00` |
| SHA-1 | `3f3e40d58e584d61998655dceeacd626e4ab35d1` |
| SHA-256 | `51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f` |
| SHA3-384 | `68bb4c32937fc56506bf057db9d4623fe2a1b8c6397100655a48e8d53936455a812fdddaa3381b0aa31f0eadefcf854d` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1B4F5335BF1AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oc:iJiafuIO7rhWEES4p` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_078_51cda73c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f"
    family = "SalatStealer"
    file_name = "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:49"
  condition:
    hash.sha256(0, filesize) == "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f"
}
```

### Sample 79: `1c7819f6a9304391`

| Field | Value |
|---|---|
| SHA-256 | `1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef` |
| Family label | `SalatStealer` |
| File name | `1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:05:44` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14620973580baa9652a4930a0e5c1a00` |
| SHA-1 | `92f85bde0761fbd1c7441c307b3553b39c8cd579` |
| SHA-256 | `1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef` |
| SHA3-384 | `c73fda2840bcca1ef6708455b7fdba90d92412eccb138f16d5ad9a0c8acfa9aef94a49714509b1f516562fe44ff73bfe` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T153F5335BF1AF47B3F7D9A871560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OS:iJiafuIO7rhWEES4z` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_079_1c7819f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef"
    family = "SalatStealer"
    file_name = "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:44"
  condition:
    hash.sha256(0, filesize) == "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef"
}
```

### Sample 80: `f374939c71458fed`

| Field | Value |
|---|---|
| SHA-256 | `f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91` |
| Family label | `SalatStealer` |
| File name | `f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91.exe` |
| File type | `exe` |
| First seen | `2026-10-26 03:05:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a5ec86fbd0cf8bb6669022d31e6bd88` |
| SHA-1 | `215b1a040a78a2bff73863b12d5b3540bf9cc0df` |
| SHA-256 | `f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91` |
| SHA3-384 | `f3f80bd66fd35d428ea21c611ee01e281e913a81472b5558ea397f25a6afe31804b61a1a5a46f1d9adaa2b602835b652` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D1F5335BF1AF47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4O0:iJiafuIO7rhWEES4B` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_080_f374939c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91"
    family = "SalatStealer"
    file_name = "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:38"
  condition:
    hash.sha256(0, filesize) == "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91"
}
```

### Sample 81: `5c73e0b861cabc1c`

| Field | Value |
|---|---|
| SHA-256 | `5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6` |
| Family label | `unknown` |
| File name | `5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6` |
| File type | `elf` |
| First seen | `2026-10-26 02:53:08` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d0075d15c51e0763c8b9340fc8372fe` |
| SHA-1 | `5503ce84e84acebd5f9e17d9df0bfcae3b4a4126` |
| SHA-256 | `5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6` |
| SHA3-384 | `b121254ad3e6e928a879db29ae780344b077220fea7552e37701fd46fd37bca621180065614514259f2ec78cc7a3bd77` |
| TLSH | `T18B060973E59441E4C2EED174C625A213BEE0389B173423D77BD1A6E11B76FE46AB8320` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQu:cqYUQuVDt0TZE9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_5c73e0b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6"
    family = "unknown"
    file_name = "5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6"
    file_type = "elf"
    first_seen = "2026-10-26 02:53:08"
  condition:
    hash.sha256(0, filesize) == "5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6"
}
```

### Sample 82: `815e8321b51a418a`

| Field | Value |
|---|---|
| SHA-256 | `815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d` |
| Family label | `unknown` |
| File name | `815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d` |
| File type | `elf` |
| First seen | `2026-10-26 02:34:43` |
| Reporter | `vlasovmichael` |
| Tags | `elf, honeypot, trojan.multiverze` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf59468c8559e1266bceffc1389f2226` |
| SHA-1 | `474946893210d47c727d0961d9f22a53a645903e` |
| SHA-256 | `815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d` |
| SHA3-384 | `9d1f3cd3ccb2e800b4ba78d22817a7cbda0d35ef6db575d8da5f8ed412ee6a530dff8af7b29ebd1b0c2524519731ac65` |
| TLSH | `T1B257DF77814638E9E9B98CB4D01025416DAC788B5778A3C7BAC871E667EB7E08D3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQp:cqYUQuVDt0TZE6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_815e8321
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d"
    family = "unknown"
    file_name = "815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d"
    file_type = "elf"
    first_seen = "2026-10-26 02:34:43"
  condition:
    hash.sha256(0, filesize) == "815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d"
}
```

### Sample 83: `1897cd92b634628f`

| Field | Value |
|---|---|
| SHA-256 | `1897cd92b634628fbbf0fd9fc9caa3fed63b4c4032c9aea6419a1ed9c2d29205` |
| Family label | `SalatStealer` |
| File name | `746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:31:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8356c930d859fd9f8e73de92cce3966` |
| SHA-1 | `77cbc811a7aca69d354416d8bd8a50961fefb760` |
| SHA-256 | `1897cd92b634628fbbf0fd9fc9caa3fed63b4c4032c9aea6419a1ed9c2d29205` |
| SHA3-384 | `e07315e85f2e3f268b015d91f29ddeda67b5592af8db21b3df213aa11581d9abfc4818b8eee8c636abfd9985fb39a037` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T127C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+P:yBkKr5rszpNDy+P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_083_1897cd92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1897cd92b634628fbbf0fd9fc9caa3fed63b4c4032c9aea6419a1ed9c2d29205"
    family = "SalatStealer"
    file_name = "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:31:46"
  condition:
    hash.sha256(0, filesize) == "1897cd92b634628fbbf0fd9fc9caa3fed63b4c4032c9aea6419a1ed9c2d29205"
}
```

### Sample 84: `5ac0973b12872c8d`

| Field | Value |
|---|---|
| SHA-256 | `5ac0973b12872c8d1de7d0e8799a0b04ee78ecde0f0ef71a94a3103bae752f1c` |
| Family label | `SalatStealer` |
| File name | `90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:29:59` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `faf3d0f50a10c7fedbbf9e2e6c176e54` |
| SHA-1 | `f33f30076a50e00ec71cb5c0a4e5113b82fcff59` |
| SHA-256 | `5ac0973b12872c8d1de7d0e8799a0b04ee78ecde0f0ef71a94a3103bae752f1c` |
| SHA3-384 | `82be55edc05de8cc2ad7157e1853192fdf85dc56f3f0ae7231a4378c211c5cd728d6496589cd55f14287377521670e4b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18CC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+P:yBkKr5rszpNDy+P` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_084_5ac0973b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac0973b12872c8d1de7d0e8799a0b04ee78ecde0f0ef71a94a3103bae752f1c"
    family = "SalatStealer"
    file_name = "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:59"
  condition:
    hash.sha256(0, filesize) == "5ac0973b12872c8d1de7d0e8799a0b04ee78ecde0f0ef71a94a3103bae752f1c"
}
```

### Sample 85: `f0f2523f2cb030e7`

| Field | Value |
|---|---|
| SHA-256 | `f0f2523f2cb030e73e38ce36552963c0bfafa10b2e09bec28fb7c740f811c37f` |
| Family label | `SalatStealer` |
| File name | `950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:29:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a99ed9294af8ebdeb97e726142117831` |
| SHA-1 | `5d268eb1329151a3146919747eb14f2a1ec0962a` |
| SHA-256 | `f0f2523f2cb030e73e38ce36552963c0bfafa10b2e09bec28fb7c740f811c37f` |
| SHA3-384 | `8fb81816976add763ab29a5fad89ebd8bee0c7071777826db6c8229425c5d485b6c3d3ba55b39ad0df7ab18838256778` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T141C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+I:yBkKr5rszpNDy+I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_085_f0f2523f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0f2523f2cb030e73e38ce36552963c0bfafa10b2e09bec28fb7c740f811c37f"
    family = "SalatStealer"
    file_name = "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:51"
  condition:
    hash.sha256(0, filesize) == "f0f2523f2cb030e73e38ce36552963c0bfafa10b2e09bec28fb7c740f811c37f"
}
```

### Sample 86: `dae026c3c9598221`

| Field | Value |
|---|---|
| SHA-256 | `dae026c3c9598221e5a7c11bacacd08a9d59f340286de242d79da69e0b283b9b` |
| Family label | `SalatStealer` |
| File name | `e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:29:44` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d233f524664e24889a76d94e1c538d39` |
| SHA-1 | `def5fcd9f03a760b7295bdb385018727bc550440` |
| SHA-256 | `dae026c3c9598221e5a7c11bacacd08a9d59f340286de242d79da69e0b283b9b` |
| SHA3-384 | `8497ea97dbc29fb926ddd3c7976b461dd1e184b2e48e14b896cec54d4b2827c082799e40ee968695c7991f02a0df1a57` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T127C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+V:yBkKr5rszpNDy+V` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_086_dae026c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dae026c3c9598221e5a7c11bacacd08a9d59f340286de242d79da69e0b283b9b"
    family = "SalatStealer"
    file_name = "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:44"
  condition:
    hash.sha256(0, filesize) == "dae026c3c9598221e5a7c11bacacd08a9d59f340286de242d79da69e0b283b9b"
}
```

### Sample 87: `4def57e2b534cafb`

| Field | Value |
|---|---|
| SHA-256 | `4def57e2b534cafb37648640bbcac0bf8cb41a8fcc42f38c7bf8cc5eba8d26a0` |
| Family label | `SalatStealer` |
| File name | `fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:29:37` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f531722a83d5babad496f32866891e09` |
| SHA-1 | `b16c9a2785786dff52961182fcdd74331881cfe3` |
| SHA-256 | `4def57e2b534cafb37648640bbcac0bf8cb41a8fcc42f38c7bf8cc5eba8d26a0` |
| SHA3-384 | `39b3987f98567b675142503abf2022e14351da3c120b92c059fb39277e89e10769071df747aaf0c8ee1520fb962ea77a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E9C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+F:yBkKr5rszpNDy+F` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_087_4def57e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4def57e2b534cafb37648640bbcac0bf8cb41a8fcc42f38c7bf8cc5eba8d26a0"
    family = "SalatStealer"
    file_name = "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:37"
  condition:
    hash.sha256(0, filesize) == "4def57e2b534cafb37648640bbcac0bf8cb41a8fcc42f38c7bf8cc5eba8d26a0"
}
```

### Sample 88: `44ad1f0200906e1f`

| Field | Value |
|---|---|
| SHA-256 | `44ad1f0200906e1fffc07d5c94e3577a79038108a3436448855b3f6dd2883f90` |
| Family label | `SalatStealer` |
| File name | `46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:29:29` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01695b16e30569370b653681628df598` |
| SHA-1 | `bf7ad47dfa245e7a6f5327d839497ca539d0e675` |
| SHA-256 | `44ad1f0200906e1fffc07d5c94e3577a79038108a3436448855b3f6dd2883f90` |
| SHA3-384 | `def6fa45d7cad80a472cd9e7649e42e7a7da58f2470b99c9d1b3726d288e695e35897458a27000641f598206e0f20349` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D5C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+T:yBkKr5rszpNDy+T` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_088_44ad1f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ad1f0200906e1fffc07d5c94e3577a79038108a3436448855b3f6dd2883f90"
    family = "SalatStealer"
    file_name = "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:29"
  condition:
    hash.sha256(0, filesize) == "44ad1f0200906e1fffc07d5c94e3577a79038108a3436448855b3f6dd2883f90"
}
```

### Sample 89: `7083e04a4889d45d`

| Field | Value |
|---|---|
| SHA-256 | `7083e04a4889d45d0af520a7167ef86dfb1c7228e4d03069f22ec80b4172f820` |
| Family label | `SalatStealer` |
| File name | `b8ab7dcb982eb6c2.bin` |
| File type | `exe` |
| First seen | `2026-10-26 02:29:03` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87a181684cb73e9f4964260e7e20aff5` |
| SHA-1 | `90ba74043d944f369f364373aabf3e2a23ed1c60` |
| SHA-256 | `7083e04a4889d45d0af520a7167ef86dfb1c7228e4d03069f22ec80b4172f820` |
| SHA3-384 | `ef9b5c57eadbb029a5c3191fb71c4771f642b495ae2591fcb2f91aa5dd1256c17540f9aac0eb7c02663ba3697977d265` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T13FC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+I:yBkKr5rszpNDy+I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_089_7083e04a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7083e04a4889d45d0af520a7167ef86dfb1c7228e4d03069f22ec80b4172f820"
    family = "SalatStealer"
    file_name = "b8ab7dcb982eb6c2.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:03"
  condition:
    hash.sha256(0, filesize) == "7083e04a4889d45d0af520a7167ef86dfb1c7228e4d03069f22ec80b4172f820"
}
```

### Sample 90: `9d6740d5b7abd4af`

| Field | Value |
|---|---|
| SHA-256 | `9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6` |
| Family label | `SalatStealer` |
| File name | `09f365cc415195f7.bin` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:57` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5964ebf09e797f154f147933eb42e92f` |
| SHA-1 | `27d806047552f1ea730dcd22d76ac7a8d7c89a39` |
| SHA-256 | `9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6` |
| SHA3-384 | `8dbb0e1115f2489008a8616307067207ba871e677733d1400bd14cf1bdace5c2b09346fcb06b350b0b9a23a68db60ab2` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T111C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+8:yBkKr5rszpNDy+8` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_090_9d6740d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6"
    family = "SalatStealer"
    file_name = "09f365cc415195f7.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:57"
  condition:
    hash.sha256(0, filesize) == "9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6"
}
```

### Sample 91: `1912356db2d96170`

| Field | Value |
|---|---|
| SHA-256 | `1912356db2d96170c052c920bf9a636594a22946b64725f967d1253163b11d2c` |
| Family label | `SalatStealer` |
| File name | `191cc4b9334d555d.bin` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:51` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09459f5247d62eeee34dddc52c93ce81` |
| SHA-1 | `8429fd9aa9ac659261555fb3107212783520e0fc` |
| SHA-256 | `1912356db2d96170c052c920bf9a636594a22946b64725f967d1253163b11d2c` |
| SHA3-384 | `e2d4a2cb417e6d55429c575ba1af201053d3aeb078d77ded9a5835d3bfc2353baacae49fd9a28a8feca1d527b2d7b8b0` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1B8C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+g:yBkKr5rszpNDy+g` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_091_1912356d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1912356db2d96170c052c920bf9a636594a22946b64725f967d1253163b11d2c"
    family = "SalatStealer"
    file_name = "191cc4b9334d555d.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:51"
  condition:
    hash.sha256(0, filesize) == "1912356db2d96170c052c920bf9a636594a22946b64725f967d1253163b11d2c"
}
```

### Sample 92: `27fc5c5f89537a46`

| Field | Value |
|---|---|
| SHA-256 | `27fc5c5f89537a463da16cb92725a0cdd9e59774a200f5964945f96bf6902d06` |
| Family label | `SalatStealer` |
| File name | `cc5353f305b429e7.bin` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:45` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `953e19e6f49d577e6ec1485b108ff964` |
| SHA-1 | `1fb8deb23eb0eca67dcd1e7796bfe58f1bc8636f` |
| SHA-256 | `27fc5c5f89537a463da16cb92725a0cdd9e59774a200f5964945f96bf6902d06` |
| SHA3-384 | `c4df104c11835fc531cc27022b8e42d51d4efe1f4e61eab390b2cfce318e904a88000f71c196c7960f98259f0b979c3e` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F6C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+H:yBkKr5rszpNDy+H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_092_27fc5c5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27fc5c5f89537a463da16cb92725a0cdd9e59774a200f5964945f96bf6902d06"
    family = "SalatStealer"
    file_name = "cc5353f305b429e7.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:45"
  condition:
    hash.sha256(0, filesize) == "27fc5c5f89537a463da16cb92725a0cdd9e59774a200f5964945f96bf6902d06"
}
```

### Sample 93: `746ac20caf66f45e`

| Field | Value |
|---|---|
| SHA-256 | `746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b` |
| Family label | `SalatStealer` |
| File name | `746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:20` |
| Reporter | `Tuxxin` |
| Tags | `exe, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d560bc2c8247e4d839671bd4e8686e7` |
| SHA-1 | `417aa41a80319ebedb7aa67d8059ccc46dd14be8` |
| SHA-256 | `746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b` |
| SHA3-384 | `3cb68448e25bb10fed864424d772bb29e29384de4bf9d6c75a9ef44013888a5e732f0c2c1b2263ba089e7a81866cd29f` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1FBF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0846BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Oz:iJiafuIO7rhWEES4O` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_093_746ac20c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b"
    family = "SalatStealer"
    file_name = "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:20"
  condition:
    hash.sha256(0, filesize) == "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b"
}
```

### Sample 94: `90aa7c29c95140cc`

| Field | Value |
|---|---|
| SHA-256 | `90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5` |
| Family label | `SalatStealer` |
| File name | `90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f0f77446d885160e4c9af55e38bcdd0` |
| SHA-1 | `3b0925a047f5b7ec1a768d10c021abf95f010a99` |
| SHA-256 | `90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5` |
| SHA3-384 | `efc1ce01cee9d28ca9e29c7f37cfe98aeaa06dffd1706f14280c028e54f54d507a86d94170446cbab2694da29e53950e` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T185F5335BF5AB47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OL:iJiafuIO7rhWEES42` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_094_90aa7c29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5"
    family = "SalatStealer"
    file_name = "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:15"
  condition:
    hash.sha256(0, filesize) == "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5"
}
```

### Sample 95: `950e3bdd4166acbc`

| Field | Value |
|---|---|
| SHA-256 | `950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e` |
| Family label | `SalatStealer` |
| File name | `950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8867e78848d49a3d1e829235f4400954` |
| SHA-1 | `b561ef00b6411e1a48ef14f9e34b73e68d7881e2` |
| SHA-256 | `950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e` |
| SHA3-384 | `ab634e43cf52c7c71e1e8f5a35ae47a80fc50584d6550a9a71b9250e7fe0f9637f6cb56c5107db2319711fb185c4932e` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1D9F5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Ok:iJiafuIO7rhWEES41` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_095_950e3bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e"
    family = "SalatStealer"
    file_name = "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:10"
  condition:
    hash.sha256(0, filesize) == "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e"
}
```

### Sample 96: `e0fabbd75a800c5c`

| Field | Value |
|---|---|
| SHA-256 | `e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14` |
| Family label | `SalatStealer` |
| File name | `e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:05` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b837bb0338e9489b2233aa45a73453d` |
| SHA-1 | `95112975b08e2028e8c2348b6aaaa5445f22cd33` |
| SHA-256 | `e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14` |
| SHA3-384 | `a5335d27485a8afa3c73d45c7382fad9c81730f907b392dc32c3a5158e5bdbc7f0c9114dbaf56e529362269e81fe9c57` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T14FF5335BF5AF47B3F7D9A831560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4Op:iJiafuIO7rhWEES4o` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_096_e0fabbd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14"
    family = "SalatStealer"
    file_name = "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:05"
  condition:
    hash.sha256(0, filesize) == "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14"
}
```

### Sample 97: `fea6e379e5864f82`

| Field | Value |
|---|---|
| SHA-256 | `fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6` |
| Family label | `SalatStealer` |
| File name | `fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:28:00` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f46b6a534232efbc1ca9fd9752f853d3` |
| SHA-1 | `5d3e7b5f9b60c211518250595ea047fe6faef7cf` |
| SHA-256 | `fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6` |
| SHA3-384 | `0af557b3088cf64e0f7493cef57264293292ec8bb75b3381b2e8f099da168346ed51d37cd472c27d1f9f02abda578061` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T15DF5335BF1AB47B3F7D9A931560FC66458B09FE40A20D38AD4DBAA9F0886BD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OR:iJiafuIO7rhWEES4m` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_097_fea6e379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6"
    family = "SalatStealer"
    file_name = "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:00"
  condition:
    hash.sha256(0, filesize) == "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6"
}
```

### Sample 98: `46f32f4ac32495bd`

| Field | Value |
|---|---|
| SHA-256 | `46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49` |
| Family label | `SalatStealer` |
| File name | `46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49.exe` |
| File type | `exe` |
| First seen | `2026-10-26 02:27:55` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `243485293aafd05d71436ae77f3d484c` |
| SHA-1 | `7ec0d345b58ef23bc705ec3a6dbf3533446465b2` |
| SHA-256 | `46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49` |
| SHA3-384 | `1cc9df560097e57fc683fbf207f0e0bb43da9dc41f979bd9f678c331802e47cd96e93f23854752a94a537fa84fe3680c` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1A0F5335BF1AB47B3F7D9A835560FC66458B09FE40A20D38AD4DBAA9F0886FD0C241375` |
| SSDEEP | `98304:niJ2oaNEfaVbzxGvBkBWZGVLTfh7wpEES4OX:iJiafuIO7rhWEES4I` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_098_46f32f4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49"
    family = "SalatStealer"
    file_name = "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:27:55"
  condition:
    hash.sha256(0, filesize) == "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49"
}
```

### Sample 99: `96c3c711e5a92dd5`

| Field | Value |
|---|---|
| SHA-256 | `96c3c711e5a92dd5c9952a92d2ecf0deb1bf1bb895e520194ccb3903490f8980` |
| Family label | `SalatStealer` |
| File name | `233f83c036e611b6.bin` |
| File type | `exe` |
| First seen | `2026-10-26 02:27:33` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36fdc34928c9959d0bafe1af2094b150` |
| SHA-1 | `141a10c5773ee0045a005582f06b8dea8115e103` |
| SHA-256 | `96c3c711e5a92dd5c9952a92d2ecf0deb1bf1bb895e520194ccb3903490f8980` |
| SHA3-384 | `6beb295d6573daa6b7b95d2970447a8ce490342fc72506116cc3fdce95f8aa3053f582f1e5c7d955fee667a3785fd451` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1F4C65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+T:yBkKr5rszpNDy+T` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_099_96c3c711
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96c3c711e5a92dd5c9952a92d2ecf0deb1bf1bb895e520194ccb3903490f8980"
    family = "SalatStealer"
    file_name = "233f83c036e611b6.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:27:33"
  condition:
    hash.sha256(0, filesize) == "96c3c711e5a92dd5c9952a92d2ecf0deb1bf1bb895e520194ccb3903490f8980"
}
```

### Sample 100: `a222ed12296268d4`

| Field | Value |
|---|---|
| SHA-256 | `a222ed12296268d4e3e30a74ba5f1a0c101749f52fd5a077cc5a7eb5d3377b5a` |
| Family label | `SalatStealer` |
| File name | `b051bdb181f635f1.bin` |
| File type | `exe` |
| First seen | `2026-10-26 02:27:26` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c61e4d32a3478882ed0bbf177b82bf50` |
| SHA-1 | `5baacc1e500832e89d6be0d9ae79c1c7b4613522` |
| SHA-256 | `a222ed12296268d4e3e30a74ba5f1a0c101749f52fd5a077cc5a7eb5d3377b5a` |
| SHA3-384 | `938f1e372e3611b620c3a96f3cf7d711e00125f1cb20afd9f91eaa14be7bdd12dccf836810acfae64f827614cbc6a4bc` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1DCC65B11FACB54F6F9036831406BB27F23355D058B28CB9BEB183B6AF877691187A705` |
| SSDEEP | `98304:tjhOBNrzuaCerzFi6bszT1JX4pG2IfZE+A:yBkKr5rszpNDy+A` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_100_a222ed12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a222ed12296268d4e3e30a74ba5f1a0c101749f52fd5a077cc5a7eb5d3377b5a"
    family = "SalatStealer"
    file_name = "b051bdb181f635f1.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:27:26"
  condition:
    hash.sha256(0, filesize) == "a222ed12296268d4e3e30a74ba5f1a0c101749f52fd5a077cc5a7eb5d3377b5a"
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
 * Generated: 2026-10-26T04:57:41.916524+00:00
 */

rule MalwareBazaar_unknown_001_bf7a8c0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf7a8c0ad143e00843d4238f6e97b7f8cc533d2c9663afd724663ef7af982ec3"
    family = "unknown"
    file_name = "Bassist.vbs"
    file_type = "vbs"
    first_seen = "2026-10-26 04:45:20"
  condition:
    hash.sha256(0, filesize) == "bf7a8c0ad143e00843d4238f6e97b7f8cc533d2c9663afd724663ef7af982ec3"
}

rule MalwareBazaar_RemcosRAT_002_9cb0006b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9cb0006ba80d05eed418511693eba7bde1d9ef3d6fc4ae4ff877f304758d5cb7"
    family = "RemcosRAT"
    file_name = "4567890766567896765YourQuotation.JS.js"
    file_type = "js"
    first_seen = "2026-10-26 04:40:10"
  condition:
    hash.sha256(0, filesize) == "9cb0006ba80d05eed418511693eba7bde1d9ef3d6fc4ae4ff877f304758d5cb7"
}

rule MalwareBazaar_SalatStealer_003_e42de348
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e42de348c01da6a95b259804866e362d74fc0ea918f5a83362cb60e483d86afe"
    family = "SalatStealer"
    file_name = "4ffd58dd83a3f89c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 04:26:22"
  condition:
    hash.sha256(0, filesize) == "e42de348c01da6a95b259804866e362d74fc0ea918f5a83362cb60e483d86afe"
}

rule MalwareBazaar_SalatStealer_004_4ffd58dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ffd58dd83a3f89cade6d58e13b5919410e0cf1f30afdbf60bad1f716a061ac0"
    family = "SalatStealer"
    file_name = "4ffd58dd83a3f89c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 04:25:50"
  condition:
    hash.sha256(0, filesize) == "4ffd58dd83a3f89cade6d58e13b5919410e0cf1f30afdbf60bad1f716a061ac0"
}

rule MalwareBazaar_unknown_005_61d1c1ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61d1c1ca3ed32698a440f3815606b23283a41a2c282567bfca2ee904b0932c6b"
    family = "unknown"
    file_name = "macho_61d1c1ca3ed3.bin"
    file_type = "macho"
    first_seen = "2026-10-26 04:24:43"
  condition:
    hash.sha256(0, filesize) == "61d1c1ca3ed32698a440f3815606b23283a41a2c282567bfca2ee904b0932c6b"
}

rule MalwareBazaar_unknown_006_87c041a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87c041a4ae659d820ea1f586da9324764740cef43f167adefcef6c28d7595152"
    family = "unknown"
    file_name = "RFQ PINACLE OM-JB-DNR AD-36588 - JOB IN HAND.vbs"
    file_type = "vbs"
    first_seen = "2026-10-26 04:15:44"
  condition:
    hash.sha256(0, filesize) == "87c041a4ae659d820ea1f586da9324764740cef43f167adefcef6c28d7595152"
}

rule MalwareBazaar_unknown_007_34e5887d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435"
    family = "unknown"
    file_name = "ORDER_QUOTATION_FORM.com"
    file_type = "exe"
    first_seen = "2026-10-26 03:55:31"
  condition:
    hash.sha256(0, filesize) == "34e5887dd33383ebaefa05e6237615463987affd4af6846163fba94221b0b435"
}

rule MalwareBazaar_RemcosRAT_008_04d9c053
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4"
    family = "RemcosRAT"
    file_name = "Quotation.JS.js"
    file_type = "js"
    first_seen = "2026-10-26 03:45:10"
  condition:
    hash.sha256(0, filesize) == "04d9c053e5cff50a9eb0e974dd7b2b6a7065099329ba5073c769b4fe17f654f4"
}

rule MalwareBazaar_unknown_009_f9829cdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2"
    family = "unknown"
    file_name = "f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:32:58"
  condition:
    hash.sha256(0, filesize) == "f9829cddd02a096061cda97a4469b18a2afa791581134d7c32801824c8fdc5e2"
}

rule MalwareBazaar_SalatStealer_010_deb10b2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2"
    family = "SalatStealer"
    file_name = "1fc26715d960f204.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:28:01"
  condition:
    hash.sha256(0, filesize) == "deb10b2a3c921bb2e0cd7a2180f96a6f0cdb1cb830e55b885b53df4d3118d8f2"
}

rule MalwareBazaar_SalatStealer_011_49818c65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d"
    family = "SalatStealer"
    file_name = "380a427f08c55b15.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:27:51"
  condition:
    hash.sha256(0, filesize) == "49818c65eaad6ee5093f2b3253b2511e0733ac9800ec0b7033210e2ac462037d"
}

rule MalwareBazaar_SalatStealer_012_d98684d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842"
    family = "SalatStealer"
    file_name = "ab25adf6f1b4b69b.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:27:44"
  condition:
    hash.sha256(0, filesize) == "d98684d84b676fbd89c39f01152c14ed7171065e59d1a231a15a077715859842"
}

rule MalwareBazaar_SalatStealer_013_965746db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5"
    family = "SalatStealer"
    file_name = "b95779be1565278c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:52"
  condition:
    hash.sha256(0, filesize) == "965746db162d04837da30254e20451f985efb1aff56b724baaa770b7f3de76a5"
}

rule MalwareBazaar_SalatStealer_014_56047cbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08"
    family = "SalatStealer"
    file_name = "dbbbbfb98939a25f.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:47"
  condition:
    hash.sha256(0, filesize) == "56047cbe27a63d0cea335992c8111c06a8b2d1124c02c7e984bc2d0996732f08"
}

rule MalwareBazaar_SalatStealer_015_1fc26715
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba"
    family = "SalatStealer"
    file_name = "1fc26715d960f204.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:41"
  condition:
    hash.sha256(0, filesize) == "1fc26715d960f204b10dcd967843728b552ae22a7647147deb8a6f3c86b899ba"
}

rule MalwareBazaar_SalatStealer_016_50b42020
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384"
    family = "SalatStealer"
    file_name = "5fc8200c7584303a.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:41"
  condition:
    hash.sha256(0, filesize) == "50b420204ab02f3848f862e0d8dedc740711e9d79c35fd90188b98205ce7e384"
}

rule MalwareBazaar_SalatStealer_017_f960ee2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f960ee2bf8316da09be6a44e024edd609e21f582ad094dc58803c5b93e08c79e"
    family = "SalatStealer"
    file_name = "44901fe5e07cb3a5.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:35"
  condition:
    hash.sha256(0, filesize) == "f960ee2bf8316da09be6a44e024edd609e21f582ad094dc58803c5b93e08c79e"
}

rule MalwareBazaar_SalatStealer_018_380a427f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "380a427f08c55b158cc0d90c38d3f741ea08a24a2811a2d9ca0c1d2dab5bfc66"
    family = "SalatStealer"
    file_name = "380a427f08c55b15.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:31"
  condition:
    hash.sha256(0, filesize) == "380a427f08c55b158cc0d90c38d3f741ea08a24a2811a2d9ca0c1d2dab5bfc66"
}

rule MalwareBazaar_SalatStealer_019_ab25adf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab25adf6f1b4b69b915555f1df2e7c4703b44a28a9aa0377e096b36c4bf406e6"
    family = "SalatStealer"
    file_name = "ab25adf6f1b4b69b.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:21"
  condition:
    hash.sha256(0, filesize) == "ab25adf6f1b4b69b915555f1df2e7c4703b44a28a9aa0377e096b36c4bf406e6"
}

rule MalwareBazaar_SalatStealer_020_b95779be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b95779be1565278c9595423f93d8dc6bbdc4bda8abbed130f4f8924d03300862"
    family = "SalatStealer"
    file_name = "b95779be1565278c.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:11"
  condition:
    hash.sha256(0, filesize) == "b95779be1565278c9595423f93d8dc6bbdc4bda8abbed130f4f8924d03300862"
}

rule MalwareBazaar_SalatStealer_021_dbbbbfb9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dbbbbfb98939a25f1b2ab0e260aa01f7f6b569799aba107daf1cb17d66475295"
    family = "SalatStealer"
    file_name = "dbbbbfb98939a25f.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:26:02"
  condition:
    hash.sha256(0, filesize) == "dbbbbfb98939a25f1b2ab0e260aa01f7f6b569799aba107daf1cb17d66475295"
}

rule MalwareBazaar_SalatStealer_022_5fc8200c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fc8200c7584303a0a9967875ce8050b95a9838b38e24ac0f35b595f79ca6217"
    family = "SalatStealer"
    file_name = "5fc8200c7584303a.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:25:52"
  condition:
    hash.sha256(0, filesize) == "5fc8200c7584303a0a9967875ce8050b95a9838b38e24ac0f35b595f79ca6217"
}

rule MalwareBazaar_SalatStealer_023_44901fe5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44901fe5e07cb3a5e0d4e278126e40f491ca8c67eb431bd2fcf764568bc16a65"
    family = "SalatStealer"
    file_name = "44901fe5e07cb3a5.bin"
    file_type = "exe"
    first_seen = "2026-10-26 03:25:42"
  condition:
    hash.sha256(0, filesize) == "44901fe5e07cb3a5e0d4e278126e40f491ca8c67eb431bd2fcf764568bc16a65"
}

rule MalwareBazaar_Mirai_024_18dc14d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345"
    family = "Mirai"
    file_name = "titanjr.m68k"
    file_type = "elf"
    first_seen = "2026-10-26 03:20:57"
  condition:
    hash.sha256(0, filesize) == "18dc14d98be70b0b3733839cd8582e3ead95e6dbfda2d9e0e44cc771c85b7345"
}

rule MalwareBazaar_SalatStealer_025_6ca51009
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ca51009e9135f05a3ed7772f7fb00c87e973d71cfbb4292f46c369c2e5e27cd"
    family = "SalatStealer"
    file_name = "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:17:01"
  condition:
    hash.sha256(0, filesize) == "6ca51009e9135f05a3ed7772f7fb00c87e973d71cfbb4292f46c369c2e5e27cd"
}

rule MalwareBazaar_SalatStealer_026_c32adbd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c32adbd683ac24aa6dcf4d8d5bba1457dcdd116446a44cf7dc0f3f4937fc739e"
    family = "SalatStealer"
    file_name = "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:16:54"
  condition:
    hash.sha256(0, filesize) == "c32adbd683ac24aa6dcf4d8d5bba1457dcdd116446a44cf7dc0f3f4937fc739e"
}

rule MalwareBazaar_SalatStealer_027_f8ed72c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8ed72c81eadb12f513f2245163ec5cf89b1433199a4c6a8d9aaa44460818486"
    family = "SalatStealer"
    file_name = "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:16:44"
  condition:
    hash.sha256(0, filesize) == "f8ed72c81eadb12f513f2245163ec5cf89b1433199a4c6a8d9aaa44460818486"
}

rule MalwareBazaar_SalatStealer_028_c2ee0b2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2ee0b2f58eedd5c3690c5766870f17608e16bff99c2217e902b281d53ca4f85"
    family = "SalatStealer"
    file_name = "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:15:02"
  condition:
    hash.sha256(0, filesize) == "c2ee0b2f58eedd5c3690c5766870f17608e16bff99c2217e902b281d53ca4f85"
}

rule MalwareBazaar_SalatStealer_029_4fc7a8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3"
    family = "SalatStealer"
    file_name = "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:56"
  condition:
    hash.sha256(0, filesize) == "4fc7a8e8b3f31afaca715d1d1cf0e5fe99eaf1cc904168d84b2a59c9530cadf3"
}

rule MalwareBazaar_SalatStealer_030_c4939596
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4939596c1549254f379ba7d7ebc85525af699e24011dc7ddf6ffdc37eb0cce1"
    family = "SalatStealer"
    file_name = "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:55"
  condition:
    hash.sha256(0, filesize) == "c4939596c1549254f379ba7d7ebc85525af699e24011dc7ddf6ffdc37eb0cce1"
}

rule MalwareBazaar_SalatStealer_031_d5e40d66
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0"
    family = "SalatStealer"
    file_name = "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:51"
  condition:
    hash.sha256(0, filesize) == "d5e40d66ee25be808e3d7bd0926ef0a95cbac0397752a9317db0c006ae4914d0"
}

rule MalwareBazaar_SalatStealer_032_ba834639
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0"
    family = "SalatStealer"
    file_name = "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:46"
  condition:
    hash.sha256(0, filesize) == "ba8346394f23db90f338477662ad89875aa004ca9acdd292690ba695fe1aa5d0"
}

rule MalwareBazaar_SalatStealer_033_db62273b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db62273ba408eeb6246b973f11cfa96313c1e8d5d6831e9b783db5e765544836"
    family = "SalatStealer"
    file_name = "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:14:07"
  condition:
    hash.sha256(0, filesize) == "db62273ba408eeb6246b973f11cfa96313c1e8d5d6831e9b783db5e765544836"
}

rule MalwareBazaar_unknown_034_f586e25f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f586e25f4fa4fb7ef2945dda68d6b18c84ba812f1de761e205cea75686e91f6f"
    family = "unknown"
    file_name = "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:59"
  condition:
    hash.sha256(0, filesize) == "f586e25f4fa4fb7ef2945dda68d6b18c84ba812f1de761e205cea75686e91f6f"
}

rule MalwareBazaar_unknown_035_4dd43a8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518"
    family = "unknown"
    file_name = "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:54"
  condition:
    hash.sha256(0, filesize) == "4dd43a8aea19f785570aed976c78b9dadf3dc6df954a2278b7d55373de964518"
}

rule MalwareBazaar_SalatStealer_036_599cd060
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66"
    family = "SalatStealer"
    file_name = "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:39"
  condition:
    hash.sha256(0, filesize) == "599cd0608c4f96e700d0460ac182bc8aa85b82d231bca1fce7da3e70cffebf66"
}

rule MalwareBazaar_SalatStealer_037_6b1ae5d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a"
    family = "SalatStealer"
    file_name = "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:34"
  condition:
    hash.sha256(0, filesize) == "6b1ae5d5a3575a9a7ef22960d0adf2f6549a81359161d38ab4253ab44e80130a"
}

rule MalwareBazaar_SalatStealer_038_4be7c435
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26"
    family = "SalatStealer"
    file_name = "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:29"
  condition:
    hash.sha256(0, filesize) == "4be7c4355dee7e8792e2a8a0fd199d5208b0b7f10287ffb50813f4bac87d0d26"
}

rule MalwareBazaar_SalatStealer_039_be22e2e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be22e2e21368e30cc8089edb0543459cfc404c3a1645f3b870a1ad05760a0343"
    family = "SalatStealer"
    file_name = "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:26"
  condition:
    hash.sha256(0, filesize) == "be22e2e21368e30cc8089edb0543459cfc404c3a1645f3b870a1ad05760a0343"
}

rule MalwareBazaar_SalatStealer_040_0b09b5c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b"
    family = "SalatStealer"
    file_name = "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:24"
  condition:
    hash.sha256(0, filesize) == "0b09b5c8c4e7133eaf940954a0ed8c62e26bc028d14a5c28c0c5f4fd4c01014b"
}

rule MalwareBazaar_SalatStealer_041_01b4818e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845"
    family = "SalatStealer"
    file_name = "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:19"
  condition:
    hash.sha256(0, filesize) == "01b4818ebcd9a88c60ba75abd4667e3016cbef37243a7574eb1cbb4b31ec2845"
}

rule MalwareBazaar_SalatStealer_042_28c7ddc2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28c7ddc294a263b8ca8a76fdec743c11cc9553447e66499882d5086d3f44d9bb"
    family = "SalatStealer"
    file_name = "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:13:02"
  condition:
    hash.sha256(0, filesize) == "28c7ddc294a263b8ca8a76fdec743c11cc9553447e66499882d5086d3f44d9bb"
}

rule MalwareBazaar_SalatStealer_043_9c5a43a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c5a43a6c1d5d68e2c67d16b89fab04d838f8fa25daf863df8774d5be24004ff"
    family = "SalatStealer"
    file_name = "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:55"
  condition:
    hash.sha256(0, filesize) == "9c5a43a6c1d5d68e2c67d16b89fab04d838f8fa25daf863df8774d5be24004ff"
}

rule MalwareBazaar_SalatStealer_044_ecfd4196
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecfd4196785d5944fe1e947fd3e23ed87dfccc246a0553bc6ab5f7a3e6ad4102"
    family = "SalatStealer"
    file_name = "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:47"
  condition:
    hash.sha256(0, filesize) == "ecfd4196785d5944fe1e947fd3e23ed87dfccc246a0553bc6ab5f7a3e6ad4102"
}

rule MalwareBazaar_SalatStealer_045_f48fd32b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f48fd32b4c3c6dc7553630d4c624ab46e4b0458b5362515407ec6e7c2d46c1f1"
    family = "SalatStealer"
    file_name = "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:40"
  condition:
    hash.sha256(0, filesize) == "f48fd32b4c3c6dc7553630d4c624ab46e4b0458b5362515407ec6e7c2d46c1f1"
}

rule MalwareBazaar_SalatStealer_046_b647fada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b647fada3a64d2dad979b8d18c0e2ed34944e2ba4cc60889cc06b093eb3f396e"
    family = "SalatStealer"
    file_name = "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:12:31"
  condition:
    hash.sha256(0, filesize) == "b647fada3a64d2dad979b8d18c0e2ed34944e2ba4cc60889cc06b093eb3f396e"
}

rule MalwareBazaar_SalatStealer_047_6d2365d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d2365d521653fef1c85938fe6e8ec7d67d3fae28515344733ff802a7f74ea18"
    family = "SalatStealer"
    file_name = "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:36"
  condition:
    hash.sha256(0, filesize) == "6d2365d521653fef1c85938fe6e8ec7d67d3fae28515344733ff802a7f74ea18"
}

rule MalwareBazaar_SalatStealer_048_8daad70d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8daad70d021307c29446df9c72e93b13aaa8b41106c2c87d1b1e46ee16a0c76c"
    family = "SalatStealer"
    file_name = "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:25"
  condition:
    hash.sha256(0, filesize) == "8daad70d021307c29446df9c72e93b13aaa8b41106c2c87d1b1e46ee16a0c76c"
}

rule MalwareBazaar_SalatStealer_049_65490ae0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1"
    family = "SalatStealer"
    file_name = "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:03"
  condition:
    hash.sha256(0, filesize) == "65490ae0988454e9772c1ee1e54030aab7bafca07616cd2cff7103cf529f60c1"
}

rule MalwareBazaar_SalatStealer_050_f6c74c5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6c74c5ac49453f0d43e3c459de39bfaa8bc68db1847b4123600ddb4607d9757"
    family = "SalatStealer"
    file_name = "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:11:01"
  condition:
    hash.sha256(0, filesize) == "f6c74c5ac49453f0d43e3c459de39bfaa8bc68db1847b4123600ddb4607d9757"
}

rule MalwareBazaar_SalatStealer_051_46eeb050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7"
    family = "SalatStealer"
    file_name = "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:58"
  condition:
    hash.sha256(0, filesize) == "46eeb050ee375b52ed28cc9dd593e8b25fb148e92f01878d5bb073e9fb25ecb7"
}

rule MalwareBazaar_SalatStealer_052_81bfade2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81bfade2a8f36b41b76f42088b0171cd98bc691e50161e9d7b15bf9f3a205b31"
    family = "SalatStealer"
    file_name = "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:55"
  condition:
    hash.sha256(0, filesize) == "81bfade2a8f36b41b76f42088b0171cd98bc691e50161e9d7b15bf9f3a205b31"
}

rule MalwareBazaar_SalatStealer_053_de856619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a"
    family = "SalatStealer"
    file_name = "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:53"
  condition:
    hash.sha256(0, filesize) == "de8566192e11b9fe1814307c5747f984e8095d6bd730241f9a95487a9a35951a"
}

rule MalwareBazaar_SalatStealer_054_9178eae7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0"
    family = "SalatStealer"
    file_name = "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:49"
  condition:
    hash.sha256(0, filesize) == "9178eae708a885cd85b9e2d724f756abefe53bd497dd0aeed75be53ae23be9b0"
}

rule MalwareBazaar_SalatStealer_055_58cafffe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "58cafffe8b371b4e89eea07bfe2100bce7f77df31dfb2b9cc2ea08612b09d7c4"
    family = "SalatStealer"
    file_name = "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:47"
  condition:
    hash.sha256(0, filesize) == "58cafffe8b371b4e89eea07bfe2100bce7f77df31dfb2b9cc2ea08612b09d7c4"
}

rule MalwareBazaar_SalatStealer_056_f585889e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2"
    family = "SalatStealer"
    file_name = "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:44"
  condition:
    hash.sha256(0, filesize) == "f585889eea97199802c699315490ce258b23c5e244eb0a5d60f1b7b7537290c2"
}

rule MalwareBazaar_SalatStealer_057_7d094950
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7d09495041b89cb3c4e49870c0534b9e9c3910950ce4838756e5daf2b610e25c"
    family = "SalatStealer"
    file_name = "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:39"
  condition:
    hash.sha256(0, filesize) == "7d09495041b89cb3c4e49870c0534b9e9c3910950ce4838756e5daf2b610e25c"
}

rule MalwareBazaar_SalatStealer_058_1f2de816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75"
    family = "SalatStealer"
    file_name = "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:39"
  condition:
    hash.sha256(0, filesize) == "1f2de816dd49ccf3074102b38902c1ccc81b1786d0789971bbfb70ec3fd2fc75"
}

rule MalwareBazaar_SalatStealer_059_30b07d7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96"
    family = "SalatStealer"
    file_name = "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:10:04"
  condition:
    hash.sha256(0, filesize) == "30b07d7dfc830487a76b7c2b811bcbf96cdc0aeabbf54b2f14c5c70ef3ed3b96"
}

rule MalwareBazaar_SalatStealer_060_087148ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9"
    family = "SalatStealer"
    file_name = "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:59"
  condition:
    hash.sha256(0, filesize) == "087148ec3f18d6b8b699d0d5940dc23af4e3e7c920049c6c865254b3bb958ce9"
}

rule MalwareBazaar_SalatStealer_061_5b951b57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5"
    family = "SalatStealer"
    file_name = "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:54"
  condition:
    hash.sha256(0, filesize) == "5b951b57c8529a2c09b4aadcc83376d7652c9674a61283fff443851d818bbab5"
}

rule MalwareBazaar_SalatStealer_062_4e0dfca1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769"
    family = "SalatStealer"
    file_name = "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:49"
  condition:
    hash.sha256(0, filesize) == "4e0dfca1772897e782d3b66dcfee2121349a5e384a918a41c869eade10247769"
}

rule MalwareBazaar_SalatStealer_063_07be1a5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac"
    family = "SalatStealer"
    file_name = "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:44"
  condition:
    hash.sha256(0, filesize) == "07be1a5a5d75c8cf33a17f4379f13bbdf20f8e3b30df291934088759300defac"
}

rule MalwareBazaar_SalatStealer_064_76886114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a"
    family = "SalatStealer"
    file_name = "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:39"
  condition:
    hash.sha256(0, filesize) == "7688611419ae279d5f9683d3a3bfbb0050f604a6e5c76679c03b4795c7e1cf6a"
}

rule MalwareBazaar_SalatStealer_065_6295455b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6295455b0e17a38176a0c45681d0c13b6266fe0b465816a594e7e23af82ec23c"
    family = "SalatStealer"
    file_name = "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:31"
  condition:
    hash.sha256(0, filesize) == "6295455b0e17a38176a0c45681d0c13b6266fe0b465816a594e7e23af82ec23c"
}

rule MalwareBazaar_SalatStealer_066_7e4c129f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31"
    family = "SalatStealer"
    file_name = "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:09:25"
  condition:
    hash.sha256(0, filesize) == "7e4c129f5bd09beffae196c2ea7d6528efc9a72142e2b4da665389544e4e7d31"
}

rule MalwareBazaar_SalatStealer_067_0fce7fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fce7fe633685a0b907f2b26ed26604ac04fc1496f570ff10e50019c28eb1a17"
    family = "SalatStealer"
    file_name = "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:32"
  condition:
    hash.sha256(0, filesize) == "0fce7fe633685a0b907f2b26ed26604ac04fc1496f570ff10e50019c28eb1a17"
}

rule MalwareBazaar_SalatStealer_068_1768dae4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1768dae488b76147fb0bd76dc4aaa498fe7ecc5b8e3e3a802381b9d7c365f483"
    family = "SalatStealer"
    file_name = "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:26"
  condition:
    hash.sha256(0, filesize) == "1768dae488b76147fb0bd76dc4aaa498fe7ecc5b8e3e3a802381b9d7c365f483"
}

rule MalwareBazaar_SalatStealer_069_9aeae30a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4"
    family = "SalatStealer"
    file_name = "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:22"
  condition:
    hash.sha256(0, filesize) == "9aeae30a3e6d49b4b2e3db2c7aeea8e33aad823ca487898fcdd4107a4f6555c4"
}

rule MalwareBazaar_SalatStealer_070_47958f93
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b"
    family = "SalatStealer"
    file_name = "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:18"
  condition:
    hash.sha256(0, filesize) == "47958f939631f1adba24b37c21a53bed74dd6179fa5beb0d2b912816ed4b7d8b"
}

rule MalwareBazaar_SalatStealer_071_38602089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305"
    family = "SalatStealer"
    file_name = "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:13"
  condition:
    hash.sha256(0, filesize) == "38602089a296b98914abbd7939f0f94a9c6135b4ee839ab2aef016df2488e305"
}

rule MalwareBazaar_SalatStealer_072_501e191d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402"
    family = "SalatStealer"
    file_name = "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:08:08"
  condition:
    hash.sha256(0, filesize) == "501e191da3be2d085394eb13e133c40a59ee222bd45182259fa465c65698c402"
}

rule MalwareBazaar_SalatStealer_073_b6a075d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6a075d0ccd0b63e057244a64cd672074cc8a5f5579bb07d6291a1c648bad6bf"
    family = "SalatStealer"
    file_name = "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:45"
  condition:
    hash.sha256(0, filesize) == "b6a075d0ccd0b63e057244a64cd672074cc8a5f5579bb07d6291a1c648bad6bf"
}

rule MalwareBazaar_SalatStealer_074_43271699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4327169987154a2a6770742919b916aff0c958f649145336a555c290c0d858ca"
    family = "SalatStealer"
    file_name = "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:39"
  condition:
    hash.sha256(0, filesize) == "4327169987154a2a6770742919b916aff0c958f649145336a555c290c0d858ca"
}

rule MalwareBazaar_SalatStealer_075_ef3fafc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef3fafc754d4aa5597378fac2c27582dc974ab53077137f0c234638f42a5c009"
    family = "SalatStealer"
    file_name = "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:30"
  condition:
    hash.sha256(0, filesize) == "ef3fafc754d4aa5597378fac2c27582dc974ab53077137f0c234638f42a5c009"
}

rule MalwareBazaar_SalatStealer_076_7f002f5d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f002f5d4cd461e27bec8016fcf981bba7b78dfd6386f3a9807a024f953dfbde"
    family = "SalatStealer"
    file_name = "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:06:23"
  condition:
    hash.sha256(0, filesize) == "7f002f5d4cd461e27bec8016fcf981bba7b78dfd6386f3a9807a024f953dfbde"
}

rule MalwareBazaar_SalatStealer_077_e1bc1d85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1"
    family = "SalatStealer"
    file_name = "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:54"
  condition:
    hash.sha256(0, filesize) == "e1bc1d85b1e60ccf6d49c90677768d93bd4d65d819029fd6cdd7bbfb57b2efb1"
}

rule MalwareBazaar_SalatStealer_078_51cda73c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f"
    family = "SalatStealer"
    file_name = "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:49"
  condition:
    hash.sha256(0, filesize) == "51cda73c920806c6e71b1ca225017e863da345aaddb66429022fef3ff58d1f5f"
}

rule MalwareBazaar_SalatStealer_079_1c7819f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef"
    family = "SalatStealer"
    file_name = "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:44"
  condition:
    hash.sha256(0, filesize) == "1c7819f6a930439129c191c4b6741e44807350a64eaa9cfe966c5d12b9e4f0ef"
}

rule MalwareBazaar_SalatStealer_080_f374939c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91"
    family = "SalatStealer"
    file_name = "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91.exe"
    file_type = "exe"
    first_seen = "2026-10-26 03:05:38"
  condition:
    hash.sha256(0, filesize) == "f374939c71458fed913b6ef0287cc4f01a3612d69f0740807a7e820cb9dfdd91"
}

rule MalwareBazaar_unknown_081_5c73e0b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6"
    family = "unknown"
    file_name = "5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6"
    file_type = "elf"
    first_seen = "2026-10-26 02:53:08"
  condition:
    hash.sha256(0, filesize) == "5c73e0b861cabc1ce5d9905f927385252914944768b766e7709627a545fd02c6"
}

rule MalwareBazaar_unknown_082_815e8321
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d"
    family = "unknown"
    file_name = "815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d"
    file_type = "elf"
    first_seen = "2026-10-26 02:34:43"
  condition:
    hash.sha256(0, filesize) == "815e8321b51a418aeaf5c41c420a595a7edd3e5fb08fd520b5b512e80578ac1d"
}

rule MalwareBazaar_SalatStealer_083_1897cd92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1897cd92b634628fbbf0fd9fc9caa3fed63b4c4032c9aea6419a1ed9c2d29205"
    family = "SalatStealer"
    file_name = "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:31:46"
  condition:
    hash.sha256(0, filesize) == "1897cd92b634628fbbf0fd9fc9caa3fed63b4c4032c9aea6419a1ed9c2d29205"
}

rule MalwareBazaar_SalatStealer_084_5ac0973b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac0973b12872c8d1de7d0e8799a0b04ee78ecde0f0ef71a94a3103bae752f1c"
    family = "SalatStealer"
    file_name = "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:59"
  condition:
    hash.sha256(0, filesize) == "5ac0973b12872c8d1de7d0e8799a0b04ee78ecde0f0ef71a94a3103bae752f1c"
}

rule MalwareBazaar_SalatStealer_085_f0f2523f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0f2523f2cb030e73e38ce36552963c0bfafa10b2e09bec28fb7c740f811c37f"
    family = "SalatStealer"
    file_name = "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:51"
  condition:
    hash.sha256(0, filesize) == "f0f2523f2cb030e73e38ce36552963c0bfafa10b2e09bec28fb7c740f811c37f"
}

rule MalwareBazaar_SalatStealer_086_dae026c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dae026c3c9598221e5a7c11bacacd08a9d59f340286de242d79da69e0b283b9b"
    family = "SalatStealer"
    file_name = "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:44"
  condition:
    hash.sha256(0, filesize) == "dae026c3c9598221e5a7c11bacacd08a9d59f340286de242d79da69e0b283b9b"
}

rule MalwareBazaar_SalatStealer_087_4def57e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4def57e2b534cafb37648640bbcac0bf8cb41a8fcc42f38c7bf8cc5eba8d26a0"
    family = "SalatStealer"
    file_name = "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:37"
  condition:
    hash.sha256(0, filesize) == "4def57e2b534cafb37648640bbcac0bf8cb41a8fcc42f38c7bf8cc5eba8d26a0"
}

rule MalwareBazaar_SalatStealer_088_44ad1f02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ad1f0200906e1fffc07d5c94e3577a79038108a3436448855b3f6dd2883f90"
    family = "SalatStealer"
    file_name = "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:29"
  condition:
    hash.sha256(0, filesize) == "44ad1f0200906e1fffc07d5c94e3577a79038108a3436448855b3f6dd2883f90"
}

rule MalwareBazaar_SalatStealer_089_7083e04a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7083e04a4889d45d0af520a7167ef86dfb1c7228e4d03069f22ec80b4172f820"
    family = "SalatStealer"
    file_name = "b8ab7dcb982eb6c2.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:29:03"
  condition:
    hash.sha256(0, filesize) == "7083e04a4889d45d0af520a7167ef86dfb1c7228e4d03069f22ec80b4172f820"
}

rule MalwareBazaar_SalatStealer_090_9d6740d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6"
    family = "SalatStealer"
    file_name = "09f365cc415195f7.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:57"
  condition:
    hash.sha256(0, filesize) == "9d6740d5b7abd4aff685678510b547c131bda2c7a086ba955368a4cf4715baa6"
}

rule MalwareBazaar_SalatStealer_091_1912356d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1912356db2d96170c052c920bf9a636594a22946b64725f967d1253163b11d2c"
    family = "SalatStealer"
    file_name = "191cc4b9334d555d.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:51"
  condition:
    hash.sha256(0, filesize) == "1912356db2d96170c052c920bf9a636594a22946b64725f967d1253163b11d2c"
}

rule MalwareBazaar_SalatStealer_092_27fc5c5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27fc5c5f89537a463da16cb92725a0cdd9e59774a200f5964945f96bf6902d06"
    family = "SalatStealer"
    file_name = "cc5353f305b429e7.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:45"
  condition:
    hash.sha256(0, filesize) == "27fc5c5f89537a463da16cb92725a0cdd9e59774a200f5964945f96bf6902d06"
}

rule MalwareBazaar_SalatStealer_093_746ac20c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b"
    family = "SalatStealer"
    file_name = "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:20"
  condition:
    hash.sha256(0, filesize) == "746ac20caf66f45e6e9bcf0f0d50c0d07f028537ae4d9e9b36b766b15279de6b"
}

rule MalwareBazaar_SalatStealer_094_90aa7c29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5"
    family = "SalatStealer"
    file_name = "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:15"
  condition:
    hash.sha256(0, filesize) == "90aa7c29c95140ccc0e81a92088f8c63ee05eff17cd24497c6f12e90ffc36dc5"
}

rule MalwareBazaar_SalatStealer_095_950e3bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e"
    family = "SalatStealer"
    file_name = "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:10"
  condition:
    hash.sha256(0, filesize) == "950e3bdd4166acbcecdc906ad5462334b51bdca12039398cdf64c81323e2481e"
}

rule MalwareBazaar_SalatStealer_096_e0fabbd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14"
    family = "SalatStealer"
    file_name = "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:05"
  condition:
    hash.sha256(0, filesize) == "e0fabbd75a800c5c18bab1a50d8225a0282c18f966acd76e4a4a914163940d14"
}

rule MalwareBazaar_SalatStealer_097_fea6e379
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6"
    family = "SalatStealer"
    file_name = "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:28:00"
  condition:
    hash.sha256(0, filesize) == "fea6e379e5864f824165cd54548ec905672862fbe3cabfd04b7c59bb691541e6"
}

rule MalwareBazaar_SalatStealer_098_46f32f4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49"
    family = "SalatStealer"
    file_name = "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49.exe"
    file_type = "exe"
    first_seen = "2026-10-26 02:27:55"
  condition:
    hash.sha256(0, filesize) == "46f32f4ac32495bdcfeb8f388423b79a3ce8401425f3ef294b6efabdbddc1e49"
}

rule MalwareBazaar_SalatStealer_099_96c3c711
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96c3c711e5a92dd5c9952a92d2ecf0deb1bf1bb895e520194ccb3903490f8980"
    family = "SalatStealer"
    file_name = "233f83c036e611b6.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:27:33"
  condition:
    hash.sha256(0, filesize) == "96c3c711e5a92dd5c9952a92d2ecf0deb1bf1bb895e520194ccb3903490f8980"
}

rule MalwareBazaar_SalatStealer_100_a222ed12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a222ed12296268d4e3e30a74ba5f1a0c101749f52fd5a077cc5a7eb5d3377b5a"
    family = "SalatStealer"
    file_name = "b051bdb181f635f1.bin"
    file_type = "exe"
    first_seen = "2026-10-26 02:27:26"
  condition:
    hash.sha256(0, filesize) == "a222ed12296268d4e3e30a74ba5f1a0c101749f52fd5a077cc5a7eb5d3377b5a"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

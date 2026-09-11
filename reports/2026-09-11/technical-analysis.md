# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-11

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 546 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 546 |
| Unique family labels | 8 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 65 |
| Mirai | 17 |
| VShell | 13 |
| NetSupport | 1 |
| ConnectWise | 1 |
| njrat | 1 |
| MassLogger | 1 |
| CoinMiner | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 31 |
| unknown | 25 |
| exe | 23 |
| sh | 11 |
| zip | 4 |
| js | 3 |
| vbs | 2 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `e1c18c4e147bfacf`

| Field | Value |
|---|---|
| SHA-256 | `e1c18c4e147bfacfe050d441bde8ac4591f2e7d4320dbc28da78b61647fbb04d` |
| Family label | `unknown` |
| File name | `JAG93498680733_20260911_044325_690d130890.js` |
| File type | `js` |
| First seen | `2026-09-11 04:48:56` |
| Reporter | `KodaDr` |
| Tags | `js, Loader, UpCrypter` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `907b2b1136f064e7beba0aed1ff1a383` |
| SHA-1 | `0a0bb1334dd4aa5a119ab50d89def9e2b2443ff2` |
| SHA-256 | `e1c18c4e147bfacfe050d441bde8ac4591f2e7d4320dbc28da78b61647fbb04d` |
| SHA3-384 | `eb8838db6f339375f738a1d3b628c44ec935f1de6b13187fb685614368c9146e17558b3f63b604fd25d89d85a07624d8` |
| TLSH | `T146553024327F930870F352DC95EC1A5246BEF36A263F67AC82B52D8C23E2D425D95B53` |
| SSDEEP | `24576:Ctssf3ue5hIIbTq6FdEEDtssf3ue5hIIbTq6FdEEktssf3ue5hIIbTq6FdEEDtsz:Ctssf3ue5hIIbTq6FdEEDtssf3ue5hIy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_e1c18c4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1c18c4e147bfacfe050d441bde8ac4591f2e7d4320dbc28da78b61647fbb04d"
    family = "unknown"
    file_name = "JAG93498680733_20260911_044325_690d130890.js"
    file_type = "js"
    first_seen = "2026-09-11 04:48:56"
  condition:
    hash.sha256(0, filesize) == "e1c18c4e147bfacfe050d441bde8ac4591f2e7d4320dbc28da78b61647fbb04d"
}
```

### Sample 2: `9a8c3e3982fdfabb`

| Field | Value |
|---|---|
| SHA-256 | `9a8c3e3982fdfabba73d82309fa0b0326586f001f0e623886eb40432d8dcc8ef` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-11 04:14:35` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e65eca26b3e238a7a9aaaa329fc211c5` |
| SHA-1 | `3a55a912d8bdd5c7006cf4fd672b178bb682f829` |
| SHA-256 | `9a8c3e3982fdfabba73d82309fa0b0326586f001f0e623886eb40432d8dcc8ef` |
| SHA3-384 | `1dbe3a0193bcc8e21f5e2c7fc4c709d281494b4b4c42f86d86d0dd6b458ef610ab23239e2ff2915bac55a51abcc7f124` |
| TLSH | `T122C28C966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11F9CD618B1A` |
| SSDEEP | `768:v8vCB+25j6es8RU9FYpMSUpi+20qUpi+20YQX:v8l25Jyd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_9a8c3e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a8c3e3982fdfabba73d82309fa0b0326586f001f0e623886eb40432d8dcc8ef"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 04:14:35"
  condition:
    hash.sha256(0, filesize) == "9a8c3e3982fdfabba73d82309fa0b0326586f001f0e623886eb40432d8dcc8ef"
}
```

### Sample 3: `07c0a0af63dde8dc`

| Field | Value |
|---|---|
| SHA-256 | `07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656` |
| Family label | `Mirai` |
| File name | `07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656.elf` |
| File type | `elf` |
| First seen | `2026-09-11 04:04:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4ae6a78e83cc685fbe6c7a95a476302` |
| SHA-1 | `965801aad155fbf4bc1c5026ee65173cb5a5661d` |
| SHA-256 | `07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656` |
| SHA3-384 | `40d99f8ec027b7749f6f85a3b91bd23fbcdc21032d2b4180e00569f1974238190df1c2eae3f2d0f4e25b616d82c86513` |
| TLSH | `T112D33A05F5508767C2D2237AFB9A825D37332B6497DB33219A24BFB42BC279D1E39121` |
| TELFHASH | `t1c2214042a6be8a286bf34a28ec7c03f015511a2372813e70ff1ec6c0553700ab525daf` |
| SSDEEP | `3072:YiyLFeGtAgT6akMibb+a7BR8hPkILWm+WkNQTktc5y2:Q7AW6akL9BGhPVWm+WkNQTky5y2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_07c0a0af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656"
    family = "Mirai"
    file_name = "07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656.elf"
    file_type = "elf"
    first_seen = "2026-09-11 04:04:29"
  condition:
    hash.sha256(0, filesize) == "07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656"
}
```

### Sample 4: `7369528260774703`

| Field | Value |
|---|---|
| SHA-256 | `73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559` |
| Family label | `Mirai` |
| File name | `73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559.elf` |
| File type | `elf` |
| First seen | `2026-09-11 04:04:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86ce8546c68b52df125b999a5f2a19fe` |
| SHA-1 | `5554ecf01767be73808f3e2f07a307f688abbe57` |
| SHA-256 | `73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559` |
| SHA3-384 | `de80fd6e77a6e96b6e406a8be85150433790891efcad77c7094cc0324dc8f4eacba34ecd66d22d5e1155e8ace757a033` |
| TLSH | `T1FBC31A45F9404B27C2D227BAE78E439D37366A54D7E733116B38BEB42BC57981E39120` |
| TELFHASH | `t109210042b6be8a282ff24a28ac7c03f025516a2373817e70ef5ec5c41537006b565e9f` |
| SSDEEP | `3072:58oRM2GLKh+4LPrVZh/AmMdVzrDD1PQ3L/z5XC5:5rqVG+sTVDomODD1PQ3L/z5XC5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_73695282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559"
    family = "Mirai"
    file_name = "73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559.elf"
    file_type = "elf"
    first_seen = "2026-09-11 04:04:24"
  condition:
    hash.sha256(0, filesize) == "73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559"
}
```

### Sample 5: `188401154e54bdc9`

| Field | Value |
|---|---|
| SHA-256 | `188401154e54bdc983556e45f6281a1e32f6bb3802a55465e3a8ecc504f51d92` |
| Family label | `unknown` |
| File name | `NEW_LETTER_OF_AUTHORIZATION.js` |
| File type | `js` |
| First seen | `2026-09-11 04:01:52` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `061fc58d9776da2dc1e39ed3f6b3afa2` |
| SHA-1 | `98db7ebaeeb42976fd7a8534358e135d159bd735` |
| SHA-256 | `188401154e54bdc983556e45f6281a1e32f6bb3802a55465e3a8ecc504f51d92` |
| SHA3-384 | `39e57c4ad7189c4c42437d87e1ae38aa8110645ca5c9a2fc01d9cabc30869881fb22007120e6f092d73daf4b4a0a1857` |
| TLSH | `T1B5E584B43F831101C73E35D6CD8D099D0965EEA49CA5B291A3CB2DEC4CA7087B6E4F5A` |
| SSDEEP | `12288:iyDxp+oZPtCjlSeiB/PqHeiYUUp8w4NA4thD7yrknOWaekOj5uIsMIF0Rz7TtLvS:7v1rHpb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_18840115
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "188401154e54bdc983556e45f6281a1e32f6bb3802a55465e3a8ecc504f51d92"
    family = "unknown"
    file_name = "NEW_LETTER_OF_AUTHORIZATION.js"
    file_type = "js"
    first_seen = "2026-09-11 04:01:52"
  condition:
    hash.sha256(0, filesize) == "188401154e54bdc983556e45f6281a1e32f6bb3802a55465e3a8ecc504f51d92"
}
```

### Sample 6: `6d6adbff7df2734a`

| Field | Value |
|---|---|
| SHA-256 | `6d6adbff7df2734a190003658eeaea6f2cbef90953b3bbc116d3a411aa02ed66` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-11 03:42:36` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a7a763c0e99f2c13553d902fbcca92f` |
| SHA-1 | `b267192102d2784aeaea11d9185087fe6d8b1063` |
| SHA-256 | `6d6adbff7df2734a190003658eeaea6f2cbef90953b3bbc116d3a411aa02ed66` |
| SHA3-384 | `75911ff4e5b6db4c107ac826a4a000a43de8dee208a1ffb3fb6a9d653168bcf65a1881ef742965803536f03e7d5cd4ca` |
| TLSH | `T1DD235C551A857C149E99C4371D7E2F0CB9AD43E6320852EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:uVEJVIhtMd9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:MEJ2M+cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_6d6adbff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d6adbff7df2734a190003658eeaea6f2cbef90953b3bbc116d3a411aa02ed66"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 03:42:36"
  condition:
    hash.sha256(0, filesize) == "6d6adbff7df2734a190003658eeaea6f2cbef90953b3bbc116d3a411aa02ed66"
}
```

### Sample 7: `2776db94daae85ee`

| Field | Value |
|---|---|
| SHA-256 | `2776db94daae85ee1013c8274828d48e1c08705a690fa953f22209830b7618bd` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-11 03:40:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26497e624e5ee97c5bd9fcc5f8b62278` |
| SHA-1 | `acc9813dcdb7cff7ca9982af964d7942ae9dd762` |
| SHA-256 | `2776db94daae85ee1013c8274828d48e1c08705a690fa953f22209830b7618bd` |
| SHA3-384 | `e5ae35fd731b5ea821df3e854212402e0e0625d1bcc37103975ebe6d01b44010ac8fa705ea1a47fa3eef7e57218c2211` |
| TLSH | `T17D235B6516857C24AE98C8361C7E2F0CB9AD43E6324452EE7FCF3CF68C4A6AD910971D` |
| SSDEEP | `768:W+19GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:W+mcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_2776db94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2776db94daae85ee1013c8274828d48e1c08705a690fa953f22209830b7618bd"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 03:40:37"
  condition:
    hash.sha256(0, filesize) == "2776db94daae85ee1013c8274828d48e1c08705a690fa953f22209830b7618bd"
}
```

### Sample 8: `aead598cf4d5c0f3`

| Field | Value |
|---|---|
| SHA-256 | `aead598cf4d5c0f3c294fec64fe9cc13d06ddc054ac2b799ce457300f6080287` |
| Family label | `unknown` |
| File name | `HuGN.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 03:36:37` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `137fc5eb91de75821df441e50ef9e40f` |
| SHA-256 | `aead598cf4d5c0f3c294fec64fe9cc13d06ddc054ac2b799ce457300f6080287` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_aead598c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aead598cf4d5c0f3c294fec64fe9cc13d06ddc054ac2b799ce457300f6080287"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 03:36:37"
  condition:
    hash.sha256(0, filesize) == "aead598cf4d5c0f3c294fec64fe9cc13d06ddc054ac2b799ce457300f6080287"
}
```

### Sample 9: `06b74f0ddef0180a`

| Field | Value |
|---|---|
| SHA-256 | `06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8` |
| Family label | `unknown` |
| File name | `06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8` |
| File type | `elf` |
| First seen | `2026-09-11 03:32:58` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b56189abff51248be9ff70abc1bff44` |
| SHA-1 | `acc61d24d6db52c9145b6050c1a4e764ceebc31a` |
| SHA-256 | `06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8` |
| SHA3-384 | `114fa8a87f8ae4df94f7db5412c090555103fcb8a56fd95a08b918ca62f8627c39203bfc8bf949bdc9b5f33520f4b847` |
| TLSH | `T11553121F04C26EAAFD0672EA9D4CC9EB400D2FAE9D5C5A91D9187383A609DD44913ECD` |
| SSDEEP | `1536:5Z4h5QANIVsDgK+wgQP+h2YAC4iFjdTyjvKweq6:n43QAiVsDn5P+h2D8j18H6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_06b74f0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8"
    family = "unknown"
    file_name = "06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8"
    file_type = "elf"
    first_seen = "2026-09-11 03:32:58"
  condition:
    hash.sha256(0, filesize) == "06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8"
}
```

### Sample 10: `ae2cd00c16b69111`

| Field | Value |
|---|---|
| SHA-256 | `ae2cd00c16b6911133d21eada3d44e30eee5de57a9d4167f408fc5bbe7a30f88` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-11 03:28:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c1055403dfb8586e5730fa5de39a54b` |
| SHA-1 | `2a2ae5974dbb3c68d69c441168bfab853d263363` |
| SHA-256 | `ae2cd00c16b6911133d21eada3d44e30eee5de57a9d4167f408fc5bbe7a30f88` |
| SHA3-384 | `6b09248d03cb192b8b4c61824d50929897e0ab731a28518274671e0ccc23a3977924e8680b63b9f9262bf7d4ec2fb6a6` |
| TLSH | `T135C28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D4A3C71DC12FACD618B1A` |
| SSDEEP | `768:W8vCB+25j6es8Rs9FYpMSUpi+20qUpi+20YQX:W8l25J6d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_ae2cd00c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2cd00c16b6911133d21eada3d44e30eee5de57a9d4167f408fc5bbe7a30f88"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 03:28:34"
  condition:
    hash.sha256(0, filesize) == "ae2cd00c16b6911133d21eada3d44e30eee5de57a9d4167f408fc5bbe7a30f88"
}
```

### Sample 11: `84e7371263c069cf`

| Field | Value |
|---|---|
| SHA-256 | `84e7371263c069cf99bc4aa2cccd55120576b1725a563c234e1850bd142a78cb` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 03:26:39` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e386f78ec0700dcde71ac7b6cb63e366` |
| SHA-256 | `84e7371263c069cf99bc4aa2cccd55120576b1725a563c234e1850bd142a78cb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_84e73712
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84e7371263c069cf99bc4aa2cccd55120576b1725a563c234e1850bd142a78cb"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 03:26:39"
  condition:
    hash.sha256(0, filesize) == "84e7371263c069cf99bc4aa2cccd55120576b1725a563c234e1850bd142a78cb"
}
```

### Sample 12: `99ab596c4872cfc7`

| Field | Value |
|---|---|
| SHA-256 | `99ab596c4872cfc705cffdf2ce178218e919bc7e22192e3e4bc3a6f1d5968552` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-11 03:26:38` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10bf088571a35b66d344170609432722` |
| SHA-256 | `99ab596c4872cfc705cffdf2ce178218e919bc7e22192e3e4bc3a6f1d5968552` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_99ab596c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ab596c4872cfc705cffdf2ce178218e919bc7e22192e3e4bc3a6f1d5968552"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 03:26:38"
  condition:
    hash.sha256(0, filesize) == "99ab596c4872cfc705cffdf2ce178218e919bc7e22192e3e4bc3a6f1d5968552"
}
```

### Sample 13: `cd9655a77201f73e`

| Field | Value |
|---|---|
| SHA-256 | `cd9655a77201f73e69953ec5b53f898de41983c1b4dcedd0c431955b9c20b241` |
| Family label | `Mirai` |
| File name | `telnet` |
| File type | `elf` |
| First seen | `2026-09-11 03:20:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e0c4109aa0afe9ed135a0a0d1ecdd4a5` |
| SHA-1 | `c80e0c1f476da9015c9a6a426b6098320ae768e9` |
| SHA-256 | `cd9655a77201f73e69953ec5b53f898de41983c1b4dcedd0c431955b9c20b241` |
| SHA3-384 | `7ef5efe96c740dd1f86d98fb597b75f438685a0b792d6270bbe0658ad0387348b4feb58a35bdcd74bddb51f509865918` |
| TLSH | `T141B31B45F951472BC2D337BAF78E428D37356A5497E733216A387EB42BC6B881E39120` |
| TELFHASH | `t109210042b6be8a282ff24a28ac7c03f025516a2373817e70ef5ec5c41537006b565e9f` |
| SSDEEP | `3072:E4RPpM/GL9bK8Jhg0xnhBDmTo9tjvDMC+QH1q45Di5:EKSwlKSh1xhBDmTiDMC+QH1q45Di5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_cd9655a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd9655a77201f73e69953ec5b53f898de41983c1b4dcedd0c431955b9c20b241"
    family = "Mirai"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-09-11 03:20:35"
  condition:
    hash.sha256(0, filesize) == "cd9655a77201f73e69953ec5b53f898de41983c1b4dcedd0c431955b9c20b241"
}
```

### Sample 14: `2af14633ff24e289`

| Field | Value |
|---|---|
| SHA-256 | `2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3` |
| Family label | `unknown` |
| File name | `2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3.bin` |
| File type | `zip` |
| First seen | `2026-09-11 03:09:18` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4201a4fab8b8f7536caafb316f44d181` |
| SHA-1 | `e3724098bf7d09f38d48339c8d8c23ac4d1f1082` |
| SHA-256 | `2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3` |
| SHA3-384 | `31e42fe91c685376a703bb7a459e1346cc3fbb283e807e32fd8b410fc62a3e04b40098c40ea70b2374501482aa59e9a3` |
| TLSH | `T1CBF31253053775E0C87A73FCAC1488AC1A6C891D2592B137A3CAB0DD5DB7F2A64BD2C9` |
| SSDEEP | `3072:zgHmvwQoM7HCZQmPgu3XmmUg5hFu5MNTsHLRL:iRo7EpIu3Xmjg745OsZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_2af14633
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3"
    family = "unknown"
    file_name = "2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3.bin"
    file_type = "zip"
    first_seen = "2026-09-11 03:09:18"
  condition:
    hash.sha256(0, filesize) == "2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3"
}
```

### Sample 15: `76248563dc3fbd1a`

| Field | Value |
|---|---|
| SHA-256 | `76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf` |
| Family label | `unknown` |
| File name | `76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf.bin` |
| File type | `exe` |
| First seen | `2026-09-11 02:38:31` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e68f8d5e235ba07f491dff13b7288ba` |
| SHA-1 | `29e30b954127321a45f327427652e8f40c4681eb` |
| SHA-256 | `76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf` |
| SHA3-384 | `60d2abd2f15261b3d1f7c73ccbddb14cee33aa0e0b9f8fcea4509c139ca93dd815aa96b0c8b094452a0abc018ee6a887` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T169366B03EEA548F9D296D73588774242B764BC499B3533D32E60BA742F363D0AE79B40` |
| SSDEEP | `49152:uFKpz7i7FAlc03DCBGcm+a1h6TczyJPj4RRHrYvAaaB:uc3XND1aJrCOkB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_76248563
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf"
    family = "unknown"
    file_name = "76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf.bin"
    file_type = "exe"
    first_seen = "2026-09-11 02:38:31"
  condition:
    hash.sha256(0, filesize) == "76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf"
}
```

### Sample 16: `7497e359bc00ee6e`

| Field | Value |
|---|---|
| SHA-256 | `7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41` |
| Family label | `unknown` |
| File name | `7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 02:34:22` |
| Reporter | `Tuxxin` |
| Tags | `script` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b3f0d1e676ea8c69aa89f85e1531f94` |
| SHA-256 | `7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_7497e359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41"
    family = "unknown"
    file_name = "7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 02:34:22"
  condition:
    hash.sha256(0, filesize) == "7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41"
}
```

### Sample 17: `076f3b4defa1a6a3`

| Field | Value |
|---|---|
| SHA-256 | `076f3b4defa1a6a31101021ef25ec20a755dbfb68ca7ffe6a192a0713b11b659` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 02:29:23` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX1.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `922991915fe3b11cc491d8e37e33fe4b` |
| SHA-1 | `7bc095ac2b48d341f27e11ff07c3a55959816878` |
| SHA-256 | `076f3b4defa1a6a31101021ef25ec20a755dbfb68ca7ffe6a192a0713b11b659` |
| SHA3-384 | `6ddd339d289a1d709c8312b2c6b4a9079c28b4e93b0bee4126cf1cc684e61618bdcde77eeb792aa5706c77501b51b0c8` |
| IMPHASH | `70d2e884fa127843c5bcbb53da86b6c8` |
| TLSH | `T1C9771256E2FD00E8D5BAC0BCC6575517EBB23459173097EB52A48A692F33BE0AE3D310` |
| SSDEEP | `786432:suMLuHXoeOvHiwB3sn+h1hW25F+wX0ff6yajCs6+4S3Nftc:s5uoeeCwDrhWG+tf6fj4ulc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_076f3b4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "076f3b4defa1a6a31101021ef25ec20a755dbfb68ca7ffe6a192a0713b11b659"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 02:29:23"
  condition:
    hash.sha256(0, filesize) == "076f3b4defa1a6a31101021ef25ec20a755dbfb68ca7ffe6a192a0713b11b659"
}
```

### Sample 18: `4e428fb03df8cdf9`

| Field | Value |
|---|---|
| SHA-256 | `4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464` |
| Family label | `NetSupport` |
| File name | `4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464.bin` |
| File type | `zip` |
| First seen | `2026-09-11 02:10:03` |
| Reporter | `Tuxxin` |
| Tags | `NetSupport, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6265a60b9669d3b135bb8ef40a3ce74f` |
| SHA-1 | `a1372cc3fe0966ca7d33a56b381bf978fe15ed39` |
| SHA-256 | `4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464` |
| SHA3-384 | `5282e152942a099b99b1c924c99b1f17df40bb090feb0aa33cf4f962dad1d51922aebc0aa20e562962e8fad3b230e94b` |
| TLSH | `T172A533A4216DE07CF967747ECA9A91C8473C2403329AB313F5BB0CC56F46A666374EC6` |
| SSDEEP | `49152:CDMtGEdbNpje98aVxbGBPrQUUNBhdoZYnir6iOAPfAJx:7GEVeh3GBPFvrGAwz` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_018_4e428fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464"
    family = "NetSupport"
    file_name = "4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464.bin"
    file_type = "zip"
    first_seen = "2026-09-11 02:10:03"
  condition:
    hash.sha256(0, filesize) == "4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464"
}
```

### Sample 19: `382a96ce056c847c`

| Field | Value |
|---|---|
| SHA-256 | `382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430` |
| Family label | `VShell` |
| File name | `382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430.exe` |
| File type | `exe` |
| First seen | `2026-09-11 02:05:03` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5fcaacbce04810aa5e12121b477e5d35` |
| SHA-1 | `7e23dafa873aea37f862fd6c8f387f19ba9c1f6b` |
| SHA-256 | `382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430` |
| SHA3-384 | `b5aedff37ae953e35151523d12b4d0488bb91879699dff5546151a50e7547bb1a925293740c78bee3d4d3f3b9ec78759` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T18691A6C5F757E6B2EC1C17F500A37994C4682E14827C9B464FE16F0C3C111AA3C3DA12` |
| SSDEEP | `48:6I7lwe70FQ08ScfJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1Yu09aq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_019_382a96ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430"
    family = "VShell"
    file_name = "382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430.exe"
    file_type = "exe"
    first_seen = "2026-09-11 02:05:03"
  condition:
    hash.sha256(0, filesize) == "382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430"
}
```

### Sample 20: `941f22db88f2c0f6`

| Field | Value |
|---|---|
| SHA-256 | `941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e` |
| Family label | `VShell` |
| File name | `941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e.exe` |
| File type | `exe` |
| First seen | `2026-09-11 02:04:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c0298637545878ea93be495da06b120` |
| SHA-1 | `f0fab89d1fa451ba5854ae9bf64c55de692f1f61` |
| SHA-256 | `941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e` |
| SHA3-384 | `1ead223b9a9c93b23db6b90ed3bd4f43bf34e761ae24a0348570cc06f925a54a4700e31d3aefa606503b86e25cd371d8` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T16371B58160545AF2D94CA37F8487B8A6FD4EB249A2C80B0F0798981A2FB147BB1D9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DLJ7jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DLJf++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_020_941f22db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e"
    family = "VShell"
    file_name = "941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e.exe"
    file_type = "exe"
    first_seen = "2026-09-11 02:04:13"
  condition:
    hash.sha256(0, filesize) == "941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e"
}
```

### Sample 21: `fccbb54155bf5a95`

| Field | Value |
|---|---|
| SHA-256 | `fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27` |
| Family label | `unknown` |
| File name | `fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27.elf` |
| File type | `elf` |
| First seen | `2026-09-11 01:55:05` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b6b854fcdb010a9a16e694533b2889a` |
| SHA-1 | `b6c401fe0ea01775f2bf752a8a244cba6af17b98` |
| SHA-256 | `fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27` |
| SHA3-384 | `d6da3d8e774a1bf53fc918d7352b049f4cce7ac8d4300ae320725b143e295e93e24946d3060f58359deecd7fdd4cc5e1` |
| TLSH | `T12426AE16B6A244FDC0E6C430838BD673AD35B8545221397B7684AB312F76F305F6EBA1` |
| SSDEEP | `98304:8grH+8UprnVnq+Zvqz1vL9TWo16X22jKRlKR:rbC7c+hahTZ1HRlKR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_fccbb541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27"
    family = "unknown"
    file_name = "fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27.elf"
    file_type = "elf"
    first_seen = "2026-09-11 01:55:05"
  condition:
    hash.sha256(0, filesize) == "fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27"
}
```

### Sample 22: `18b41b9483a6331e`

| Field | Value |
|---|---|
| SHA-256 | `18b41b9483a6331e8549a57567022f86863e7b5d4496d493e7ee67c6799b5da1` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-11 01:49:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e03e959675515438d8cd9bafcc11d694` |
| SHA-1 | `c73a549fc0e82583dc93f50bcc8bc0588ef148c1` |
| SHA-256 | `18b41b9483a6331e8549a57567022f86863e7b5d4496d493e7ee67c6799b5da1` |
| SHA3-384 | `72b02e601b99c07c0ad7b849d4876e46b2202368b1c19e917e2e97707b7e75228b5c5a69cefd556a1eb3d7cca35fd2e5` |
| TLSH | `T14CC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:F8vCB+25j6es8R729FYpMSUpi+20qUpi+20YQX:F8l25J8d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_18b41b94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18b41b9483a6331e8549a57567022f86863e7b5d4496d493e7ee67c6799b5da1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 01:49:00"
  condition:
    hash.sha256(0, filesize) == "18b41b9483a6331e8549a57567022f86863e7b5d4496d493e7ee67c6799b5da1"
}
```

### Sample 23: `1f2160b814d7cb02`

| Field | Value |
|---|---|
| SHA-256 | `1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257` |
| Family label | `VShell` |
| File name | `1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257.exe` |
| File type | `exe` |
| First seen | `2026-09-11 01:34:18` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c32ef810e4af158f922da6d382d4a5c9` |
| SHA-1 | `bb2e8002f0402362d886a0fc56589138c2c08ec7` |
| SHA-256 | `1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257` |
| SHA3-384 | `0123b47def4a027cdc2fe75913e30f77a33a24d2fb22fc63616a8565c513ef8a8722c73942b9d5f2e4a56735e6f0e2b4` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17271B54160541AF2D94CE37F8587B895FD5EB248A2C80B0B03D8985A2F7547BB0DA613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DFHnwkSjk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6Dlnq++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_023_1f2160b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257"
    family = "VShell"
    file_name = "1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:34:18"
  condition:
    hash.sha256(0, filesize) == "1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257"
}
```

### Sample 24: `7085ab2e2e21bf54`

| Field | Value |
|---|---|
| SHA-256 | `7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c` |
| Family label | `VShell` |
| File name | `7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c.exe` |
| File type | `exe` |
| First seen | `2026-09-11 01:34:13` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `054f08bf3102d326be1128d9a732807c` |
| SHA-1 | `1c78d097d465796af0e3ebbe5c9ae584e542776f` |
| SHA-256 | `7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c` |
| SHA3-384 | `7bf264397af4861ca3104d770ed53b55a084c3ea1712f88468213074bea7f5d16c7836f9ab3ad414b9b473fda1be8f78` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1DA71D68160505AF2E94CE37F8487B896FD4FB248A2C80B0F0798D81B2F7507BB0D9623` |
| SSDEEP | `48:6IZUBQYxZul2EywS6Dfujk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6Df0++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_024_7085ab2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c"
    family = "VShell"
    file_name = "7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:34:13"
  condition:
    hash.sha256(0, filesize) == "7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c"
}
```

### Sample 25: `7775a816832913ef`

| Field | Value |
|---|---|
| SHA-256 | `7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a` |
| Family label | `unknown` |
| File name | `7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a.exe` |
| File type | `exe` |
| First seen | `2026-09-11 01:34:09` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07f6161197a1e18cd8b81ad12e4ceb19` |
| SHA-1 | `25dc86e9721ef1cd5f03c28aa238c1852afb46fe` |
| SHA-256 | `7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a` |
| SHA3-384 | `2158a923e84196f04cd918c533f275eb1829d6578e31de3f37e3b6cdbbe9490beed3459b65181f5b25b164c7dfd244e3` |
| IMPHASH | `ac778398ab1370dcce0b55e5f48fff30` |
| TLSH | `T120D4F117BA7A02ECE42580778156DA33BB75F802039066EF13D81A4ABF5D5D84F3DE62` |
| SSDEEP | `12288:5Kz3AO49KRoSXPBWVvlOXATW3dGmXweWr7eqRNv:5Y3AOtTWZEXAi3d9w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_7775a816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a"
    family = "unknown"
    file_name = "7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:34:09"
  condition:
    hash.sha256(0, filesize) == "7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a"
}
```

### Sample 26: `7a99500e3e70175b`

| Field | Value |
|---|---|
| SHA-256 | `7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835` |
| Family label | `Mirai` |
| File name | `7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835.elf` |
| File type | `elf` |
| First seen | `2026-09-11 01:24:17` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `977c66f766665013bafbfb5dd0e0d5dc` |
| SHA-1 | `fe3e56d3d7c5daaba9eda545a7e311584a150468` |
| SHA-256 | `7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835` |
| SHA3-384 | `b1fe6f607bc7be02e173431a4bb22cf8c26e763565f564386041c4aa07b4e2a1bcb966e266938171760617ec0d1430fb` |
| TLSH | `T1AC833A91B981566EC6D063BFFA5E538D337563E8C2DE7213D9218B1133CA51F0A73A90` |
| TELFHASH | `t1aef08b04fe768e1948f29a71ccbd17a0d547522761a21720ef56cae0cc3e458f308d5d` |
| SSDEEP | `1536:nj6MGt7b7+WBDScgEKvJECHVgFrqQyjVz/aWmPzqIydFKW:jL27biWwcgEKvJEugkJra6cW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_7a99500e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835"
    family = "Mirai"
    file_name = "7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835.elf"
    file_type = "elf"
    first_seen = "2026-09-11 01:24:17"
  condition:
    hash.sha256(0, filesize) == "7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835"
}
```

### Sample 27: `920d4127eab982c9`

| Field | Value |
|---|---|
| SHA-256 | `920d4127eab982c98b0962ff09ef19f84bc10e6ca76c8d49993ce2fcb2d3474f` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-11 01:15:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4434ae8f83f91b8cfa6890a482d151b` |
| SHA-1 | `1458d18b4f9f57e2659f99198374a07ef290f7e4` |
| SHA-256 | `920d4127eab982c98b0962ff09ef19f84bc10e6ca76c8d49993ce2fcb2d3474f` |
| SHA3-384 | `a640fc25abe698c6e30137bf71ed0878222e89fdbd623d16d18de278981ad0c81c99f015bdd99593d19358c5aaff2dbb` |
| TLSH | `T1DAB23B91E7C3E0F7E88401FD1152D7516336F438216AFD4BEB2026BBB812921E757BA9` |
| TELFHASH | `t1d4f046c23daa01e8fa80fe4dd31f2a43db2a6ab8173570ef4cf5b20632c111481a141a` |
| SSDEEP | `384:fORoHGlOvCRVvpnzR3sGzBWl7uRI9BcwQZU8c1j9v4IFWkS+UGuyD:kYGlOvCRVvpnV3NAH9YU8cL4IFNStZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_920d4127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "920d4127eab982c98b0962ff09ef19f84bc10e6ca76c8d49993ce2fcb2d3474f"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-11 01:15:29"
  condition:
    hash.sha256(0, filesize) == "920d4127eab982c98b0962ff09ef19f84bc10e6ca76c8d49993ce2fcb2d3474f"
}
```

### Sample 28: `74109e2ad03f4b3d`

| Field | Value |
|---|---|
| SHA-256 | `74109e2ad03f4b3d057a41b8a720378d58405604c5e2d8828e15d601c5a0bd28` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-11 01:15:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46f4676e013a274bb23d82a3ca0c4d92` |
| SHA-1 | `4ee15ffe825e4de3dd6b83f87baf72b125e94564` |
| SHA-256 | `74109e2ad03f4b3d057a41b8a720378d58405604c5e2d8828e15d601c5a0bd28` |
| SHA3-384 | `e2c6c9f9723e064b7ca69d711e21c6762526cc46200704756fd49868534e490b908e2f8aa1d40679a6dc354e60b0ff2c` |
| TLSH | `T14D62C023956B07C0D75AC0390D7E7D8F2428B02CEA0C569ABB68357EC562F583D2CEC6` |
| SSDEEP | `384:M8ZeCivRadYdy/nfBD6AKzLxHgKK0VzANaNJawcudoD7UqkX0qWT+IC/:OCiEP5omKK0VHnbcuyD7UB8S/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_74109e2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74109e2ad03f4b3d057a41b8a720378d58405604c5e2d8828e15d601c5a0bd28"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-11 01:15:03"
  condition:
    hash.sha256(0, filesize) == "74109e2ad03f4b3d057a41b8a720378d58405604c5e2d8828e15d601c5a0bd28"
}
```

### Sample 29: `f9e7443abc9bae81`

| Field | Value |
|---|---|
| SHA-256 | `f9e7443abc9bae8168ac51896b9b1976d2884f8a076f983eb7f2214cfa28bd8a` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-11 01:15:01` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a16b359f59c4a43e687cd0bc7bf04f5c` |
| SHA-1 | `b10c2ad2125c20cb9490fbf01fb26a7c07f1a49f` |
| SHA-256 | `f9e7443abc9bae8168ac51896b9b1976d2884f8a076f983eb7f2214cfa28bd8a` |
| SHA3-384 | `9d918fe4c6a12694e41a486824342f3b42388a8e2966129b0a5779ab217669237e11ba7e95af883f45a7529d126e11b7` |
| TLSH | `T13AB23C91E7C3E0F7E88401FD1152D7516336F438216AFD4BEB2026BBB812921E757BA9` |
| TELFHASH | `t1d4f046c23daa01e8fa80fe4dd31f2a43db2a6ab8173570ef4cf5b20632c111481a141a` |
| SSDEEP | `384:fORoHGlOvCRVvpnzR3sGzBWl7uRI9BcwQZU8c1j9v4IFWkS+UGuyK:kYGlOvCRVvpnV3NAH9YU8cL4IFNStZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_f9e7443a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9e7443abc9bae8168ac51896b9b1976d2884f8a076f983eb7f2214cfa28bd8a"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-11 01:15:01"
  condition:
    hash.sha256(0, filesize) == "f9e7443abc9bae8168ac51896b9b1976d2884f8a076f983eb7f2214cfa28bd8a"
}
```

### Sample 30: `b0f048d712bec3be`

| Field | Value |
|---|---|
| SHA-256 | `b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5` |
| Family label | `VShell` |
| File name | `b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5.exe` |
| File type | `exe` |
| First seen | `2026-09-11 01:14:06` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `adf3339e1164aabe953eb446bebb4297` |
| SHA-1 | `e9c1cb357c83f83eecc77d5810bf8035d2cccbd0` |
| SHA-256 | `b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5` |
| SHA3-384 | `6707aaaaa5f08957ade8490a14c4425da7f5708a7bd1da5ebaf088443ebce96cad5e7fdb8fcf862b0524a2e0b1b21357` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T111716198F3136EF1E43C87F900D3A524D029ABBCC250BF4D5E60381E3C210BA265AF96` |
| SSDEEP | `48:6Icwm0ot2W0J8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jJt2SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_030_b0f048d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5"
    family = "VShell"
    file_name = "b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:14:06"
  condition:
    hash.sha256(0, filesize) == "b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5"
}
```

### Sample 31: `d74ee8bb9337b8dd`

| Field | Value |
|---|---|
| SHA-256 | `d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c` |
| Family label | `VShell` |
| File name | `d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c.exe` |
| File type | `exe` |
| First seen | `2026-09-11 01:10:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df3b60d22cf60a8b6d2343f1808ec011` |
| SHA-1 | `3cc0542bef21ecdcc29e238ac553def8f26cf5b4` |
| SHA-256 | `d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c` |
| SHA3-384 | `fe71b8c11c12821bb8e331f7cd566cd624847104601ffdb6fb385b54d1f6a589a0a2cc6dd3b93e72e94bda0e773ae0cb` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T19471B54160541AF2D98CA37F8487B896FD5FB248A2C80B0F0798981A2F7547BB0E9613` |
| SSDEEP | `48:6IZUBQYxZul2EywS6DD8jk7QLzgzIzQz4zAzo157D9N9XM/geu3ahr0/x:2BQMZ7EywS6DDG++D9vXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_031_d74ee8bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c"
    family = "VShell"
    file_name = "d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:10:47"
  condition:
    hash.sha256(0, filesize) == "d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c"
}
```

### Sample 32: `c887d8e750abfa03`

| Field | Value |
|---|---|
| SHA-256 | `c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d` |
| Family label | `VShell` |
| File name | `c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d.exe` |
| File type | `exe` |
| First seen | `2026-09-11 01:04:15` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87347b13b666b21111ce83ee33bd39f9` |
| SHA-1 | `9688a6055c89d168d0dbbcba6bfc52e7ce75f0e3` |
| SHA-256 | `c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d` |
| SHA3-384 | `3c43a4682c6107bd4a9773d93e085f298eefd70e26c0ac3aa979d28f4129d4c04673e0d983813ce5305bc233cf3183d2` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T141716198F3176EF1E82C87F940D3A624C0199BBCC150BF4D5E60381D3C220BA255AF97` |
| SSDEEP | `48:6Icwm0Zt2WCcJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jkt/SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_032_c887d8e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d"
    family = "VShell"
    file_name = "c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:04:15"
  condition:
    hash.sha256(0, filesize) == "c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d"
}
```

### Sample 33: `87fc39acdd817bf8`

| Field | Value |
|---|---|
| SHA-256 | `87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0` |
| Family label | `VShell` |
| File name | `87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:49:12` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e4de30bd3676c1320ed81abcad51c62` |
| SHA-1 | `453c0d4d78cb6324d46b4e26e611cdd56ca3fa6b` |
| SHA-256 | `87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0` |
| SHA3-384 | `c2f79ec7f9778f8aa5669da3d3b9cbf1e8d3bf3282f34cd1c5e285db1e3c95e52c3a4bd669c33ee39b6caae7752003a5` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T14091C64170B989E7E85C41BF4C0FB8A4B919740A41C483A60378A5953E3957BF5BCB0E` |
| SSDEEP | `48:6IIF9BlQaexNbgZS7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMNW70cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_033_87fc39ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0"
    family = "VShell"
    file_name = "87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:49:12"
  condition:
    hash.sha256(0, filesize) == "87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0"
}
```

### Sample 34: `f7015ee8de9f30f1`

| Field | Value |
|---|---|
| SHA-256 | `f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a` |
| Family label | `VShell` |
| File name | `f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:44:22` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b49dc04d598f9fc62237987bacaa3132` |
| SHA-1 | `2203f428d735dec8903520e518f97060c54731a0` |
| SHA-256 | `f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a` |
| SHA3-384 | `6cd683a142352602c28f6d8ad63e8b6ca4129754bd68ee5e4bc064979d8698e3fcb04bb11ae3db99953013cd951dfc70` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T10591A6C6F75BE6B2EC1C07F500A37994C8682E14927C9B464FA16F1C3C111AA3C3DA52` |
| SSDEEP | `48:6I7lwe77UR08SvJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1O09xq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_034_f7015ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a"
    family = "VShell"
    file_name = "f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:44:22"
  condition:
    hash.sha256(0, filesize) == "f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a"
}
```

### Sample 35: `b4cce37e7607ed6c`

| Field | Value |
|---|---|
| SHA-256 | `b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e` |
| Family label | `unknown` |
| File name | `b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:40:01` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ec9c3d03b34c967ba38800ddcf48bf4` |
| SHA-1 | `705a1cbda2008347d47f01e17d63a8067a34e6b4` |
| SHA-256 | `b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e` |
| SHA3-384 | `88c7526283558115b3e88850646a3030811cfad64e10969f4e3b14116056cde517069356be04736d5ada9d4e46de9890` |
| IMPHASH | `68dd933174a3195c69af3610ed1d5fdf` |
| TLSH | `T140F36B0BB3A524F9D177863988952606F77278321B218BEF0764077A6F332D19D3EB61` |
| SSDEEP | `3072:PGGsDWfHMjTrTXTrTnTrTRT7TnTpTbTHTeS0iThTNTfLqt+GoWtNCrOXMGgjJ+ZH:PG3DWfTOLqH9C4MGS/Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_b4cce37e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e"
    family = "unknown"
    file_name = "b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:40:01"
  condition:
    hash.sha256(0, filesize) == "b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e"
}
```

### Sample 36: `b48c831677227ef7`

| Field | Value |
|---|---|
| SHA-256 | `b48c831677227ef7465d3421b89748b6783d83e3f0eeaf5a918337faf8a05516` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-11 00:29:16` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `527949981b42190a2a90d446bf2bd03b` |
| SHA-1 | `3e2e5034c2eb9fb3c6d4a905460096fcea286d03` |
| SHA-256 | `b48c831677227ef7465d3421b89748b6783d83e3f0eeaf5a918337faf8a05516` |
| SHA3-384 | `849f7f31a42643ce8e1594394aacd7cbb110db9e488dfe84e52f926bed01495e6da50778e1cd97a81cf78a7a834101dc` |
| IMPHASH | `5af915f278815e76bad476ef32593028` |
| TLSH | `T1E6564B05FADB84F1E9132A3141AB621F263868084F39DB9BDF403E25EDB77D51C2674A` |
| SSDEEP | `49152:BO34iPobSgCkAwlVjKPNqFhHupWiIKHNEHVy+iz7FJeOeRQ4sSZGiTqRuYFfeMoI:B9iPKSgCbuKWqNRp0bP9PYahyZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_b48c8316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48c831677227ef7465d3421b89748b6783d83e3f0eeaf5a918337faf8a05516"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 00:29:16"
  condition:
    hash.sha256(0, filesize) == "b48c831677227ef7465d3421b89748b6783d83e3f0eeaf5a918337faf8a05516"
}
```

### Sample 37: `169298ed649518bb`

| Field | Value |
|---|---|
| SHA-256 | `169298ed649518bbc5a2dde2ee10ec51d034c34d3363b83e3aae0f66561e85c2` |
| Family label | `unknown` |
| File name | `Betalernes.vbs` |
| File type | `vbs` |
| First seen | `2026-09-11 00:24:29` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8e8f6de9e21baf1a7ab84472ec117ce` |
| SHA-1 | `1b40e51d6f6ada80b667d80fb508dac574df63e9` |
| SHA-256 | `169298ed649518bbc5a2dde2ee10ec51d034c34d3363b83e3aae0f66561e85c2` |
| SHA3-384 | `fa5e0b070fd9ca925c13153eacc6b21c668fa4861216f693189059f348d22ee07246b2ee16c53cc951630d85d984183c` |
| TLSH | `T106720898DF415268A9074BF28C4FD576CA705AEA78220470AFACF1681D56B4C3A7C1FF` |
| SSDEEP | `384:d4mJm70JVdffzoFpHzkcqCNhVfgfIf6f7fshfbFfXfwfEf7zfyftzf9zfFzfsnf4:dZ5VdXwTpFIwiTshpPYs7L6tL9LFLsf4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_169298ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "169298ed649518bbc5a2dde2ee10ec51d034c34d3363b83e3aae0f66561e85c2"
    family = "unknown"
    file_name = "Betalernes.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 00:24:29"
  condition:
    hash.sha256(0, filesize) == "169298ed649518bbc5a2dde2ee10ec51d034c34d3363b83e3aae0f66561e85c2"
}
```

### Sample 38: `829fb6a87053a889`

| Field | Value |
|---|---|
| SHA-256 | `829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9` |
| Family label | `ConnectWise` |
| File name | `829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:24:15` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6482f22ccd7de1105396b98008a4965` |
| SHA-1 | `705f1cfdf7aba701397699fef33e9286fb2bd987` |
| SHA-256 | `829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9` |
| SHA3-384 | `965825131d1813ff0139b3b1fc4f50adbeb7e364f523224cd2468c60865f58658f5df1681537a5dec1daadab16712c5b` |
| IMPHASH | `9771ee6344923fa220489ab01239bdfd` |
| TLSH | `T11046E111B3DA95B9D4BF063CD87A82699A74BC044712C7EF53D4BD2D2D32BC05A323A6` |
| SSDEEP | `49152:sEEL5cx5xTkYJkGYYpT0+TFiH7efP8Q1yJJ4ZD1F5z97oL1YbGQ+okRPGHpRPqM8:FEs6efPNwJ4t1h0cG5FGJRPxow8O` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_038_829fb6a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9"
    family = "ConnectWise"
    file_name = "829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:24:15"
  condition:
    hash.sha256(0, filesize) == "829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9"
}
```

### Sample 39: `f70398b06589c320`

| Field | Value |
|---|---|
| SHA-256 | `f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28` |
| Family label | `unknown` |
| File name | `f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:15:50` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `63f6c349537789272bebc8eaa6c1ed00` |
| SHA-256 | `f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_f70398b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28"
    family = "unknown"
    file_name = "f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:15:50"
  condition:
    hash.sha256(0, filesize) == "f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28"
}
```

### Sample 40: `c1f252ac1e2eb746`

| Field | Value |
|---|---|
| SHA-256 | `c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329` |
| Family label | `unknown` |
| File name | `c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:15:32` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `629f126adaf289bfef54e8b42a3c4ec2` |
| SHA-256 | `c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_c1f252ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329"
    family = "unknown"
    file_name = "c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:15:32"
  condition:
    hash.sha256(0, filesize) == "c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329"
}
```

### Sample 41: `a92c33568de0e5cd`

| Field | Value |
|---|---|
| SHA-256 | `a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287` |
| Family label | `unknown` |
| File name | `a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:15:15` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2348fae7990e48debf9227cc3372386` |
| SHA-256 | `a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_a92c3356
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287"
    family = "unknown"
    file_name = "a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:15:15"
  condition:
    hash.sha256(0, filesize) == "a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287"
}
```

### Sample 42: `197ca9f27aeb1c65`

| Field | Value |
|---|---|
| SHA-256 | `197ca9f27aeb1c6552140113bd0040d14668c26f0eedb53de97fbe85adbfffeb` |
| Family label | `unknown` |
| File name | `Lovgivendes.vbs` |
| File type | `vbs` |
| First seen | `2026-09-11 00:15:14` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7e3cc59a5f7a4d2f609ed017f13975b` |
| SHA-1 | `65205083bc8a7f45f36c120f4afdd2648cdc4d68` |
| SHA-256 | `197ca9f27aeb1c6552140113bd0040d14668c26f0eedb53de97fbe85adbfffeb` |
| SHA3-384 | `05048ee0a198f7bb10de6f8f66ca0bef4bbd7e071ed01eebc1a5deb32214c32d36f140240aa18a4f714177806206868f` |
| TLSH | `T1E1821BA19C611B35840B97E6FA4B01358D7510A6F4122636EFECF92B4C1630CE67F7A7` |
| SSDEEP | `384:YcR1KpHzsK9bErMlui02JJs+risHw8cMpOx/nl7s:jR1kTn9bErtsuoPHKMANni` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_197ca9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197ca9f27aeb1c6552140113bd0040d14668c26f0eedb53de97fbe85adbfffeb"
    family = "unknown"
    file_name = "Lovgivendes.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 00:15:14"
  condition:
    hash.sha256(0, filesize) == "197ca9f27aeb1c6552140113bd0040d14668c26f0eedb53de97fbe85adbfffeb"
}
```

### Sample 43: `a7aaea314591d777`

| Field | Value |
|---|---|
| SHA-256 | `a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3` |
| Family label | `unknown` |
| File name | `a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:14:57` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `121ce46a6e2f454809edf81f18636cb4` |
| SHA-256 | `a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_a7aaea31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3"
    family = "unknown"
    file_name = "a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:57"
  condition:
    hash.sha256(0, filesize) == "a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3"
}
```

### Sample 44: `7c003fcb8152be89`

| Field | Value |
|---|---|
| SHA-256 | `7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca` |
| Family label | `unknown` |
| File name | `7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:14:40` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a385e633d997801ba760f0020fb06db` |
| SHA-256 | `7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_7c003fcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca"
    family = "unknown"
    file_name = "7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:40"
  condition:
    hash.sha256(0, filesize) == "7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca"
}
```

### Sample 45: `63a406d6fb2be220`

| Field | Value |
|---|---|
| SHA-256 | `63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5` |
| Family label | `VShell` |
| File name | `63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:14:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb7a3fb8202da12514db46a222fc7490` |
| SHA-1 | `5a6003d5510e5959f4086c98279ee2869e58d06c` |
| SHA-256 | `63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5` |
| SHA3-384 | `28540edd716b1d2f5dde826a290cd3a2590f112de6812b6319a4620ece161cbb0cab4745c296491c25cfade7a1ec7250` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T106715198F3176EF5E43C46F940D3A564D059ABBCC250BF8D5E60381D3C210BA255AFA7` |
| SSDEEP | `48:6Icwm0szt2WuJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jXtcSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_045_63a406d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5"
    family = "VShell"
    file_name = "63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:14:38"
  condition:
    hash.sha256(0, filesize) == "63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5"
}
```

### Sample 46: `9ce8e6ed0c77eb57`

| Field | Value |
|---|---|
| SHA-256 | `9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0` |
| Family label | `VShell` |
| File name | `9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:14:35` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `300b699cdcb734370f72331d7dec4444` |
| SHA-1 | `fe200c27f17fc8b772c9f40ada913d43bd8378bc` |
| SHA-256 | `9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0` |
| SHA3-384 | `ce5559852c130b22562ec106c36811db5c89d04adc025dbfb3923e126d019482b9ef8c26f415593d7257308d895916cf` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1BE91D64170B988E7E85C41BF4C0FB8A0B919780A41C483A60338A5953F3A57BF07CB0D` |
| SSDEEP | `48:6IIF9BlQaex3gZ17An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMaC0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_046_9ce8e6ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0"
    family = "VShell"
    file_name = "9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:14:35"
  condition:
    hash.sha256(0, filesize) == "9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0"
}
```

### Sample 47: `6e0d6c8d02bbb95a`

| Field | Value |
|---|---|
| SHA-256 | `6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c` |
| Family label | `unknown` |
| File name | `6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:14:23` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6646985db5aa572608d2b77003c6982` |
| SHA-256 | `6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_6e0d6c8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c"
    family = "unknown"
    file_name = "6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:23"
  condition:
    hash.sha256(0, filesize) == "6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c"
}
```

### Sample 48: `55a6247650a59791`

| Field | Value |
|---|---|
| SHA-256 | `55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a` |
| Family label | `unknown` |
| File name | `55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:14:06` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02e97d22a0565be9452931627c2cc2f1` |
| SHA-256 | `55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_55a62476
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a"
    family = "unknown"
    file_name = "55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:06"
  condition:
    hash.sha256(0, filesize) == "55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a"
}
```

### Sample 49: `41d5d05ebc7d59fd`

| Field | Value |
|---|---|
| SHA-256 | `41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1` |
| Family label | `unknown` |
| File name | `41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:13:48` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bf2203e6d76141a07fd48a23355e838` |
| SHA-256 | `41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_41d5d05e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1"
    family = "unknown"
    file_name = "41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:13:48"
  condition:
    hash.sha256(0, filesize) == "41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1"
}
```

### Sample 50: `37f56fd97af1e3bb`

| Field | Value |
|---|---|
| SHA-256 | `37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f` |
| Family label | `unknown` |
| File name | `37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:13:31` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa7f3de390290568c321fb60340e8e07` |
| SHA-256 | `37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_37f56fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f"
    family = "unknown"
    file_name = "37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:13:31"
  condition:
    hash.sha256(0, filesize) == "37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f"
}
```

### Sample 51: `2a2c3fec2bab0b2c`

| Field | Value |
|---|---|
| SHA-256 | `2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503` |
| Family label | `unknown` |
| File name | `2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:13:13` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbc27a59eba57311aa78c0f1ddf6c3db` |
| SHA-256 | `2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_2a2c3fec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503"
    family = "unknown"
    file_name = "2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:13:13"
  condition:
    hash.sha256(0, filesize) == "2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503"
}
```

### Sample 52: `12edefda13664060`

| Field | Value |
|---|---|
| SHA-256 | `12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6` |
| Family label | `unknown` |
| File name | `12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:12:56` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4875a6f46e45be846376d65181023275` |
| SHA-256 | `12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_12edefda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6"
    family = "unknown"
    file_name = "12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:12:56"
  condition:
    hash.sha256(0, filesize) == "12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6"
}
```

### Sample 53: `021b737b3e5ae81c`

| Field | Value |
|---|---|
| SHA-256 | `021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062` |
| Family label | `unknown` |
| File name | `021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062.bin` |
| File type | `unknown` |
| First seen | `2026-09-11 00:12:39` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd88b8c4f2d415147351e284e675bf87` |
| SHA-256 | `021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_021b737b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062"
    family = "unknown"
    file_name = "021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:12:39"
  condition:
    hash.sha256(0, filesize) == "021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062"
}
```

### Sample 54: `f016a21e0132c742`

| Field | Value |
|---|---|
| SHA-256 | `f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d` |
| Family label | `unknown` |
| File name | `f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d` |
| File type | `elf` |
| First seen | `2026-09-11 00:10:04` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f396b7009fcc1b377c4813e728cbe8c` |
| SHA-1 | `bcf6f06eefb33a2ce014628dd7031b48738064ed` |
| SHA-256 | `f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d` |
| SHA3-384 | `28418e9371f1df85e9fc892e791f5c3d19f8fa50d864fb2be5f823e5439821135ebf04410e23cb4a8d730fafa5f62c99` |
| TLSH | `T1C8866C73945624D8E1ADC974D5141213BEA8388B573863CBBBC476F51BBABE48E78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQl:cqYUQuVDt0TZEq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_f016a21e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d"
    family = "unknown"
    file_name = "f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d"
    file_type = "elf"
    first_seen = "2026-09-11 00:10:04"
  condition:
    hash.sha256(0, filesize) == "f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d"
}
```

### Sample 55: `e60b08b9f64d2d74`

| Field | Value |
|---|---|
| SHA-256 | `e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab` |
| Family label | `njrat` |
| File name | `e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:09:52` |
| Reporter | `Tuxxin` |
| Tags | `exe, njrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b92ad12a0b36a8c392f357686772df1` |
| SHA-1 | `c9b310129dfd8ca8fbe110012ebb62282b8e3360` |
| SHA-256 | `e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab` |
| SHA3-384 | `9fac176488fd069314b2ce60aca1e5bff8885ece56fb7743ded1c33c2b4cbaaaf549fb6692dadef5efed39bec6ed64e1` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T19B735C4FFB15C588C3AD4F7B85A3544443ADE8A76427E77B24CC0EE16E228D8894FD49` |
| SSDEEP | `1536:vTAY30YyLQ/xemN62NzLlQihEcwlUqq4Nxa2VbVev4RQ:d3dfewLnktHxpVbVevr` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_055_e60b08b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab"
    family = "njrat"
    file_name = "e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:09:52"
  condition:
    hash.sha256(0, filesize) == "e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab"
}
```

### Sample 56: `6ae3d6fb2cf1eba4`

| Field | Value |
|---|---|
| SHA-256 | `6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d` |
| Family label | `VShell` |
| File name | `6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:09:47` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24d322d5cec845a830bfbadc3b172ee2` |
| SHA-1 | `76e3115fd46ab158cd1b5005ee5a44a54823b370` |
| SHA-256 | `6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d` |
| SHA3-384 | `e8a6a8b05716c785fc0f9160c9a2fcb45993fd407a785298ce6be16d532e82e9de0a61612af6a45200024f4f2f8f9c93` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1E391C5C5F757E6B2EC1C07F600A379A4C4682E14827C9B464FE16F0C3C111AA3D3EA12` |
| SSDEEP | `48:6I7lwe7AIG08SLJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1C091q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_056_6ae3d6fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d"
    family = "VShell"
    file_name = "6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:09:47"
  condition:
    hash.sha256(0, filesize) == "6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d"
}
```

### Sample 57: `aa75d6c809b96790`

| Field | Value |
|---|---|
| SHA-256 | `aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e` |
| Family label | `VShell` |
| File name | `aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e.exe` |
| File type | `exe` |
| First seen | `2026-09-11 00:09:43` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4aad73caa05337c716f32a9455d3e58c` |
| SHA-1 | `e9f19ce41262150926381604f0f1a296eb74724c` |
| SHA-256 | `aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e` |
| SHA3-384 | `e8ddc4143933568205d9c86c4fa70bf128af5403c7e8baad717994042451309610f70af8c0e647f16f049dfacfcb415a` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1B991A5C5F75BE6B6EC1C17F500A3B9A4C4682E18827C9B464FA16F0C3C111AA3D3EA12` |
| SSDEEP | `48:6I7lwe7Oi08SKJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1/09kq1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_057_aa75d6c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e"
    family = "VShell"
    file_name = "aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:09:43"
  condition:
    hash.sha256(0, filesize) == "aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e"
}
```

### Sample 58: `49bfdba40d37aa9d`

| Field | Value |
|---|---|
| SHA-256 | `49bfdba40d37aa9dcbd98d64744bbd1ce30a52527a2c4501dffe83c67ccc04e7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-10 23:48:40` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `821780151635ac80458a71eeedcd7c75` |
| SHA-1 | `bd25d99c9fc40862ebccd469d9d725a689ac963e` |
| SHA-256 | `49bfdba40d37aa9dcbd98d64744bbd1ce30a52527a2c4501dffe83c67ccc04e7` |
| SHA3-384 | `fcc32cf2c36341af28eb8b25d7e3d32dd902f3594cd1056f891a302007e0a08dcb5707e76e312a16392a3324fc91f190` |
| IMPHASH | `2ec3493fee0a968668bc5969e1a514cb` |
| TLSH | `T17D95128EEA9506F6D57DD5B880125602BFA17C220B60DFDB27112D722E63BE89F3C711` |
| SSDEEP | `49152:8a7SbC6peJ/0JzQzmoTCRq98h2Vvbzi51WDOxTY3AjDX:KApCsRDe/WSxT2y` |
| ICON-DHASH | `f0f89a9a9adcf830` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_49bfdba4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49bfdba40d37aa9dcbd98d64744bbd1ce30a52527a2c4501dffe83c67ccc04e7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-10 23:48:40"
  condition:
    hash.sha256(0, filesize) == "49bfdba40d37aa9dcbd98d64744bbd1ce30a52527a2c4501dffe83c67ccc04e7"
}
```

### Sample 59: `57825a9b5cb3a9fa`

| Field | Value |
|---|---|
| SHA-256 | `57825a9b5cb3a9fae14a4ed1338fb5e18d09522083ebc59079a4426b90deb078` |
| Family label | `unknown` |
| File name | `b` |
| File type | `unknown` |
| First seen | `2026-09-10 23:11:25` |
| Reporter | `monitorsg` |
| Tags | `KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a008422b327c96d1862c40757cfa48cd` |
| SHA-256 | `57825a9b5cb3a9fae14a4ed1338fb5e18d09522083ebc59079a4426b90deb078` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_57825a9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57825a9b5cb3a9fae14a4ed1338fb5e18d09522083ebc59079a4426b90deb078"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 23:11:25"
  condition:
    hash.sha256(0, filesize) == "57825a9b5cb3a9fae14a4ed1338fb5e18d09522083ebc59079a4426b90deb078"
}
```

### Sample 60: `95e59654363348b1`

| Field | Value |
|---|---|
| SHA-256 | `95e59654363348b1a8a938a540bbb5c3568b7f4fe8889981df11ba336e684c70` |
| Family label | `Mirai` |
| File name | `titan.sh4` |
| File type | `elf` |
| First seen | `2026-09-10 23:03:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `612c3173dccd3edbb71bb2f249bf226f` |
| SHA-1 | `d7f50858d64f389c80d8c13db97ce350fff66e58` |
| SHA-256 | `95e59654363348b1a8a938a540bbb5c3568b7f4fe8889981df11ba336e684c70` |
| SHA3-384 | `af182fb546e997655555d75d2e3faf29984055bb2d1008055089f367e26e7979d9e6e9273c07a55f28ce591a79f10534` |
| TLSH | `T1FD144997F1129D81F14206F4216CC7F03F12A5E723372D91E9BB82F99B538AA7C15B62` |
| SSDEEP | `3072:CAAl2uYRkzR5Op3zzLw7D+DNXC8a1WUq:Cn2uK/p3PLwX+DNS8WWUq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_95e59654
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95e59654363348b1a8a938a540bbb5c3568b7f4fe8889981df11ba336e684c70"
    family = "Mirai"
    file_name = "titan.sh4"
    file_type = "elf"
    first_seen = "2026-09-10 23:03:31"
  condition:
    hash.sha256(0, filesize) == "95e59654363348b1a8a938a540bbb5c3568b7f4fe8889981df11ba336e684c70"
}
```

### Sample 61: `3a2ffd6778cb05e0`

| Field | Value |
|---|---|
| SHA-256 | `3a2ffd6778cb05e07f29548115ce05a6fb517da58859ae21a6a9da13a225dbb8` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-10 22:57:01` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44dc43b7e215a2c2461e0550422b94ab` |
| SHA-256 | `3a2ffd6778cb05e07f29548115ce05a6fb517da58859ae21a6a9da13a225dbb8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_3a2ffd67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2ffd6778cb05e07f29548115ce05a6fb517da58859ae21a6a9da13a225dbb8"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-10 22:57:01"
  condition:
    hash.sha256(0, filesize) == "3a2ffd6778cb05e07f29548115ce05a6fb517da58859ae21a6a9da13a225dbb8"
}
```

### Sample 62: `120016439fae62b7`

| Field | Value |
|---|---|
| SHA-256 | `120016439fae62b789b9fa9ffb92c5ce101eeb39a2a463375b35399d0772bafc` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-10 22:52:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d27d6a3c3b8d3a73be15e7edf428aa19` |
| SHA-1 | `717d5d949e7c63d4026ea162bcbbc19645806ce7` |
| SHA-256 | `120016439fae62b789b9fa9ffb92c5ce101eeb39a2a463375b35399d0772bafc` |
| SHA3-384 | `5158b2f5af7311f133a72609c3fda86b734eb4eb150c472ea872ee6557c7bff9371b0f868de3b05dbb98c468ca64159b` |
| TLSH | `T18B235C6516857C24AE98C4361C7E2F0CB9AD43E6324452EE7FCF3CF68C4A6AD910971D` |
| SSDEEP | `768:4+H9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:4+wcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_12001643
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "120016439fae62b789b9fa9ffb92c5ce101eeb39a2a463375b35399d0772bafc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-10 22:52:29"
  condition:
    hash.sha256(0, filesize) == "120016439fae62b789b9fa9ffb92c5ce101eeb39a2a463375b35399d0772bafc"
}
```

### Sample 63: `34c917a284c6c118`

| Field | Value |
|---|---|
| SHA-256 | `34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620` |
| Family label | `Mirai` |
| File name | `titan.x32` |
| File type | `elf` |
| First seen | `2026-09-10 22:48:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09641b8345d7160683e3b7cfeb83c2e0` |
| SHA-1 | `a098331db2d5267fa05ea6bbdfb886d0a1172536` |
| SHA-256 | `34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620` |
| SHA3-384 | `5c321fbb6eafd4f4cf61f2b2abd45cfd8688830d7d7020abebaa59ec790e7c121b184be67ff4f2fd9f11ff27de8621de` |
| TLSH | `T1BC243A0EF902D8F1F07291F1068ED3E17D30A4F75237AD62EF6B2AB1BA272915D05259` |
| TELFHASH | `t15d618bf76e7e19e973d09d0ad20b2f21ee2ed737246031a205f2076032bbd415166c39` |
| SSDEEP | `6144:/xITIUbZDsSj+U4DnKayMU4QeMsbYH8cxNkqejKa:0ZDsSj+U1a44QHsbYH8czkx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_34c917a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620"
    family = "Mirai"
    file_name = "titan.x32"
    file_type = "elf"
    first_seen = "2026-09-10 22:48:58"
  condition:
    hash.sha256(0, filesize) == "34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620"
}
```

### Sample 64: `c87f3de339e04c47`

| Field | Value |
|---|---|
| SHA-256 | `c87f3de339e04c475797bd29a1505ca69cc3ddd1d9fc3639847bd9bb1cd973fe` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-10 22:25:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e33b9f16cbba4af3d5198a2331621533` |
| SHA-1 | `36af69935607bbbf278a177bf53584fd2a8c37ba` |
| SHA-256 | `c87f3de339e04c475797bd29a1505ca69cc3ddd1d9fc3639847bd9bb1cd973fe` |
| SHA3-384 | `083321952271a30256f8054a08a28277db68ff38e316046c203c5db25bf0d63d6fe364760b595a67bf19ac9e3b05f6ac` |
| TLSH | `T196C26D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11FACD618B1A` |
| SSDEEP | `768:b8vCB+25j6es8Rb9FYpMSUpi+20qUpi+20YQX:b8l25Jtd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_c87f3de3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c87f3de339e04c475797bd29a1505ca69cc3ddd1d9fc3639847bd9bb1cd973fe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-10 22:25:39"
  condition:
    hash.sha256(0, filesize) == "c87f3de339e04c475797bd29a1505ca69cc3ddd1d9fc3639847bd9bb1cd973fe"
}
```

### Sample 65: `bf98d3c0dfd79f8a`

| Field | Value |
|---|---|
| SHA-256 | `bf98d3c0dfd79f8a433876fd9b9148cb95bc8a1254e7c1bda6ba4c0c66cbf00f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-10 22:00:00` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9acf1e7234a8fa8a86841540b80250f2` |
| SHA-1 | `575b707cefea1a2f1621da51f6bf164ca9eb4b72` |
| SHA-256 | `bf98d3c0dfd79f8a433876fd9b9148cb95bc8a1254e7c1bda6ba4c0c66cbf00f` |
| SHA3-384 | `f8ee4c9817c9de284db1cba6b8ed2f30239329e818bdee53264d3f3093d45a71a22a9187d64c16334a265b7326b688c3` |
| TLSH | `T109C28E966A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C71DC11F9CD618B1A` |
| SSDEEP | `768:P8vCB+25j6es8Ry9FYpMSUpi+20qUpi+20YQX:P8l25JUd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_bf98d3c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf98d3c0dfd79f8a433876fd9b9148cb95bc8a1254e7c1bda6ba4c0c66cbf00f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-10 22:00:00"
  condition:
    hash.sha256(0, filesize) == "bf98d3c0dfd79f8a433876fd9b9148cb95bc8a1254e7c1bda6ba4c0c66cbf00f"
}
```

### Sample 66: `a0728a70bf9817b0`

| Field | Value |
|---|---|
| SHA-256 | `a0728a70bf9817b016d28e65090293e3fcd99825db92fc91044f985a479de885` |
| Family label | `Mirai` |
| File name | `titan.ppc440` |
| File type | `elf` |
| First seen | `2026-09-10 21:46:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ba80e4df83a57d126745a384576291e` |
| SHA-1 | `893674ef47be7ea540b6e2050d120ce0546b153a` |
| SHA-256 | `a0728a70bf9817b016d28e65090293e3fcd99825db92fc91044f985a479de885` |
| SHA3-384 | `a2cf8a30c7dd2b17f5394e76f0f5aaa0384277b120a3cc62c28d6c05de614c680605cc2e65f3d1080fc4436274794d6a` |
| TLSH | `T1C0444C02F7050962F5420DB05A7F07E6FFA140C305B5A80E5A0F97DA1B339BAE5D7BA9` |
| SSDEEP | `6144:bhS7LU9biCSwzaJySCWJDSyIeiOdEk8VsK0a:bhCwFiyZ+8GKl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_a0728a70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0728a70bf9817b016d28e65090293e3fcd99825db92fc91044f985a479de885"
    family = "Mirai"
    file_name = "titan.ppc440"
    file_type = "elf"
    first_seen = "2026-09-10 21:46:37"
  condition:
    hash.sha256(0, filesize) == "a0728a70bf9817b016d28e65090293e3fcd99825db92fc91044f985a479de885"
}
```

### Sample 67: `98f66f2bb6de3fb7`

| Field | Value |
|---|---|
| SHA-256 | `98f66f2bb6de3fb755ceac5b1a38fd3e45ad1727e825e7b11865dc67f4a00bf0` |
| Family label | `Mirai` |
| File name | `dbg` |
| File type | `elf` |
| First seen | `2026-09-10 21:37:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0acf0c3f21d5272e3fc74fd3bf7b3df3` |
| SHA-1 | `d68e1b339bc148d04ff7d23b05b1727908fbd3d3` |
| SHA-256 | `98f66f2bb6de3fb755ceac5b1a38fd3e45ad1727e825e7b11865dc67f4a00bf0` |
| SHA3-384 | `0a19ea54b799c6fc17d5ea0345f683e5252f54988a350be78aab6ac6ce1b5afd40f9a44da3ebf62062678980a1364374` |
| TLSH | `T159357D1AF2B3B0BCD057C03043AFDBA2A835F47912216D7B36C496352D66DA01B69F67` |
| TELFHASH | `t194a1efb04ee939b0a7d2e511b351f975aeb618f212f436f11a276dc4edd0f800ca582e` |
| SSDEEP | `12288:b8u5t7NeFJY7LPHwS07xM4N2wsG/zt0ydNsmyYbiUphB5k:b8qt7NeF6fwS07xM44wj/z1dF3ph` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_98f66f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98f66f2bb6de3fb755ceac5b1a38fd3e45ad1727e825e7b11865dc67f4a00bf0"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-09-10 21:37:33"
  condition:
    hash.sha256(0, filesize) == "98f66f2bb6de3fb755ceac5b1a38fd3e45ad1727e825e7b11865dc67f4a00bf0"
}
```

### Sample 68: `81905a4e04a59b22`

| Field | Value |
|---|---|
| SHA-256 | `81905a4e04a59b225dd0437cc23804a2f417fe760e0b3b320beaa07d23bd9daa` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-10 21:29:32` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41cb3fd19959a59f8e8700374aa06575` |
| SHA-1 | `2f77ab162fe5eb261f6eaa633e35723e6610ff9c` |
| SHA-256 | `81905a4e04a59b225dd0437cc23804a2f417fe760e0b3b320beaa07d23bd9daa` |
| SHA3-384 | `c79e8efe219392bc495ac5b26c17e6279d19e80c9ffe42d0597899e5b073100ba4ba045b05481a23feac98100e84a916` |
| TLSH | `T106236C651A957C149E98C4371D7E2F0CB9AD43E6320452EE7FCB3CF28C8AA9D920971D` |
| SSDEEP | `768:kVEJVIhtMs9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:6EJ2MBcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_81905a4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81905a4e04a59b225dd0437cc23804a2f417fe760e0b3b320beaa07d23bd9daa"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-10 21:29:32"
  condition:
    hash.sha256(0, filesize) == "81905a4e04a59b225dd0437cc23804a2f417fe760e0b3b320beaa07d23bd9daa"
}
```

### Sample 69: `93488f440d49aa01`

| Field | Value |
|---|---|
| SHA-256 | `93488f440d49aa01f7af8c85bb5b379a9d678030c0577a95b3e8f6499b4f3709` |
| Family label | `unknown` |
| File name | `goodthingsforbestpersonforme.hta` |
| File type | `hta` |
| First seen | `2026-09-10 21:27:33` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de37abcbc25e7990e9d45513766a7548` |
| SHA-1 | `80ccf4a79090420723c4835badb8a4368b643972` |
| SHA-256 | `93488f440d49aa01f7af8c85bb5b379a9d678030c0577a95b3e8f6499b4f3709` |
| SHA3-384 | `2dd9414defb5290c5afaf0afd8e522fca02da5b2b3b94c778989c6bb11c5b695b7506d975540291559445999ae947f46` |
| TLSH | `T1E9F05C4184E0891A523016142EC0F9095E96EA474349AE4C76AA50B91FC47C1CDCF47C` |
| SSDEEP | `6:qTIuJzhqIwGiY63fAbplilAl3t11/+SR0AqIbR2AWHwlJCSdNV4LKTjawlJdGnFa:qTp0JYyg9193R5qsPWKrVyqAEd2QL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_93488f44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93488f440d49aa01f7af8c85bb5b379a9d678030c0577a95b3e8f6499b4f3709"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-09-10 21:27:33"
  condition:
    hash.sha256(0, filesize) == "93488f440d49aa01f7af8c85bb5b379a9d678030c0577a95b3e8f6499b4f3709"
}
```

### Sample 70: `186a6db335efde57`

| Field | Value |
|---|---|
| SHA-256 | `186a6db335efde574d407a28c95d28b52508bca07f3214f44f136b336fd9436c` |
| Family label | `unknown` |
| File name | `vywerrzo27.hta` |
| File type | `unknown` |
| First seen | `2026-09-10 21:19:33` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bcf1f53ea55b1e2fcea94fff31a7e49d` |
| SHA-256 | `186a6db335efde574d407a28c95d28b52508bca07f3214f44f136b336fd9436c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_186a6db3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "186a6db335efde574d407a28c95d28b52508bca07f3214f44f136b336fd9436c"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-10 21:19:33"
  condition:
    hash.sha256(0, filesize) == "186a6db335efde574d407a28c95d28b52508bca07f3214f44f136b336fd9436c"
}
```

### Sample 71: `279fa88c40a4d003`

| Field | Value |
|---|---|
| SHA-256 | `279fa88c40a4d0036aef618c8a445f5936727418835394908db0f1b4507d89ff` |
| Family label | `unknown` |
| File name | `b` |
| File type | `unknown` |
| First seen | `2026-09-10 21:07:42` |
| Reporter | `monitorsg` |
| Tags | `KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bba36a55af9a7cebd6a3e58b57fb971` |
| SHA-256 | `279fa88c40a4d0036aef618c8a445f5936727418835394908db0f1b4507d89ff` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_279fa88c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "279fa88c40a4d0036aef618c8a445f5936727418835394908db0f1b4507d89ff"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 21:07:42"
  condition:
    hash.sha256(0, filesize) == "279fa88c40a4d0036aef618c8a445f5936727418835394908db0f1b4507d89ff"
}
```

### Sample 72: `f840ab670cff8c5a`

| Field | Value |
|---|---|
| SHA-256 | `f840ab670cff8c5a85b52a8133ad961aa8863abca0bcb1f12de1012e48d38dfb` |
| Family label | `MassLogger` |
| File name | `Debit note#202490304-01.exe` |
| File type | `exe` |
| First seen | `2026-09-10 20:46:19` |
| Reporter | `James_inthe_box` |
| Tags | `exe, MassLogger` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `666cccdaddeff034a642409aa45e151c` |
| SHA-1 | `ae586e9673adf898850a2eb2b1d2c9d55d0aefb2` |
| SHA-256 | `f840ab670cff8c5a85b52a8133ad961aa8863abca0bcb1f12de1012e48d38dfb` |
| SHA3-384 | `d8753b665661eadc0e17ce6fa7121e0c22112e55a92feee6786d60c76112466d50132411d2fec2e4ab8fbe82595e15dd` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13C15F1982626E707C9A497B80A31E7B427B92EDAB910D3065FDA7EEF7875F110C04353` |
| SSDEEP | `24576:DRVqj0qdPVKtqKwoZyo802t3VtwlOl4ZP8c:1M2qYZ3802t3DwEl4ZE` |

#### Technical Assessment

- The sample is tracked as `MassLogger` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MassLogger_072_f840ab67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f840ab670cff8c5a85b52a8133ad961aa8863abca0bcb1f12de1012e48d38dfb"
    family = "MassLogger"
    file_name = "Debit note#202490304-01.exe"
    file_type = "exe"
    first_seen = "2026-09-10 20:46:19"
  condition:
    hash.sha256(0, filesize) == "f840ab670cff8c5a85b52a8133ad961aa8863abca0bcb1f12de1012e48d38dfb"
}
```

### Sample 73: `ca8104bc7a7ec934`

| Field | Value |
|---|---|
| SHA-256 | `ca8104bc7a7ec934e700a7d9b0e7a3e4b22fb4495d036f1b6463d7c6c54211d5` |
| Family label | `unknown` |
| File name | `b` |
| File type | `unknown` |
| First seen | `2026-09-10 20:08:00` |
| Reporter | `monitorsg` |
| Tags | `KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fedce70eae7fe81ef488d3a6aa54856d` |
| SHA-256 | `ca8104bc7a7ec934e700a7d9b0e7a3e4b22fb4495d036f1b6463d7c6c54211d5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_ca8104bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca8104bc7a7ec934e700a7d9b0e7a3e4b22fb4495d036f1b6463d7c6c54211d5"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 20:08:00"
  condition:
    hash.sha256(0, filesize) == "ca8104bc7a7ec934e700a7d9b0e7a3e4b22fb4495d036f1b6463d7c6c54211d5"
}
```

### Sample 74: `d66895d8da6d5eb1`

| Field | Value |
|---|---|
| SHA-256 | `d66895d8da6d5eb1d8658647c80f66dce40236c06bb600f1c62a44a657f923b3` |
| Family label | `unknown` |
| File name | `SafeWatch.msix` |
| File type | `zip` |
| First seen | `2026-09-10 19:42:19` |
| Reporter | `Tuxxin` |
| Tags | `browser-hijacker, msix, PhantomJack, PseudoJack, PseudoTDS, signed, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e15214cda228ab5c255a8a683b04bdf1` |
| SHA-1 | `6ddd7814b479b4373d44ac12e8c7b4181ecbce8b` |
| SHA-256 | `d66895d8da6d5eb1d8658647c80f66dce40236c06bb600f1c62a44a657f923b3` |
| SHA3-384 | `c3adbd8dff67ef8215aec122037a9730c19157a5f11b4d2c99a81c8fa4d6de8211bc89d3a95952fd19c2bb029790a853` |
| TLSH | `T15468336D1DEA9825EC2436367BD680A1861773F209C12DD9B73C018FB859A7D2B43CDB` |
| SSDEEP | `3145728:lHGbWo2eTzb9Nmo7WryQ5hzM007Wf4oUIEiNN9Uw:AbOGPXiZIP7Wfw6T` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_d66895d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d66895d8da6d5eb1d8658647c80f66dce40236c06bb600f1c62a44a657f923b3"
    family = "unknown"
    file_name = "SafeWatch.msix"
    file_type = "zip"
    first_seen = "2026-09-10 19:42:19"
  condition:
    hash.sha256(0, filesize) == "d66895d8da6d5eb1d8658647c80f66dce40236c06bb600f1c62a44a657f923b3"
}
```

### Sample 75: `8a9006cfaee22741`

| Field | Value |
|---|---|
| SHA-256 | `8a9006cfaee227415eeef0d645183ca423c80b9a8181e35a57bec71468e72daa` |
| Family label | `unknown` |
| File name | `PrivacyKeeper.msix` |
| File type | `zip` |
| First seen | `2026-09-10 19:42:02` |
| Reporter | `Tuxxin` |
| Tags | `browser-hijacker, msix, PhantomJack, PseudoJack, PseudoTDS, signed, whack.sh, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a66cfd2472301486f24b91a813f32d2` |
| SHA-1 | `8c20d3a80732c07a1d4f2a5a4b229b6c7f8a0fd2` |
| SHA-256 | `8a9006cfaee227415eeef0d645183ca423c80b9a8181e35a57bec71468e72daa` |
| SHA3-384 | `cd525b218eb5df8aa178741b43a17c8b438995ed6982f54359a8db7971adfe7d6ccd3782f4de4142ee7c7baac9887ece` |
| TLSH | `T19668338890F4A19AFF0A1473B7D6E0F65C579BE118D2D9D2132802CE053AC19BB57B6F` |
| SSDEEP | `3145728:eTRZHEfqcw/qTE4OuVqm2hyLzblq76AapzhBrlm1NxnmJP:8HEFCqQruB+yRqMpdBosJP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_8a9006cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9006cfaee227415eeef0d645183ca423c80b9a8181e35a57bec71468e72daa"
    family = "unknown"
    file_name = "PrivacyKeeper.msix"
    file_type = "zip"
    first_seen = "2026-09-10 19:42:02"
  condition:
    hash.sha256(0, filesize) == "8a9006cfaee227415eeef0d645183ca423c80b9a8181e35a57bec71468e72daa"
}
```

### Sample 76: `8de1357454488bd0`

| Field | Value |
|---|---|
| SHA-256 | `8de1357454488bd0702f0f22e912b412af41d814dffdc7c76f416d75d7dc1dc6` |
| Family label | `unknown` |
| File name | `SecuredWeb.appinstaller` |
| File type | `unknown` |
| First seen | `2026-09-10 19:41:36` |
| Reporter | `Tuxxin` |
| Tags | `appinstaller, AutoJack, browser-hijacker, msix, PhantomJack, PseudoJack, PseudoTDS, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `325a71719ab7c42fb3bafc248555336b` |
| SHA-256 | `8de1357454488bd0702f0f22e912b412af41d814dffdc7c76f416d75d7dc1dc6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_8de13574
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de1357454488bd0702f0f22e912b412af41d814dffdc7c76f416d75d7dc1dc6"
    family = "unknown"
    file_name = "SecuredWeb.appinstaller"
    file_type = "unknown"
    first_seen = "2026-09-10 19:41:36"
  condition:
    hash.sha256(0, filesize) == "8de1357454488bd0702f0f22e912b412af41d814dffdc7c76f416d75d7dc1dc6"
}
```

### Sample 77: `b8f0c82894032766`

| Field | Value |
|---|---|
| SHA-256 | `b8f0c82894032766293b7f6e6feaf287a366edd4886b8e665c41bc5103d512ce` |
| Family label | `unknown` |
| File name | `PrivacyKeeper.appinstaller` |
| File type | `unknown` |
| First seen | `2026-09-10 19:41:30` |
| Reporter | `Tuxxin` |
| Tags | `appinstaller, AutoJack, browser-hijacker, msix, PhantomJack, PseudoJack, PseudoTDS, whack.sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7edc0fdab2e7ec2803405c515b8c62b3` |
| SHA-256 | `b8f0c82894032766293b7f6e6feaf287a366edd4886b8e665c41bc5103d512ce` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_b8f0c828
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8f0c82894032766293b7f6e6feaf287a366edd4886b8e665c41bc5103d512ce"
    family = "unknown"
    file_name = "PrivacyKeeper.appinstaller"
    file_type = "unknown"
    first_seen = "2026-09-10 19:41:30"
  condition:
    hash.sha256(0, filesize) == "b8f0c82894032766293b7f6e6feaf287a366edd4886b8e665c41bc5103d512ce"
}
```

### Sample 78: `47088ba906f0633c`

| Field | Value |
|---|---|
| SHA-256 | `47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9` |
| Family label | `Mirai` |
| File name | `47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9` |
| File type | `elf` |
| First seen | `2026-09-10 19:24:01` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88b04b57646ebddb1dfeb98cffc1e634` |
| SHA-1 | `dd79b8a4ca6f4ae1f8ff8df494876e875379b5ac` |
| SHA-256 | `47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9` |
| SHA3-384 | `8247c77871ec02cf4da56e2a52a18f665adc40381d8c140f34ae4397b97e283cdb54de894dbd4cd7a1e2ddda21306937` |
| TLSH | `T108E45C0ABB124FBFE86ACE7203FB1B111AAE119716A1D7A2F27CD1107D1524F1457FA8` |
| TELFHASH | `t1715103faa6be18e497e45801d24e2f616d0ee77b285033b145f3dd24321be8150bbc39` |
| SSDEEP | `6144:0/YDmqVHPOgC9WtAP0ZJ4GSikDy7dLSdqXa2G7Yn03D9fqpajnKM36FL5EjCrdtt:mqVHWgChc7kDl2SJQwpqgmOnwDSdY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_47088ba9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9"
    family = "Mirai"
    file_name = "47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9"
    file_type = "elf"
    first_seen = "2026-09-10 19:24:01"
  condition:
    hash.sha256(0, filesize) == "47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9"
}
```

### Sample 79: `1cf42fc4fe44fda0`

| Field | Value |
|---|---|
| SHA-256 | `1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329` |
| Family label | `Mirai` |
| File name | `1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329` |
| File type | `elf` |
| First seen | `2026-09-10 19:23:59` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c0a11d33090f1f16f54fd450f90f096` |
| SHA-1 | `78ca406d75d6442a05f76eccc1cead764de6b570` |
| SHA-256 | `1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329` |
| SHA3-384 | `796edacb88f0ee5bff1d255bd6ca975bcdaee43481d94a1d1f2e1d7ac8f97ebcfe18368fb0553a0810ba1341f3644282` |
| TLSH | `T14824E80AAF510EBBDCABCD3702EA1B0128CC541721A57B767274D518F54BA4F1AE3DB8` |
| SSDEEP | `3072:h2JZLxaR4kaDFhnOllYSUPzVqLezyH6hh1P8U:h2JZLoR4kWFeYSUwLg8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_1cf42fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329"
    family = "Mirai"
    file_name = "1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:59"
  condition:
    hash.sha256(0, filesize) == "1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329"
}
```

### Sample 80: `254fcb123b257466`

| Field | Value |
|---|---|
| SHA-256 | `254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752` |
| Family label | `Mirai` |
| File name | `254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752` |
| File type | `elf` |
| First seen | `2026-09-10 19:23:57` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `117c23de7f9d8b025ad637ef44cdde94` |
| SHA-1 | `8637eeef51e9404ab930795b451c3e4ba6922fb9` |
| SHA-256 | `254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752` |
| SHA3-384 | `13f4dc9af246299816ffbed4236028be5b74b41f1ff97d98194de2f4f37c4e519b4b785bb4b1758ac7f4132002a93e9c` |
| TLSH | `T134E39FB3F30B1051C42306F417CBAB9C2E3315425F6B86E3BCAA313A2A765DE5915BE5` |
| SSDEEP | `3072:JbUCLX2tCmjRuuKX+3kWctWHaFL5EQg5CrdtRTPub01iHq:xpajnKM36FL5EjCrdtwHq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_254fcb12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752"
    family = "Mirai"
    file_name = "254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:57"
  condition:
    hash.sha256(0, filesize) == "254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752"
}
```

### Sample 81: `77820b9edff723a4`

| Field | Value |
|---|---|
| SHA-256 | `77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286` |
| Family label | `Mirai` |
| File name | `77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286` |
| File type | `elf` |
| First seen | `2026-09-10 19:23:56` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `846f8c82853098b8289f40d63462dba9` |
| SHA-1 | `f31dc663880b6ff602ed5c2ce08e44e4847465a3` |
| SHA-256 | `77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286` |
| SHA3-384 | `b1717030f1589b7d5205e3e7269f59fdfcc84a1fb119ab9d445a642300e98a55678db953857922045996bb4e24ff7391` |
| TLSH | `T1A214B80E6E228F7EF6A9C73547B78E24975823D613E1D645E1ACD2111E2038E641FFE8` |
| TELFHASH | `t1f0416e180e7817b4a6696c5d049dff67e6a331da7e126c238a11e85ae769b434d60c0c` |
| SSDEEP | `3072:QDy7dLvKdqzLH6p3o1s7n+Xnn3Z+32Em6hh1Pf65:QDy7dLSdqXa2G7Yn03D9fc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_77820b9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286"
    family = "Mirai"
    file_name = "77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:56"
  condition:
    hash.sha256(0, filesize) == "77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286"
}
```

### Sample 82: `9ce6baace15dff75`

| Field | Value |
|---|---|
| SHA-256 | `9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c` |
| Family label | `Mirai` |
| File name | `9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c` |
| File type | `elf` |
| First seen | `2026-09-10 19:23:54` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `792c404e80a608d6275f5a76002028a6` |
| SHA-1 | `b6b0b78a2333bf09944261096ac5e10aef6f376b` |
| SHA-256 | `9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c` |
| SHA3-384 | `2451958995a0da95e5f5465cd04a062df98b18e04841921c74d5fe6ba5601334ef1fae14c5456980eb8d4a52e9072255` |
| TLSH | `T11FC36CD5F643D4FADD5305B12037BB378F32D07B1129EA83E7785A22AC61A01D61AB9C` |
| TELFHASH | `t1715103faa6be18e497e45801d24e2f616d0ee77b285033b145f3dd24321be8150bbc39` |
| SSDEEP | `3072:qXmkYDpMgztjHQ8bigC93mtevNVw3w0Y83ESF4G0hAB1Qi:0/YDmqVHPOgC9WtAP0ZJ4GSi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_9ce6baac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c"
    family = "Mirai"
    file_name = "9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:54"
  condition:
    hash.sha256(0, filesize) == "9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c"
}
```

### Sample 83: `ce973eacc5546aa7`

| Field | Value |
|---|---|
| SHA-256 | `ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670` |
| Family label | `Mirai` |
| File name | `ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670` |
| File type | `sh` |
| First seen | `2026-09-10 19:23:52` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaab1bcd002dcf8c1669c85036c02580` |
| SHA-1 | `6ab02b41c1bf8c50bafadf5ee188754241ceb18d` |
| SHA-256 | `ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670` |
| SHA3-384 | `e3a660bfd60701c1ab000ffacc039f42e6dced5ca3efa787d79a2af9f3852a93b290488cd36356f1480f6241d5a29e86` |
| TLSH | `T1B051C486C56E6E32A11EDF0EB751C2BD200141BFADE393F0DD6AC71902868F175E6B16` |
| SSDEEP | `48:py7Slb+7cb+7ay767rumy9lb+rb+nTy7vpyUlb+gTb+gLyU/yYlb+fWb+AyY3yiR:U7Slb+7cb+7R767rud9lb+rb+e7vUUlJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_ce973eac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670"
    family = "Mirai"
    file_name = "ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670"
    file_type = "sh"
    first_seen = "2026-09-10 19:23:52"
  condition:
    hash.sha256(0, filesize) == "ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670"
}
```

### Sample 84: `3019ba8ec2449305`

| Field | Value |
|---|---|
| SHA-256 | `3019ba8ec2449305d0afb051b4ef3cee7071fefd3e5c6c3205fff5ce3da7dcb2` |
| Family label | `unknown` |
| File name | `b` |
| File type | `unknown` |
| First seen | `2026-09-10 19:10:59` |
| Reporter | `monitorsg` |
| Tags | `KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aeebaaf5d773f2acf843f33a6f416cbd` |
| SHA-256 | `3019ba8ec2449305d0afb051b4ef3cee7071fefd3e5c6c3205fff5ce3da7dcb2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_3019ba8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3019ba8ec2449305d0afb051b4ef3cee7071fefd3e5c6c3205fff5ce3da7dcb2"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 19:10:59"
  condition:
    hash.sha256(0, filesize) == "3019ba8ec2449305d0afb051b4ef3cee7071fefd3e5c6c3205fff5ce3da7dcb2"
}
```

### Sample 85: `06ac326301636602`

| Field | Value |
|---|---|
| SHA-256 | `06ac3263016366029d5875f3242a6a46a4801a2a37501c6b2e5992295b52dfd6` |
| Family label | `unknown` |
| File name | `0ce3cebbf09f2b0b.js` |
| File type | `js` |
| First seen | `2026-09-10 19:09:54` |
| Reporter | `rmceoin` |
| Tags | `EtherRAT, js, KongTuke` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `39755c38163b0fbff39e734eea25f37e` |
| SHA-1 | `ba7ee242753b8c827d5fc8f6672083b3c3811f2c` |
| SHA-256 | `06ac3263016366029d5875f3242a6a46a4801a2a37501c6b2e5992295b52dfd6` |
| SHA3-384 | `7edb00129dbfc7f22acc4143383155c056cabd318a7897ba866d8daed8fe3f10929ba69b7423e0f91726469d7ce125ce` |
| TLSH | `T16542639926B76124467361DD4BA74009623EE4133384D9ACBF9CC3091FD7668C6E3AEC` |
| SSDEEP | `192:kR9xN2nul9fsgCgaNhyj/KkXS+H7GATFhYHG9jAvBUR1On3a7LyRfKCCm:kRb6NhsCk3jxFR1On3Nz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_06ac3263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06ac3263016366029d5875f3242a6a46a4801a2a37501c6b2e5992295b52dfd6"
    family = "unknown"
    file_name = "0ce3cebbf09f2b0b.js"
    file_type = "js"
    first_seen = "2026-09-10 19:09:54"
  condition:
    hash.sha256(0, filesize) == "06ac3263016366029d5875f3242a6a46a4801a2a37501c6b2e5992295b52dfd6"
}
```

### Sample 86: `a2fc403da369d890`

| Field | Value |
|---|---|
| SHA-256 | `a2fc403da369d8906e27f4899b9c87bab2b9343b17a95516e221da0fb0ba7a15` |
| Family label | `unknown` |
| File name | `4pi3llms81.hta` |
| File type | `unknown` |
| First seen | `2026-09-10 19:08:33` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `776156c6719a4ae3e76bceb9af6844b0` |
| SHA-1 | `bd4de2010720c12e09e8933f3f6d3b69f2b03e95` |
| SHA-256 | `a2fc403da369d8906e27f4899b9c87bab2b9343b17a95516e221da0fb0ba7a15` |
| SHA3-384 | `5602a0de3974b697a0fbc64ce1ddf705d409e132cb9b5b5cc758233937db0f6fd00f7340d2a89c77848d924969abbba3` |
| TLSH | `T11DA108757B8570695BE601E6A17BA75C363E42A0340B8023EB6EFCD13C61E5B4097F8A` |
| SSDEEP | `96:nIzJBd5pAJ9/OEeg2J9LCBCfq/0CqR4oDt/haIKlDjfq97BoL:IzJBd5pAKEj8qCfY0hBcXDjfAyL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_a2fc403d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2fc403da369d8906e27f4899b9c87bab2b9343b17a95516e221da0fb0ba7a15"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-10 19:08:33"
  condition:
    hash.sha256(0, filesize) == "a2fc403da369d8906e27f4899b9c87bab2b9343b17a95516e221da0fb0ba7a15"
}
```

### Sample 87: `e3ac3cffebd0089e`

| Field | Value |
|---|---|
| SHA-256 | `e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32` |
| Family label | `unknown` |
| File name | `e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32` |
| File type | `sh` |
| First seen | `2026-09-10 19:00:16` |
| Reporter | `EnthecSolutions` |
| Tags | `enthec, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87c17de32d7e5b8e1de0e6e18adcd572` |
| SHA-1 | `6324f0ef6f0de1d22696747d383068e412be9f80` |
| SHA-256 | `e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32` |
| SHA3-384 | `bfa345d6789754ce404ed698631995e2096d5ea01f8361681c6c612858ef01c752b3f1822d7a9450d0b79dfc18589ea3` |
| TLSH | `T1583143EB151056322002CA4DB7B33598728DE1F72E5FDBD0DA490EF9464978CF161FA9` |
| SSDEEP | `24:4A7HSpqV6MWblYXhDXDsd5nr19ge4Uu4l:H7ypqVPYlYxDKP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_e3ac3cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32"
    family = "unknown"
    file_name = "e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32"
    file_type = "sh"
    first_seen = "2026-09-10 19:00:16"
  condition:
    hash.sha256(0, filesize) == "e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32"
}
```

### Sample 88: `e5a665da69d6ee08`

| Field | Value |
|---|---|
| SHA-256 | `e5a665da69d6ee08e46566dd1048c25554bdf620f63a152758a11cd1d9e6d634` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-10 18:39:29` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-GCleaner, exe, F, PMIX0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99eb27ff6b08c4ee8b66c01470c3aa08` |
| SHA-1 | `89bb7970b0d7bf8e57657c271967230e0773a47d` |
| SHA-256 | `e5a665da69d6ee08e46566dd1048c25554bdf620f63a152758a11cd1d9e6d634` |
| SHA3-384 | `fb428ba58e65ad28ce93a3c6e4b0e826239a95137085052971e2382efc824238cf68157b462bd7eaab82e8a8d5603b30` |
| IMPHASH | `9eba512b03d8cac8a6c4424e25e9f06e` |
| TLSH | `T15008DF1663E111AAD577D178C7AB6203EB72B40B13308BDF329C43652F63AE45E7A760` |
| SSDEEP | `1572864:r6zuLINumgj6ycpjIsMmUit+kmmxI8JCGG:r6zcmgmNj9M4mmxNJzG` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_088_e5a665da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5a665da69d6ee08e46566dd1048c25554bdf620f63a152758a11cd1d9e6d634"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-10 18:39:29"
  condition:
    hash.sha256(0, filesize) == "e5a665da69d6ee08e46566dd1048c25554bdf620f63a152758a11cd1d9e6d634"
}
```

### Sample 89: `66fbd782f3a7bdbf`

| Field | Value |
|---|---|
| SHA-256 | `66fbd782f3a7bdbf9ab71f08d7c9cd2d938e4ae6d584967214787f64fd1dd4f6` |
| Family label | `Mirai` |
| File name | `mirai.mipsel` |
| File type | `elf` |
| First seen | `2026-09-10 18:37:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be0a437a6d276fad77d3d04474453cf0` |
| SHA-1 | `060febfea8712700ed98f1c3daa0be1977142ca4` |
| SHA-256 | `66fbd782f3a7bdbf9ab71f08d7c9cd2d938e4ae6d584967214787f64fd1dd4f6` |
| SHA3-384 | `36762beb423659139ae1a16d05976f1e945ebb0716f795f2a1eb97b1e6f157717e3afb47e867158fa22a80e251893d09` |
| TLSH | `T148D45A06EF851FEBC4AFCE30852E835B15ED9D8702D1A63860BC8D5CBA9D2591FD7848` |
| SSDEEP | `12288:YHuHyxiqtq3CikGcb9XmrBqV9yPLw+w7uVEOlD6PH2hVecTNc9/Z5//qRLPueodx:3CrZib255mgtmqZj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_66fbd782
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66fbd782f3a7bdbf9ab71f08d7c9cd2d938e4ae6d584967214787f64fd1dd4f6"
    family = "Mirai"
    file_name = "mirai.mipsel"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:43"
  condition:
    hash.sha256(0, filesize) == "66fbd782f3a7bdbf9ab71f08d7c9cd2d938e4ae6d584967214787f64fd1dd4f6"
}
```

### Sample 90: `20494d7c6537bc60`

| Field | Value |
|---|---|
| SHA-256 | `20494d7c6537bc60a076bc7583a6a1eb07720bbe408708e6d2aec8717377de3b` |
| Family label | `unknown` |
| File name | `tiny_bot.mipsel` |
| File type | `elf` |
| First seen | `2026-09-10 18:37:41` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df635801efafe41a8e27caa55eb818e0` |
| SHA-1 | `3651c30079d7d978e029c7063da91e65cb9734db` |
| SHA-256 | `20494d7c6537bc60a076bc7583a6a1eb07720bbe408708e6d2aec8717377de3b` |
| SHA3-384 | `c3665e41644bd68dcb7cbc4693f33497af538e6bf16baf53ba4f5f7273eec8b31c296f21b00c1ed628b6f537ef03aad5` |
| TLSH | `T1D7D44A06FF441FEBC46FCD30452EC20711ECE9C756D1A62A71FC8A9CBA5D25A4AD3988` |
| SSDEEP | `12288:LZjfDErwLEZzryQc2+vPIo4ew2jyNBimtSuZtj17P1mPWLdDeqRna3juZqYT1aN6:FLEZzryEOIZqj0v+YLXzBj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_20494d7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20494d7c6537bc60a076bc7583a6a1eb07720bbe408708e6d2aec8717377de3b"
    family = "unknown"
    file_name = "tiny_bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:41"
  condition:
    hash.sha256(0, filesize) == "20494d7c6537bc60a076bc7583a6a1eb07720bbe408708e6d2aec8717377de3b"
}
```

### Sample 91: `c459207f8f9e5810`

| Field | Value |
|---|---|
| SHA-256 | `c459207f8f9e5810cbde75ee5de0440a146cf9d57f765ed434171ce4192deed1` |
| Family label | `Mirai` |
| File name | `mirai.mips` |
| File type | `elf` |
| First seen | `2026-09-10 18:37:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b989033cac06cf72e82f209ab8e9f3ef` |
| SHA-1 | `72d8003eb5f73f000b9b92074038239678c4c8e8` |
| SHA-256 | `c459207f8f9e5810cbde75ee5de0440a146cf9d57f765ed434171ce4192deed1` |
| SHA3-384 | `9c1db55b53437d80ea2f19e3ec6bdc174f3d5bb513f19c99ed9e7e91289f1c896d9075103de082aab434f5a5e7119bf1` |
| TLSH | `T195D47D9377218FA4E360D17105F3C7255AA521A20BE390C6A3BCD6207B51A6D6C6FFF8` |
| TELFHASH | `t10f4170080d7817e0a3655c5d09ddff76e6a330db7e252d238a50f86aa768b838d11c1c` |
| SSDEEP | `12288:dR1NN4L9DC+klwwVJu+M+4yBDDI5aydREQe4c8ptVwbqk:dR/N4L9G+kBRM+4yeaynEQeeun` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_c459207f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c459207f8f9e5810cbde75ee5de0440a146cf9d57f765ed434171ce4192deed1"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:40"
  condition:
    hash.sha256(0, filesize) == "c459207f8f9e5810cbde75ee5de0440a146cf9d57f765ed434171ce4192deed1"
}
```

### Sample 92: `33e406193df703b5`

| Field | Value |
|---|---|
| SHA-256 | `33e406193df703b518a6ab20e0dc296bb82776361b3bc65a1b6bb50a83c29b0a` |
| Family label | `unknown` |
| File name | `tiny_bot.mips` |
| File type | `elf` |
| First seen | `2026-09-10 18:37:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e9d1f676b959baa77b7435bdb7c2370` |
| SHA-1 | `40857c9224fe69e6c8b802df9a523e6354d7dc78` |
| SHA-256 | `33e406193df703b518a6ab20e0dc296bb82776361b3bc65a1b6bb50a83c29b0a` |
| SHA3-384 | `1bf0f1b1676fbe34180f68710e4971b8cccb79e80d50196bc876aa7de6a670d62099d9192b1bdaec55bc6c4e79b1ec0c` |
| TLSH | `T119D46B627711DFA4D364D2B009F3C6555AE421A20AF240C6B2BCCB1C7E6162D6D6FEF8` |
| TELFHASH | `t10731a3180d3813a4a3755c5d59edff37e66330de7e126d338e10e8aaab2d9428e10c1c` |
| SSDEEP | `12288:574L4YOTU+Jc9CdtzcNF389384+nqDg1NDWY31CWLydA8puAreMg5:t4L4XTUcjzWF38927DL3oW2xqb5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_33e40619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33e406193df703b518a6ab20e0dc296bb82776361b3bc65a1b6bb50a83c29b0a"
    family = "unknown"
    file_name = "tiny_bot.mips"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:38"
  condition:
    hash.sha256(0, filesize) == "33e406193df703b518a6ab20e0dc296bb82776361b3bc65a1b6bb50a83c29b0a"
}
```

### Sample 93: `c829d0e33ceaa65c`

| Field | Value |
|---|---|
| SHA-256 | `c829d0e33ceaa65cf5063682e306e654a29d68fd2e604f300e0abc777b7ce717` |
| Family label | `unknown` |
| File name | `tiny_bot.arm7` |
| File type | `elf` |
| First seen | `2026-09-10 18:37:37` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3be58c77841a353801dfa773796415a2` |
| SHA-1 | `8178fa070a55b35979f06fde283fc4e3c4825da4` |
| SHA-256 | `c829d0e33ceaa65cf5063682e306e654a29d68fd2e604f300e0abc777b7ce717` |
| SHA3-384 | `84f3982bf2312a9bd1baa652335698dc17248da93378b2ccfc2d2202ed0cf66141d676dc75edeaa579ee2eab3ff96437` |
| TLSH | `T1C2A43955F8809F61C6C539B6F74D82A873074B79D3EBB2069A145B343BE786B0F3A601` |
| TELFHASH | `t126d0a76566642df9b2d344c6c0ba753b117941c9a54585c8d7a19cdc5923fc32049c33` |
| SSDEEP | `12288:c/y3RQ3CJyKZTKQ3jiwF0upqieDvmiWVn8pHPEt:iy3RMaKmj7FNqilq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_c829d0e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c829d0e33ceaa65cf5063682e306e654a29d68fd2e604f300e0abc777b7ce717"
    family = "unknown"
    file_name = "tiny_bot.arm7"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:37"
  condition:
    hash.sha256(0, filesize) == "c829d0e33ceaa65cf5063682e306e654a29d68fd2e604f300e0abc777b7ce717"
}
```

### Sample 94: `254a26c23115f6f3`

| Field | Value |
|---|---|
| SHA-256 | `254a26c23115f6f363ad11d29d7d9f4b0b284edebb122960f5aa43c28b625d70` |
| Family label | `unknown` |
| File name | `tiny_bot.arm64` |
| File type | `elf` |
| First seen | `2026-09-10 18:37:35` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5c37ed83144c5e187fce11131f98130` |
| SHA-1 | `35949927fb9d91758412c3dfa49429f810a2d726` |
| SHA-256 | `254a26c23115f6f363ad11d29d7d9f4b0b284edebb122960f5aa43c28b625d70` |
| SHA3-384 | `c9a4636c04637e473e48dc30a93a271b9024b3d63d693255ccea51718bf77b3a95ddc6b80424b212a8f79734d1fe0fe9` |
| TLSH | `T1C4C48D59FE5E3C42E2C7E23CDB8983E1A32BB5E4D35352A23941430CD9C6AE5CFA1651` |
| SSDEEP | `12288:fpgLxZwzZoDpSkWdMdACa2aNJ+EbKvQBjbGs5/+WwE:fExZ/TWdua2uJ+c1BjSV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_254a26c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254a26c23115f6f363ad11d29d7d9f4b0b284edebb122960f5aa43c28b625d70"
    family = "unknown"
    file_name = "tiny_bot.arm64"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:35"
  condition:
    hash.sha256(0, filesize) == "254a26c23115f6f363ad11d29d7d9f4b0b284edebb122960f5aa43c28b625d70"
}
```

### Sample 95: `6fe242f8b01c1bc2`

| Field | Value |
|---|---|
| SHA-256 | `6fe242f8b01c1bc25acc08db4b041d984f4c3dcbd1ea2dd4827657a8da2740a6` |
| Family label | `unknown` |
| File name | `tiny_bot.x86_64` |
| File type | `elf` |
| First seen | `2026-09-10 18:36:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `417684090df537fcaf4e462e3f892373` |
| SHA-1 | `b41ba45042658477d00e459fbda3ca5a59ce049e` |
| SHA-256 | `6fe242f8b01c1bc25acc08db4b041d984f4c3dcbd1ea2dd4827657a8da2740a6` |
| SHA3-384 | `f345d9c597bce888f55bd63348fb1a1502912904b0d94ed4cb9e8463a92cfc26846e132768f278596acb55bf46d9ea40` |
| TLSH | `T19C125617E3A058E7C43CD33849A75324B6F3B83856F223276E4429282CE72595E76E94` |
| SSDEEP | `12:BvwvCyQu/TL3E+DAi8Z0ChhzzxB52EMEqUeqbtTxk+rVsU1x+2BcvbAa4E0QfEvd:GpQu/H3Egb00cUEB3eETxkZUP+lbsy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_6fe242f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe242f8b01c1bc25acc08db4b041d984f4c3dcbd1ea2dd4827657a8da2740a6"
    family = "unknown"
    file_name = "tiny_bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:06"
  condition:
    hash.sha256(0, filesize) == "6fe242f8b01c1bc25acc08db4b041d984f4c3dcbd1ea2dd4827657a8da2740a6"
}
```

### Sample 96: `2b2525b502443927`

| Field | Value |
|---|---|
| SHA-256 | `2b2525b502443927ee21bc21726fcafc533b96883d30dbeb97569decec550f42` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-09-10 18:36:05` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4af0b36596fe936768a57e4ed0c5e376` |
| SHA-1 | `75d7fde8e206e6130335e9d4dec4e9263230b75e` |
| SHA-256 | `2b2525b502443927ee21bc21726fcafc533b96883d30dbeb97569decec550f42` |
| SHA3-384 | `971b7df7d179d3dade6c63037927cb0f3be625e0e5a6349d211baf5f2e91281db24ada881f34edfe6bdb0273818e266e` |
| TLSH | `T11EB32A867B108FA1D379953009F38B97ABA6269617E29545E36CDD003F6035C782FFE8` |
| TELFHASH | `t18811484d113548df79db49f18c791ba6c60fcc05b8e15e20cf9dcbc485a68099618e5f` |
| SSDEEP | `1536:qtF7XQUOS/DcTS+KOLisrzyxVFba08fx4eohB6cFs8tVoHXqjNGFgovrZuNH:CF7XQUBR+t5yxVFm08f+s8tKPjZQH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_2b2525b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b2525b502443927ee21bc21726fcafc533b96883d30dbeb97569decec550f42"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:05"
  condition:
    hash.sha256(0, filesize) == "2b2525b502443927ee21bc21726fcafc533b96883d30dbeb97569decec550f42"
}
```

### Sample 97: `65b25aa01a1fc7cc`

| Field | Value |
|---|---|
| SHA-256 | `65b25aa01a1fc7cc0cb5a6df0944980c7391062f698414b95f16111cb0db5498` |
| Family label | `unknown` |
| File name | `mips-bk` |
| File type | `elf` |
| First seen | `2026-09-10 18:36:03` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28db09de568dd52bddcceca8973c6f70` |
| SHA-1 | `09b9a79dc0cd1fb9bc5aa97a145fe6a68ccef5c1` |
| SHA-256 | `65b25aa01a1fc7cc0cb5a6df0944980c7391062f698414b95f16111cb0db5498` |
| SHA3-384 | `941001081c46d64ff90bb0352f2d63a9121be8b30789cc01cf4092598fbd769773c93df6ac8784bc55e7859f33999cb4` |
| TLSH | `T1D7B3198777118FA1C279963009F38B93ABB6269627E29545F36CD9003F6435C682FFE4` |
| TELFHASH | `t18811484d113548df79db49f18c791ba6c60fcc05b8e15e20cf9dcbc485a68099618e5f` |
| SSDEEP | `1536:vPtFFAME4WWPOZAunyy+l8jcvAbUMZ+oOD0dpnM2FmCCGTvrZj:NFFAMEX/1nEkcvAAMIlMM2FmCCMjZj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_65b25aa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65b25aa01a1fc7cc0cb5a6df0944980c7391062f698414b95f16111cb0db5498"
    family = "unknown"
    file_name = "mips-bk"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:03"
  condition:
    hash.sha256(0, filesize) == "65b25aa01a1fc7cc0cb5a6df0944980c7391062f698414b95f16111cb0db5498"
}
```

### Sample 98: `a2e58adc8bca368b`

| Field | Value |
|---|---|
| SHA-256 | `a2e58adc8bca368b22b94c4b1a375ab96b19731fc82072abfe229772d5ff2ebf` |
| Family label | `unknown` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-09-10 18:36:02` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f24ca42222dcd0578559b787cdbd1976` |
| SHA-1 | `edc562c92dea80ffc70909810dbf03ea34b1b964` |
| SHA-256 | `a2e58adc8bca368b22b94c4b1a375ab96b19731fc82072abfe229772d5ff2ebf` |
| SHA3-384 | `cd84225280963e04fa3d6a09a8f9f36aad0de415078049a4f91ceb323ee8585551a189ed6863e3ba250a4602f83f7c79` |
| TLSH | `T150B31945EEA00FDFC4AFCE30461F031726ED589F96E1633A527CDC4876AA2598AD3948` |
| TELFHASH | `t18811484d113548df79db49f18c791ba6c60fcc05b8e15e20cf9dcbc485a68099618e5f` |
| SSDEEP | `3072:LvFlVfJU2XD/dS1Hoyjo7eAdDB6ZPtJ5V:DFlL/dS1FedD8ZPt9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_a2e58adc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2e58adc8bca368b22b94c4b1a375ab96b19731fc82072abfe229772d5ff2ebf"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:02"
  condition:
    hash.sha256(0, filesize) == "a2e58adc8bca368b22b94c4b1a375ab96b19731fc82072abfe229772d5ff2ebf"
}
```

### Sample 99: `060f1a11d5bcd55f`

| Field | Value |
|---|---|
| SHA-256 | `060f1a11d5bcd55f7e3a22c6f82a07d74496de607939e5d26a99baaebf564e49` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-09-10 18:36:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66a3ea3ed5af993867a7652f47d4c960` |
| SHA-1 | `40f50f4406f5e9fa1bf3d46ff8a8f8879b8dc887` |
| SHA-256 | `060f1a11d5bcd55f7e3a22c6f82a07d74496de607939e5d26a99baaebf564e49` |
| SHA3-384 | `b7cdea6a8111919ec5500ec7cc462d160e6ac1b6302136a2a5d98dacd88163a400c60318b039b247fcb090a3a7acd663` |
| TLSH | `T15D932A95F890CF21C6D56A7BFB5E428873130B78D3D931028D25AF3467EB95A4F3A902` |
| SSDEEP | `1536:lPLQ1BrkcScPOXKSobs+yovAIKQ7ba5kVtK46/PeFMfv9CoOb+hxVgEQO+KOU9Yw:lP4Br+XKtnf/bTVE4SmYvkoOoxaXKJx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_060f1a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "060f1a11d5bcd55f7e3a22c6f82a07d74496de607939e5d26a99baaebf564e49"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:01"
  condition:
    hash.sha256(0, filesize) == "060f1a11d5bcd55f7e3a22c6f82a07d74496de607939e5d26a99baaebf564e49"
}
```

### Sample 100: `b7d6a8638f8acb69`

| Field | Value |
|---|---|
| SHA-256 | `b7d6a8638f8acb69b2e287f939136d4da4137aca37f47ee452e166e5f30e2320` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-09-10 18:35:59` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb960866fc490d36be6962ec6fd445db` |
| SHA-1 | `534c0f5541136c506b3e8db009f1e60b768d1620` |
| SHA-256 | `b7d6a8638f8acb69b2e287f939136d4da4137aca37f47ee452e166e5f30e2320` |
| SHA3-384 | `518a1e974d71809aad8f813852b80427eeab4c636fcf9191f0d77e98a67e9b7584a83c3579bc070088253d04d4c56c90` |
| TLSH | `T1FF734B02B5D190FEC4DAC274879FD167EA33BC9913207AAB2794BA711F36E211B0E751` |
| SSDEEP | `1536:iCz83HCmTZj3I0lNT6ZuRx+gtwS0Xizh/by4/upmBorn:ixB3jlP+iwTyZbcpT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_b7d6a863
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7d6a8638f8acb69b2e287f939136d4da4137aca37f47ee452e166e5f30e2320"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-10 18:35:59"
  condition:
    hash.sha256(0, filesize) == "b7d6a8638f8acb69b2e287f939136d4da4137aca37f47ee452e166e5f30e2320"
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
 * Generated: 2026-09-11T04:49:23.888577+00:00
 */

rule MalwareBazaar_unknown_001_e1c18c4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1c18c4e147bfacfe050d441bde8ac4591f2e7d4320dbc28da78b61647fbb04d"
    family = "unknown"
    file_name = "JAG93498680733_20260911_044325_690d130890.js"
    file_type = "js"
    first_seen = "2026-09-11 04:48:56"
  condition:
    hash.sha256(0, filesize) == "e1c18c4e147bfacfe050d441bde8ac4591f2e7d4320dbc28da78b61647fbb04d"
}

rule MalwareBazaar_unknown_002_9a8c3e39
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9a8c3e3982fdfabba73d82309fa0b0326586f001f0e623886eb40432d8dcc8ef"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 04:14:35"
  condition:
    hash.sha256(0, filesize) == "9a8c3e3982fdfabba73d82309fa0b0326586f001f0e623886eb40432d8dcc8ef"
}

rule MalwareBazaar_Mirai_003_07c0a0af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656"
    family = "Mirai"
    file_name = "07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656.elf"
    file_type = "elf"
    first_seen = "2026-09-11 04:04:29"
  condition:
    hash.sha256(0, filesize) == "07c0a0af63dde8dc2e36dc58b630dcad6563263e992877aaa704530afb8a5656"
}

rule MalwareBazaar_Mirai_004_73695282
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559"
    family = "Mirai"
    file_name = "73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559.elf"
    file_type = "elf"
    first_seen = "2026-09-11 04:04:24"
  condition:
    hash.sha256(0, filesize) == "73695282607747038a31f516e3f8310a67ae6f2f9e4a0b90b55a40f77272e559"
}

rule MalwareBazaar_unknown_005_18840115
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "188401154e54bdc983556e45f6281a1e32f6bb3802a55465e3a8ecc504f51d92"
    family = "unknown"
    file_name = "NEW_LETTER_OF_AUTHORIZATION.js"
    file_type = "js"
    first_seen = "2026-09-11 04:01:52"
  condition:
    hash.sha256(0, filesize) == "188401154e54bdc983556e45f6281a1e32f6bb3802a55465e3a8ecc504f51d92"
}

rule MalwareBazaar_unknown_006_6d6adbff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d6adbff7df2734a190003658eeaea6f2cbef90953b3bbc116d3a411aa02ed66"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 03:42:36"
  condition:
    hash.sha256(0, filesize) == "6d6adbff7df2734a190003658eeaea6f2cbef90953b3bbc116d3a411aa02ed66"
}

rule MalwareBazaar_unknown_007_2776db94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2776db94daae85ee1013c8274828d48e1c08705a690fa953f22209830b7618bd"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-11 03:40:37"
  condition:
    hash.sha256(0, filesize) == "2776db94daae85ee1013c8274828d48e1c08705a690fa953f22209830b7618bd"
}

rule MalwareBazaar_unknown_008_aead598c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aead598cf4d5c0f3c294fec64fe9cc13d06ddc054ac2b799ce457300f6080287"
    family = "unknown"
    file_name = "HuGN.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 03:36:37"
  condition:
    hash.sha256(0, filesize) == "aead598cf4d5c0f3c294fec64fe9cc13d06ddc054ac2b799ce457300f6080287"
}

rule MalwareBazaar_unknown_009_06b74f0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8"
    family = "unknown"
    file_name = "06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8"
    file_type = "elf"
    first_seen = "2026-09-11 03:32:58"
  condition:
    hash.sha256(0, filesize) == "06b74f0ddef0180a092d00fb8974aa2598f631e0d6437acc97dd4d05e3b86bf8"
}

rule MalwareBazaar_unknown_010_ae2cd00c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae2cd00c16b6911133d21eada3d44e30eee5de57a9d4167f408fc5bbe7a30f88"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 03:28:34"
  condition:
    hash.sha256(0, filesize) == "ae2cd00c16b6911133d21eada3d44e30eee5de57a9d4167f408fc5bbe7a30f88"
}

rule MalwareBazaar_unknown_011_84e73712
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84e7371263c069cf99bc4aa2cccd55120576b1725a563c234e1850bd142a78cb"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 03:26:39"
  condition:
    hash.sha256(0, filesize) == "84e7371263c069cf99bc4aa2cccd55120576b1725a563c234e1850bd142a78cb"
}

rule MalwareBazaar_unknown_012_99ab596c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ab596c4872cfc705cffdf2ce178218e919bc7e22192e3e4bc3a6f1d5968552"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-11 03:26:38"
  condition:
    hash.sha256(0, filesize) == "99ab596c4872cfc705cffdf2ce178218e919bc7e22192e3e4bc3a6f1d5968552"
}

rule MalwareBazaar_Mirai_013_cd9655a7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd9655a77201f73e69953ec5b53f898de41983c1b4dcedd0c431955b9c20b241"
    family = "Mirai"
    file_name = "telnet"
    file_type = "elf"
    first_seen = "2026-09-11 03:20:35"
  condition:
    hash.sha256(0, filesize) == "cd9655a77201f73e69953ec5b53f898de41983c1b4dcedd0c431955b9c20b241"
}

rule MalwareBazaar_unknown_014_2af14633
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3"
    family = "unknown"
    file_name = "2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3.bin"
    file_type = "zip"
    first_seen = "2026-09-11 03:09:18"
  condition:
    hash.sha256(0, filesize) == "2af14633ff24e28939e9bb880f62ca80a27c70753383181acc227fc97171a8d3"
}

rule MalwareBazaar_unknown_015_76248563
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf"
    family = "unknown"
    file_name = "76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf.bin"
    file_type = "exe"
    first_seen = "2026-09-11 02:38:31"
  condition:
    hash.sha256(0, filesize) == "76248563dc3fbd1a539d6bcc4275c843695ed08872b8794fe738e3b1657eafbf"
}

rule MalwareBazaar_unknown_016_7497e359
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41"
    family = "unknown"
    file_name = "7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 02:34:22"
  condition:
    hash.sha256(0, filesize) == "7497e359bc00ee6ec94d4f42d74ba1128ef3873e947e6d60ace5ca0fbe336e41"
}

rule MalwareBazaar_unknown_017_076f3b4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "076f3b4defa1a6a31101021ef25ec20a755dbfb68ca7ffe6a192a0713b11b659"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 02:29:23"
  condition:
    hash.sha256(0, filesize) == "076f3b4defa1a6a31101021ef25ec20a755dbfb68ca7ffe6a192a0713b11b659"
}

rule MalwareBazaar_NetSupport_018_4e428fb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464"
    family = "NetSupport"
    file_name = "4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464.bin"
    file_type = "zip"
    first_seen = "2026-09-11 02:10:03"
  condition:
    hash.sha256(0, filesize) == "4e428fb03df8cdf9d154b14eb7d4e2fa1d147a835a8c6e81b1863115f3cff464"
}

rule MalwareBazaar_VShell_019_382a96ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430"
    family = "VShell"
    file_name = "382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430.exe"
    file_type = "exe"
    first_seen = "2026-09-11 02:05:03"
  condition:
    hash.sha256(0, filesize) == "382a96ce056c847c21fe3d45afe6eff00df1fda4a816f27dd32bbe903e202430"
}

rule MalwareBazaar_VShell_020_941f22db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e"
    family = "VShell"
    file_name = "941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e.exe"
    file_type = "exe"
    first_seen = "2026-09-11 02:04:13"
  condition:
    hash.sha256(0, filesize) == "941f22db88f2c0f64e2af53a93389ccff2c005701ea80d3c5c1dbe200d25bd1e"
}

rule MalwareBazaar_unknown_021_fccbb541
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27"
    family = "unknown"
    file_name = "fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27.elf"
    file_type = "elf"
    first_seen = "2026-09-11 01:55:05"
  condition:
    hash.sha256(0, filesize) == "fccbb54155bf5a958392b73712f78dd370f6d19400c34b3e6d6cc9ac1702ad27"
}

rule MalwareBazaar_unknown_022_18b41b94
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18b41b9483a6331e8549a57567022f86863e7b5d4496d493e7ee67c6799b5da1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-11 01:49:00"
  condition:
    hash.sha256(0, filesize) == "18b41b9483a6331e8549a57567022f86863e7b5d4496d493e7ee67c6799b5da1"
}

rule MalwareBazaar_VShell_023_1f2160b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257"
    family = "VShell"
    file_name = "1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:34:18"
  condition:
    hash.sha256(0, filesize) == "1f2160b814d7cb02c38b535077ff03202ed67144e37211dbf027e38fb1959257"
}

rule MalwareBazaar_VShell_024_7085ab2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c"
    family = "VShell"
    file_name = "7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:34:13"
  condition:
    hash.sha256(0, filesize) == "7085ab2e2e21bf54635088d37a25f05bf6a8e338c8917b3ed00923ee447a915c"
}

rule MalwareBazaar_unknown_025_7775a816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a"
    family = "unknown"
    file_name = "7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:34:09"
  condition:
    hash.sha256(0, filesize) == "7775a816832913eff8e6b3cac3444d955b788abbb94d3bf7a676d4a9d4d8748a"
}

rule MalwareBazaar_Mirai_026_7a99500e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835"
    family = "Mirai"
    file_name = "7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835.elf"
    file_type = "elf"
    first_seen = "2026-09-11 01:24:17"
  condition:
    hash.sha256(0, filesize) == "7a99500e3e70175bd9d7b7ca7ea7e723a6c7b019a70338211ce2d7b24a273835"
}

rule MalwareBazaar_unknown_027_920d4127
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "920d4127eab982c98b0962ff09ef19f84bc10e6ca76c8d49993ce2fcb2d3474f"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-11 01:15:29"
  condition:
    hash.sha256(0, filesize) == "920d4127eab982c98b0962ff09ef19f84bc10e6ca76c8d49993ce2fcb2d3474f"
}

rule MalwareBazaar_unknown_028_74109e2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74109e2ad03f4b3d057a41b8a720378d58405604c5e2d8828e15d601c5a0bd28"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-11 01:15:03"
  condition:
    hash.sha256(0, filesize) == "74109e2ad03f4b3d057a41b8a720378d58405604c5e2d8828e15d601c5a0bd28"
}

rule MalwareBazaar_unknown_029_f9e7443a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9e7443abc9bae8168ac51896b9b1976d2884f8a076f983eb7f2214cfa28bd8a"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-11 01:15:01"
  condition:
    hash.sha256(0, filesize) == "f9e7443abc9bae8168ac51896b9b1976d2884f8a076f983eb7f2214cfa28bd8a"
}

rule MalwareBazaar_VShell_030_b0f048d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5"
    family = "VShell"
    file_name = "b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:14:06"
  condition:
    hash.sha256(0, filesize) == "b0f048d712bec3be0aea8d6e2e5d54ec8d0d5350e3f389a2b4ac477b79c819e5"
}

rule MalwareBazaar_VShell_031_d74ee8bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c"
    family = "VShell"
    file_name = "d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:10:47"
  condition:
    hash.sha256(0, filesize) == "d74ee8bb9337b8dd250ce28e0e8607680f83719a28906f6410aa4a6addbd720c"
}

rule MalwareBazaar_VShell_032_c887d8e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d"
    family = "VShell"
    file_name = "c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d.exe"
    file_type = "exe"
    first_seen = "2026-09-11 01:04:15"
  condition:
    hash.sha256(0, filesize) == "c887d8e750abfa0312f20cc0f54314e36352ab9ac0cbbdcd108a9c63fda4bd0d"
}

rule MalwareBazaar_VShell_033_87fc39ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0"
    family = "VShell"
    file_name = "87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:49:12"
  condition:
    hash.sha256(0, filesize) == "87fc39acdd817bf8e788ab7cb00fbf19cf53767635107e07a02e781053df1ff0"
}

rule MalwareBazaar_VShell_034_f7015ee8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a"
    family = "VShell"
    file_name = "f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:44:22"
  condition:
    hash.sha256(0, filesize) == "f7015ee8de9f30f151d6f6c64fc7eee072af3b9f033f88f1bfe2aaf76dcc0f3a"
}

rule MalwareBazaar_unknown_035_b4cce37e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e"
    family = "unknown"
    file_name = "b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:40:01"
  condition:
    hash.sha256(0, filesize) == "b4cce37e7607ed6c3dcbb3248131c9aa37a200157d2b106cd3323443c41e857e"
}

rule MalwareBazaar_unknown_036_b48c8316
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48c831677227ef7465d3421b89748b6783d83e3f0eeaf5a918337faf8a05516"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-11 00:29:16"
  condition:
    hash.sha256(0, filesize) == "b48c831677227ef7465d3421b89748b6783d83e3f0eeaf5a918337faf8a05516"
}

rule MalwareBazaar_unknown_037_169298ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "169298ed649518bbc5a2dde2ee10ec51d034c34d3363b83e3aae0f66561e85c2"
    family = "unknown"
    file_name = "Betalernes.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 00:24:29"
  condition:
    hash.sha256(0, filesize) == "169298ed649518bbc5a2dde2ee10ec51d034c34d3363b83e3aae0f66561e85c2"
}

rule MalwareBazaar_ConnectWise_038_829fb6a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9"
    family = "ConnectWise"
    file_name = "829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:24:15"
  condition:
    hash.sha256(0, filesize) == "829fb6a87053a889d41cc7686073e3cd31b05199c4e6b7d83ac620429cdb64f9"
}

rule MalwareBazaar_unknown_039_f70398b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28"
    family = "unknown"
    file_name = "f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:15:50"
  condition:
    hash.sha256(0, filesize) == "f70398b06589c320a1794a603abdb394890fe04166da190380c7b0b003148a28"
}

rule MalwareBazaar_unknown_040_c1f252ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329"
    family = "unknown"
    file_name = "c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:15:32"
  condition:
    hash.sha256(0, filesize) == "c1f252ac1e2eb74611c0bcb7568ee37967688e1d3b9a8cb15f06259e377ee329"
}

rule MalwareBazaar_unknown_041_a92c3356
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287"
    family = "unknown"
    file_name = "a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:15:15"
  condition:
    hash.sha256(0, filesize) == "a92c33568de0e5cd0d1fc8e9a11cd263a844a041a7c6af0e74702090c6f63287"
}

rule MalwareBazaar_unknown_042_197ca9f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "197ca9f27aeb1c6552140113bd0040d14668c26f0eedb53de97fbe85adbfffeb"
    family = "unknown"
    file_name = "Lovgivendes.vbs"
    file_type = "vbs"
    first_seen = "2026-09-11 00:15:14"
  condition:
    hash.sha256(0, filesize) == "197ca9f27aeb1c6552140113bd0040d14668c26f0eedb53de97fbe85adbfffeb"
}

rule MalwareBazaar_unknown_043_a7aaea31
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3"
    family = "unknown"
    file_name = "a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:57"
  condition:
    hash.sha256(0, filesize) == "a7aaea314591d7774926bf15ba1028b52710dd55567db3f64ea710b546cc8db3"
}

rule MalwareBazaar_unknown_044_7c003fcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca"
    family = "unknown"
    file_name = "7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:40"
  condition:
    hash.sha256(0, filesize) == "7c003fcb8152be894923225d630e7103a4f7d592ef59b9c7bcca19070380bbca"
}

rule MalwareBazaar_VShell_045_63a406d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5"
    family = "VShell"
    file_name = "63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:14:38"
  condition:
    hash.sha256(0, filesize) == "63a406d6fb2be2206a48d451ecd67e3ef9199dec0e0cff60583e713fd4401df5"
}

rule MalwareBazaar_VShell_046_9ce8e6ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0"
    family = "VShell"
    file_name = "9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:14:35"
  condition:
    hash.sha256(0, filesize) == "9ce8e6ed0c77eb573469d826cc752d284918ab4fa254adf054fd3de245ddf9d0"
}

rule MalwareBazaar_unknown_047_6e0d6c8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c"
    family = "unknown"
    file_name = "6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:23"
  condition:
    hash.sha256(0, filesize) == "6e0d6c8d02bbb95ae463754fba319c7bd7c9fcfc2433c90974e851b2c224df8c"
}

rule MalwareBazaar_unknown_048_55a62476
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a"
    family = "unknown"
    file_name = "55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:14:06"
  condition:
    hash.sha256(0, filesize) == "55a6247650a59791da551c3054caa28bbb8bdbe7ae4a62d11a2142acd7748e8a"
}

rule MalwareBazaar_unknown_049_41d5d05e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1"
    family = "unknown"
    file_name = "41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:13:48"
  condition:
    hash.sha256(0, filesize) == "41d5d05ebc7d59fd1566c045e855d1e504a309ee83f6c001c53abe2c1aeb3ea1"
}

rule MalwareBazaar_unknown_050_37f56fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f"
    family = "unknown"
    file_name = "37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:13:31"
  condition:
    hash.sha256(0, filesize) == "37f56fd97af1e3bb0fc9dababd806ea9d2dc6ac9a625dc165bba911716e6ff9f"
}

rule MalwareBazaar_unknown_051_2a2c3fec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503"
    family = "unknown"
    file_name = "2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:13:13"
  condition:
    hash.sha256(0, filesize) == "2a2c3fec2bab0b2c8d716e184740faec6af526ec6d4f2d909d00dfcaf205e503"
}

rule MalwareBazaar_unknown_052_12edefda
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6"
    family = "unknown"
    file_name = "12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:12:56"
  condition:
    hash.sha256(0, filesize) == "12edefda136640606e304f5e22eb7779b7d5576bd7ded350b5e2c2f66bb984c6"
}

rule MalwareBazaar_unknown_053_021b737b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062"
    family = "unknown"
    file_name = "021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062.bin"
    file_type = "unknown"
    first_seen = "2026-09-11 00:12:39"
  condition:
    hash.sha256(0, filesize) == "021b737b3e5ae81c30111587c2b109a20205b33a2c13220491a402e892e4c062"
}

rule MalwareBazaar_unknown_054_f016a21e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d"
    family = "unknown"
    file_name = "f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d"
    file_type = "elf"
    first_seen = "2026-09-11 00:10:04"
  condition:
    hash.sha256(0, filesize) == "f016a21e0132c7422ef77e2e0232899d53ec3e8c07c99803e94158c85196623d"
}

rule MalwareBazaar_njrat_055_e60b08b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab"
    family = "njrat"
    file_name = "e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:09:52"
  condition:
    hash.sha256(0, filesize) == "e60b08b9f64d2d74593a081c5cdc9f82efd76af53fd9b42cab5bef3888e1b5ab"
}

rule MalwareBazaar_VShell_056_6ae3d6fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d"
    family = "VShell"
    file_name = "6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:09:47"
  condition:
    hash.sha256(0, filesize) == "6ae3d6fb2cf1eba4b8889ae3da6e2a79786c7e3073e40aeae1962dd416f01b7d"
}

rule MalwareBazaar_VShell_057_aa75d6c8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e"
    family = "VShell"
    file_name = "aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e.exe"
    file_type = "exe"
    first_seen = "2026-09-11 00:09:43"
  condition:
    hash.sha256(0, filesize) == "aa75d6c809b96790c6337880c7792340383519050d5dd1384efcff89aca3477e"
}

rule MalwareBazaar_unknown_058_49bfdba4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "49bfdba40d37aa9dcbd98d64744bbd1ce30a52527a2c4501dffe83c67ccc04e7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-10 23:48:40"
  condition:
    hash.sha256(0, filesize) == "49bfdba40d37aa9dcbd98d64744bbd1ce30a52527a2c4501dffe83c67ccc04e7"
}

rule MalwareBazaar_unknown_059_57825a9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57825a9b5cb3a9fae14a4ed1338fb5e18d09522083ebc59079a4426b90deb078"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 23:11:25"
  condition:
    hash.sha256(0, filesize) == "57825a9b5cb3a9fae14a4ed1338fb5e18d09522083ebc59079a4426b90deb078"
}

rule MalwareBazaar_Mirai_060_95e59654
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "95e59654363348b1a8a938a540bbb5c3568b7f4fe8889981df11ba336e684c70"
    family = "Mirai"
    file_name = "titan.sh4"
    file_type = "elf"
    first_seen = "2026-09-10 23:03:31"
  condition:
    hash.sha256(0, filesize) == "95e59654363348b1a8a938a540bbb5c3568b7f4fe8889981df11ba336e684c70"
}

rule MalwareBazaar_unknown_061_3a2ffd67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2ffd6778cb05e07f29548115ce05a6fb517da58859ae21a6a9da13a225dbb8"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-10 22:57:01"
  condition:
    hash.sha256(0, filesize) == "3a2ffd6778cb05e07f29548115ce05a6fb517da58859ae21a6a9da13a225dbb8"
}

rule MalwareBazaar_unknown_062_12001643
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "120016439fae62b789b9fa9ffb92c5ce101eeb39a2a463375b35399d0772bafc"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-10 22:52:29"
  condition:
    hash.sha256(0, filesize) == "120016439fae62b789b9fa9ffb92c5ce101eeb39a2a463375b35399d0772bafc"
}

rule MalwareBazaar_Mirai_063_34c917a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620"
    family = "Mirai"
    file_name = "titan.x32"
    file_type = "elf"
    first_seen = "2026-09-10 22:48:58"
  condition:
    hash.sha256(0, filesize) == "34c917a284c6c118b54132c49c1cf7b40653c147ad74523c710c044f1f98d620"
}

rule MalwareBazaar_unknown_064_c87f3de3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c87f3de339e04c475797bd29a1505ca69cc3ddd1d9fc3639847bd9bb1cd973fe"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-10 22:25:39"
  condition:
    hash.sha256(0, filesize) == "c87f3de339e04c475797bd29a1505ca69cc3ddd1d9fc3639847bd9bb1cd973fe"
}

rule MalwareBazaar_unknown_065_bf98d3c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf98d3c0dfd79f8a433876fd9b9148cb95bc8a1254e7c1bda6ba4c0c66cbf00f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-10 22:00:00"
  condition:
    hash.sha256(0, filesize) == "bf98d3c0dfd79f8a433876fd9b9148cb95bc8a1254e7c1bda6ba4c0c66cbf00f"
}

rule MalwareBazaar_Mirai_066_a0728a70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0728a70bf9817b016d28e65090293e3fcd99825db92fc91044f985a479de885"
    family = "Mirai"
    file_name = "titan.ppc440"
    file_type = "elf"
    first_seen = "2026-09-10 21:46:37"
  condition:
    hash.sha256(0, filesize) == "a0728a70bf9817b016d28e65090293e3fcd99825db92fc91044f985a479de885"
}

rule MalwareBazaar_Mirai_067_98f66f2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98f66f2bb6de3fb755ceac5b1a38fd3e45ad1727e825e7b11865dc67f4a00bf0"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-09-10 21:37:33"
  condition:
    hash.sha256(0, filesize) == "98f66f2bb6de3fb755ceac5b1a38fd3e45ad1727e825e7b11865dc67f4a00bf0"
}

rule MalwareBazaar_unknown_068_81905a4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81905a4e04a59b225dd0437cc23804a2f417fe760e0b3b320beaa07d23bd9daa"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-10 21:29:32"
  condition:
    hash.sha256(0, filesize) == "81905a4e04a59b225dd0437cc23804a2f417fe760e0b3b320beaa07d23bd9daa"
}

rule MalwareBazaar_unknown_069_93488f44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93488f440d49aa01f7af8c85bb5b379a9d678030c0577a95b3e8f6499b4f3709"
    family = "unknown"
    file_name = "goodthingsforbestpersonforme.hta"
    file_type = "hta"
    first_seen = "2026-09-10 21:27:33"
  condition:
    hash.sha256(0, filesize) == "93488f440d49aa01f7af8c85bb5b379a9d678030c0577a95b3e8f6499b4f3709"
}

rule MalwareBazaar_unknown_070_186a6db3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "186a6db335efde574d407a28c95d28b52508bca07f3214f44f136b336fd9436c"
    family = "unknown"
    file_name = "vywerrzo27.hta"
    file_type = "unknown"
    first_seen = "2026-09-10 21:19:33"
  condition:
    hash.sha256(0, filesize) == "186a6db335efde574d407a28c95d28b52508bca07f3214f44f136b336fd9436c"
}

rule MalwareBazaar_unknown_071_279fa88c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "279fa88c40a4d0036aef618c8a445f5936727418835394908db0f1b4507d89ff"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 21:07:42"
  condition:
    hash.sha256(0, filesize) == "279fa88c40a4d0036aef618c8a445f5936727418835394908db0f1b4507d89ff"
}

rule MalwareBazaar_MassLogger_072_f840ab67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f840ab670cff8c5a85b52a8133ad961aa8863abca0bcb1f12de1012e48d38dfb"
    family = "MassLogger"
    file_name = "Debit note#202490304-01.exe"
    file_type = "exe"
    first_seen = "2026-09-10 20:46:19"
  condition:
    hash.sha256(0, filesize) == "f840ab670cff8c5a85b52a8133ad961aa8863abca0bcb1f12de1012e48d38dfb"
}

rule MalwareBazaar_unknown_073_ca8104bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca8104bc7a7ec934e700a7d9b0e7a3e4b22fb4495d036f1b6463d7c6c54211d5"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 20:08:00"
  condition:
    hash.sha256(0, filesize) == "ca8104bc7a7ec934e700a7d9b0e7a3e4b22fb4495d036f1b6463d7c6c54211d5"
}

rule MalwareBazaar_unknown_074_d66895d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d66895d8da6d5eb1d8658647c80f66dce40236c06bb600f1c62a44a657f923b3"
    family = "unknown"
    file_name = "SafeWatch.msix"
    file_type = "zip"
    first_seen = "2026-09-10 19:42:19"
  condition:
    hash.sha256(0, filesize) == "d66895d8da6d5eb1d8658647c80f66dce40236c06bb600f1c62a44a657f923b3"
}

rule MalwareBazaar_unknown_075_8a9006cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a9006cfaee227415eeef0d645183ca423c80b9a8181e35a57bec71468e72daa"
    family = "unknown"
    file_name = "PrivacyKeeper.msix"
    file_type = "zip"
    first_seen = "2026-09-10 19:42:02"
  condition:
    hash.sha256(0, filesize) == "8a9006cfaee227415eeef0d645183ca423c80b9a8181e35a57bec71468e72daa"
}

rule MalwareBazaar_unknown_076_8de13574
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8de1357454488bd0702f0f22e912b412af41d814dffdc7c76f416d75d7dc1dc6"
    family = "unknown"
    file_name = "SecuredWeb.appinstaller"
    file_type = "unknown"
    first_seen = "2026-09-10 19:41:36"
  condition:
    hash.sha256(0, filesize) == "8de1357454488bd0702f0f22e912b412af41d814dffdc7c76f416d75d7dc1dc6"
}

rule MalwareBazaar_unknown_077_b8f0c828
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8f0c82894032766293b7f6e6feaf287a366edd4886b8e665c41bc5103d512ce"
    family = "unknown"
    file_name = "PrivacyKeeper.appinstaller"
    file_type = "unknown"
    first_seen = "2026-09-10 19:41:30"
  condition:
    hash.sha256(0, filesize) == "b8f0c82894032766293b7f6e6feaf287a366edd4886b8e665c41bc5103d512ce"
}

rule MalwareBazaar_Mirai_078_47088ba9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9"
    family = "Mirai"
    file_name = "47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9"
    file_type = "elf"
    first_seen = "2026-09-10 19:24:01"
  condition:
    hash.sha256(0, filesize) == "47088ba906f0633c9887e35dd2394d9587dea5da0e557dc290986237184fa3a9"
}

rule MalwareBazaar_Mirai_079_1cf42fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329"
    family = "Mirai"
    file_name = "1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:59"
  condition:
    hash.sha256(0, filesize) == "1cf42fc4fe44fda09cbdaf754ae9589ab7690b1078467a465f23b86c0a28e329"
}

rule MalwareBazaar_Mirai_080_254fcb12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752"
    family = "Mirai"
    file_name = "254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:57"
  condition:
    hash.sha256(0, filesize) == "254fcb123b2574664ecc127e02e842eb8996095dc4c7788eeb446a6822bb8752"
}

rule MalwareBazaar_Mirai_081_77820b9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286"
    family = "Mirai"
    file_name = "77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:56"
  condition:
    hash.sha256(0, filesize) == "77820b9edff723a4c6ad8752c1cc5b443fccf57aaca82944598e28a847508286"
}

rule MalwareBazaar_Mirai_082_9ce6baac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c"
    family = "Mirai"
    file_name = "9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c"
    file_type = "elf"
    first_seen = "2026-09-10 19:23:54"
  condition:
    hash.sha256(0, filesize) == "9ce6baace15dff75745ab8028f5d49dcc18082e7110dc035fa20328a4d2c935c"
}

rule MalwareBazaar_Mirai_083_ce973eac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670"
    family = "Mirai"
    file_name = "ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670"
    file_type = "sh"
    first_seen = "2026-09-10 19:23:52"
  condition:
    hash.sha256(0, filesize) == "ce973eacc5546aa7bac9850c4f0d80fd9eb5323ebc09c7bdda433d00e313d670"
}

rule MalwareBazaar_unknown_084_3019ba8e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3019ba8ec2449305d0afb051b4ef3cee7071fefd3e5c6c3205fff5ce3da7dcb2"
    family = "unknown"
    file_name = "b"
    file_type = "unknown"
    first_seen = "2026-09-10 19:10:59"
  condition:
    hash.sha256(0, filesize) == "3019ba8ec2449305d0afb051b4ef3cee7071fefd3e5c6c3205fff5ce3da7dcb2"
}

rule MalwareBazaar_unknown_085_06ac3263
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06ac3263016366029d5875f3242a6a46a4801a2a37501c6b2e5992295b52dfd6"
    family = "unknown"
    file_name = "0ce3cebbf09f2b0b.js"
    file_type = "js"
    first_seen = "2026-09-10 19:09:54"
  condition:
    hash.sha256(0, filesize) == "06ac3263016366029d5875f3242a6a46a4801a2a37501c6b2e5992295b52dfd6"
}

rule MalwareBazaar_unknown_086_a2fc403d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2fc403da369d8906e27f4899b9c87bab2b9343b17a95516e221da0fb0ba7a15"
    family = "unknown"
    file_name = "4pi3llms81.hta"
    file_type = "unknown"
    first_seen = "2026-09-10 19:08:33"
  condition:
    hash.sha256(0, filesize) == "a2fc403da369d8906e27f4899b9c87bab2b9343b17a95516e221da0fb0ba7a15"
}

rule MalwareBazaar_unknown_087_e3ac3cff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32"
    family = "unknown"
    file_name = "e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32"
    file_type = "sh"
    first_seen = "2026-09-10 19:00:16"
  condition:
    hash.sha256(0, filesize) == "e3ac3cffebd0089e011b524e399f02cfe444d55a57c3f1b13cf1676baf87eb32"
}

rule MalwareBazaar_CoinMiner_088_e5a665da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5a665da69d6ee08e46566dd1048c25554bdf620f63a152758a11cd1d9e6d634"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-10 18:39:29"
  condition:
    hash.sha256(0, filesize) == "e5a665da69d6ee08e46566dd1048c25554bdf620f63a152758a11cd1d9e6d634"
}

rule MalwareBazaar_Mirai_089_66fbd782
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66fbd782f3a7bdbf9ab71f08d7c9cd2d938e4ae6d584967214787f64fd1dd4f6"
    family = "Mirai"
    file_name = "mirai.mipsel"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:43"
  condition:
    hash.sha256(0, filesize) == "66fbd782f3a7bdbf9ab71f08d7c9cd2d938e4ae6d584967214787f64fd1dd4f6"
}

rule MalwareBazaar_unknown_090_20494d7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20494d7c6537bc60a076bc7583a6a1eb07720bbe408708e6d2aec8717377de3b"
    family = "unknown"
    file_name = "tiny_bot.mipsel"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:41"
  condition:
    hash.sha256(0, filesize) == "20494d7c6537bc60a076bc7583a6a1eb07720bbe408708e6d2aec8717377de3b"
}

rule MalwareBazaar_Mirai_091_c459207f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c459207f8f9e5810cbde75ee5de0440a146cf9d57f765ed434171ce4192deed1"
    family = "Mirai"
    file_name = "mirai.mips"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:40"
  condition:
    hash.sha256(0, filesize) == "c459207f8f9e5810cbde75ee5de0440a146cf9d57f765ed434171ce4192deed1"
}

rule MalwareBazaar_unknown_092_33e40619
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "33e406193df703b518a6ab20e0dc296bb82776361b3bc65a1b6bb50a83c29b0a"
    family = "unknown"
    file_name = "tiny_bot.mips"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:38"
  condition:
    hash.sha256(0, filesize) == "33e406193df703b518a6ab20e0dc296bb82776361b3bc65a1b6bb50a83c29b0a"
}

rule MalwareBazaar_unknown_093_c829d0e3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c829d0e33ceaa65cf5063682e306e654a29d68fd2e604f300e0abc777b7ce717"
    family = "unknown"
    file_name = "tiny_bot.arm7"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:37"
  condition:
    hash.sha256(0, filesize) == "c829d0e33ceaa65cf5063682e306e654a29d68fd2e604f300e0abc777b7ce717"
}

rule MalwareBazaar_unknown_094_254a26c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "254a26c23115f6f363ad11d29d7d9f4b0b284edebb122960f5aa43c28b625d70"
    family = "unknown"
    file_name = "tiny_bot.arm64"
    file_type = "elf"
    first_seen = "2026-09-10 18:37:35"
  condition:
    hash.sha256(0, filesize) == "254a26c23115f6f363ad11d29d7d9f4b0b284edebb122960f5aa43c28b625d70"
}

rule MalwareBazaar_unknown_095_6fe242f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe242f8b01c1bc25acc08db4b041d984f4c3dcbd1ea2dd4827657a8da2740a6"
    family = "unknown"
    file_name = "tiny_bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:06"
  condition:
    hash.sha256(0, filesize) == "6fe242f8b01c1bc25acc08db4b041d984f4c3dcbd1ea2dd4827657a8da2740a6"
}

rule MalwareBazaar_unknown_096_2b2525b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b2525b502443927ee21bc21726fcafc533b96883d30dbeb97569decec550f42"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:05"
  condition:
    hash.sha256(0, filesize) == "2b2525b502443927ee21bc21726fcafc533b96883d30dbeb97569decec550f42"
}

rule MalwareBazaar_unknown_097_65b25aa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65b25aa01a1fc7cc0cb5a6df0944980c7391062f698414b95f16111cb0db5498"
    family = "unknown"
    file_name = "mips-bk"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:03"
  condition:
    hash.sha256(0, filesize) == "65b25aa01a1fc7cc0cb5a6df0944980c7391062f698414b95f16111cb0db5498"
}

rule MalwareBazaar_unknown_098_a2e58adc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2e58adc8bca368b22b94c4b1a375ab96b19731fc82072abfe229772d5ff2ebf"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:02"
  condition:
    hash.sha256(0, filesize) == "a2e58adc8bca368b22b94c4b1a375ab96b19731fc82072abfe229772d5ff2ebf"
}

rule MalwareBazaar_Mirai_099_060f1a11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "060f1a11d5bcd55f7e3a22c6f82a07d74496de607939e5d26a99baaebf564e49"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-09-10 18:36:01"
  condition:
    hash.sha256(0, filesize) == "060f1a11d5bcd55f7e3a22c6f82a07d74496de607939e5d26a99baaebf564e49"
}

rule MalwareBazaar_unknown_100_b7d6a863
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7d6a8638f8acb69b2e287f939136d4da4137aca37f47ee452e166e5f30e2320"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-09-10 18:35:59"
  condition:
    hash.sha256(0, filesize) == "b7d6a8638f8acb69b2e287f939136d4da4137aca37f47ee452e166e5f30e2320"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

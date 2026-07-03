# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-03

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 626 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 626 |
| Unique family labels | 14 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 49 |
| Mirai | 27 |
| Gafgyt | 11 |
| WannaCry | 2 |
| Prometei | 2 |
| MaskGramStealer | 1 |
| CoinMiner | 1 |
| Formbook | 1 |
| AgentTesla | 1 |
| SalatStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 49 |
| apk | 18 |
| sh | 16 |
| exe | 12 |
| js | 2 |
| unknown | 2 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `0275c6cf588a7e26`

| Field | Value |
|---|---|
| SHA-256 | `0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86` |
| Family label | `MaskGramStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 04:05:09` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, MaskGramStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1cc183b4feb7f01efb4e39d1465c323` |
| SHA-1 | `3e49d1d2f401a5bbfc33926fee77b30f0c5f8f67` |
| SHA-256 | `0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86` |
| SHA3-384 | `902defa771c5f377e7437ea893eeb34018293dd383ce88ca87425738e58dc34db4cfa82f61703d4657b366687e8835d1` |
| IMPHASH | `d1c35276ff2b8e9d448afb940bccb1f0` |
| TLSH | `T120044A5BD8D540EDEC1AC6748999E237A8B2F85A1936BA4F1BA0DF061F90B30771DF04` |
| SSDEEP | `3072:crNBN2eWx8Adi2MdtBcdEOPn9SL5g3QJTw9wAu7TkJgY/r:Wydt8tBc+Olo5gUw9w5WgY/` |

#### Technical Assessment

- The sample is tracked as `MaskGramStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_MaskGramStealer_001_0275c6cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 04:05:09"
  condition:
    hash.sha256(0, filesize) == "0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86"
}
```

### Sample 2: `d2a8fc67ee43ce1b`

| Field | Value |
|---|---|
| SHA-256 | `d2a8fc67ee43ce1bf1af64da8cf5798a81303121fae64e2dfd1386f483ce55ba` |
| Family label | `unknown` |
| File name | `DiscordThemeTest#2.exe` |
| File type | `exe` |
| First seen | `2026-07-03 03:59:41` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5c38c0a8c4444f9c37f4b56b6c5138e` |
| SHA-1 | `b16e3a1c2333ecebdf35ca7afbe36bcd4938a49d` |
| SHA-256 | `d2a8fc67ee43ce1bf1af64da8cf5798a81303121fae64e2dfd1386f483ce55ba` |
| SHA3-384 | `b3e67f21b01eff547b286f59a824df0451277bf4d4b4dd331325fe9ceb12b6f6c3dfdc6612b1ee03e2ada849d793d04e` |
| IMPHASH | `4ec7a9af8aea061f5934796a877e8f55` |
| TLSH | `T1DC76333264E08479E4EA2B7E4639CBF4693E76150720EDCB53D82879C613AC1763D7E2` |
| SSDEEP | `196608:cxajcbr+7JdWs/KdmdO5XiO8ZAJqAa2+r94iOpjb4:cxycf+7JBNdYXy0VYGRw` |
| ICON-DHASH | `c6c2ccc4f4e0e0f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_d2a8fc67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a8fc67ee43ce1bf1af64da8cf5798a81303121fae64e2dfd1386f483ce55ba"
    family = "unknown"
    file_name = "DiscordThemeTest#2.exe"
    file_type = "exe"
    first_seen = "2026-07-03 03:59:41"
  condition:
    hash.sha256(0, filesize) == "d2a8fc67ee43ce1bf1af64da8cf5798a81303121fae64e2dfd1386f483ce55ba"
}
```

### Sample 3: `d6d1f2dd6db3177c`

| Field | Value |
|---|---|
| SHA-256 | `d6d1f2dd6db3177ccbde0fe17170cc4fa81078d1a9a900f1f5dd73ddce5f06e6` |
| Family label | `unknown` |
| File name | `app(4).apk` |
| File type | `apk` |
| First seen | `2026-07-03 03:08:21` |
| Reporter | `BastianHein_` |
| Tags | `apk, mparivahan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e044aa1347523b51bd989a427851f68f` |
| SHA-1 | `ef0a818e4a43fbe061993bee655640bd230fc5d2` |
| SHA-256 | `d6d1f2dd6db3177ccbde0fe17170cc4fa81078d1a9a900f1f5dd73ddce5f06e6` |
| SHA3-384 | `69fe451ec74f69b0547488ae17b19a603cfe22a88ef9fe7827b07ed47a4a090bab54de2b136e6c5ff24fd96bcc41ace7` |
| TLSH | `T19D56E14BA745569AC4FA83B90C3732251D477D214BA38287DB2C3E3C687B5F48E979C8` |
| SSDEEP | `98304:BahN44Rt0vyaN470sxdBYhMvkzd/HmuODiMpjIoWeB1hdao9u9+6TYkXGaytbhoq:Bab6DyFdBKMEGLDDhD5uo9QEkXYNJ3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_d6d1f2dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6d1f2dd6db3177ccbde0fe17170cc4fa81078d1a9a900f1f5dd73ddce5f06e6"
    family = "unknown"
    file_name = "app(4).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:08:21"
  condition:
    hash.sha256(0, filesize) == "d6d1f2dd6db3177ccbde0fe17170cc4fa81078d1a9a900f1f5dd73ddce5f06e6"
}
```

### Sample 4: `ca9ae76de1945487`

| Field | Value |
|---|---|
| SHA-256 | `ca9ae76de194548709966263c227709d5c57c8e57f07f50d1532cf52fc5f438d` |
| Family label | `unknown` |
| File name | `app(3).apk` |
| File type | `apk` |
| First seen | `2026-07-03 03:08:04` |
| Reporter | `BastianHein_` |
| Tags | `apk, mparivahan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bf8e9415f1aeae1edb06a19f9b49a71` |
| SHA-1 | `e21330f6f9b3fd20a6f29c6fbb53677c36adbc99` |
| SHA-256 | `ca9ae76de194548709966263c227709d5c57c8e57f07f50d1532cf52fc5f438d` |
| SHA3-384 | `37a946b83b4962bf441b6525d1f36f7c7ca02c0199eb152b405f2069a9cb56080584dd522db394f45deec5d04f4f0391` |
| TLSH | `T13556E04BE741565AC4FA82B91C3736251D477D214BA3828BDB2C3E3C687B1F48E979C8` |
| SSDEEP | `98304:A0dxcNxc/pOl5UcF+/A6BZTyxU+N9Hg407iqpkUoyJpThdaC9AnIeUlsm1LhJ2uU:A0jcNxc/Ul5uA6BhylAX7ZWvA+C9fdw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_ca9ae76d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca9ae76de194548709966263c227709d5c57c8e57f07f50d1532cf52fc5f438d"
    family = "unknown"
    file_name = "app(3).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:08:04"
  condition:
    hash.sha256(0, filesize) == "ca9ae76de194548709966263c227709d5c57c8e57f07f50d1532cf52fc5f438d"
}
```

### Sample 5: `84ddfdd7862e3c34`

| Field | Value |
|---|---|
| SHA-256 | `84ddfdd7862e3c3481ae65b64d9087ab7c5c29355a29e9e7c3a4011a631f7387` |
| Family label | `unknown` |
| File name | `app(2).apk` |
| File type | `apk` |
| First seen | `2026-07-03 03:07:50` |
| Reporter | `BastianHein_` |
| Tags | `apk, mparivahan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ee0e3f5d62aa50c8fb91c59e15d71a4` |
| SHA-1 | `2b0cf7ea9cdd7905565e02a9a35def1291bdba45` |
| SHA-256 | `84ddfdd7862e3c3481ae65b64d9087ab7c5c29355a29e9e7c3a4011a631f7387` |
| SHA3-384 | `04951da5ebf3a9cc48fbea3d24d4a20a444e7a0c543c075c4f5b18c15ce552dafc5766e3e48b9d8f7ed5c5789d1cfdfd` |
| TLSH | `T16776F14BE741565AC4F987B91C3732251D477C214BA3868BDB2C3E38687B5F08E97AC8` |
| SSDEEP | `196608:IabbmIopeU96Ijli6cS9w2+A8LntlY1XLcqe:IafmIgf9nli6cGH8LrY1bU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_84ddfdd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84ddfdd7862e3c3481ae65b64d9087ab7c5c29355a29e9e7c3a4011a631f7387"
    family = "unknown"
    file_name = "app(2).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:07:50"
  condition:
    hash.sha256(0, filesize) == "84ddfdd7862e3c3481ae65b64d9087ab7c5c29355a29e9e7c3a4011a631f7387"
}
```

### Sample 6: `cb7744fe6345dd0e`

| Field | Value |
|---|---|
| SHA-256 | `cb7744fe6345dd0e4f15f1acdde23ecb6d484b3c8a6ce8792628a6a1453eefa4` |
| Family label | `unknown` |
| File name | `app(1).apk` |
| File type | `apk` |
| First seen | `2026-07-03 03:07:36` |
| Reporter | `BastianHein_` |
| Tags | `apk, mparivahan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb63a912c5765addf3d30a1db8d01252` |
| SHA-1 | `7b52441aeb89988a642349327b66a52e541d5df6` |
| SHA-256 | `cb7744fe6345dd0e4f15f1acdde23ecb6d484b3c8a6ce8792628a6a1453eefa4` |
| SHA3-384 | `651ebb663fe221e8f948e5c2e43ed6d54f1d21515577b79ea2bdd8bd73874a52d91324d7996a6316ee7c472313844354` |
| TLSH | `T1FE56E18BE745565AC4F982B90C3736251D477D214BA3828BDB2C3E3C687B1F48E979C8` |
| SSDEEP | `98304:AaaCVfzs5U+48Sn0QVojNjwGfDiWpm/oOLjchdYq9+cjTTRYjE08zfhSEk6n:Aa5ad4L05MqDVoAnsq99yg5Sin` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_cb7744fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb7744fe6345dd0e4f15f1acdde23ecb6d484b3c8a6ce8792628a6a1453eefa4"
    family = "unknown"
    file_name = "app(1).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:07:36"
  condition:
    hash.sha256(0, filesize) == "cb7744fe6345dd0e4f15f1acdde23ecb6d484b3c8a6ce8792628a6a1453eefa4"
}
```

### Sample 7: `fca210ed8b28a954`

| Field | Value |
|---|---|
| SHA-256 | `fca210ed8b28a9544d0db5a8387fe75c26091003041220a9d28cb445e8169aad` |
| Family label | `unknown` |
| File name | `app.apk` |
| File type | `apk` |
| First seen | `2026-07-03 03:07:22` |
| Reporter | `BastianHein_` |
| Tags | `apk, Arsink, GhostBat, mparivahan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `986bc4bf920d7f572cca6715d3f31e93` |
| SHA-1 | `ea31131371f2307d03b5453c94aa333fcfd6b182` |
| SHA-256 | `fca210ed8b28a9544d0db5a8387fe75c26091003041220a9d28cb445e8169aad` |
| SHA3-384 | `1abd0fe101e4a2574ada9f100e7427b967a0e976440bbeec64608b23444f82d1cde2f810ab88c80ab67aa0bc894f3c45` |
| TLSH | `T139760148F7485A1AC8FB53361D7626211D8BBD168B83C6435B543E3C69BB5E00F9BACC` |
| SSDEEP | `196608:pRgUrwLubPZt54iHq6jwgBulJZmuhiy3NrCc8BvLlzA:vgnyzZnZmtJky3NOc8BjlzA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_fca210ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fca210ed8b28a9544d0db5a8387fe75c26091003041220a9d28cb445e8169aad"
    family = "unknown"
    file_name = "app.apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:07:22"
  condition:
    hash.sha256(0, filesize) == "fca210ed8b28a9544d0db5a8387fe75c26091003041220a9d28cb445e8169aad"
}
```

### Sample 8: `7286691d7986d2ba`

| Field | Value |
|---|---|
| SHA-256 | `7286691d7986d2ba342adfc68697a81a3c7050ccbcad3ca4600f4205993c6588` |
| Family label | `unknown` |
| File name | `armv7l.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 02:31:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de6a5be52b665c5fb7914892c4e7cac6` |
| SHA-1 | `a3e020fd83ef612a380b79a353d6d7e9c4f11345` |
| SHA-256 | `7286691d7986d2ba342adfc68697a81a3c7050ccbcad3ca4600f4205993c6588` |
| SHA3-384 | `c6cf90bcd07e132366454721e52ce751bf6f399be188590bd354ae2f386e59a5a1238e54c5b84f6b20543572aae51d68` |
| TLSH | `T1BDF31A5CF9418B5BC5D0257AF69B128C33724B24FFDA3B05DD146B283BD2B299E2B201` |
| SSDEEP | `3072:RqzNsnSVOr/P++DutK2ozamci7h26MRXvEiA0QMLX1:RPSVOr/G++oz/cZy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_7286691d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7286691d7986d2ba342adfc68697a81a3c7050ccbcad3ca4600f4205993c6588"
    family = "unknown"
    file_name = "armv7l.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 02:31:51"
  condition:
    hash.sha256(0, filesize) == "7286691d7986d2ba342adfc68697a81a3c7050ccbcad3ca4600f4205993c6588"
}
```

### Sample 9: `3d4d751665fc9f52`

| Field | Value |
|---|---|
| SHA-256 | `3d4d751665fc9f5247f34d7c3db5381d83c55cd1d49311b3570f2c002b36cb1e` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-03 02:30:37` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3dcad3fff390dcb7acbb7a379e3cdbcf` |
| SHA-1 | `39d84147173f4274b80a3a730d1ccf12ee91fdbc` |
| SHA-256 | `3d4d751665fc9f5247f34d7c3db5381d83c55cd1d49311b3570f2c002b36cb1e` |
| SHA3-384 | `4b12517f994ac27c73190d51d34ac29ed048063c32105afe77fed3c5a8c0e3e38f686c2919b202e85e7fe70bddd93f03` |
| IMPHASH | `efac5a148b2811065a6dd0ccd3f84052` |
| TLSH | `T19F76D013D5E68EF4C11BEABD8A625332AA14748C5E32B12C25E5F3665FF0E34A15DB30` |
| SSDEEP | `196608:A3FsbYYpSTgKKOxaSZoYvBvqmgmInErzvD:LYYpSTgKKOxaSZoGvSmInErzvD` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_009_3d4d7516
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d4d751665fc9f5247f34d7c3db5381d83c55cd1d49311b3570f2c002b36cb1e"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 02:30:37"
  condition:
    hash.sha256(0, filesize) == "3d4d751665fc9f5247f34d7c3db5381d83c55cd1d49311b3570f2c002b36cb1e"
}
```

### Sample 10: `a6264afd465d3a04`

| Field | Value |
|---|---|
| SHA-256 | `a6264afd465d3a04bc0594251771ca50e372a8d40068707a67830be581bb2c2b` |
| Family label | `Formbook` |
| File name | `Settlement Contract.pdf.exe` |
| File type | `exe` |
| First seen | `2026-07-03 02:17:44` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b131788c78be101415eb77a32a97866` |
| SHA-1 | `b8d2f8ead2d58c5ebf2d58e9fb29fa9f35f09217` |
| SHA-256 | `a6264afd465d3a04bc0594251771ca50e372a8d40068707a67830be581bb2c2b` |
| SHA3-384 | `34d7c922c08e8671931fdf00eab90328b92a30b63b8f20d7f47c96edd588f2abfab2a92f11b263a3df29eb8e40905e65` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AB3512541359CB06C4B34BF80A71D27487B8AEC8B926D20B9FDABDDFB97A7905414383` |
| SSDEEP | `24576:Ia6Uwla6M23FPhXlykEd0gMIfNmzqZk5D:Ia69YcFF2d0SfMzq2` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_010_a6264afd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6264afd465d3a04bc0594251771ca50e372a8d40068707a67830be581bb2c2b"
    family = "Formbook"
    file_name = "Settlement Contract.pdf.exe"
    file_type = "exe"
    first_seen = "2026-07-03 02:17:44"
  condition:
    hash.sha256(0, filesize) == "a6264afd465d3a04bc0594251771ca50e372a8d40068707a67830be581bb2c2b"
}
```

### Sample 11: `b60ce046f32587bc`

| Field | Value |
|---|---|
| SHA-256 | `b60ce046f32587bc6b87df4cd530c6728af82c482df2a3fe14c88d5fd252ca30` |
| Family label | `unknown` |
| File name | `mipsel.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 02:15:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dcb639debc37ac422ff510310bcbd02` |
| SHA-1 | `60c2ba144d76c92a104e213d5fb1622787505bc3` |
| SHA-256 | `b60ce046f32587bc6b87df4cd530c6728af82c482df2a3fe14c88d5fd252ca30` |
| SHA3-384 | `ad8b5e4c75cc52c5ad1c1edc779817cd907da102849bafd8a9b443dddd7ef07b0a91ba5601246792e71185afdf7f68ee` |
| TLSH | `T177141742EE811ABBC44ECF31415B838A12EDD48643FB571B6178C95E7E5EA0E1CC7E98` |
| TELFHASH | `t13501cb4db27909ab6df38264c8a50f65d283e85bb4f21a25db04fbc08276489d11fe0e` |
| SSDEEP | `3072:TF4CBlWO6z53AVchKREMIBQLxJuW48SEqWs6ILlHVW8+2nV8ga24+BeWDIhfgENZ:TSAchKABQLxJD9VqWPIp1WJQ2P` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_b60ce046
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60ce046f32587bc6b87df4cd530c6728af82c482df2a3fe14c88d5fd252ca30"
    family = "unknown"
    file_name = "mipsel.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 02:15:53"
  condition:
    hash.sha256(0, filesize) == "b60ce046f32587bc6b87df4cd530c6728af82c482df2a3fe14c88d5fd252ca30"
}
```

### Sample 12: `94faff7500a2f959`

| Field | Value |
|---|---|
| SHA-256 | `94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36` |
| Family label | `WannaCry` |
| File name | `94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36` |
| File type | `exe` |
| First seen | `2026-07-03 02:15:32` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `094cdc3550ebb0d6a7ad470eae50b506` |
| SHA-1 | `2135c244eea8e44b66050079b144a675ffbe118f` |
| SHA-256 | `94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36` |
| SHA3-384 | `a2de861bdb174933249fa7901d013635ffd1af8b31ef49a8847309f09c9ca0971f77b68d96c748ede99bd4fc10053ce7` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1B336235932BC91BCD106267484B78D26E7B33C9623FD5B0F4B844AAB0D13B59BB64B43` |
| SSDEEP | `49152:jnXnAQqMSPbcBVQej/1INRx+TSqTdX1HkQgv:DXDqPoBhz1aRxcSUDkB` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_012_94faff75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36"
    family = "WannaCry"
    file_name = "94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36"
    file_type = "exe"
    first_seen = "2026-07-03 02:15:32"
  condition:
    hash.sha256(0, filesize) == "94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36"
}
```

### Sample 13: `a2b929416dba2511`

| Field | Value |
|---|---|
| SHA-256 | `a2b929416dba251191a074ec1a186e696d279eaff6f4dba271a4b9a0ee228c82` |
| Family label | `unknown` |
| File name | `output_0yditfsf.js` |
| File type | `js` |
| First seen | `2026-07-03 02:01:20` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8ba7a8dc1449224d5812364c0bdf2a2` |
| SHA-1 | `b102b60800bf3e94ae62f28203962eb5f4013992` |
| SHA-256 | `a2b929416dba251191a074ec1a186e696d279eaff6f4dba271a4b9a0ee228c82` |
| SHA3-384 | `009fd0b72d775a6cdb11af5b2d187d3e119d34c011dc845a343705b594a224ac07f62e5fff3b364127065862be9d8617` |
| TLSH | `T10A85B1ACFA7931D45871CA535C65C101DB7BAA73192DAC0D22DA0B8C0E17E4BB96873F` |
| SSDEEP | `12288:q3yVGrOuQUn4uEVTJjpV9iJRqPP/V/EXYVMeasKSpwS5BenSpdQKip:q3y8iq4FoJUGXVsJXip` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_a2b92941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2b929416dba251191a074ec1a186e696d279eaff6f4dba271a4b9a0ee228c82"
    family = "unknown"
    file_name = "output_0yditfsf.js"
    file_type = "js"
    first_seen = "2026-07-03 02:01:20"
  condition:
    hash.sha256(0, filesize) == "a2b929416dba251191a074ec1a186e696d279eaff6f4dba271a4b9a0ee228c82"
}
```

### Sample 14: `7ccf139c5192acde`

| Field | Value |
|---|---|
| SHA-256 | `7ccf139c5192acdec6370f391801390935df872849212349f27f388b0a39674d` |
| Family label | `unknown` |
| File name | `powerpc.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 01:59:53` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a1eade10058a6cab8a99cc93583daf7` |
| SHA-1 | `7cfa17e555f9826a77c47b8d910032693155d835` |
| SHA-256 | `7ccf139c5192acdec6370f391801390935df872849212349f27f388b0a39674d` |
| SHA3-384 | `3a380738f80a44c86fc2a7c1165cc62031d17fa6d91a435ff0bc73759975dac7ca02718a683b513b7e874e88ae136a25` |
| TLSH | `T143046C23FF1C1423C4939E701D3B07E6D37594C242BAA60965096B291B33AF55D8BBBE` |
| SSDEEP | `3072:D0appabjyuyzvRpn9EqEtTJPsaGtQS1sFoEuo:YaWbjRsfn95EtTJPsaGtQa1i` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_7ccf139c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ccf139c5192acdec6370f391801390935df872849212349f27f388b0a39674d"
    family = "unknown"
    file_name = "powerpc.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:59:53"
  condition:
    hash.sha256(0, filesize) == "7ccf139c5192acdec6370f391801390935df872849212349f27f388b0a39674d"
}
```

### Sample 15: `770db614b0e7b3cd`

| Field | Value |
|---|---|
| SHA-256 | `770db614b0e7b3cd571f12eb94bc8b06c7c151f37c4ecc41656476bbb4d3084e` |
| Family label | `unknown` |
| File name | `lil` |
| File type | `sh` |
| First seen | `2026-07-03 01:59:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44f4dafb99216514a2d1476e4303f59f` |
| SHA-1 | `6ec536fa006254cfe7c1a10b096832e29b030c43` |
| SHA-256 | `770db614b0e7b3cd571f12eb94bc8b06c7c151f37c4ecc41656476bbb4d3084e` |
| SHA3-384 | `8128f3482d4b3533df4df30ceb48847c33b14b82155eea512a9e16cf7f181356ee04dfdfc1096024562d6e886bfce1ef` |
| TLSH | `T1E901C2C68650BD4080AADA1D25976458F861C3CF16468F74FF6C6D7DEBA8C04B027F98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaIjSIFD/X5yjVq9NOX:e9Qp+MsI2IFD/XExqNOX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_770db614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "770db614b0e7b3cd571f12eb94bc8b06c7c151f37c4ecc41656476bbb4d3084e"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-03 01:59:52"
  condition:
    hash.sha256(0, filesize) == "770db614b0e7b3cd571f12eb94bc8b06c7c151f37c4ecc41656476bbb4d3084e"
}
```

### Sample 16: `cfe32ce53eb6ec90`

| Field | Value |
|---|---|
| SHA-256 | `cfe32ce53eb6ec90806eba86f53c778f07879ef82a898b3d45f4d43af8de2761` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-03 01:55:51` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `93e5908865ff5e3ef981daddec661da7` |
| SHA-1 | `6a68a7049296a2ba638d7a6e4d423e45ed35d840` |
| SHA-256 | `cfe32ce53eb6ec90806eba86f53c778f07879ef82a898b3d45f4d43af8de2761` |
| SHA3-384 | `b95ee15cee7a716215ce1ac5e835db849f31a056699192e788e679ef65250225409665a5800e9b8d439bdff5335a64e7` |
| TLSH | `T1E8236C6516857C24AE99C4375C7F2F0CB9A983E6314491DDBFCA3CF28C49A9CE21871D` |
| SSDEEP | `768:cr9NyXsZztC29GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:6HusZmcB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_cfe32ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe32ce53eb6ec90806eba86f53c778f07879ef82a898b3d45f4d43af8de2761"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-03 01:55:51"
  condition:
    hash.sha256(0, filesize) == "cfe32ce53eb6ec90806eba86f53c778f07879ef82a898b3d45f4d43af8de2761"
}
```

### Sample 17: `876de7e7e43dbfac`

| Field | Value |
|---|---|
| SHA-256 | `876de7e7e43dbfacb7e37487d926eac189ddf717966e09fc439b986a20719b54` |
| Family label | `unknown` |
| File name | `x86_64.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 01:53:51` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2e9c80fbc26a5fecb938565c91c7726` |
| SHA-1 | `421f5a31b53c70188eaaf4603c1661d0461d28ef` |
| SHA-256 | `876de7e7e43dbfacb7e37487d926eac189ddf717966e09fc439b986a20719b54` |
| SHA3-384 | `492930f2e2014a712b13d7547ebe219527fae31ef54a61159e5906a1574b817de7cde50e4a87240dc9ddc85e9cb283b9` |
| TLSH | `T1D3A32A17AE91C0BEC08AD2745BDBD2B2F732F8A51221361F3354AA223FB1F951B18755` |
| SSDEEP | `1536:WmZwg5l0gs0sqSdV080/zEi90M1gAbfvLYKlorF8AaCML:WmZtQgniHOE20zAbyF+L` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_876de7e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "876de7e7e43dbfacb7e37487d926eac189ddf717966e09fc439b986a20719b54"
    family = "unknown"
    file_name = "x86_64.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:53:51"
  condition:
    hash.sha256(0, filesize) == "876de7e7e43dbfacb7e37487d926eac189ddf717966e09fc439b986a20719b54"
}
```

### Sample 18: `f8183b625153b4b0`

| Field | Value |
|---|---|
| SHA-256 | `f8183b625153b4b06f974c697d52a2d273a4e7d981f4f33e8ff27c203653f600` |
| Family label | `Mirai` |
| File name | `tmips` |
| File type | `elf` |
| First seen | `2026-07-03 01:53:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ab28916ee26d2982841b582fb7fd888d` |
| SHA-1 | `f56d49ece59f99523a875668390fc35067f0ab80` |
| SHA-256 | `f8183b625153b4b06f974c697d52a2d273a4e7d981f4f33e8ff27c203653f600` |
| SHA3-384 | `cc5dcbf73d6e7c674d19146131ac707bc208ee8979791688bc2c97975bd2f6bf4811575dcd3f342317f44d3de0120b9c` |
| TLSH | `T10EB3D81E2E219F7EF36DC2354BB74E25939823C627E1D685D25CEA005E7038D641FBA8` |
| TELFHASH | `t1a8114818493813f4d7b60d9d6bddfb76e49170df46215e378d00e96eab6d9069900c2c` |
| SSDEEP | `3072:uKY6AV7RBY0Rhj81E3Do8cErFQ+QsninsQg:uKY6AV7/Y0RhjU8cEKpoQg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_f8183b62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8183b625153b4b06f974c697d52a2d273a4e7d981f4f33e8ff27c203653f600"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-03 01:53:50"
  condition:
    hash.sha256(0, filesize) == "f8183b625153b4b06f974c697d52a2d273a4e7d981f4f33e8ff27c203653f600"
}
```

### Sample 19: `836da0de8ba87bd6`

| Field | Value |
|---|---|
| SHA-256 | `836da0de8ba87bd62b094e1b10f9fb6ffb8eee1be7bc4aedea73a40950fce2a3` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-03 01:49:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ce5b314c8b93e952e315ff3c5e8839c` |
| SHA-1 | `0b627f2cf4c43021eab0aec7dc76e0a993eb1978` |
| SHA-256 | `836da0de8ba87bd62b094e1b10f9fb6ffb8eee1be7bc4aedea73a40950fce2a3` |
| SHA3-384 | `e58692f18bfb3f989eea260c6ddc4711671619b631a99a55f4afc16fef1be636694712d18fe809e7b0b170a812058c9e` |
| TLSH | `T1A9A3865A3E21DFBEF56C82304BB78A20979823D626E0D685F25CD70C1E7124E585F7E8` |
| TELFHASH | `t1ce215108493817f0d7a15c9d6becff76e46170db5a265e33ce00fda9966d9429d00c2c` |
| SSDEEP | `1536:oaqPQeQTOrgA3TPxpCYvuvr/7T+IiHXgeY1JNIXLXRhALb:BdeQTOriYvuz/77iHXaIthALb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_836da0de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "836da0de8ba87bd62b094e1b10f9fb6ffb8eee1be7bc4aedea73a40950fce2a3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-03 01:49:49"
  condition:
    hash.sha256(0, filesize) == "836da0de8ba87bd62b094e1b10f9fb6ffb8eee1be7bc4aedea73a40950fce2a3"
}
```

### Sample 20: `122797288af9166c`

| Field | Value |
|---|---|
| SHA-256 | `122797288af9166cb10192292e0edf66abe21704010b5f93389a96860a614780` |
| Family label | `unknown` |
| File name | `aarch64.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 01:41:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `306e9a2a9886a7c2ec9d8f74f51074df` |
| SHA-1 | `b95a40ab0e7cef1e408d542f09c85e1ade20fd6d` |
| SHA-256 | `122797288af9166cb10192292e0edf66abe21704010b5f93389a96860a614780` |
| SHA3-384 | `9697c4027a383c5851f23bd008e419f844f05acb27d3ee4775fe7fb2b2e744c7602a9eaf50e4a210792d8e22fcc93c11` |
| TLSH | `T19A047D48B74CEB07C19093B79D6F0623633138567B4B87627A19361DEDE27EC9C2631A` |
| SSDEEP | `3072:DIdLXg+1gYsMmN4hWCiDSfQKVX0MmTGXM6TFQWuw/z/vJE+r:DyLg+1g4niG4KVkMLXM6xQWui7x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_12279728
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "122797288af9166cb10192292e0edf66abe21704010b5f93389a96860a614780"
    family = "unknown"
    file_name = "aarch64.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:41:55"
  condition:
    hash.sha256(0, filesize) == "122797288af9166cb10192292e0edf66abe21704010b5f93389a96860a614780"
}
```

### Sample 21: `674fc0b5ead7acd8`

| Field | Value |
|---|---|
| SHA-256 | `674fc0b5ead7acd834747c2a568ef218640b7787a2201d4724dd8d43292904ce` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-03 01:29:49` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06708897fa510f0dc35e3c2cf1ce8211` |
| SHA-1 | `96c2f631ebf5c45f152d36e0273f9a875ac3489d` |
| SHA-256 | `674fc0b5ead7acd834747c2a568ef218640b7787a2201d4724dd8d43292904ce` |
| SHA3-384 | `efa21258c61495a053175ca2da9d6da1003b61238313997b368c56c8e68c4f508c6c66a5ee725f05d344136ae59ff937` |
| TLSH | `T1DDD05E927663053050A24C15EAC77910B6285B7F5D94E32EB98716302F4575AB4907A5` |
| SSDEEP | `6:hTcFpW2cWo6pAulNXYq4HvXDG+NjVsNXYrkJ:VLv76pPiq4HvXDGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_674fc0b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "674fc0b5ead7acd834747c2a568ef218640b7787a2201d4724dd8d43292904ce"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-03 01:29:49"
  condition:
    hash.sha256(0, filesize) == "674fc0b5ead7acd834747c2a568ef218640b7787a2201d4724dd8d43292904ce"
}
```

### Sample 22: `6453182787fa76dc`

| Field | Value |
|---|---|
| SHA-256 | `6453182787fa76dc0043ca1fb77af822584066d02b1491b25ae042a40b140901` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-03 01:27:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7fc768b36e73fad53a00d4101cb62f3` |
| SHA-1 | `ae64d1cca4b098304fc0ac00aa382019f0431c2e` |
| SHA-256 | `6453182787fa76dc0043ca1fb77af822584066d02b1491b25ae042a40b140901` |
| SHA3-384 | `58d9076f41387cc818e8ad49a27a997050c27128fa92d00af6af938d46d659f2642196d613bf5938b399ec613a9d5a47` |
| TLSH | `T16E01AFC64750BA4080299A1E669751A4F421C3CF06464B787F9C5D7DFBA8504B027F98` |
| SSDEEP | `24:kXCKysE2hi0ziQvZohaIjg7IF0oX5ujVqjN67:e9Qp+MsIk7IF0oXAxmN67` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_64531827
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6453182787fa76dc0043ca1fb77af822584066d02b1491b25ae042a40b140901"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-03 01:27:52"
  condition:
    hash.sha256(0, filesize) == "6453182787fa76dc0043ca1fb77af822584066d02b1491b25ae042a40b140901"
}
```

### Sample 23: `55489cc3ce1f7d31`

| Field | Value |
|---|---|
| SHA-256 | `55489cc3ce1f7d3129f1bebc8103631692993a66bc05f5e136ad3f4760c13fe7` |
| Family label | `Mirai` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-03 01:24:01` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d34db49b84c9debe60162cd201e7f92b` |
| SHA-1 | `d12117d1a8e0cb98365d4b6357471665c1ff837e` |
| SHA-256 | `55489cc3ce1f7d3129f1bebc8103631692993a66bc05f5e136ad3f4760c13fe7` |
| SHA3-384 | `46e80e3115d40ef1a0a8a18c0b03f464c187cfc8e26398707bdfef6820cff4b262ef8a29ba2715dc30a2c9e02a13b884` |
| TLSH | `T1BB011ECF27516245044CCD68746BCA045B46EBC0F4B80F1EEB88A87B5EE6708705AF6B` |
| SSDEEP | `12:UjQj+Jjeq+JjqNNIl5zA+Jjz0LKj+JjxgOs+JjveC+Jj1ON/+JjJSE+Jj8taKA+E:yQ+etuNI7/OK+qEWVIyJ68tBDbKcYxn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_55489cc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55489cc3ce1f7d3129f1bebc8103631692993a66bc05f5e136ad3f4760c13fe7"
    family = "Mirai"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-03 01:24:01"
  condition:
    hash.sha256(0, filesize) == "55489cc3ce1f7d3129f1bebc8103631692993a66bc05f5e136ad3f4760c13fe7"
}
```

### Sample 24: `2c27b5e45366cc70`

| Field | Value |
|---|---|
| SHA-256 | `2c27b5e45366cc70af89e5f00a6b8adad2cb842e6249f9649119b8afb87905d5` |
| Family label | `Mirai` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-03 01:13:52` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e342284fd3cd0c877437f3e1eca77d0f` |
| SHA-1 | `4939e5cffa5fd552d888522304363ecf0b97f016` |
| SHA-256 | `2c27b5e45366cc70af89e5f00a6b8adad2cb842e6249f9649119b8afb87905d5` |
| SHA3-384 | `881728e6ce619afa0c8d3f0e80d3dea7f07eaa0bbc29cd3721c0e44b862c0d24ae24748fe486a07e4fce8bc62fe66bc2` |
| TLSH | `T178019ECF2795A2831A4CCD6CB46BC54C6A41EAC4F4B44D1AF358E8795EE63083056F76` |
| SSDEEP | `24:3J3TQQehuNI7fOKQqqWZIUJs8tBDrKyYHR:FQQeh3fOxqqeIUWiDr1Yx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_2c27b5e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c27b5e45366cc70af89e5f00a6b8adad2cb842e6249f9649119b8afb87905d5"
    family = "Mirai"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-03 01:13:52"
  condition:
    hash.sha256(0, filesize) == "2c27b5e45366cc70af89e5f00a6b8adad2cb842e6249f9649119b8afb87905d5"
}
```

### Sample 25: `40fd96e5c870ccef`

| Field | Value |
|---|---|
| SHA-256 | `40fd96e5c870ccefd680bf559b7f72e7e994e3ccb4d0cb5d68836db41180bf64` |
| Family label | `unknown` |
| File name | `m68k.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 01:11:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0466c3b5cb3f9a2bc40506582f7b6ad` |
| SHA-1 | `2c60ea7298c62fda2037e65f95c8e41bc3938c1f` |
| SHA-256 | `40fd96e5c870ccefd680bf559b7f72e7e994e3ccb4d0cb5d68836db41180bf64` |
| SHA3-384 | `24a891f574bd0b3a124bb8ec4be576cf12570962c29035bd4b359e0c31eb803258a6761b75d6ba61d5547d2000280b3d` |
| TLSH | `T1EEC36C92BB197E3FD176893AC48783057B38AD409E462613902D76576EB32D01E3B7CA` |
| SSDEEP | `1536:V+WZ485cfj57Acp3dsM4SzW3oims27oCvB6n0UMaGjQrRQrYso1wwBWh6m1aLnNg:V+WZ3UiM4SzKKR7JvFwvoY/1BbmoH6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_40fd96e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40fd96e5c870ccefd680bf559b7f72e7e994e3ccb4d0cb5d68836db41180bf64"
    family = "unknown"
    file_name = "m68k.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:11:54"
  condition:
    hash.sha256(0, filesize) == "40fd96e5c870ccefd680bf559b7f72e7e994e3ccb4d0cb5d68836db41180bf64"
}
```

### Sample 26: `6c84c70119003236`

| Field | Value |
|---|---|
| SHA-256 | `6c84c701190032361e71713159e3c501810c42b56af1664d016f291e405c0e44` |
| Family label | `unknown` |
| File name | `mips.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 01:02:00` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a1ba9513c1e878831286d5bf056190a` |
| SHA-1 | `de081828272ec48c032fbe58d7e8ad33c1d93d5d` |
| SHA-256 | `6c84c701190032361e71713159e3c501810c42b56af1664d016f291e405c0e44` |
| SHA3-384 | `4366e229ed55624518cb981ac9d6ecac44a8c3ae031f743835f32949ef9f98bc6dc37307cdb2df8597d5d2a56ba27afa` |
| TLSH | `T1F31419A67711AF6AC168C53405F383E597F6239127A38145F22CDA2C2E6234C1DAFEF5` |
| TELFHASH | `t13501cb4db27909ab6df38264c8a50f65d283e85bb4f21a25db04fbc08276489d11fe0e` |
| SSDEEP | `3072:UB0esp+BkbxVPGD4kMIPePazOjHQedC0FRY46Hw3:UBOJPOZ/GSz8o0h6M` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_6c84c701
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c84c701190032361e71713159e3c501810c42b56af1664d016f291e405c0e44"
    family = "unknown"
    file_name = "mips.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:02:00"
  condition:
    hash.sha256(0, filesize) == "6c84c701190032361e71713159e3c501810c42b56af1664d016f291e405c0e44"
}
```

### Sample 27: `fe5cfaef3ae8218a`

| Field | Value |
|---|---|
| SHA-256 | `fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41` |
| Family label | `unknown` |
| File name | `fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41` |
| File type | `elf` |
| First seen | `2026-07-03 01:01:59` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a70515c2375dacdf5182382fdc4d580` |
| SHA-1 | `ae8d37dd27b372d18de229dd34409eba7da15adf` |
| SHA-256 | `fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41` |
| SHA3-384 | `ba2d122abc38014d957832293e5781c7e08e31cd9f86866c8f873a30a50f50854f7ff5fa50df231b8535e16de306ff5b` |
| TLSH | `T157F5F857E59550E4C0EED174C726A223BAA13899073433E36FA1A7B11F36FE46ABC314` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQO:cqYUQuVDt0TO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_fe5cfaef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41"
    family = "unknown"
    file_name = "fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41"
    file_type = "elf"
    first_seen = "2026-07-03 01:01:59"
  condition:
    hash.sha256(0, filesize) == "fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41"
}
```

### Sample 28: `eea78ce9b7a3d5e5`

| Field | Value |
|---|---|
| SHA-256 | `eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5` |
| Family label | `unknown` |
| File name | `eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5` |
| File type | `elf` |
| First seen | `2026-07-03 01:01:53` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f40814165f01097278f12054eb681d9` |
| SHA-1 | `02b710f8be3a3b810023c5d634cb5c66358315a6` |
| SHA-256 | `eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5` |
| SHA3-384 | `e1e5ed8aa9b3101f4126e64fe0ede9ada11359955a12485e1187ac18d31688ef0684312e6ae56ef063fd5081629856b6` |
| TLSH | `T11137CF77814338E9E5A98DB4D11025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQM:cqYUQuVDt0TZEH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_eea78ce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5"
    family = "unknown"
    file_name = "eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5"
    file_type = "elf"
    first_seen = "2026-07-03 01:01:53"
  condition:
    hash.sha256(0, filesize) == "eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5"
}
```

### Sample 29: `344b34cb507ea23d`

| Field | Value |
|---|---|
| SHA-256 | `344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f` |
| Family label | `unknown` |
| File name | `344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f` |
| File type | `elf` |
| First seen | `2026-07-03 01:01:42` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67bd3c671b8cdc08d5f762955189d211` |
| SHA-1 | `c03972760df6e184401cc83df5ea6e8e83a88a2b` |
| SHA-256 | `344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f` |
| SHA3-384 | `904cf84c4b0471892a6d083a45b13f7b051c0232f0335ef1609126132a7c232f84d322496f5e0cc573ea4ce47fa9d4c8` |
| TLSH | `T1A307AD77814338E9E5A98CB4D51025426DAC388B5738A3C7BAC471F667EA7E48E3D730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQS:cqYUQuVDt0TZEN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_344b34cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f"
    family = "unknown"
    file_name = "344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f"
    file_type = "elf"
    first_seen = "2026-07-03 01:01:42"
  condition:
    hash.sha256(0, filesize) == "344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f"
}
```

### Sample 30: `472c62f3dd43ab1d`

| Field | Value |
|---|---|
| SHA-256 | `472c62f3dd43ab1d2bc83e6366f136de3f21305980ab965a1ce9399fe79c3637` |
| Family label | `Mirai` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-07-03 00:59:53` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ca61d932e862af25e7100808d3cf2318` |
| SHA-1 | `fc644b2e529d8d41c2a7eba3e6b7e810d20d6226` |
| SHA-256 | `472c62f3dd43ab1d2bc83e6366f136de3f21305980ab965a1ce9399fe79c3637` |
| SHA3-384 | `4b17c1609b3e988bd06d7b8dceae9bceff45edad03a36aa120fdde25c49e9bb116443962b45f3e83213b23d277d67873` |
| TLSH | `T1BA1173CF1395A211088CCDA4746BC8186944EFD074940F4ED78CE4B66FE6B1C7157F59` |
| SSDEEP | `24:EQgke7kuNI75kOKgkqikWDkI8kJEk8tBlk9kKakYHR:EQgke7k35kOLkqikukI8kWkilk9k3kYx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_472c62f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "472c62f3dd43ab1d2bc83e6366f136de3f21305980ab965a1ce9399fe79c3637"
    family = "Mirai"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-03 00:59:53"
  condition:
    hash.sha256(0, filesize) == "472c62f3dd43ab1d2bc83e6366f136de3f21305980ab965a1ce9399fe79c3637"
}
```

### Sample 31: `2759a1bc0be90cca`

| Field | Value |
|---|---|
| SHA-256 | `2759a1bc0be90cca057cbf9a76cd4d7cb50a8c052e4d9896d2c69e7ae11adc8b` |
| Family label | `unknown` |
| File name | `i686.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 00:47:56` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dfb4c14c8510f77bb4e04d0407a1330` |
| SHA-1 | `033744f650d6f7ea32049d145bc8853cdc867b9c` |
| SHA-256 | `2759a1bc0be90cca057cbf9a76cd4d7cb50a8c052e4d9896d2c69e7ae11adc8b` |
| SHA3-384 | `6e916e7468f95da154fe5390e0d61e5cdd51a1794e9cb37076c0eca37a2147cfcaa2973bf00630078c1f085b7e8c1226` |
| TLSH | `T14EC34B46F792C4B3E1C301335053C7A55771EA32014ACE0BF7087E759D6678A8A6BBAD` |
| SSDEEP | `3072:baNv2L8VfSL99oIW403a6VQjQDoCTTS7XFHrHlorjXbLf:2Nv2NoD/nDU79rMn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_2759a1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2759a1bc0be90cca057cbf9a76cd4d7cb50a8c052e4d9896d2c69e7ae11adc8b"
    family = "unknown"
    file_name = "i686.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 00:47:56"
  condition:
    hash.sha256(0, filesize) == "2759a1bc0be90cca057cbf9a76cd4d7cb50a8c052e4d9896d2c69e7ae11adc8b"
}
```

### Sample 32: `52bbf76f3cf2dddd`

| Field | Value |
|---|---|
| SHA-256 | `52bbf76f3cf2dddd96c72cc97a701e06e650af628ecdb119c5d448ea5a961b34` |
| Family label | `unknown` |
| File name | `armv5l.ghost` |
| File type | `elf` |
| First seen | `2026-07-03 00:35:54` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d08914985a890b964d6381691360f0b` |
| SHA-1 | `281bda2fb385e1e6495dc9c54085adbd50f7e435` |
| SHA-256 | `52bbf76f3cf2dddd96c72cc97a701e06e650af628ecdb119c5d448ea5a961b34` |
| SHA3-384 | `574e0ffb8219e2654bc0224c1c3aa7c0b9d2121082e61d893a5d44c42942fdff97b23a83034ffce8e7425e353a229141` |
| TLSH | `T19DF3195CF550872BC6D0267AF69B128C33725B64FFDE3705E9147B283BD2B299D2A201` |
| SSDEEP | `3072:k/TCXUoEEVYA/0SJdnt2a7PHMlDkzM7hkqxysTQNrki:kBXmYA/0uBtiDkzl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_52bbf76f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52bbf76f3cf2dddd96c72cc97a701e06e650af628ecdb119c5d448ea5a961b34"
    family = "unknown"
    file_name = "armv5l.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 00:35:54"
  condition:
    hash.sha256(0, filesize) == "52bbf76f3cf2dddd96c72cc97a701e06e650af628ecdb119c5d448ea5a961b34"
}
```

### Sample 33: `ecafb11a4c92905e`

| Field | Value |
|---|---|
| SHA-256 | `ecafb11a4c92905e8e00f586411412d8c17b3f7ed1175c07ee2464a1d88521e7` |
| Family label | `unknown` |
| File name | `w.sh` |
| File type | `sh` |
| First seen | `2026-07-03 00:15:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `61c6dde79072e991be818c547f73cdb3` |
| SHA-1 | `9f1d912cf943d06fc932644026db88ec1f73c8f0` |
| SHA-256 | `ecafb11a4c92905e8e00f586411412d8c17b3f7ed1175c07ee2464a1d88521e7` |
| SHA3-384 | `5eb8d7895436caa103c82764289e68d655921ad3dee3f358abf8f2f1b46e7dad13feb16b90c00cf6071c8f6c27d093d4` |
| TLSH | `T1FE1106CE029067398CE8CD6C706FD6049C74AAC430A54F5D9E9C98B3A7A7D70AD16F2D` |
| SSDEEP | `24:Em3zBgm3Tlm3xNIIYm3dKSrm3jT1m35uqafm3pl9Rm35em3Dqgm3z/1m3rFm3hz:EwBgUlGYqxrgT1cuqafA9ReeAqgU/1g2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_ecafb11a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecafb11a4c92905e8e00f586411412d8c17b3f7ed1175c07ee2464a1d88521e7"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-03 00:15:57"
  condition:
    hash.sha256(0, filesize) == "ecafb11a4c92905e8e00f586411412d8c17b3f7ed1175c07ee2464a1d88521e7"
}
```

### Sample 34: `0b0bf190c3d68ead`

| Field | Value |
|---|---|
| SHA-256 | `0b0bf190c3d68ead801da7152302540fa34f2ca5d81c8263dd2da0b3faf0bdc4` |
| Family label | `unknown` |
| File name | `c.sh` |
| File type | `sh` |
| First seen | `2026-07-03 00:15:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1db3e73ca525221c53ffdfb422bbef5e` |
| SHA-1 | `0d8a66ffd60eb27b52bfb6faeede119740d4fc86` |
| SHA-256 | `0b0bf190c3d68ead801da7152302540fa34f2ca5d81c8263dd2da0b3faf0bdc4` |
| SHA3-384 | `6d12e0b2b28e4e108d47d8d92ba02d67461b228518b3cf3c8a652555f6777cd502231d78f0336380ca82c6929031c361` |
| TLSH | `T1B6118C8D02A05A3E6FFCCC6CB06FD208AC71E5C430B14F15DA64D42395A71606C15F3E` |
| SSDEEP | `24:3J3Tm3zBxm3Tkm3xNIIpm3dKSKm3jT0m35uqaOm3pl9Am3f9rm3Dqxm3z/0m3rE4:FwBxUkGpqxKgT0cuqaOA9A29rAqxU/06` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_0b0bf190
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b0bf190c3d68ead801da7152302540fa34f2ca5d81c8263dd2da0b3faf0bdc4"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-03 00:15:56"
  condition:
    hash.sha256(0, filesize) == "0b0bf190c3d68ead801da7152302540fa34f2ca5d81c8263dd2da0b3faf0bdc4"
}
```

### Sample 35: `695b9a53c9fbf59f`

| Field | Value |
|---|---|
| SHA-256 | `695b9a53c9fbf59f55dd818bd2bbacbb7bcc49b816d779bd9e8a9d0c82b5fc98` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-02 23:57:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f674f0ec6dc3947d6de0d0fc3ccf24b` |
| SHA-1 | `1be34c554d99ba4e00504080aa6d265723f9c429` |
| SHA-256 | `695b9a53c9fbf59f55dd818bd2bbacbb7bcc49b816d779bd9e8a9d0c82b5fc98` |
| SHA3-384 | `64d8de827cd6bf9b210160aea29062209f65d7869584ce442de2006b6f2e3e80294dc2f8e49d692eebe89f1faede930a` |
| TLSH | `T13DE33981B9C25A27C5E523BFFA6E418D3325A3E4D2DE711798635F2037C691B0E73A84` |
| TELFHASH | `t183b092180d300ab852008992c86ea28a04867aabae1274d2f591be399c92dc01403e2b` |
| SSDEEP | `3072:83IUFhqIstIWkxTsk/Y4rFabolkCY4x4nTGdl:83IUF6YTlg4rFabsK4STGdl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_695b9a53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "695b9a53c9fbf59f55dd818bd2bbacbb7bcc49b816d779bd9e8a9d0c82b5fc98"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-02 23:57:52"
  condition:
    hash.sha256(0, filesize) == "695b9a53c9fbf59f55dd818bd2bbacbb7bcc49b816d779bd9e8a9d0c82b5fc98"
}
```

### Sample 36: `723696487c125323`

| Field | Value |
|---|---|
| SHA-256 | `723696487c125323ef50aebab1864d41de10bf0b94a34b9faa3cb6226d469b60` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-02 23:57:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `14a49aec4d6b36545cd4652fb4a17908` |
| SHA-1 | `ac7eb04dfd1cd949e0145b70e6ca796b7ba62830` |
| SHA-256 | `723696487c125323ef50aebab1864d41de10bf0b94a34b9faa3cb6226d469b60` |
| SHA3-384 | `9bbd2bbcba0b03a75ddb7962276d06482969ab9cd7257bb8623f41424590d0d69a424eede362cc7947624ef2c71a7c2e` |
| TLSH | `T1B293F885BCC3452AC9D413BFB52E519E332173E5D2CE7212D8A30B653A8762B0E63F95` |
| TELFHASH | `t1d9e06800fd699a1ca9d39670ed5902b6a2022233b61b0b11cfe4cbd0843b004b60de9e` |
| SSDEEP | `1536:zlPOIwP1VibOMQ4Vi/ciz7Ou8Wu1bfPRPRY5VGv9s4PfP9af:wFGOELp1m4PfIf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_72369648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "723696487c125323ef50aebab1864d41de10bf0b94a34b9faa3cb6226d469b60"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-02 23:57:51"
  condition:
    hash.sha256(0, filesize) == "723696487c125323ef50aebab1864d41de10bf0b94a34b9faa3cb6226d469b60"
}
```

### Sample 37: `1a06cabc732fb4ba`

| Field | Value |
|---|---|
| SHA-256 | `1a06cabc732fb4ba0c71b49ba648edfc1af4e138580cba520c00ee483f574b1d` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-07-02 23:57:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `050e7cf7cca5c79fc7975a8d73e7585d` |
| SHA-1 | `6ec57e3699dde519a44d09340d6c52617a99e02a` |
| SHA-256 | `1a06cabc732fb4ba0c71b49ba648edfc1af4e138580cba520c00ee483f574b1d` |
| SHA3-384 | `880189bd21da2d0c7807a8eddc98b8c9e3220f45a86a69c3b55591ad5869225f936413c312f961bfacb39ac7091da3bd` |
| TLSH | `T1CFE34C85BCC28A22C5D513BFF92E018E331267E8D2DE7212DD621F24778796B0E77A45` |
| TELFHASH | `t1d9e0ab30762a017ce15718b4485bcb3fb3a530259b622474cfee9e1c9f372c21061b2a` |
| SSDEEP | `3072:IsxfP/ROdS5DMbCl/t19iEG5VH0aVxbZlV2q2OeO4Y:tGswbCpt1Q5x0alKq2W4Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_1a06cabc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a06cabc732fb4ba0c71b49ba648edfc1af4e138580cba520c00ee483f574b1d"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-02 23:57:50"
  condition:
    hash.sha256(0, filesize) == "1a06cabc732fb4ba0c71b49ba648edfc1af4e138580cba520c00ee483f574b1d"
}
```

### Sample 38: `fd80731a69f51e1d`

| Field | Value |
|---|---|
| SHA-256 | `fd80731a69f51e1d797cd0c0b34b064a296658468a5ee859563280c73f1794cd` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ad1044288d1dfce396e30d8e3dad4e0` |
| SHA-1 | `ca89f1d8c4f654e9b16b55bc586d49125dbad9b4` |
| SHA-256 | `fd80731a69f51e1d797cd0c0b34b064a296658468a5ee859563280c73f1794cd` |
| SHA3-384 | `7e4d3ec19b6051545b6d352c6d2e53edd86f0a3e4760abee94632a9139425fb35b4eac073f8d3cf6c800a7ff7e13ad39` |
| TLSH | `T13FC38E32D5A4A9D4C0624135E462EA304F63E6C902971EBF2FD68A754087D64FF09BFB` |
| SSDEEP | `3072:byj5ZKoipZS9HBYHlmq1+rOBQ6BKKlz6B2E1E:bytZskhMl0mQ6B5DE1E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_fd80731a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd80731a69f51e1d797cd0c0b34b064a296658468a5ee859563280c73f1794cd"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:58"
  condition:
    hash.sha256(0, filesize) == "fd80731a69f51e1d797cd0c0b34b064a296658468a5ee859563280c73f1794cd"
}
```

### Sample 39: `b9ab18bab7c7f2c5`

| Field | Value |
|---|---|
| SHA-256 | `b9ab18bab7c7f2c596d99816b284c1f107a2702f648d0d480c242305f3b57d10` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1718312cb29c5d7c62a482c44ffd9cb2` |
| SHA-1 | `bddbcd3f6b3a5b90a4ac99e58a28a24dfe147a70` |
| SHA-256 | `b9ab18bab7c7f2c596d99816b284c1f107a2702f648d0d480c242305f3b57d10` |
| SHA3-384 | `df931d186823bd1e7be9a0b233d50fd82608427f35d5f1eaed58301f11101e1e5426542f299a2e0ea918e65ab02ad325` |
| TLSH | `T1EED34C07722C0F07D5A20AB1263E5BE093FE95D111F4BB89691E6B5A5732E3B1482FCD` |
| SSDEEP | `3072:eiipkAST2h+SJ0I8b/FKJAhUZAs5yPZVfv3:6kDT2UE+/FyAhUZAs5yPzfv3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_b9ab18ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ab18bab7c7f2c596d99816b284c1f107a2702f648d0d480c242305f3b57d10"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:57"
  condition:
    hash.sha256(0, filesize) == "b9ab18bab7c7f2c596d99816b284c1f107a2702f648d0d480c242305f3b57d10"
}
```

### Sample 40: `f7bb9631725f583a`

| Field | Value |
|---|---|
| SHA-256 | `f7bb9631725f583a88be4f08895c26c92ef9d069d18b03934d38fc3aa794b351` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe6b9e82228e6eb482317313b896f97b` |
| SHA-1 | `d6c8a9e46c05a51a4606b95061dbb0ca37cf17d0` |
| SHA-256 | `f7bb9631725f583a88be4f08895c26c92ef9d069d18b03934d38fc3aa794b351` |
| SHA3-384 | `7220ea488c196baf3b8c60b9f890cbfa784119bd980a5c4c750bbed39b2ac8c17cf554f0eb04c2f09e12916a7b890262` |
| TLSH | `T1C604C50EAE618F7DF79983341BB78E219758338326E1C546E1ACD7115F9428E241FFA8` |
| TELFHASH | `t1312193484a7423e067345c991aadfb77e16030da7b226d378e11a5ab67ad9829e20c0c` |
| SSDEEP | `3072:x98b/DqKAuv5nPyZhFKLLj1kQnUqopYRE7X7kZYoMMRlGsvFb41LFJjKHZ/UZcp7:x98b/DqKAuv5nPyZhFKLLj1kQnUqopYT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_f7bb9631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7bb9631725f583a88be4f08895c26c92ef9d069d18b03934d38fc3aa794b351"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:56"
  condition:
    hash.sha256(0, filesize) == "f7bb9631725f583a88be4f08895c26c92ef9d069d18b03934d38fc3aa794b351"
}
```

### Sample 41: `3bce162c4900bf77`

| Field | Value |
|---|---|
| SHA-256 | `3bce162c4900bf770a866a3483abb609c57c110d08dfb626e2b7dbfe24b89531` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40603f2ccbda72ea3988a4737e066b84` |
| SHA-1 | `c62047ac8a136105e12652e86a58de7c37d6c8db` |
| SHA-256 | `3bce162c4900bf770a866a3483abb609c57c110d08dfb626e2b7dbfe24b89531` |
| SHA3-384 | `2de12e0ae16f57a9a094875b7220ff5d742df41e71168add20f675b527f30ca57f4a039528622ac82fce255510aa5374` |
| TLSH | `T11CE33B9DB402AE7EFC0BD57E4CA70E15FA31E3B12153172A629BFD63A8321650D17E81` |
| SSDEEP | `3072:SwzwVQJr9BDFuYEPG93wLbw6hkodsdb50MHp5FEAYt:EI5uYEPGhV65sZ50MlEAYt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_3bce162c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bce162c4900bf770a866a3483abb609c57c110d08dfb626e2b7dbfe24b89531"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:55"
  condition:
    hash.sha256(0, filesize) == "3bce162c4900bf770a866a3483abb609c57c110d08dfb626e2b7dbfe24b89531"
}
```

### Sample 42: `66aedd8aa6bd95a3`

| Field | Value |
|---|---|
| SHA-256 | `66aedd8aa6bd95a344ce8b3f0ae0b9c898157e8b92d33a9d6b841baccb3b181f` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b6dfd3e2a266f8ee02ed97806f6fb1b` |
| SHA-1 | `a66b9cd97db40dcc7b24e23a9524d0d41384dc51` |
| SHA-256 | `66aedd8aa6bd95a344ce8b3f0ae0b9c898157e8b92d33a9d6b841baccb3b181f` |
| SHA3-384 | `4823f785e2c2549143bef9c6261bec84ee29ffd6ee21782fccdf592e35a17e89199a7394d2fb7c20463cef91715fe60e` |
| TLSH | `T16DE3492274791A2BC4D6987E91F70B21F1F1D7D929A8D90E7EB20D4FEF202502713AB5` |
| SSDEEP | `3072:MPXI8371j5SWNwhdg5Qk7NQX5qcXHqwAH309CryQl8x4bCfj:P8Jj5SWozk7kq5XYQmx4ufj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_66aedd8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66aedd8aa6bd95a344ce8b3f0ae0b9c898157e8b92d33a9d6b841baccb3b181f"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:53"
  condition:
    hash.sha256(0, filesize) == "66aedd8aa6bd95a344ce8b3f0ae0b9c898157e8b92d33a9d6b841baccb3b181f"
}
```

### Sample 43: `75031c5077a2fac9`

| Field | Value |
|---|---|
| SHA-256 | `75031c5077a2fac9ced0dec41e1b15f403684d40f8b67ead30ba92c898d70b5b` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba0ee7dd2b150692a679dc01745e6584` |
| SHA-1 | `23f02743559cbb8101a99639c3433989dec97b1b` |
| SHA-256 | `75031c5077a2fac9ced0dec41e1b15f403684d40f8b67ead30ba92c898d70b5b` |
| SHA3-384 | `b96461163aa62804797fc68e0d4a7264895d54dfcb5dc810fb89056b7525ed65b893fa0295e48654b357d2ae721153e4` |
| TLSH | `T1C2D33902F48DC0FCC486C1341B6FAA3AA935FDDE123CF2A767D0AB126D8BE61591D954` |
| TELFHASH | `t166318f245e93798d71cac78bb39ded4ef8f604a04cc2b0157f1b6a94d817acc0c76021` |
| SSDEEP | `3072:WuFDnONmxGrw5oqs+/Yy4210G46nhpvIzxwprXcGzQH1XViDut9O:tONmxGrw5oqs+/z4210G46hpvAqjzAFg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_75031c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75031c5077a2fac9ced0dec41e1b15f403684d40f8b67ead30ba92c898d70b5b"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:52"
  condition:
    hash.sha256(0, filesize) == "75031c5077a2fac9ced0dec41e1b15f403684d40f8b67ead30ba92c898d70b5b"
}
```

### Sample 44: `b41cf0e4ce86234c`

| Field | Value |
|---|---|
| SHA-256 | `b41cf0e4ce86234ca0055c4c1b55ddbb336eeed04a53745c78b5e372252dc96c` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `470ab50934d8f58200d4bed01c2472e0` |
| SHA-1 | `f8a4a1dc31f7a1adc8beb2b0cbf536145ae9dbcd` |
| SHA-256 | `b41cf0e4ce86234ca0055c4c1b55ddbb336eeed04a53745c78b5e372252dc96c` |
| SHA3-384 | `9c2025f40e39d06c7ffc044b51a3610d46891379a308f41e978e486e8478d712bdd6f354d3a8cd943d562fe7a1cf55a9` |
| TLSH | `T1CAA3E792BCC2562BC5E523BEA67E568D336073E4C2DA7117D8A34B107B8251F0E63F84` |
| TELFHASH | `t1d9e06800fd699a1ca9d39670ed5902b6a2022233b61b0b11cfe4cbd0843b004b60de9e` |
| SSDEEP | `1536:onACdChqI8Ub0Bp6/CNfJzVPo41Xe/BLG/vXb/9tJJMVI5FUqZrYlq:onACQhqIMBpjVXeSX72I5FPZcq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_b41cf0e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b41cf0e4ce86234ca0055c4c1b55ddbb336eeed04a53745c78b5e372252dc96c"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:51"
  condition:
    hash.sha256(0, filesize) == "b41cf0e4ce86234ca0055c4c1b55ddbb336eeed04a53745c78b5e372252dc96c"
}
```

### Sample 45: `19242bfef334f455`

| Field | Value |
|---|---|
| SHA-256 | `19242bfef334f4554ee013586a0265adfe503496e2ebac07f922bd3ce2a9e37d` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-02 23:55:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `699eb8d8dc5db7d65f246f764251859e` |
| SHA-1 | `509e4f12eee205f1fcd45c72c76eec84899237f4` |
| SHA-256 | `19242bfef334f4554ee013586a0265adfe503496e2ebac07f922bd3ce2a9e37d` |
| SHA3-384 | `6357d07a5172cc195866819fef42f29dc0d828b0d38db0cd65234e4491c4664a0b6f29a04409a0a10aa2c9038ea1656d` |
| TLSH | `T12BB33AC1E64FD4F8D91641702267EB379B32FC76013EDA93D7A49B727C93A4198062AC` |
| TELFHASH | `t19b31d1f8fa661cdcabe09503e24ea761ed1de57b347021fd19f6266032b214192bdc35` |
| SSDEEP | `3072:KJFrpq7W7PTL9rH5crC3MFZnKOiKYW9iHGNIiP4r:OG7WDTL1H5crIMFZKOiQL4r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_19242bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19242bfef334f4554ee013586a0265adfe503496e2ebac07f922bd3ce2a9e37d"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:50"
  condition:
    hash.sha256(0, filesize) == "19242bfef334f4554ee013586a0265adfe503496e2ebac07f922bd3ce2a9e37d"
}
```

### Sample 46: `9b263a5a34d25550`

| Field | Value |
|---|---|
| SHA-256 | `9b263a5a34d255506fe51b8f57d8fe44fcfd387efd0e57263e95d5e7be92e40f` |
| Family label | `unknown` |
| File name | `wget.sh` |
| File type | `sh` |
| First seen | `2026-07-02 23:06:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `931c38d7da0121c65d4c5b6d16f42819` |
| SHA-1 | `84705726e34389ebdfcc12a71de62da89cd5d8cc` |
| SHA-256 | `9b263a5a34d255506fe51b8f57d8fe44fcfd387efd0e57263e95d5e7be92e40f` |
| SHA3-384 | `819b72118612c9c7f37c044cdc592247ab4611010edffb9d39db27b5265dedbf02f47df28d03bffdc04e8f5ef79f8720` |
| TLSH | `T126F096CE0150365589CDD94FBBB3C92C245687CD168F5BC978AD051AA6446EAF044B6C` |
| SSDEEP | `12:KSs6wZUJQNyHe0uUJRsHUbVSYeJBOUbg5pB:KSKZ16vsQle7qpB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_9b263a5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b263a5a34d255506fe51b8f57d8fe44fcfd387efd0e57263e95d5e7be92e40f"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-02 23:06:29"
  condition:
    hash.sha256(0, filesize) == "9b263a5a34d255506fe51b8f57d8fe44fcfd387efd0e57263e95d5e7be92e40f"
}
```

### Sample 47: `5891a3295e44a2a3`

| Field | Value |
|---|---|
| SHA-256 | `5891a3295e44a2a3e03cab01e78efa6c7e2650227fa611420d42b857c38d4dcb` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxni386xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:05:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dcabd5b3f2b719c29782e6d355a703f8` |
| SHA-1 | `da37dff3cd6a4fb813acb28511395bc538869696` |
| SHA-256 | `5891a3295e44a2a3e03cab01e78efa6c7e2650227fa611420d42b857c38d4dcb` |
| SHA3-384 | `0d8ca669b98d354313a311956626e91e2e31aa4244fc64f729ddf4aee1f7f4041bb727e51553f38d9ebe5ca1498754b3` |
| TLSH | `T194C35B82E6A2D0F1E68701B00557F3E68935EA305416CEC6EFA93D71EC717829D9BB1C` |
| TELFHASH | `t1dd4107fa5ea60ce873d49c05d35e1730b909da3b687036aa40f31e7536fad9212b5c35` |
| SSDEEP | `3072:3atpsoRNjmj1VGCr75MoS9SrPwVrx5tiycw:VoRNjmj1VGFVrRiyb` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_047_5891a329
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5891a3295e44a2a3e03cab01e78efa6c7e2650227fa611420d42b857c38d4dcb"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:05:00"
  condition:
    hash.sha256(0, filesize) == "5891a3295e44a2a3e03cab01e78efa6c7e2650227fa611420d42b857c38d4dcb"
}
```

### Sample 48: `83f2f05f1b8734ca`

| Field | Value |
|---|---|
| SHA-256 | `83f2f05f1b8734caea6a85321e9dfbf29ba321078f75c288de7d19b369db0c35` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnaarch64xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0656ffb0c6e265e722788faf4fc6934` |
| SHA-1 | `0062829f32d51787b97f9a95392cbadf20b501d7` |
| SHA-256 | `83f2f05f1b8734caea6a85321e9dfbf29ba321078f75c288de7d19b369db0c35` |
| SHA3-384 | `5d3464c3aea40534e4c499731686a22be331d6d9b7595fb4bb338ec483ed9c2421d488cead960adfccf80315a1393e00` |
| TLSH | `T16D148D68FE4F78D2D2C7E37DAE4A0FA2312779749565C0B51A00A29FD5EAFD488C0613` |
| SSDEEP | `3072:badBpAIWIfbEdOcdY3rZiigZ2eNRzPxD:bOVfbEdxm4iubR` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_048_83f2f05f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83f2f05f1b8734caea6a85321e9dfbf29ba321078f75c288de7d19b369db0c35"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:57"
  condition:
    hash.sha256(0, filesize) == "83f2f05f1b8734caea6a85321e9dfbf29ba321078f75c288de7d19b369db0c35"
}
```

### Sample 49: `84006c5bdfeeefd4`

| Field | Value |
|---|---|
| SHA-256 | `84006c5bdfeeefd4e541150c016fca2235e94686091383e4b0f92d6a2c569ecb` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnpowerpcxnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80734682211af4a5502b81b1d2b02389` |
| SHA-1 | `26c35de87871ab69d536674bcdfc2cec17a3c919` |
| SHA-256 | `84006c5bdfeeefd4e541150c016fca2235e94686091383e4b0f92d6a2c569ecb` |
| SHA3-384 | `84b9adf112fb8b984cee8032944a9df6e0d2565717002c148c9491e2fb0fcd1bafc5338fb11f2bac8703b5d28ebbf45b` |
| TLSH | `T103145A05FB0C0463CA931CF48E3F0BFAA3621A9115F99115250D7F5A1A32DB7A68BFD9` |
| SSDEEP | `3072:ESZAGIiEgACYrerYqlNSwppHaecY4NX6UaN:HZ15BTYCrYq1QDY634` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_84006c5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84006c5bdfeeefd4e541150c016fca2235e94686091383e4b0f92d6a2c569ecb"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:50"
  condition:
    hash.sha256(0, filesize) == "84006c5bdfeeefd4e541150c016fca2235e94686091383e4b0f92d6a2c569ecb"
}
```

### Sample 50: `ffb8ddbabd993eaf`

| Field | Value |
|---|---|
| SHA-256 | `ffb8ddbabd993eaff6bb842707ec5c73cb1ba6aa8c15bd17fb3adda06a2c6944` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnx86_64xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `59cb7dd4a3cdd5409357057649353525` |
| SHA-1 | `7a56b5927e4ff15421cddf7f3dcb2886a2485c72` |
| SHA-256 | `ffb8ddbabd993eaff6bb842707ec5c73cb1ba6aa8c15bd17fb3adda06a2c6944` |
| SHA3-384 | `ac26e4dfb18378b0c97745cde7889eccd2890e97da9d5862536bab4c4fe7e2eac0f04b49ce62c7bf4e40a12daa6c60fa` |
| TLSH | `T175D35C0A78D274FCC687D170926E9F61EA3A745C02183DBBA3C2AE711937ED05E15F62` |
| TELFHASH | `t1c331eeb14e9a366812c7a712f319bf69f073150205f1f4e99d376de8ce123824fa30a2` |
| SSDEEP | `3072:lAF2acRfkY6z3xv+ErH4vk9954rlvLFZW8YYQD:yIRfe3xvvSrlvZZ7UD` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_050_ffb8ddba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb8ddbabd993eaff6bb842707ec5c73cb1ba6aa8c15bd17fb3adda06a2c6944"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnx86_64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:47"
  condition:
    hash.sha256(0, filesize) == "ffb8ddbabd993eaff6bb842707ec5c73cb1ba6aa8c15bd17fb3adda06a2c6944"
}
```

### Sample 51: `09850882df56f887`

| Field | Value |
|---|---|
| SHA-256 | `09850882df56f887392a08d100456dc3644f4acbb26c8434218574a0bbee07bb` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnmipsxnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6bd45cb7eaa6d1ebb30709369dff1332` |
| SHA-1 | `d549d9e76447342854a556829f177d6b489740e6` |
| SHA-256 | `09850882df56f887392a08d100456dc3644f4acbb26c8434218574a0bbee07bb` |
| SHA3-384 | `bea60e60a2635fb0df789b1f00e9cb4e015f60d29bb06ea343940bc6b8413352949e53748b94b83b9758c33c4cbc1929` |
| TLSH | `T109F33B47B7208FB1C368967109B3CB67A6E6269216E19985E66DCD107F3035C6C3FFA0` |
| TELFHASH | `t1d9c002145c7457f15108dd5540dc7f29c5f51dcf15431d1fd9183c654631d831f00d59` |
| SSDEEP | `3072:93VJgTdgahP/2o/ZrTheIsnjCWRXFm4UpM1wLxpPNNOziH9fam:9FJMgWPZr8IaCWReS1WpPem7` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_051_09850882
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09850882df56f887392a08d100456dc3644f4acbb26c8434218574a0bbee07bb"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:44"
  condition:
    hash.sha256(0, filesize) == "09850882df56f887392a08d100456dc3644f4acbb26c8434218574a0bbee07bb"
}
```

### Sample 52: `661bdb7b97063415`

| Field | Value |
|---|---|
| SHA-256 | `661bdb7b97063415dda2647862e4a1110b10f71beb1ff58ca4c9deaee350fc6f` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmicroblazexnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df41e644d7de9dceaad7e3e09337d7cb` |
| SHA-1 | `93e48d77fd86fd7c236661306c4ec45fce6c150a` |
| SHA-256 | `661bdb7b97063415dda2647862e4a1110b10f71beb1ff58ca4c9deaee350fc6f` |
| SHA3-384 | `55e02c491473b2c84eaf85b6a1927b1b6c855c9bd6969f4661e4c2b9717dafd448d81f43fc69bac5751bc270c49d6237` |
| TLSH | `T179147120FA0663B1CC731A34A79A2E5A6E7704559FEB26312D1F533CDE628509B31F8D` |
| SSDEEP | `3072:IcHZcggt1NJmeDQBwnKUDMaVsb3pjr1lCRXUKG:IcY5JpMByVs9jSSf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_661bdb7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "661bdb7b97063415dda2647862e4a1110b10f71beb1ff58ca4c9deaee350fc6f"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmicroblazexnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:24"
  condition:
    hash.sha256(0, filesize) == "661bdb7b97063415dda2647862e4a1110b10f71beb1ff58ca4c9deaee350fc6f"
}
```

### Sample 53: `f0fba59fac26fe8a`

| Field | Value |
|---|---|
| SHA-256 | `f0fba59fac26fe8a909040d381156f5db6c7c03d47a723b6545e47a5377d59bd` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnsh2xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b43c06732fcce85cf6e5c80be7a71769` |
| SHA-1 | `6143a72ecdc8f50493e27d90ef51788b5bac835a` |
| SHA-256 | `f0fba59fac26fe8a909040d381156f5db6c7c03d47a723b6545e47a5377d59bd` |
| SHA3-384 | `c69b011fe5835e953e1b1ef17b1e2a57b9ed5685c0e12c7fe2409e542f3ddd640e2782e422b6c11733b0a89853cd5413` |
| TLSH | `T1D2D3B021E4006DD1EC2129F578BA97B80350EE700BDE5582EFFDF95E647BD9438AD2A0` |
| SSDEEP | `3072:PnicTtkAg7FSGp+VJE6AqUjq+c7zAbpb9/xU:PiySSGp+PMmT7zMplq` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_053_f0fba59f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0fba59fac26fe8a909040d381156f5db6c7c03d47a723b6545e47a5377d59bd"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnsh2xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:22"
  condition:
    hash.sha256(0, filesize) == "f0fba59fac26fe8a909040d381156f5db6c7c03d47a723b6545e47a5377d59bd"
}
```

### Sample 54: `6cb30f950e7f2f03`

| Field | Value |
|---|---|
| SHA-256 | `6cb30f950e7f2f038e986b811fa758fa55badf9576bde9073ba9ae19768dcc9a` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnor1kxnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f893e8fbaea671eb60d80e1c4930270c` |
| SHA-1 | `3bc5a2d11de0438e693d30abdaf07aeb87830ffa` |
| SHA-256 | `6cb30f950e7f2f038e986b811fa758fa55badf9576bde9073ba9ae19768dcc9a` |
| SHA3-384 | `892714c90f505a18b33f5dcdae1884b744bb27e4c6b5058b67638bca434c928d56d01afedd70f21c261b1512a4566b53` |
| TLSH | `T14D04392F358191F0F6411B746BCBD3976C390BBF51A9909F6B416329B6E0B7BA02C487` |
| SSDEEP | `3072:7mPX5bl7RDfPIX5eG/L1AL0SFU66gOSNL9CnNgRdgJi55w3UXS:7eJpJUVD1A8n0YNgEJi5aki` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_054_6cb30f95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cb30f950e7f2f038e986b811fa758fa55badf9576bde9073ba9ae19768dcc9a"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnor1kxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:21"
  condition:
    hash.sha256(0, filesize) == "6cb30f950e7f2f038e986b811fa758fa55badf9576bde9073ba9ae19768dcc9a"
}
```

### Sample 55: `861782bd78b9ff5d`

| Field | Value |
|---|---|
| SHA-256 | `861782bd78b9ff5dedc79d8c6c6f03f8abb1fc9a8b81e0291073637cface272b` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnsh4xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4912b63d5c3f88f5530bc8405bd0f523` |
| SHA-1 | `b570ed873eccc0decec870511a239b3648331e4c` |
| SHA-256 | `861782bd78b9ff5dedc79d8c6c6f03f8abb1fc9a8b81e0291073637cface272b` |
| SHA3-384 | `544b52e2fcc31c4bd2189786c88e8f852922aeb75bbce658f119abf56a91cd34994249a70af0ef6c2cbee29933097262` |
| TLSH | `T109D3CF32E0086DA0DD2117B43476597C0340DEB40AD59243EFBEE5AE28B7DA57DEEB60` |
| SSDEEP | `3072:jNOFV2mOAc6NBmjOd1CVOHVv3WDxGGRhaUNhkv0Z26:xOFgpOEoVv3MXL5NhGO26` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_055_861782bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "861782bd78b9ff5dedc79d8c6c6f03f8abb1fc9a8b81e0291073637cface272b"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnsh4xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:20"
  condition:
    hash.sha256(0, filesize) == "861782bd78b9ff5dedc79d8c6c6f03f8abb1fc9a8b81e0291073637cface272b"
}
```

### Sample 56: `ded73b48bfe87062`

| Field | Value |
|---|---|
| SHA-256 | `ded73b48bfe87062892030bceb68815d779c51c736c3278ffb00f340bdc220dc` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnloongarch64xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c9e2c3e0e594e5c2591542649a54e39` |
| SHA-1 | `c4fc096f8944cc2dc8335875891bc5172f2733a8` |
| SHA-256 | `ded73b48bfe87062892030bceb68815d779c51c736c3278ffb00f340bdc220dc` |
| SHA3-384 | `164133a4a90913f20ab4d3146f234adc75f191cffa8972b1879e8bc2be1bf7a5026676fc638fd1b773596d38db5f3133` |
| TLSH | `T10B146C2BB3C39CE6C51063308C316362776FD7081958EAFFDA1B3794A9977225A246C7` |
| SSDEEP | `6144:1R9Om5159ZA0mzoWcz4Mm4ztkES7IKTtj:BZAyFzQSdS7Iu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_ded73b48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ded73b48bfe87062892030bceb68815d779c51c736c3278ffb00f340bdc220dc"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnloongarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:19"
  condition:
    hash.sha256(0, filesize) == "ded73b48bfe87062892030bceb68815d779c51c736c3278ffb00f340bdc220dc"
}
```

### Sample 57: `8168a485ec800b17`

| Field | Value |
|---|---|
| SHA-256 | `8168a485ec800b17645de89c8201a335287c9fd57e6af15600eb5bb4d16b895c` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxni386xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fc0df51ad0b663ad98e2159e20834943` |
| SHA-1 | `72dd48f868a2f6a877b277f6993bffa031352663` |
| SHA-256 | `8168a485ec800b17645de89c8201a335287c9fd57e6af15600eb5bb4d16b895c` |
| SHA3-384 | `a4050232e36851866f5e8932ea9106c81cc408b9b33b5d49469ffcf01e88d31a8921fae5da4ed81aed48290f6abf57b6` |
| TLSH | `T1DE5302EBA0D4BDCCD19A4330050F0A0B3EC666B86099663B72C4F6A54AF2750DFD8BD5` |
| TELFHASH | `t1a0b01122cc8a8e020200882e0a0a022fe280feb82c0bf303a0b80c28e0b2c8e0000083` |
| SSDEEP | `1536:C1/S5aOdeB51F+yuXkoPgvFbFX6hTZ0f8ASADQLkg4azHs:CM5az1Fy0oPgdZX6hTo8R4QLGazHs` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_057_8168a485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8168a485ec800b17645de89c8201a335287c9fd57e6af15600eb5bb4d16b895c"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:17"
  condition:
    hash.sha256(0, filesize) == "8168a485ec800b17645de89c8201a335287c9fd57e6af15600eb5bb4d16b895c"
}
```

### Sample 58: `e5e16639ec6ec60c`

| Field | Value |
|---|---|
| SHA-256 | `e5e16639ec6ec60c5a5ebe598254f926e93e5e9c2f453ebc3225e0650b57e66e` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnaarch64xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `292452452facc1e8a71e5429df0a1600` |
| SHA-1 | `441fb1bf5279c44789bf297870b6f6931996d3ce` |
| SHA-256 | `e5e16639ec6ec60c5a5ebe598254f926e93e5e9c2f453ebc3225e0650b57e66e` |
| SHA3-384 | `9a74c743526bbbfa1c64bf94d247606d18e36b4256b5f093c5806596521c4d2d29420c658365ea6387fea5a2420967a9` |
| TLSH | `T1D26302CF7EB02A1AD1DCA1B1713819D9DC3A9D8AD643865CD3E2E796473943264CCB0B` |
| SSDEEP | `1536:saxZLmYKVDNSl2y08yumeJyGYVmIMGj8NO:saxZLmYKX+t08jmeJhYTj8NO` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_058_e5e16639
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5e16639ec6ec60c5a5ebe598254f926e93e5e9c2f453ebc3225e0650b57e66e"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:16"
  condition:
    hash.sha256(0, filesize) == "e5e16639ec6ec60c5a5ebe598254f926e93e5e9c2f453ebc3225e0650b57e66e"
}
```

### Sample 59: `20161e9b6edc8c42`

| Field | Value |
|---|---|
| SHA-256 | `20161e9b6edc8c42af263a9099a5f285473da5c4935a600f373b7da8a3111515` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnriscv64xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7c3a58268fcd339afba309a965e9dbb` |
| SHA-1 | `f005b873b0e4809ac5c6403fb4d82ef92585f45e` |
| SHA-256 | `20161e9b6edc8c42af263a9099a5f285473da5c4935a600f373b7da8a3111515` |
| SHA3-384 | `fff3e6d4a25c6e7a8344d4a8ce9935a8f0ace23bec97a58b0396ed855cc46b9ac4fcf18e7a5b96925d5ba50739cad468` |
| TLSH | `T1F5B3E085B210AE55C02672FCB1870A9093B17E7B4B9A150B4473F5B46DBCCD47E0BEDA` |
| SSDEEP | `3072:jx63zpjhO5z01nCU375P5wk5SOez7wud:as5zqhr5Nzy7wy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_20161e9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20161e9b6edc8c42af263a9099a5f285473da5c4935a600f373b7da8a3111515"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnriscv64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:15"
  condition:
    hash.sha256(0, filesize) == "20161e9b6edc8c42af263a9099a5f285473da5c4935a600f373b7da8a3111515"
}
```

### Sample 60: `715a4e536e913c7e`

| Field | Value |
|---|---|
| SHA-256 | `715a4e536e913c7eee6f4bf1c072e564045d9880f3043e788c9a2c13dd28b957` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnm68kxnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3eb2dc993c71aa18458b8df06f0bdc69` |
| SHA-1 | `f84daa11f0434369319b8d473c9806465d97f33a` |
| SHA-256 | `715a4e536e913c7eee6f4bf1c072e564045d9880f3043e788c9a2c13dd28b957` |
| SHA3-384 | `7f95945b9a093e67e5bb57c96d846efcd623ceead33b6108e064beb607f95f62f95c5e1909466428ffdca6076db45116` |
| TLSH | `T1DAB3AF87B2907ABEF0A45E3FC4135E26A6259F705583273D71FDF9906E3A3503292E42` |
| SSDEEP | `1536:tdNSXAeuUGWnKYUqwaJ1Xq/3A5hcB57laZeCNjHWBOdiyWT15Ov6fHzN8rSR:t3SrlGWnKTU83AQB5A5Liy36fBUSR` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_060_715a4e53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "715a4e536e913c7eee6f4bf1c072e564045d9880f3043e788c9a2c13dd28b957"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnm68kxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:13"
  condition:
    hash.sha256(0, filesize) == "715a4e536e913c7eee6f4bf1c072e564045d9880f3043e788c9a2c13dd28b957"
}
```

### Sample 61: `ab53eda5b03e2e44`

| Field | Value |
|---|---|
| SHA-256 | `ab53eda5b03e2e4420963e35ccf3e165380be9aabb86f2bbf423e135733157fa` |
| Family label | `unknown` |
| File name | `xnxnxnxnxnxnxnxnriscv32xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:12` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1340cbe4d918a9c81f264b4c311b585c` |
| SHA-1 | `2143123dfc46d38976e73c15b98938ff02abae84` |
| SHA-256 | `ab53eda5b03e2e4420963e35ccf3e165380be9aabb86f2bbf423e135733157fa` |
| SHA3-384 | `75a0bca246a0212accf9993eab2eda1cd82b617d0b009da0ff47078b3c17f5c4ce13dd2dfad6b21f9be5bf51eef25d86` |
| TLSH | `T140C3F185BB6369D1C1A242BDA4C00AC387916E318FE313080699F674387DDFB1F69DE9` |
| SSDEEP | `3072:OBb4K+nqsnSjZldbaUXGSgqTWo1OWqEwztlMMTnK:0OCDjXG9qTWywxlxTnK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_ab53eda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab53eda5b03e2e4420963e35ccf3e165380be9aabb86f2bbf423e135733157fa"
    family = "unknown"
    file_name = "xnxnxnxnxnxnxnxnriscv32xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:12"
  condition:
    hash.sha256(0, filesize) == "ab53eda5b03e2e4420963e35ccf3e165380be9aabb86f2bbf423e135733157fa"
}
```

### Sample 62: `945ce51902a9d833`

| Field | Value |
|---|---|
| SHA-256 | `945ce51902a9d83386e58a0da359216fd6d51bc9382d96381f898c97d58a4a33` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnpowerpcxnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bda5d5d3f4668f0421c7e76e8ce45d0b` |
| SHA-1 | `1e1cecd9eb7aa47d89d8ee1e77e0023835523013` |
| SHA-256 | `945ce51902a9d83386e58a0da359216fd6d51bc9382d96381f898c97d58a4a33` |
| SHA3-384 | `d2e39df0bab83135435741589913ad7a388f68ccf9d7013ce6066bb35e91fb5bee5f55578770dbe13880814b90a3789c` |
| TLSH | `T172631247FFDC1BA9ACD92ABD07AB75DB2762A032547280B40CE54895805FE6114DBCCD` |
| SSDEEP | `1536:37MbwKNGjjH+Xq34n/q8Zu41zmX3sDgqrPw:37Mbp2L+Xqdfoz2sZrPw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_945ce519
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "945ce51902a9d83386e58a0da359216fd6d51bc9382d96381f898c97d58a4a33"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:11"
  condition:
    hash.sha256(0, filesize) == "945ce51902a9d83386e58a0da359216fd6d51bc9382d96381f898c97d58a4a33"
}
```

### Sample 63: `3d97e9a12d8d0120`

| Field | Value |
|---|---|
| SHA-256 | `3d97e9a12d8d01204887d78b3f6122a19f13bf031f42b85ce48f8efd520c3e8a` |
| Family label | `Gafgyt` |
| File name | `xnxnxnxnxnxnxnxnx86_64xnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d537c08f0dc0602656bd43655ccfb749` |
| SHA-1 | `32621c863a5ea67f945c73be9d9ab3d0455702fe` |
| SHA-256 | `3d97e9a12d8d01204887d78b3f6122a19f13bf031f42b85ce48f8efd520c3e8a` |
| SHA3-384 | `0c5f234c86695c32343056249079e3f267aef4448573ef2af15da797ea5d6dc979929d579d21157dc683e1aa679ac2dc` |
| TLSH | `T1A45302412ABCFC3ACBE3D5390B7841E545D849E4A8D6A01F43CA7CF48606D54EEE8787` |
| SSDEEP | `1536:Mdcqm5iERozq3p7o8FwOA4zCKOFGUfKbeH6UhV/uZijcCAQl:MaHJgMo8FwOA4zUFGUO3UhAZiqQl` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_063_3d97e9a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d97e9a12d8d01204887d78b3f6122a19f13bf031f42b85ce48f8efd520c3e8a"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnx86_64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:10"
  condition:
    hash.sha256(0, filesize) == "3d97e9a12d8d01204887d78b3f6122a19f13bf031f42b85ce48f8efd520c3e8a"
}
```

### Sample 64: `df34ce9e3c17ce3f`

| Field | Value |
|---|---|
| SHA-256 | `df34ce9e3c17ce3fd73320189705b2ca2c00d54f306207ba2909fa56809243db` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmipsxnxn` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17fa90a6680e6aee4c1e1f25701ea361` |
| SHA-1 | `77ac2e464ecf1454b8f390a29d3910cb965907a8` |
| SHA-256 | `df34ce9e3c17ce3fd73320189705b2ca2c00d54f306207ba2909fa56809243db` |
| SHA3-384 | `ea946933d568b02778db497666085880730143a17875200f00afaf4687adb73aba79250135483311ce06383c2302c62e` |
| TLSH | `T14E7302722177DEA1D2B2843323837D89BE278476037492BABC79676EF486E116C0C45E` |
| SSDEEP | `1536:i8zRnwvX0/jMQwZuOPFPijvDMwhQi1rYGhQZ9zWm0BlmlorJ:5zRnwP0bMQ2RijvDZZ1rYGhG13qMSJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_df34ce9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df34ce9e3c17ce3fd73320189705b2ca2c00d54f306207ba2909fa56809243db"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:08"
  condition:
    hash.sha256(0, filesize) == "df34ce9e3c17ce3fd73320189705b2ca2c00d54f306207ba2909fa56809243db"
}
```

### Sample 65: `e0de7b97caf12794`

| Field | Value |
|---|---|
| SHA-256 | `e0de7b97caf12794da7c39bd4e0f3024457acc46e933ef13861ec28d8b0c31a5` |
| Family label | `unknown` |
| File name | `curl.sh` |
| File type | `sh` |
| First seen | `2026-07-02 23:04:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa4c0201a8ef4f7b9cbe81260e2a45c9` |
| SHA-1 | `974805f86326780c7882184d88f1fd55f6515993` |
| SHA-256 | `e0de7b97caf12794da7c39bd4e0f3024457acc46e933ef13861ec28d8b0c31a5` |
| SHA3-384 | `2b306401b18824be23c7116e8d03a8fc856e1727a57cf2f19f18ee41c338f7d436a79f81b5a804b0c96338e53361f2a9` |
| TLSH | `T1F9F0A79801406A53E78D9D0FBFB3A46D1152A7D8200B7BC0B5960B1CA644B86B014777` |
| SSDEEP | `12:KhI5W3CtI1/TbNFJQ1npLOhoNFJK2yNFb8liAErNFbgeqlHE:KOQyS1bbe1npLOzT8liAc9qlk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_e0de7b97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0de7b97caf12794da7c39bd4e0f3024457acc46e933ef13861ec28d8b0c31a5"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-07-02 23:04:07"
  condition:
    hash.sha256(0, filesize) == "e0de7b97caf12794da7c39bd4e0f3024457acc46e933ef13861ec28d8b0c31a5"
}
```

### Sample 66: `4fb47b9ea12b8893`

| Field | Value |
|---|---|
| SHA-256 | `4fb47b9ea12b8893d4f91e4ad7230d20e30250abcb341a31d494d662d29714e1` |
| Family label | `unknown` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-02 23:04:06` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72aed3f8c3d012b826b4ecf98eb2ccd1` |
| SHA-1 | `0174d35778c65eea63bf7af8578fedcc3efcfdbc` |
| SHA-256 | `4fb47b9ea12b8893d4f91e4ad7230d20e30250abcb341a31d494d662d29714e1` |
| SHA3-384 | `4fb08c52c6100d5796b69f7ad048cfe1600be0e6a588720307c21f4a798ca7cbb675f627e7e50ffe17374d44c580a454` |
| TLSH | `T138E41B0AAF540EFBD82FCD3705AA1A0635CC649733A53B353574DE14BA5AA0B89D3C78` |
| SSDEEP | `6144:PYcZ9PeDlfVuUyC0Y/ydHsGvsnyxpAvzzJUVl3SoddKrLVCU2VUp:6lXyC0Y/ydHsGvYuAvzuSoELJiUp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_4fb47b9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fb47b9ea12b8893d4f91e4ad7230d20e30250abcb341a31d494d662d29714e1"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:06"
  condition:
    hash.sha256(0, filesize) == "4fb47b9ea12b8893d4f91e4ad7230d20e30250abcb341a31d494d662d29714e1"
}
```

### Sample 67: `9517c95d73657996`

| Field | Value |
|---|---|
| SHA-256 | `9517c95d736579963374276fe45955a73129e3cf23a5821fb34e61cecc800a59` |
| Family label | `Mirai` |
| File name | `main_arm7` |
| File type | `elf` |
| First seen | `2026-07-02 23:02:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a78cd1059025faee6ee5980118a39e65` |
| SHA-1 | `cdb8955af8c9e263de16032c9b5b8c33d676940d` |
| SHA-256 | `9517c95d736579963374276fe45955a73129e3cf23a5821fb34e61cecc800a59` |
| SHA3-384 | `334c2c6297cfc75aa79fd0d8f19e5ea18c09999365489b43a9b511ea565452897e719cde6908842d72e67d48d97fea8d` |
| TLSH | `T1F9042945EA404B13C0D627B9F6DF42453333AB9497EB73069528AFB43F8679E4F22A05` |
| TELFHASH | `t178310071567851269aa1ec64d9ed97b2652ac7171340ff32df26c0cc281a449f62ac0f` |
| SSDEEP | `3072:OzeSvtfD84oALv2eEQakGzORuGMzw99LHd38YhTfYo+M/RM+FDhdLn:2eSvJvoA7TEQakGzORuBGLHd38+x+M/z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_9517c95d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9517c95d736579963374276fe45955a73129e3cf23a5821fb34e61cecc800a59"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-07-02 23:02:06"
  condition:
    hash.sha256(0, filesize) == "9517c95d736579963374276fe45955a73129e3cf23a5821fb34e61cecc800a59"
}
```

### Sample 68: `dcbcba0a0d2a7daa`

| Field | Value |
|---|---|
| SHA-256 | `dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205` |
| Family label | `unknown` |
| File name | `o` |
| File type | `unknown` |
| First seen | `2026-07-02 23:02:04` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5025f7062879eb8eaaa11e76e9dde1f3` |
| SHA-256 | `dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_dcbcba0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-02 23:02:04"
  condition:
    hash.sha256(0, filesize) == "dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205"
}
```

### Sample 69: `f91e0130c1e55dfd`

| Field | Value |
|---|---|
| SHA-256 | `f91e0130c1e55dfd84d38b9865d7ff122e5060c93f33b8063165402c4d9116e4` |
| Family label | `Mirai` |
| File name | `1.sh` |
| File type | `sh` |
| First seen | `2026-07-02 23:02:03` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `471150356fa95fee7371f34a15fd6a80` |
| SHA-1 | `12ad4b1f67a604fd0470d21c36665869cbb4d29b` |
| SHA-256 | `f91e0130c1e55dfd84d38b9865d7ff122e5060c93f33b8063165402c4d9116e4` |
| SHA3-384 | `e6105c7a6010330fc55bcf970b1dbca4f3903ef02bcfb976d05af9c6c1b1d92a0133ec22c5282b1d61e41a92d1d815e0` |
| TLSH | `T1F06172C6204A83F66FB95DD322BFC8193082E49E10CE5E4D98E974B5F98CF49353C6A1` |
| SSDEEP | `96:i2Jk2q62rw26q2YH22QG2HE2VU2YEL2x82GK2qi2GaGwo2zI2+J7:RJDqpr365YHdQNHjVTY9x7GZqRnXzP+V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_f91e0130
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f91e0130c1e55dfd84d38b9865d7ff122e5060c93f33b8063165402c4d9116e4"
    family = "Mirai"
    file_name = "1.sh"
    file_type = "sh"
    first_seen = "2026-07-02 23:02:03"
  condition:
    hash.sha256(0, filesize) == "f91e0130c1e55dfd84d38b9865d7ff122e5060c93f33b8063165402c4d9116e4"
}
```

### Sample 70: `99ec0e5a73529d9b`

| Field | Value |
|---|---|
| SHA-256 | `99ec0e5a73529d9bc0ee7c385e46c802a2f94be1dabdc2aa954f2ba8de2b4d58` |
| Family label | `Mirai` |
| File name | `massload` |
| File type | `sh` |
| First seen | `2026-07-02 23:02:02` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `363b3d42d09ab34082f195b01c743c84` |
| SHA-1 | `f880cd67abafc6a22a96efeb4b49e38aef2fbb6d` |
| SHA-256 | `99ec0e5a73529d9bc0ee7c385e46c802a2f94be1dabdc2aa954f2ba8de2b4d58` |
| SHA3-384 | `1cb3fdb51c6e2bb54fd9d8022856f5451f677e353b29230a6fe838cbb0dc5369e07bdb6973ada6f8849dea019ae01e33` |
| TLSH | `T19951F8AC55611A774112FFB2B4118B2E35BFADC512A36B1C939D36AACC6C804F93C5C6` |
| SSDEEP | `48:rMpzaC56ZLaQRN9ahHJHCzXXaejrNZ3dt2TOti:r8+s6bhdri` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_99ec0e5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ec0e5a73529d9bc0ee7c385e46c802a2f94be1dabdc2aa954f2ba8de2b4d58"
    family = "Mirai"
    file_name = "massload"
    file_type = "sh"
    first_seen = "2026-07-02 23:02:02"
  condition:
    hash.sha256(0, filesize) == "99ec0e5a73529d9bc0ee7c385e46c802a2f94be1dabdc2aa954f2ba8de2b4d58"
}
```

### Sample 71: `5045790b695470f4`

| Field | Value |
|---|---|
| SHA-256 | `5045790b695470f4c147aab23fed23dd60fa3fb09166af3f23fd39a103ae3c42` |
| Family label | `unknown` |
| File name | `t` |
| File type | `unknown` |
| First seen | `2026-07-02 23:02:01` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51ccd48f4d592bed18a5b7ce12dd8e14` |
| SHA-256 | `5045790b695470f4c147aab23fed23dd60fa3fb09166af3f23fd39a103ae3c42` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_5045790b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5045790b695470f4c147aab23fed23dd60fa3fb09166af3f23fd39a103ae3c42"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-02 23:02:01"
  condition:
    hash.sha256(0, filesize) == "5045790b695470f4c147aab23fed23dd60fa3fb09166af3f23fd39a103ae3c42"
}
```

### Sample 72: `8ddea0d6c3b4a556`

| Field | Value |
|---|---|
| SHA-256 | `8ddea0d6c3b4a5560b9cf33e7f2d0c9a76a0ea0291199730489345dbae93da2d` |
| Family label | `Mirai` |
| File name | `fuck` |
| File type | `elf` |
| First seen | `2026-07-02 23:01:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1493a70f8de056117a008662bb850db3` |
| SHA-1 | `2ea832d9de0ab0f848433b5c632abed0eb9216d0` |
| SHA-256 | `8ddea0d6c3b4a5560b9cf33e7f2d0c9a76a0ea0291199730489345dbae93da2d` |
| SHA3-384 | `b72f52f4d16a5f9376fffd6a7cea6c720fe6cfb957d5a464c268433eef010e820d9c8ddf354ba1007cfae4cb3db20555` |
| TLSH | `T109055B54AD5EF803D1D7FB78EF89A3E1931FF192C74382137881124D89E5EA8D9A7884` |
| SSDEEP | `12288:pcPTrCitMzme2VB47tTZ8RjMYc4oDl0PVs5stx3n:CPTumpMTZ8Rw6oD+x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_8ddea0d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddea0d6c3b4a5560b9cf33e7f2d0c9a76a0ea0291199730489345dbae93da2d"
    family = "Mirai"
    file_name = "fuck"
    file_type = "elf"
    first_seen = "2026-07-02 23:01:59"
  condition:
    hash.sha256(0, filesize) == "8ddea0d6c3b4a5560b9cf33e7f2d0c9a76a0ea0291199730489345dbae93da2d"
}
```

### Sample 73: `fb1dc19c0ddc5113`

| Field | Value |
|---|---|
| SHA-256 | `fb1dc19c0ddc511361a6cca94dafd61d579d53a38ed3d3d8cefd25ffedc390b4` |
| Family label | `Mirai` |
| File name | `main_x86` |
| File type | `elf` |
| First seen | `2026-07-02 23:01:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8f0edaec4d5e699b55a0028a4572284` |
| SHA-1 | `f2b5d4b2e2aad03584e86beffe9b25611eac68ad` |
| SHA-256 | `fb1dc19c0ddc511361a6cca94dafd61d579d53a38ed3d3d8cefd25ffedc390b4` |
| SHA3-384 | `d572bd2431f918c12d156a3aefea01184eeae6ae869f43142712da97af9b73e9950bdf36b2ded0cecb5be0a9c06ce959` |
| TLSH | `T11D931982BA43CFB3E84314F112F79B365A31FC7E182BE982E379BDE199415C1A505768` |
| TELFHASH | `t10751b1fa6dba08ecfbd0a804c75e5bd33669ca7b153025b0406398b532f79954475c3a` |
| SSDEEP | `1536:D/QCZaxGdvts3i5JPhofsxPu++4HRsUIKqI4FrS4LSX:DYCZa8dvm3oJPhisxP5lR+KfUmDX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_fb1dc19c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb1dc19c0ddc511361a6cca94dafd61d579d53a38ed3d3d8cefd25ffedc390b4"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-07-02 23:01:57"
  condition:
    hash.sha256(0, filesize) == "fb1dc19c0ddc511361a6cca94dafd61d579d53a38ed3d3d8cefd25ffedc390b4"
}
```

### Sample 74: `9c0eb19d1579fbc9`

| Field | Value |
|---|---|
| SHA-256 | `9c0eb19d1579fbc93030d42465b90e092889b930733ffda60b5acb137a346dac` |
| Family label | `AgentTesla` |
| File name | `Quote Ref #011599.js` |
| File type | `js` |
| First seen | `2026-07-02 22:54:42` |
| Reporter | `threatcat_ch` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bee96dd6dd3f1b7452507dee0b0f6923` |
| SHA-1 | `071ec523c70a4654e66dbb257be1ac4071b330e7` |
| SHA-256 | `9c0eb19d1579fbc93030d42465b90e092889b930733ffda60b5acb137a346dac` |
| SHA3-384 | `8d65aff8c772dd873da87435fbfff66e401114145921e31bcd067a687e71a38af5fae5c5206bdfbc3083303d0fe4d5dd` |
| TLSH | `T1D9752335443DB2003427EE76C3AD64DADBCD5AE9BFAF51494036174A9227D8BCCC226B` |
| SSDEEP | `12288:Ge8IEdPRUwn+VpabD+WeKlZUQHstoMMAsfo:gPRbCu+AAko` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_074_9c0eb19d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c0eb19d1579fbc93030d42465b90e092889b930733ffda60b5acb137a346dac"
    family = "AgentTesla"
    file_name = "Quote Ref #011599.js"
    file_type = "js"
    first_seen = "2026-07-02 22:54:42"
  condition:
    hash.sha256(0, filesize) == "9c0eb19d1579fbc93030d42465b90e092889b930733ffda60b5acb137a346dac"
}
```

### Sample 75: `f5f263ec0dce3c9a`

| Field | Value |
|---|---|
| SHA-256 | `f5f263ec0dce3c9adc2a7b33a033a48865eaac6909c5022b200bce610823254b` |
| Family label | `unknown` |
| File name | `NekooCraft.jar` |
| File type | `jar` |
| First seen | `2026-07-02 22:45:43` |
| Reporter | `lucibee` |
| Tags | `jar, RapidStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ba861da8d1bb18ab35ca1e30122ae72` |
| SHA-1 | `3777848b1c8a6d1bae1e608d98060d8d4727e3b9` |
| SHA-256 | `f5f263ec0dce3c9adc2a7b33a033a48865eaac6909c5022b200bce610823254b` |
| SHA3-384 | `345ba8ed3b56d3135831230e1e8d0c7e8f3cb9cf69528ec5ebe994ec87c2ad2555a3e5759801ee165f0303010083936f` |
| TLSH | `T1972401048DA85526E6B73271C12100D2B52FD28E528E7C7709FB06DFAD96EAC953372E` |
| SSDEEP | `6144:fNQnUfduZz+L+7TdR4/z6SEGQpAMsva9qiAGht:fNQnUFuZyLWdR4/+JGQ+Bg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_f5f263ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5f263ec0dce3c9adc2a7b33a033a48865eaac6909c5022b200bce610823254b"
    family = "unknown"
    file_name = "NekooCraft.jar"
    file_type = "jar"
    first_seen = "2026-07-02 22:45:43"
  condition:
    hash.sha256(0, filesize) == "f5f263ec0dce3c9adc2a7b33a033a48865eaac6909c5022b200bce610823254b"
}
```

### Sample 76: `16e34d5b3836f196`

| Field | Value |
|---|---|
| SHA-256 | `16e34d5b3836f196864a8efe804d8dcb5938801d29bed451a3b67dca6f7b0929` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-02 22:44:10` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, SalatStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4cd834ba9819b28bb0a45a90f34f45b` |
| SHA-1 | `8e36e4e662812bec78ba97cdb43960743efc2bad` |
| SHA-256 | `16e34d5b3836f196864a8efe804d8dcb5938801d29bed451a3b67dca6f7b0929` |
| SHA3-384 | `92e7397e637e80cb1678e1e2dcdf137d8813fdf9d25ec35ca8681aef98aedd10c3620988082a3c93a240c9e3630cc5c2` |
| IMPHASH | `645ebc07ea47a6f1018aae85547b08b5` |
| TLSH | `T1B926E1037BFEB05AEA7B97B4947462814665FC774D51808E31CD048B4F9BA407EBC2BA` |
| SSDEEP | `49152:RHOlsXUMuthG59/72yB08wlTPv9RD+Y1qEkvom1UYRos6lcEutlnuAcxvTdVIrCB:kLIGKwp39GEkv1ZKe7nuACbdx9oefA4` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_076_16e34d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e34d5b3836f196864a8efe804d8dcb5938801d29bed451a3b67dca6f7b0929"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 22:44:10"
  condition:
    hash.sha256(0, filesize) == "16e34d5b3836f196864a8efe804d8dcb5938801d29bed451a3b67dca6f7b0929"
}
```

### Sample 77: `a3ade4b9e03e459a`

| Field | Value |
|---|---|
| SHA-256 | `a3ade4b9e03e459a5955d68c52f8dbf893ce0c2bfb56c1c8b7415ecfb7ec9246` |
| Family label | `unknown` |
| File name | `temp_1781774687144.apk` |
| File type | `apk` |
| First seen | `2026-07-02 22:38:50` |
| Reporter | `BastianHein_` |
| Tags | `apk, Mirax` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2be0da0c4135514667aa947eec3a04d8` |
| SHA-1 | `fc48f53b4ada8c3d31cc647562d7a54e28ea626e` |
| SHA-256 | `a3ade4b9e03e459a5955d68c52f8dbf893ce0c2bfb56c1c8b7415ecfb7ec9246` |
| SHA3-384 | `914d0a303c7e597fee19320846115d47d41d688b1f6661a4f4087e8a89357b70410505d42d9ff2b7cd9c913a53eff8cc` |
| TLSH | `T194B61206FB49E96BC0F767764D764122424B4C268B53D3936F58723C18BBAE04F4AED8` |
| SSDEEP | `196608:n3SIGw4+np11yqnmxzbrV1IGOpU+Htk5TLLJbZWO:nj7/11mxZ1I2J7WO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_a3ade4b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3ade4b9e03e459a5955d68c52f8dbf893ce0c2bfb56c1c8b7415ecfb7ec9246"
    family = "unknown"
    file_name = "temp_1781774687144.apk"
    file_type = "apk"
    first_seen = "2026-07-02 22:38:50"
  condition:
    hash.sha256(0, filesize) == "a3ade4b9e03e459a5955d68c52f8dbf893ce0c2bfb56c1c8b7415ecfb7ec9246"
}
```

### Sample 78: `d472e114361dd2c6`

| Field | Value |
|---|---|
| SHA-256 | `d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25` |
| Family label | `unknown` |
| File name | `data.apk` |
| File type | `apk` |
| First seen | `2026-07-02 22:38:22` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d38d3c4c6cf760ab22b11db3449dd547` |
| SHA-1 | `7724f6e036fd314615392d2c0963c5210747edcb` |
| SHA-256 | `d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25` |
| SHA3-384 | `cfb754540be21ab200d35cef33f9e0e6c582abfbe905bd9d548fdeba09ea98f2ee19171286b24ba519e48ffe6a83fdc6` |
| TLSH | `T10ED61287F798A92BC8F79332567A562251474C068F43D7C76948B37C28BB9D01F89BC8` |
| SSDEEP | `196608:r2IASeU636XGM4BkAf2pWi28YJjJzfq9VBs3H9dZxP0Wfes/xl8xCGG5+tklsFyF:r2pUdGiN2rtEUHZtpesZOxGpsF8KII6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_d472e114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25"
    family = "unknown"
    file_name = "data.apk"
    file_type = "apk"
    first_seen = "2026-07-02 22:38:22"
  condition:
    hash.sha256(0, filesize) == "d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25"
}
```

### Sample 79: `85ec743443fe4830`

| Field | Value |
|---|---|
| SHA-256 | `85ec743443fe4830daddd95a454fc05b6434adf486a6889134b5d50c29570c9d` |
| Family label | `AsyncRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-02 22:17:39` |
| Reporter | `Bitsight` |
| Tags | `54e64e, AsyncRAT, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `659981348eab7fcf5fc2f0ead01628bd` |
| SHA-1 | `f57b0b8dbde00c34f3b89fcebb10a3631caa2a5a` |
| SHA-256 | `85ec743443fe4830daddd95a454fc05b6434adf486a6889134b5d50c29570c9d` |
| SHA3-384 | `2bbcd4153c3854231b73c12f69794f2de9364e79092dbb8c7f3c4c4349363c84a6807e125a0b0578d83e485cde1ab46c` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T133536C013798C965E2AE46B4BCF2550106B5C2772112DB1E7CC850DBAB9FFC60A527FE` |
| SSDEEP | `768:wcUiy5HN578DsC8A+XQPeWqfmqIKE5PpF1+T45SBGHmDbDPph0oXspEpNJSucdph:KpN/RmH9xFWYUbth9NpNgucdpqKmY7` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_079_85ec7434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ec743443fe4830daddd95a454fc05b6434adf486a6889134b5d50c29570c9d"
    family = "AsyncRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 22:17:39"
  condition:
    hash.sha256(0, filesize) == "85ec743443fe4830daddd95a454fc05b6434adf486a6889134b5d50c29570c9d"
}
```

### Sample 80: `dea110082d57d210`

| Field | Value |
|---|---|
| SHA-256 | `dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e` |
| Family label | `SpyNote` |
| File name | `decrypted_600520367292854360.apk` |
| File type | `apk` |
| First seen | `2026-07-02 22:17:24` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26acec1e131c452a6478bf39f91f908b` |
| SHA-1 | `2d1ac4fc6fdbc0c3890c6dcc74d51f9feab64156` |
| SHA-256 | `dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e` |
| SHA3-384 | `0d5477a7f82d86b5589260170fd3743dfb4676390df2b3511fc31b2679d6cb5810ec49249d7aca81a089f10c0b127384` |
| TLSH | `T1B3967D1BBA029972DB3CC7B490B4CA64BF326D85E98747D325083A7CFD391CC6A85758` |
| SSDEEP | `98304:GOPR+5YbNlt4PkbInf0ld3oKn6TNmzxzBb0tsJ5L:GOZ+mltIkbNniAzAsnL` |

#### Technical Assessment

- The sample is tracked as `SpyNote` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SpyNote_080_dea11008
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e"
    family = "SpyNote"
    file_name = "decrypted_600520367292854360.apk"
    file_type = "apk"
    first_seen = "2026-07-02 22:17:24"
  condition:
    hash.sha256(0, filesize) == "dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e"
}
```

### Sample 81: `7c4d1e3bff4c3d62`

| Field | Value |
|---|---|
| SHA-256 | `7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92` |
| Family label | `WannaCry` |
| File name | `7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92` |
| File type | `exe` |
| First seen | `2026-07-02 22:15:27` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01498deabb5500164c89021f8ff6d330` |
| SHA-1 | `ef763b740a730abd79ca5c97a69933bd887fc207` |
| SHA-256 | `7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92` |
| SHA3-384 | `f79a03476c55c5eac962e612e18f3c842e52e7a80d5c131d22e7931ab50d57f13e6cdf657d00d7b15b9a3dc1e59243ff` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T17536E01A6F9F84A8C5C5DCBCD961CB75D0F76D882079822686F07DAFBE7A3C41D02192` |
| SSDEEP | `98304:DMGPoBhz1aRxcSUGBBBBBBBBBBBBBBcBBBBBBBBBBBBBB:DMGPe1CxcIBBBBBBBBBBBBBBcBBBBBB3` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_081_7c4d1e3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92"
    family = "WannaCry"
    file_name = "7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92"
    file_type = "exe"
    first_seen = "2026-07-02 22:15:27"
  condition:
    hash.sha256(0, filesize) == "7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92"
}
```

### Sample 82: `eeb2d44d0f86670a`

| Field | Value |
|---|---|
| SHA-256 | `eeb2d44d0f86670ac2ee5e0b7aa44ec41b7be9962359f59ac21f736d7b0e7889` |
| Family label | `ValleyRAT` |
| File name | `27d3039a8ca9acbcbc985b88f27720a8.exe` |
| File type | `exe` |
| First seen | `2026-07-02 22:15:11` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27d3039a8ca9acbcbc985b88f27720a8` |
| SHA-1 | `16930eeb661537d9c34578174dfa6a0f2f00cece` |
| SHA-256 | `eeb2d44d0f86670ac2ee5e0b7aa44ec41b7be9962359f59ac21f736d7b0e7889` |
| SHA3-384 | `ef26dc9158668504dd854c673449dc2105772ee516c275a781feb8ba0466acec45a3b3792b7179b8cdba8e35c628faab` |
| IMPHASH | `40ab50289f7ef5fae60801f88d4541fc` |
| TLSH | `T15FF5F123B2CBE03EE05D0B3B4572A25894FBA7617523AD57DBE4849CCF260601E3E657` |
| SSDEEP | `49152:4+MRvHGGpdT5RMSKx/l6IhcLKH6D+z6tUpnJhG6uLK67MZ2Z9ftchfudg87dqn76:4r+GT/MSKH+i6DjQJU6u2+MYchXqdnMY` |
| ICON-DHASH | `f2e4f8707899a798` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_082_eeb2d44d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb2d44d0f86670ac2ee5e0b7aa44ec41b7be9962359f59ac21f736d7b0e7889"
    family = "ValleyRAT"
    file_name = "27d3039a8ca9acbcbc985b88f27720a8.exe"
    file_type = "exe"
    first_seen = "2026-07-02 22:15:11"
  condition:
    hash.sha256(0, filesize) == "eeb2d44d0f86670ac2ee5e0b7aa44ec41b7be9962359f59ac21f736d7b0e7889"
}
```

### Sample 83: `1f30b62c19be5de9`

| Field | Value |
|---|---|
| SHA-256 | `1f30b62c19be5de98456ec6915f1618da92cab68f20bf36cf91473788437f87a` |
| Family label | `unknown` |
| File name | `ۦۖ۫.apk` |
| File type | `apk` |
| First seen | `2026-07-02 21:35:27` |
| Reporter | `BastianHein_` |
| Tags | `apk, Banker, mparivahan, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a6f930bc7c4019de3b8ebfee6a2833c` |
| SHA-1 | `e84e6ca409c5233479e322b992dd57e796eed02a` |
| SHA-256 | `1f30b62c19be5de98456ec6915f1618da92cab68f20bf36cf91473788437f87a` |
| SHA3-384 | `92038f6d57b2dbc2e2bbb93df11a3f7bf18e161a6c4893ab9c58b4ee9f6ca26adf2e2a2cd18ee7fa36f2909281ca1b30` |
| TLSH | `T11676F1EBE39056AAC6FA12B50836693C80174E754FD3C1C79A44B33D64F71E84F68AC9` |
| SSDEEP | `98304:rvqDn/p6WLVrKR88MVqSTBOZIAnOWwVIxKR7qtIhTUdCDGhD1eUdXaIrpblNsN5g:2Dn/BVGTjSmKZsCDyVsuJNsdi97fkjzq` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_1f30b62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f30b62c19be5de98456ec6915f1618da92cab68f20bf36cf91473788437f87a"
    family = "unknown"
    file_name = "ۦۖ۫.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:35:27"
  condition:
    hash.sha256(0, filesize) == "1f30b62c19be5de98456ec6915f1618da92cab68f20bf36cf91473788437f87a"
}
```

### Sample 84: `be1d961b96fb27bd`

| Field | Value |
|---|---|
| SHA-256 | `be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f` |
| Family label | `Prometei` |
| File name | `be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f` |
| File type | `elf` |
| First seen | `2026-07-02 21:34:54` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `507059336c27d5ee05cfb0f5141204c0` |
| SHA-1 | `c813d032a962650b0bd01e8d2feace85a29c0438` |
| SHA-256 | `be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f` |
| SHA3-384 | `bce3936cea2736197e8bf457396d4747e614e69f251daa7740c3f00801e73212f38d6e645f25dec06464f3e4e07af843` |
| TLSH | `T1E9A423B4F9219E9F6DD769B91B24C31DE182C172589D4C2313AE94A34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdd:Fs6pyCC/Ya2hpi6T6N4n` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_084_be1d961b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f"
    family = "Prometei"
    file_name = "be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f"
    file_type = "elf"
    first_seen = "2026-07-02 21:34:54"
  condition:
    hash.sha256(0, filesize) == "be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f"
}
```

### Sample 85: `ff825f043105b50d`

| Field | Value |
|---|---|
| SHA-256 | `ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943` |
| Family label | `Prometei` |
| File name | `ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943` |
| File type | `exe` |
| First seen | `2026-07-02 21:34:23` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d32a6f12ae3234ebab9b240102730f38` |
| SHA-1 | `0641dfbd351174bd8c5ead8962ec24ab50b5d3a7` |
| SHA-256 | `ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943` |
| SHA3-384 | `4c17dc0f2e0a133bf121f0a394de35669f818852cce2e6fa2d8df1ea6874d661e9c948728fee5443740a16ef7753e062` |
| IMPHASH | `899ad1596f9c6642245b3fb721bae585` |
| TLSH | `T12034BE63A4BCAA9FDDD82F379C4E880713B66FE5D890203E1C44710EFE2A5095F7A516` |
| SSDEEP | `6144:mGxCfPf0s3KPHfBxR8jPs1F1yD9jvryfL9SqXVdOU:mG60BpL8jk1FGjDc8GVdOU` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_085_ff825f04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943"
    family = "Prometei"
    file_name = "ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943"
    file_type = "exe"
    first_seen = "2026-07-02 21:34:23"
  condition:
    hash.sha256(0, filesize) == "ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943"
}
```

### Sample 86: `05a2da9df1b4aed7`

| Field | Value |
|---|---|
| SHA-256 | `05a2da9df1b4aed78e16349c17443ccd83cb48ed9e38e38d0c0b6ce808a9c2a8` |
| Family label | `unknown` |
| File name | `src_0.apk` |
| File type | `apk` |
| First seen | `2026-07-02 21:15:55` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb554018315541ad53fd0cb705e4d0b1` |
| SHA-1 | `17837f97ffae693637fa08aa09692e605612ff48` |
| SHA-256 | `05a2da9df1b4aed78e16349c17443ccd83cb48ed9e38e38d0c0b6ce808a9c2a8` |
| SHA3-384 | `d73aa35b616c380bb50b1f120262f4e8a26ec011f404a1a89c235b556df26ba33e495924cc97a6a7c5b7c7dde3a594f9` |
| TLSH | `T1A696E143FB49CA97D9AA83F26B270F992A170F04C742AAD34555367E2D7B1C20DC5ACC` |
| SSDEEP | `98304:wUlOOEzBDTimzR0tbqBtoRTA2GPda9yJhmjcZe:wOUNzubmCREJa9yJowZe` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_05a2da9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a2da9df1b4aed78e16349c17443ccd83cb48ed9e38e38d0c0b6ce808a9c2a8"
    family = "unknown"
    file_name = "src_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:55"
  condition:
    hash.sha256(0, filesize) == "05a2da9df1b4aed78e16349c17443ccd83cb48ed9e38e38d0c0b6ce808a9c2a8"
}
```

### Sample 87: `537f08755139d019`

| Field | Value |
|---|---|
| SHA-256 | `537f08755139d0199fb1751068eb49a92b68e0d1dcadaf03758837c3832f99c5` |
| Family label | `unknown` |
| File name | `res_obs_0.apk` |
| File type | `apk` |
| First seen | `2026-07-02 21:15:48` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `562296b99a2019731809c99a846139e7` |
| SHA-1 | `c5727db19a90d4ce60636add597cf879ef7d84ca` |
| SHA-256 | `537f08755139d0199fb1751068eb49a92b68e0d1dcadaf03758837c3832f99c5` |
| SHA3-384 | `1690a98cb3770710d35dbe619c774e2900d6ceb0e541ac2a84bf8734fb8e03b4ec1c53935d97cc8def30ea79861a7fdd` |
| TLSH | `T15E060117FFCA94BAECF243360E7563253602AC358B67A2879864327CA4B75D01F46DD8` |
| SSDEEP | `98304:fQc6eL7ACQ9GPjpZyp5tWR4qLUrWKDCURs/4:fLcCQ6pZyp1qL5KDhs4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_537f0875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "537f08755139d0199fb1751068eb49a92b68e0d1dcadaf03758837c3832f99c5"
    family = "unknown"
    file_name = "res_obs_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:48"
  condition:
    hash.sha256(0, filesize) == "537f08755139d0199fb1751068eb49a92b68e0d1dcadaf03758837c3832f99c5"
}
```

### Sample 88: `72f18d019123393a`

| Field | Value |
|---|---|
| SHA-256 | `72f18d019123393ae610dd73b25e5f30a4945430f6f835700d6bdee19f566a30` |
| Family label | `unknown` |
| File name | `output_0.apk` |
| File type | `apk` |
| First seen | `2026-07-02 21:15:42` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50d360fa0767101e1409cf6d6708ee40` |
| SHA-1 | `af62ca2c7e32e16474acdd46c311dbdb69664eb3` |
| SHA-256 | `72f18d019123393ae610dd73b25e5f30a4945430f6f835700d6bdee19f566a30` |
| SHA3-384 | `219ea39fe4283e208bbb6229ae6cab2f4c2a613eb9722b287b84cbe82a62f9119b775932c00c1c659c8dac7e2ea75d10` |
| TLSH | `T16AC70157FFC655BAFCF643360E3553692202AC358B67B28BA814327CA4B75D02E42DD8` |
| SSDEEP | `98304:1q6eL7ACQ9GPjpZyp5eWR/XmU+2bDiUOBCw:QLcCQ6pZyplXmebD+4w` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_72f18d01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72f18d019123393ae610dd73b25e5f30a4945430f6f835700d6bdee19f566a30"
    family = "unknown"
    file_name = "output_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:42"
  condition:
    hash.sha256(0, filesize) == "72f18d019123393ae610dd73b25e5f30a4945430f6f835700d6bdee19f566a30"
}
```

### Sample 89: `bf586ec8ce8528d2`

| Field | Value |
|---|---|
| SHA-256 | `bf586ec8ce8528d26ec491fa5864dc590cefae88da176246296bb849e226a0c8` |
| Family label | `unknown` |
| File name | `entry_added_0.apk` |
| File type | `apk` |
| First seen | `2026-07-02 21:15:25` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e9ee52f13377dc3ec36394508727e34` |
| SHA-1 | `d3fcc0617f887f9d1a57b54712831bc1acc70cc4` |
| SHA-256 | `bf586ec8ce8528d26ec491fa5864dc590cefae88da176246296bb849e226a0c8` |
| SHA3-384 | `54ce78d6fc78dbb8da16526b12e68a90cf6eea4bd07cb35a0de449e9db4da72195e184a69e7d7907983689b1c9393701` |
| TLSH | `T1D0C70157FFC655BAFCF643360E3553692202AC358B67B28BA814327CA4B75D02E42DD8` |
| SSDEEP | `98304:1q6eL7ACQ9GPjpZyp5eWR/XmU+2bDiUOBC7:QLcCQ6pZyplXmebD+47` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_bf586ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf586ec8ce8528d26ec491fa5864dc590cefae88da176246296bb849e226a0c8"
    family = "unknown"
    file_name = "entry_added_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:25"
  condition:
    hash.sha256(0, filesize) == "bf586ec8ce8528d26ec491fa5864dc590cefae88da176246296bb849e226a0c8"
}
```

### Sample 90: `0bc98459a42d1d01`

| Field | Value |
|---|---|
| SHA-256 | `0bc98459a42d1d0108a882671f4496f214f8a68400810b9e034cdd7212f5a4fa` |
| Family label | `unknown` |
| File name | `apksigner6222202351320183515.apk` |
| File type | `apk` |
| First seen | `2026-07-02 21:15:08` |
| Reporter | `BastianHein_` |
| Tags | `apk, Spynote` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `316362e4154db3f959f759240be2fb9d` |
| SHA-1 | `9f4a31e0387422d7e7503920f4d7814a7ea466f7` |
| SHA-256 | `0bc98459a42d1d0108a882671f4496f214f8a68400810b9e034cdd7212f5a4fa` |
| SHA3-384 | `c5ad99a80b672d55dcdeef0f5ef5503446dea0a174b938d349ec2d9c1ebbb92fb8ef153cfedd2ca99c585f74fe16472a` |
| TLSH | `T163C70157FFC655BAFCF643360E3553692202AC358B67B28BA814327CA4B75D02E42DD8` |
| SSDEEP | `98304:8q6eL7ACQ9GPjpZyp5eWR/XmU+2bDiUOBCC:FLcCQ6pZyplXmebD+4C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_0bc98459
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc98459a42d1d0108a882671f4496f214f8a68400810b9e034cdd7212f5a4fa"
    family = "unknown"
    file_name = "apksigner6222202351320183515.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:08"
  condition:
    hash.sha256(0, filesize) == "0bc98459a42d1d0108a882671f4496f214f8a68400810b9e034cdd7212f5a4fa"
}
```

### Sample 91: `275035f44dc9cf99`

| Field | Value |
|---|---|
| SHA-256 | `275035f44dc9cf992964e3954ba0af5d09e0df6b5c1009befaaeb21408cc0bba` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-02 21:14:34` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3aa8ec7fb0c2f9ecf0553bfcbd6aad64` |
| SHA-1 | `f697275f6cb26ad58e4d8debf8cec6e4f2b21671` |
| SHA-256 | `275035f44dc9cf992964e3954ba0af5d09e0df6b5c1009befaaeb21408cc0bba` |
| SHA3-384 | `d720e8de9c2313937c53a5cc550885d2e1a6c62164ec567681850772f4c2b42b57fbae984e684471aee40bbc8fb600ed` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1FBA5230F13E8476DD17A873488F2428297313C546B3867FF36E81AAD5E232C2957676E` |
| SSDEEP | `49152:nuv+8ndzSduo63YpgytG0Sar8SfB6eZTHLuSeWa/rS57:Y4oYpRDrTkqTrveZ/r` |
| ICON-DHASH | `31f0d8f866f8c0e0` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_091_275035f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "275035f44dc9cf992964e3954ba0af5d09e0df6b5c1009befaaeb21408cc0bba"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 21:14:34"
  condition:
    hash.sha256(0, filesize) == "275035f44dc9cf992964e3954ba0af5d09e0df6b5c1009befaaeb21408cc0bba"
}
```

### Sample 92: `42bf45811ef88b4c`

| Field | Value |
|---|---|
| SHA-256 | `42bf45811ef88b4cbbde334f34197beca2836a38a6d2ba45d7c9f4ec60937450` |
| Family label | `unknown` |
| File name | `p` |
| File type | `sh` |
| First seen | `2026-07-02 20:21:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a3f48f036e88ea454956e3b06bd265b` |
| SHA-1 | `8d068c6084e396e3cdc1165d2804e7cc84ec7d91` |
| SHA-256 | `42bf45811ef88b4cbbde334f34197beca2836a38a6d2ba45d7c9f4ec60937450` |
| SHA3-384 | `2f09010a9f909a49a32ef0adb949b32fabbe9773fd797d5a2fffe67115c50cf16d51f784b438f9e7ae4cf32b289286eb` |
| TLSH | `T11E01A6C68201AD00802ADA1E639B61D0B411C3CF1A4B0B687FDC5A3EFB8CC14F066FE8` |
| SSDEEP | `12:dOXOsYxcysE+vhCFN0zvy/RQvZowHkaNCRERFCEQ4r3FChXBY8Cf84n/lC+lauD:kXCKysE2hi0ziQvZohaNXj3yLPsJ7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_42bf4581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42bf45811ef88b4cbbde334f34197beca2836a38a6d2ba45d7c9f4ec60937450"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-02 20:21:07"
  condition:
    hash.sha256(0, filesize) == "42bf45811ef88b4cbbde334f34197beca2836a38a6d2ba45d7c9f4ec60937450"
}
```

### Sample 93: `b634c8c0ec3a4d68`

| Field | Value |
|---|---|
| SHA-256 | `b634c8c0ec3a4d682630eed6ac1cc8d5e2b0481110121990edcb4e0df9867698` |
| Family label | `unknown` |
| File name | `dogandcat(1).apk` |
| File type | `apk` |
| First seen | `2026-07-02 20:13:12` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3f9313c8d623b2e244a389e94f9ce69` |
| SHA-1 | `2cd571d5adbac1ba150782d2afa0be3b095569e8` |
| SHA-256 | `b634c8c0ec3a4d682630eed6ac1cc8d5e2b0481110121990edcb4e0df9867698` |
| SHA3-384 | `6b3d6c734160dc44a18c8db7b19978a2640df252723a34d809721448084e6a3528aeccf65bc02bf382a43f390cd6e174` |
| TLSH | `T183A46C06DE904D33C8AE227D45A21390373AE689A703834B260DD6B57F933EB5F876D5` |
| SSDEEP | `6144:modf9exi7x2lV5RMFs53cogD53Mpd39RCjBcMpcq34l:moT7xsvMs5Mzmp+cMpM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_b634c8c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b634c8c0ec3a4d682630eed6ac1cc8d5e2b0481110121990edcb4e0df9867698"
    family = "unknown"
    file_name = "dogandcat(1).apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:13:12"
  condition:
    hash.sha256(0, filesize) == "b634c8c0ec3a4d682630eed6ac1cc8d5e2b0481110121990edcb4e0df9867698"
}
```

### Sample 94: `f5b84a261a19b806`

| Field | Value |
|---|---|
| SHA-256 | `f5b84a261a19b8066cb609124d97bc52df08f08f564d32358a15aaf511caf5e4` |
| Family label | `unknown` |
| File name | `dogandcat.apk.signed.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-02 20:13:06` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1238a85e5e0f518348304fc59055a42` |
| SHA-1 | `2b0946805d9a5e00109ad867c33716485471931b` |
| SHA-256 | `f5b84a261a19b8066cb609124d97bc52df08f08f564d32358a15aaf511caf5e4` |
| SHA3-384 | `35d1619fb5257a216ed3293473df1858a8bde4fce8f8e1f20b0d0ed0f3184911993df766c868c5edb21cfdf227624618` |
| TLSH | `T1D6B46D06EA904E33C4AF127D45A31780373AA949AB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:/odf9exi7x2lV5RMFs53cogD53Mpd39RCjB9ruft:/oT7xsvMs5Mzmp+9ro` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_f5b84a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b84a261a19b8066cb609124d97bc52df08f08f564d32358a15aaf511caf5e4"
    family = "unknown"
    file_name = "dogandcat.apk.signed.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:13:06"
  condition:
    hash.sha256(0, filesize) == "f5b84a261a19b8066cb609124d97bc52df08f08f564d32358a15aaf511caf5e4"
}
```

### Sample 95: `cbc71b0bd3f94cb1`

| Field | Value |
|---|---|
| SHA-256 | `cbc71b0bd3f94cb163a8ab106242aa7638aced10e7b8c4d6179bc7fc5ba649f2` |
| Family label | `unknown` |
| File name | `dogandcat.apk` |
| File type | `apk` |
| First seen | `2026-07-02 20:13:01` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6249c7d715a47215fdccffca8ec7d96` |
| SHA-1 | `a709906be7f7763b5aad0a236393fabd28463c08` |
| SHA-256 | `cbc71b0bd3f94cb163a8ab106242aa7638aced10e7b8c4d6179bc7fc5ba649f2` |
| SHA3-384 | `f54d06557695401b3182cfbdbf6af89e7da0c4cf602c91d3f5360883f6624b2a9bf6759a424488a615054f8b3253704a` |
| TLSH | `T10AA45D06EA904E33C4AF127D45A31780373AA949AB43834B320DEA787FB33D65B975D5` |
| SSDEEP | `6144:1odf9exi7x2lV5RMFs53cogD53Mpd39RCjBXJW9H:1oT7xsvMs5Mzmp+XJo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_cbc71b0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbc71b0bd3f94cb163a8ab106242aa7638aced10e7b8c4d6179bc7fc5ba649f2"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:13:01"
  condition:
    hash.sha256(0, filesize) == "cbc71b0bd3f94cb163a8ab106242aa7638aced10e7b8c4d6179bc7fc5ba649f2"
}
```

### Sample 96: `5cad494f67808745`

| Field | Value |
|---|---|
| SHA-256 | `5cad494f67808745489659cd077dce429fce364a673c44c9d238d14dcca81732` |
| Family label | `unknown` |
| File name | `dog_patched.tmp.apk` |
| File type | `apk` |
| First seen | `2026-07-02 20:12:55` |
| Reporter | `BastianHein_` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dcd4b0c11087e2085ba203b9a3eef7c` |
| SHA-1 | `e2559a0431c9aa6c1881a7b44b71a099adc1bde2` |
| SHA-256 | `5cad494f67808745489659cd077dce429fce364a673c44c9d238d14dcca81732` |
| SHA3-384 | `fc1ef5b69932c06b9403881a769910c5b55d06bfd73e6fa61878cca785ad67a661185a521a78f2bb01037f88884e6ac7` |
| TLSH | `T124A45C06EA904E33C4AE127D45A31780373AA949AB43834B320DEA787FB33D65F975D5` |
| SSDEEP | `6144:iodf9exi7x2lV5RMFs53cogD53Mpd39RCjBbit+l:ioT7xsvMs5Mzmp+biI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_5cad494f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cad494f67808745489659cd077dce429fce364a673c44c9d238d14dcca81732"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:12:55"
  condition:
    hash.sha256(0, filesize) == "5cad494f67808745489659cd077dce429fce364a673c44c9d238d14dcca81732"
}
```

### Sample 97: `580877c7bf8d435f`

| Field | Value |
|---|---|
| SHA-256 | `580877c7bf8d435f28741037a3e64dfefea32d9e594196e39308af80396596bd` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-02 20:06:47` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7e9070bbf6dc64d6edd5cbcd7aeb6a40` |
| SHA-1 | `d9fac2178fae613ddc52b4c422a91ef5eea2edda` |
| SHA-256 | `580877c7bf8d435f28741037a3e64dfefea32d9e594196e39308af80396596bd` |
| SHA3-384 | `7fd65801b2f27fcf5ee158d404e18bd0a6091b098e30406def4785f0c2f6eec35d1ba4d8789857f9daf33bfd7f3ca0bc` |
| TLSH | `T1B9236C6516857C24AE99C9371C7E2F0CB9A983E5320452EDBFCB3CF28C4AA9CD11971D` |
| SSDEEP | `768:t+Z9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnW:t+ycB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_580877c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "580877c7bf8d435f28741037a3e64dfefea32d9e594196e39308af80396596bd"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-02 20:06:47"
  condition:
    hash.sha256(0, filesize) == "580877c7bf8d435f28741037a3e64dfefea32d9e594196e39308af80396596bd"
}
```

### Sample 98: `add9ff4b6e733959`

| Field | Value |
|---|---|
| SHA-256 | `add9ff4b6e73395939d91d9956fb79aae3ccf42522e8b5954d20a59f7f70ca5a` |
| Family label | `unknown` |
| File name | `WSW0` |
| File type | `sh` |
| First seen | `2026-07-02 20:02:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2237e6707dbda4bba0b1943f2334efcf` |
| SHA-1 | `4efa26973a90c236a064db737909bbc97ad5b3ce` |
| SHA-256 | `add9ff4b6e73395939d91d9956fb79aae3ccf42522e8b5954d20a59f7f70ca5a` |
| SHA3-384 | `d69e8c3412ba0fd5234050f0ccba30d0bff3d4d069bbde9e0818ce5f35ddf7756ece0c2c77790971c4391bbe7c3463a0` |
| TLSH | `T1A8D097B2C3B301B010E10454F0C76480BA19C7BF8C86C22CB93B30710F21B4AF4C2360` |
| SSDEEP | `6:hTwawF6aFasUFxvAulNXYq9DG+NjVsNXYrkJ:Vw7FXc9Piq9DGmKi2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_add9ff4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "add9ff4b6e73395939d91d9956fb79aae3ccf42522e8b5954d20a59f7f70ca5a"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-02 20:02:50"
  condition:
    hash.sha256(0, filesize) == "add9ff4b6e73395939d91d9956fb79aae3ccf42522e8b5954d20a59f7f70ca5a"
}
```

### Sample 99: `4e6276cc400b3b9e`

| Field | Value |
|---|---|
| SHA-256 | `4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d` |
| Family label | `unknown` |
| File name | `libjson_script.so.0` |
| File type | `elf` |
| First seen | `2026-07-02 19:37:06` |
| Reporter | `smica83` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54aee5f6cb2427adaf7508f987ff990d` |
| SHA-1 | `11835385c3a614d1ac8829e95096e367f80e3832` |
| SHA-256 | `4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d` |
| SHA3-384 | `01a1e1b2b87deb975b4e49b541dd1e7d6177c7c54f269c2f41bdbb0576b320d8a0c20529c03b27b8dfbee1321099d6a1` |
| TLSH | `T1EEC45C0BAED00DBBECD1C470475F81776F32F485A222A71735C5A6213E56A34AF2E7A4` |
| TELFHASH | `t190a2ff0d6b178757be1544dc5ba9a7e31943944b9a6d8bc0cad8cb0bc6302bafc12cdd` |
| SSDEEP | `6144:+sVutJn03sIq0kxOsys0wGxs5M3Fw9NkUc2rCnFJRBae6ayBFTnGvMdcijIg+Uae:+sVutJgqf9yyws5mFw9eUaGTGvMid2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_4e6276cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d"
    family = "unknown"
    file_name = "libjson_script.so.0"
    file_type = "elf"
    first_seen = "2026-07-02 19:37:06"
  condition:
    hash.sha256(0, filesize) == "4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d"
}
```

### Sample 100: `015a389e5c97ec1e`

| Field | Value |
|---|---|
| SHA-256 | `015a389e5c97ec1e545978359e19c08050ce2b3d23c88557ec9f4a540a4c6c51` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-02 19:34:09` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX3.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3542f2e27fa10e348e726fdc3a743b47` |
| SHA-1 | `ec8d4c78813660130325eb681bee334e54b28452` |
| SHA-256 | `015a389e5c97ec1e545978359e19c08050ce2b3d23c88557ec9f4a540a4c6c51` |
| SHA3-384 | `f9f478f457753f8335a82ea0004bf7d066f659abf679178ee548afc49b90e135fd5e23ba97130477add1ba5ef40a82db` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T13DC5331533E438EAE635177C89F3418B5473BC921B3562EF10C5AAB56A27A92D432F0F` |
| SSDEEP | `49152:5uFGKd/UoZtVG6bGcqzI0NQF2BwVCKn82pgVJD6NyRbHpqOjkKER20C+phnxGyjw:WjdfnU6bxhZVCcaVcNybqiX0nfnZjtW` |
| ICON-DHASH | `c884a2d9e8d8fd7c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_015a389e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "015a389e5c97ec1e545978359e19c08050ce2b3d23c88557ec9f4a540a4c6c51"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 19:34:09"
  condition:
    hash.sha256(0, filesize) == "015a389e5c97ec1e545978359e19c08050ce2b3d23c88557ec9f4a540a4c6c51"
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
 * Generated: 2026-07-03T04:12:39.746334+00:00
 */

rule MalwareBazaar_MaskGramStealer_001_0275c6cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86"
    family = "MaskGramStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 04:05:09"
  condition:
    hash.sha256(0, filesize) == "0275c6cf588a7e26e97cbd3a8d301370ebeb18470e86b21d295c8d93ca778d86"
}

rule MalwareBazaar_unknown_002_d2a8fc67
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2a8fc67ee43ce1bf1af64da8cf5798a81303121fae64e2dfd1386f483ce55ba"
    family = "unknown"
    file_name = "DiscordThemeTest#2.exe"
    file_type = "exe"
    first_seen = "2026-07-03 03:59:41"
  condition:
    hash.sha256(0, filesize) == "d2a8fc67ee43ce1bf1af64da8cf5798a81303121fae64e2dfd1386f483ce55ba"
}

rule MalwareBazaar_unknown_003_d6d1f2dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6d1f2dd6db3177ccbde0fe17170cc4fa81078d1a9a900f1f5dd73ddce5f06e6"
    family = "unknown"
    file_name = "app(4).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:08:21"
  condition:
    hash.sha256(0, filesize) == "d6d1f2dd6db3177ccbde0fe17170cc4fa81078d1a9a900f1f5dd73ddce5f06e6"
}

rule MalwareBazaar_unknown_004_ca9ae76d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ca9ae76de194548709966263c227709d5c57c8e57f07f50d1532cf52fc5f438d"
    family = "unknown"
    file_name = "app(3).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:08:04"
  condition:
    hash.sha256(0, filesize) == "ca9ae76de194548709966263c227709d5c57c8e57f07f50d1532cf52fc5f438d"
}

rule MalwareBazaar_unknown_005_84ddfdd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84ddfdd7862e3c3481ae65b64d9087ab7c5c29355a29e9e7c3a4011a631f7387"
    family = "unknown"
    file_name = "app(2).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:07:50"
  condition:
    hash.sha256(0, filesize) == "84ddfdd7862e3c3481ae65b64d9087ab7c5c29355a29e9e7c3a4011a631f7387"
}

rule MalwareBazaar_unknown_006_cb7744fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb7744fe6345dd0e4f15f1acdde23ecb6d484b3c8a6ce8792628a6a1453eefa4"
    family = "unknown"
    file_name = "app(1).apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:07:36"
  condition:
    hash.sha256(0, filesize) == "cb7744fe6345dd0e4f15f1acdde23ecb6d484b3c8a6ce8792628a6a1453eefa4"
}

rule MalwareBazaar_unknown_007_fca210ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fca210ed8b28a9544d0db5a8387fe75c26091003041220a9d28cb445e8169aad"
    family = "unknown"
    file_name = "app.apk"
    file_type = "apk"
    first_seen = "2026-07-03 03:07:22"
  condition:
    hash.sha256(0, filesize) == "fca210ed8b28a9544d0db5a8387fe75c26091003041220a9d28cb445e8169aad"
}

rule MalwareBazaar_unknown_008_7286691d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7286691d7986d2ba342adfc68697a81a3c7050ccbcad3ca4600f4205993c6588"
    family = "unknown"
    file_name = "armv7l.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 02:31:51"
  condition:
    hash.sha256(0, filesize) == "7286691d7986d2ba342adfc68697a81a3c7050ccbcad3ca4600f4205993c6588"
}

rule MalwareBazaar_CoinMiner_009_3d4d7516
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d4d751665fc9f5247f34d7c3db5381d83c55cd1d49311b3570f2c002b36cb1e"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-03 02:30:37"
  condition:
    hash.sha256(0, filesize) == "3d4d751665fc9f5247f34d7c3db5381d83c55cd1d49311b3570f2c002b36cb1e"
}

rule MalwareBazaar_Formbook_010_a6264afd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6264afd465d3a04bc0594251771ca50e372a8d40068707a67830be581bb2c2b"
    family = "Formbook"
    file_name = "Settlement Contract.pdf.exe"
    file_type = "exe"
    first_seen = "2026-07-03 02:17:44"
  condition:
    hash.sha256(0, filesize) == "a6264afd465d3a04bc0594251771ca50e372a8d40068707a67830be581bb2c2b"
}

rule MalwareBazaar_unknown_011_b60ce046
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b60ce046f32587bc6b87df4cd530c6728af82c482df2a3fe14c88d5fd252ca30"
    family = "unknown"
    file_name = "mipsel.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 02:15:53"
  condition:
    hash.sha256(0, filesize) == "b60ce046f32587bc6b87df4cd530c6728af82c482df2a3fe14c88d5fd252ca30"
}

rule MalwareBazaar_WannaCry_012_94faff75
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36"
    family = "WannaCry"
    file_name = "94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36"
    file_type = "exe"
    first_seen = "2026-07-03 02:15:32"
  condition:
    hash.sha256(0, filesize) == "94faff7500a2f959889a3fff9bed01cb30fdb6ab5dbcbe984f592a3891333f36"
}

rule MalwareBazaar_unknown_013_a2b92941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2b929416dba251191a074ec1a186e696d279eaff6f4dba271a4b9a0ee228c82"
    family = "unknown"
    file_name = "output_0yditfsf.js"
    file_type = "js"
    first_seen = "2026-07-03 02:01:20"
  condition:
    hash.sha256(0, filesize) == "a2b929416dba251191a074ec1a186e696d279eaff6f4dba271a4b9a0ee228c82"
}

rule MalwareBazaar_unknown_014_7ccf139c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ccf139c5192acdec6370f391801390935df872849212349f27f388b0a39674d"
    family = "unknown"
    file_name = "powerpc.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:59:53"
  condition:
    hash.sha256(0, filesize) == "7ccf139c5192acdec6370f391801390935df872849212349f27f388b0a39674d"
}

rule MalwareBazaar_unknown_015_770db614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "770db614b0e7b3cd571f12eb94bc8b06c7c151f37c4ecc41656476bbb4d3084e"
    family = "unknown"
    file_name = "lil"
    file_type = "sh"
    first_seen = "2026-07-03 01:59:52"
  condition:
    hash.sha256(0, filesize) == "770db614b0e7b3cd571f12eb94bc8b06c7c151f37c4ecc41656476bbb4d3084e"
}

rule MalwareBazaar_unknown_016_cfe32ce5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cfe32ce53eb6ec90806eba86f53c778f07879ef82a898b3d45f4d43af8de2761"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-03 01:55:51"
  condition:
    hash.sha256(0, filesize) == "cfe32ce53eb6ec90806eba86f53c778f07879ef82a898b3d45f4d43af8de2761"
}

rule MalwareBazaar_unknown_017_876de7e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "876de7e7e43dbfacb7e37487d926eac189ddf717966e09fc439b986a20719b54"
    family = "unknown"
    file_name = "x86_64.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:53:51"
  condition:
    hash.sha256(0, filesize) == "876de7e7e43dbfacb7e37487d926eac189ddf717966e09fc439b986a20719b54"
}

rule MalwareBazaar_Mirai_018_f8183b62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8183b625153b4b06f974c697d52a2d273a4e7d981f4f33e8ff27c203653f600"
    family = "Mirai"
    file_name = "tmips"
    file_type = "elf"
    first_seen = "2026-07-03 01:53:50"
  condition:
    hash.sha256(0, filesize) == "f8183b625153b4b06f974c697d52a2d273a4e7d981f4f33e8ff27c203653f600"
}

rule MalwareBazaar_Mirai_019_836da0de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "836da0de8ba87bd62b094e1b10f9fb6ffb8eee1be7bc4aedea73a40950fce2a3"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-03 01:49:49"
  condition:
    hash.sha256(0, filesize) == "836da0de8ba87bd62b094e1b10f9fb6ffb8eee1be7bc4aedea73a40950fce2a3"
}

rule MalwareBazaar_unknown_020_12279728
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "122797288af9166cb10192292e0edf66abe21704010b5f93389a96860a614780"
    family = "unknown"
    file_name = "aarch64.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:41:55"
  condition:
    hash.sha256(0, filesize) == "122797288af9166cb10192292e0edf66abe21704010b5f93389a96860a614780"
}

rule MalwareBazaar_unknown_021_674fc0b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "674fc0b5ead7acd834747c2a568ef218640b7787a2201d4724dd8d43292904ce"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-03 01:29:49"
  condition:
    hash.sha256(0, filesize) == "674fc0b5ead7acd834747c2a568ef218640b7787a2201d4724dd8d43292904ce"
}

rule MalwareBazaar_unknown_022_64531827
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6453182787fa76dc0043ca1fb77af822584066d02b1491b25ae042a40b140901"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-03 01:27:52"
  condition:
    hash.sha256(0, filesize) == "6453182787fa76dc0043ca1fb77af822584066d02b1491b25ae042a40b140901"
}

rule MalwareBazaar_Mirai_023_55489cc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "55489cc3ce1f7d3129f1bebc8103631692993a66bc05f5e136ad3f4760c13fe7"
    family = "Mirai"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-03 01:24:01"
  condition:
    hash.sha256(0, filesize) == "55489cc3ce1f7d3129f1bebc8103631692993a66bc05f5e136ad3f4760c13fe7"
}

rule MalwareBazaar_Mirai_024_2c27b5e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c27b5e45366cc70af89e5f00a6b8adad2cb842e6249f9649119b8afb87905d5"
    family = "Mirai"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-03 01:13:52"
  condition:
    hash.sha256(0, filesize) == "2c27b5e45366cc70af89e5f00a6b8adad2cb842e6249f9649119b8afb87905d5"
}

rule MalwareBazaar_unknown_025_40fd96e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40fd96e5c870ccefd680bf559b7f72e7e994e3ccb4d0cb5d68836db41180bf64"
    family = "unknown"
    file_name = "m68k.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:11:54"
  condition:
    hash.sha256(0, filesize) == "40fd96e5c870ccefd680bf559b7f72e7e994e3ccb4d0cb5d68836db41180bf64"
}

rule MalwareBazaar_unknown_026_6c84c701
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c84c701190032361e71713159e3c501810c42b56af1664d016f291e405c0e44"
    family = "unknown"
    file_name = "mips.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 01:02:00"
  condition:
    hash.sha256(0, filesize) == "6c84c701190032361e71713159e3c501810c42b56af1664d016f291e405c0e44"
}

rule MalwareBazaar_unknown_027_fe5cfaef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41"
    family = "unknown"
    file_name = "fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41"
    file_type = "elf"
    first_seen = "2026-07-03 01:01:59"
  condition:
    hash.sha256(0, filesize) == "fe5cfaef3ae8218abb6074de7886b83b420451ecb0088591d96b44a7426f9a41"
}

rule MalwareBazaar_unknown_028_eea78ce9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5"
    family = "unknown"
    file_name = "eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5"
    file_type = "elf"
    first_seen = "2026-07-03 01:01:53"
  condition:
    hash.sha256(0, filesize) == "eea78ce9b7a3d5e50e60db3d08218f15fd281edb79c0c175b075761858fa06e5"
}

rule MalwareBazaar_unknown_029_344b34cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f"
    family = "unknown"
    file_name = "344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f"
    file_type = "elf"
    first_seen = "2026-07-03 01:01:42"
  condition:
    hash.sha256(0, filesize) == "344b34cb507ea23dacfb1ae97a02e50eeeb3934066b64061c14cfce0de0ed60f"
}

rule MalwareBazaar_Mirai_030_472c62f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "472c62f3dd43ab1d2bc83e6366f136de3f21305980ab965a1ce9399fe79c3637"
    family = "Mirai"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-03 00:59:53"
  condition:
    hash.sha256(0, filesize) == "472c62f3dd43ab1d2bc83e6366f136de3f21305980ab965a1ce9399fe79c3637"
}

rule MalwareBazaar_unknown_031_2759a1bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2759a1bc0be90cca057cbf9a76cd4d7cb50a8c052e4d9896d2c69e7ae11adc8b"
    family = "unknown"
    file_name = "i686.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 00:47:56"
  condition:
    hash.sha256(0, filesize) == "2759a1bc0be90cca057cbf9a76cd4d7cb50a8c052e4d9896d2c69e7ae11adc8b"
}

rule MalwareBazaar_unknown_032_52bbf76f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52bbf76f3cf2dddd96c72cc97a701e06e650af628ecdb119c5d448ea5a961b34"
    family = "unknown"
    file_name = "armv5l.ghost"
    file_type = "elf"
    first_seen = "2026-07-03 00:35:54"
  condition:
    hash.sha256(0, filesize) == "52bbf76f3cf2dddd96c72cc97a701e06e650af628ecdb119c5d448ea5a961b34"
}

rule MalwareBazaar_unknown_033_ecafb11a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ecafb11a4c92905e8e00f586411412d8c17b3f7ed1175c07ee2464a1d88521e7"
    family = "unknown"
    file_name = "w.sh"
    file_type = "sh"
    first_seen = "2026-07-03 00:15:57"
  condition:
    hash.sha256(0, filesize) == "ecafb11a4c92905e8e00f586411412d8c17b3f7ed1175c07ee2464a1d88521e7"
}

rule MalwareBazaar_unknown_034_0b0bf190
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b0bf190c3d68ead801da7152302540fa34f2ca5d81c8263dd2da0b3faf0bdc4"
    family = "unknown"
    file_name = "c.sh"
    file_type = "sh"
    first_seen = "2026-07-03 00:15:56"
  condition:
    hash.sha256(0, filesize) == "0b0bf190c3d68ead801da7152302540fa34f2ca5d81c8263dd2da0b3faf0bdc4"
}

rule MalwareBazaar_Mirai_035_695b9a53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "695b9a53c9fbf59f55dd818bd2bbacbb7bcc49b816d779bd9e8a9d0c82b5fc98"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-02 23:57:52"
  condition:
    hash.sha256(0, filesize) == "695b9a53c9fbf59f55dd818bd2bbacbb7bcc49b816d779bd9e8a9d0c82b5fc98"
}

rule MalwareBazaar_Mirai_036_72369648
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "723696487c125323ef50aebab1864d41de10bf0b94a34b9faa3cb6226d469b60"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-02 23:57:51"
  condition:
    hash.sha256(0, filesize) == "723696487c125323ef50aebab1864d41de10bf0b94a34b9faa3cb6226d469b60"
}

rule MalwareBazaar_Mirai_037_1a06cabc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a06cabc732fb4ba0c71b49ba648edfc1af4e138580cba520c00ee483f574b1d"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-07-02 23:57:50"
  condition:
    hash.sha256(0, filesize) == "1a06cabc732fb4ba0c71b49ba648edfc1af4e138580cba520c00ee483f574b1d"
}

rule MalwareBazaar_Mirai_038_fd80731a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd80731a69f51e1d797cd0c0b34b064a296658468a5ee859563280c73f1794cd"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:58"
  condition:
    hash.sha256(0, filesize) == "fd80731a69f51e1d797cd0c0b34b064a296658468a5ee859563280c73f1794cd"
}

rule MalwareBazaar_Mirai_039_b9ab18ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9ab18bab7c7f2c596d99816b284c1f107a2702f648d0d480c242305f3b57d10"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:57"
  condition:
    hash.sha256(0, filesize) == "b9ab18bab7c7f2c596d99816b284c1f107a2702f648d0d480c242305f3b57d10"
}

rule MalwareBazaar_Mirai_040_f7bb9631
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7bb9631725f583a88be4f08895c26c92ef9d069d18b03934d38fc3aa794b351"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:56"
  condition:
    hash.sha256(0, filesize) == "f7bb9631725f583a88be4f08895c26c92ef9d069d18b03934d38fc3aa794b351"
}

rule MalwareBazaar_Mirai_041_3bce162c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3bce162c4900bf770a866a3483abb609c57c110d08dfb626e2b7dbfe24b89531"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:55"
  condition:
    hash.sha256(0, filesize) == "3bce162c4900bf770a866a3483abb609c57c110d08dfb626e2b7dbfe24b89531"
}

rule MalwareBazaar_Mirai_042_66aedd8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66aedd8aa6bd95a344ce8b3f0ae0b9c898157e8b92d33a9d6b841baccb3b181f"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:53"
  condition:
    hash.sha256(0, filesize) == "66aedd8aa6bd95a344ce8b3f0ae0b9c898157e8b92d33a9d6b841baccb3b181f"
}

rule MalwareBazaar_Mirai_043_75031c50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75031c5077a2fac9ced0dec41e1b15f403684d40f8b67ead30ba92c898d70b5b"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:52"
  condition:
    hash.sha256(0, filesize) == "75031c5077a2fac9ced0dec41e1b15f403684d40f8b67ead30ba92c898d70b5b"
}

rule MalwareBazaar_Mirai_044_b41cf0e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b41cf0e4ce86234ca0055c4c1b55ddbb336eeed04a53745c78b5e372252dc96c"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:51"
  condition:
    hash.sha256(0, filesize) == "b41cf0e4ce86234ca0055c4c1b55ddbb336eeed04a53745c78b5e372252dc96c"
}

rule MalwareBazaar_Mirai_045_19242bfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19242bfef334f4554ee013586a0265adfe503496e2ebac07f922bd3ce2a9e37d"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-02 23:55:50"
  condition:
    hash.sha256(0, filesize) == "19242bfef334f4554ee013586a0265adfe503496e2ebac07f922bd3ce2a9e37d"
}

rule MalwareBazaar_unknown_046_9b263a5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b263a5a34d255506fe51b8f57d8fe44fcfd387efd0e57263e95d5e7be92e40f"
    family = "unknown"
    file_name = "wget.sh"
    file_type = "sh"
    first_seen = "2026-07-02 23:06:29"
  condition:
    hash.sha256(0, filesize) == "9b263a5a34d255506fe51b8f57d8fe44fcfd387efd0e57263e95d5e7be92e40f"
}

rule MalwareBazaar_Gafgyt_047_5891a329
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5891a3295e44a2a3e03cab01e78efa6c7e2650227fa611420d42b857c38d4dcb"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:05:00"
  condition:
    hash.sha256(0, filesize) == "5891a3295e44a2a3e03cab01e78efa6c7e2650227fa611420d42b857c38d4dcb"
}

rule MalwareBazaar_Gafgyt_048_83f2f05f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83f2f05f1b8734caea6a85321e9dfbf29ba321078f75c288de7d19b369db0c35"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:57"
  condition:
    hash.sha256(0, filesize) == "83f2f05f1b8734caea6a85321e9dfbf29ba321078f75c288de7d19b369db0c35"
}

rule MalwareBazaar_Mirai_049_84006c5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84006c5bdfeeefd4e541150c016fca2235e94686091383e4b0f92d6a2c569ecb"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:50"
  condition:
    hash.sha256(0, filesize) == "84006c5bdfeeefd4e541150c016fca2235e94686091383e4b0f92d6a2c569ecb"
}

rule MalwareBazaar_Gafgyt_050_ffb8ddba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb8ddbabd993eaff6bb842707ec5c73cb1ba6aa8c15bd17fb3adda06a2c6944"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnx86_64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:47"
  condition:
    hash.sha256(0, filesize) == "ffb8ddbabd993eaff6bb842707ec5c73cb1ba6aa8c15bd17fb3adda06a2c6944"
}

rule MalwareBazaar_Gafgyt_051_09850882
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09850882df56f887392a08d100456dc3644f4acbb26c8434218574a0bbee07bb"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:44"
  condition:
    hash.sha256(0, filesize) == "09850882df56f887392a08d100456dc3644f4acbb26c8434218574a0bbee07bb"
}

rule MalwareBazaar_Mirai_052_661bdb7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "661bdb7b97063415dda2647862e4a1110b10f71beb1ff58ca4c9deaee350fc6f"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmicroblazexnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:24"
  condition:
    hash.sha256(0, filesize) == "661bdb7b97063415dda2647862e4a1110b10f71beb1ff58ca4c9deaee350fc6f"
}

rule MalwareBazaar_Gafgyt_053_f0fba59f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0fba59fac26fe8a909040d381156f5db6c7c03d47a723b6545e47a5377d59bd"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnsh2xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:22"
  condition:
    hash.sha256(0, filesize) == "f0fba59fac26fe8a909040d381156f5db6c7c03d47a723b6545e47a5377d59bd"
}

rule MalwareBazaar_Gafgyt_054_6cb30f95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cb30f950e7f2f038e986b811fa758fa55badf9576bde9073ba9ae19768dcc9a"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnor1kxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:21"
  condition:
    hash.sha256(0, filesize) == "6cb30f950e7f2f038e986b811fa758fa55badf9576bde9073ba9ae19768dcc9a"
}

rule MalwareBazaar_Gafgyt_055_861782bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "861782bd78b9ff5dedc79d8c6c6f03f8abb1fc9a8b81e0291073637cface272b"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnsh4xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:20"
  condition:
    hash.sha256(0, filesize) == "861782bd78b9ff5dedc79d8c6c6f03f8abb1fc9a8b81e0291073637cface272b"
}

rule MalwareBazaar_Mirai_056_ded73b48
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ded73b48bfe87062892030bceb68815d779c51c736c3278ffb00f340bdc220dc"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnloongarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:19"
  condition:
    hash.sha256(0, filesize) == "ded73b48bfe87062892030bceb68815d779c51c736c3278ffb00f340bdc220dc"
}

rule MalwareBazaar_Gafgyt_057_8168a485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8168a485ec800b17645de89c8201a335287c9fd57e6af15600eb5bb4d16b895c"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxni386xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:17"
  condition:
    hash.sha256(0, filesize) == "8168a485ec800b17645de89c8201a335287c9fd57e6af15600eb5bb4d16b895c"
}

rule MalwareBazaar_Gafgyt_058_e5e16639
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5e16639ec6ec60c5a5ebe598254f926e93e5e9c2f453ebc3225e0650b57e66e"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnaarch64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:16"
  condition:
    hash.sha256(0, filesize) == "e5e16639ec6ec60c5a5ebe598254f926e93e5e9c2f453ebc3225e0650b57e66e"
}

rule MalwareBazaar_Mirai_059_20161e9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20161e9b6edc8c42af263a9099a5f285473da5c4935a600f373b7da8a3111515"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnriscv64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:15"
  condition:
    hash.sha256(0, filesize) == "20161e9b6edc8c42af263a9099a5f285473da5c4935a600f373b7da8a3111515"
}

rule MalwareBazaar_Gafgyt_060_715a4e53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "715a4e536e913c7eee6f4bf1c072e564045d9880f3043e788c9a2c13dd28b957"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnm68kxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:13"
  condition:
    hash.sha256(0, filesize) == "715a4e536e913c7eee6f4bf1c072e564045d9880f3043e788c9a2c13dd28b957"
}

rule MalwareBazaar_unknown_061_ab53eda5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab53eda5b03e2e4420963e35ccf3e165380be9aabb86f2bbf423e135733157fa"
    family = "unknown"
    file_name = "xnxnxnxnxnxnxnxnriscv32xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:12"
  condition:
    hash.sha256(0, filesize) == "ab53eda5b03e2e4420963e35ccf3e165380be9aabb86f2bbf423e135733157fa"
}

rule MalwareBazaar_Mirai_062_945ce519
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "945ce51902a9d83386e58a0da359216fd6d51bc9382d96381f898c97d58a4a33"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:11"
  condition:
    hash.sha256(0, filesize) == "945ce51902a9d83386e58a0da359216fd6d51bc9382d96381f898c97d58a4a33"
}

rule MalwareBazaar_Gafgyt_063_3d97e9a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d97e9a12d8d01204887d78b3f6122a19f13bf031f42b85ce48f8efd520c3e8a"
    family = "Gafgyt"
    file_name = "xnxnxnxnxnxnxnxnx86_64xnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:10"
  condition:
    hash.sha256(0, filesize) == "3d97e9a12d8d01204887d78b3f6122a19f13bf031f42b85ce48f8efd520c3e8a"
}

rule MalwareBazaar_Mirai_064_df34ce9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "df34ce9e3c17ce3fd73320189705b2ca2c00d54f306207ba2909fa56809243db"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:08"
  condition:
    hash.sha256(0, filesize) == "df34ce9e3c17ce3fd73320189705b2ca2c00d54f306207ba2909fa56809243db"
}

rule MalwareBazaar_unknown_065_e0de7b97
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0de7b97caf12794da7c39bd4e0f3024457acc46e933ef13861ec28d8b0c31a5"
    family = "unknown"
    file_name = "curl.sh"
    file_type = "sh"
    first_seen = "2026-07-02 23:04:07"
  condition:
    hash.sha256(0, filesize) == "e0de7b97caf12794da7c39bd4e0f3024457acc46e933ef13861ec28d8b0c31a5"
}

rule MalwareBazaar_unknown_066_4fb47b9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4fb47b9ea12b8893d4f91e4ad7230d20e30250abcb341a31d494d662d29714e1"
    family = "unknown"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-02 23:04:06"
  condition:
    hash.sha256(0, filesize) == "4fb47b9ea12b8893d4f91e4ad7230d20e30250abcb341a31d494d662d29714e1"
}

rule MalwareBazaar_Mirai_067_9517c95d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9517c95d736579963374276fe45955a73129e3cf23a5821fb34e61cecc800a59"
    family = "Mirai"
    file_name = "main_arm7"
    file_type = "elf"
    first_seen = "2026-07-02 23:02:06"
  condition:
    hash.sha256(0, filesize) == "9517c95d736579963374276fe45955a73129e3cf23a5821fb34e61cecc800a59"
}

rule MalwareBazaar_unknown_068_dcbcba0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205"
    family = "unknown"
    file_name = "o"
    file_type = "unknown"
    first_seen = "2026-07-02 23:02:04"
  condition:
    hash.sha256(0, filesize) == "dcbcba0a0d2a7daa4caf7aa202362278dafacb6b38cab93f1d195ca6ff8f5205"
}

rule MalwareBazaar_Mirai_069_f91e0130
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f91e0130c1e55dfd84d38b9865d7ff122e5060c93f33b8063165402c4d9116e4"
    family = "Mirai"
    file_name = "1.sh"
    file_type = "sh"
    first_seen = "2026-07-02 23:02:03"
  condition:
    hash.sha256(0, filesize) == "f91e0130c1e55dfd84d38b9865d7ff122e5060c93f33b8063165402c4d9116e4"
}

rule MalwareBazaar_Mirai_070_99ec0e5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99ec0e5a73529d9bc0ee7c385e46c802a2f94be1dabdc2aa954f2ba8de2b4d58"
    family = "Mirai"
    file_name = "massload"
    file_type = "sh"
    first_seen = "2026-07-02 23:02:02"
  condition:
    hash.sha256(0, filesize) == "99ec0e5a73529d9bc0ee7c385e46c802a2f94be1dabdc2aa954f2ba8de2b4d58"
}

rule MalwareBazaar_unknown_071_5045790b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5045790b695470f4c147aab23fed23dd60fa3fb09166af3f23fd39a103ae3c42"
    family = "unknown"
    file_name = "t"
    file_type = "unknown"
    first_seen = "2026-07-02 23:02:01"
  condition:
    hash.sha256(0, filesize) == "5045790b695470f4c147aab23fed23dd60fa3fb09166af3f23fd39a103ae3c42"
}

rule MalwareBazaar_Mirai_072_8ddea0d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ddea0d6c3b4a5560b9cf33e7f2d0c9a76a0ea0291199730489345dbae93da2d"
    family = "Mirai"
    file_name = "fuck"
    file_type = "elf"
    first_seen = "2026-07-02 23:01:59"
  condition:
    hash.sha256(0, filesize) == "8ddea0d6c3b4a5560b9cf33e7f2d0c9a76a0ea0291199730489345dbae93da2d"
}

rule MalwareBazaar_Mirai_073_fb1dc19c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb1dc19c0ddc511361a6cca94dafd61d579d53a38ed3d3d8cefd25ffedc390b4"
    family = "Mirai"
    file_name = "main_x86"
    file_type = "elf"
    first_seen = "2026-07-02 23:01:57"
  condition:
    hash.sha256(0, filesize) == "fb1dc19c0ddc511361a6cca94dafd61d579d53a38ed3d3d8cefd25ffedc390b4"
}

rule MalwareBazaar_AgentTesla_074_9c0eb19d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c0eb19d1579fbc93030d42465b90e092889b930733ffda60b5acb137a346dac"
    family = "AgentTesla"
    file_name = "Quote Ref #011599.js"
    file_type = "js"
    first_seen = "2026-07-02 22:54:42"
  condition:
    hash.sha256(0, filesize) == "9c0eb19d1579fbc93030d42465b90e092889b930733ffda60b5acb137a346dac"
}

rule MalwareBazaar_unknown_075_f5f263ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5f263ec0dce3c9adc2a7b33a033a48865eaac6909c5022b200bce610823254b"
    family = "unknown"
    file_name = "NekooCraft.jar"
    file_type = "jar"
    first_seen = "2026-07-02 22:45:43"
  condition:
    hash.sha256(0, filesize) == "f5f263ec0dce3c9adc2a7b33a033a48865eaac6909c5022b200bce610823254b"
}

rule MalwareBazaar_SalatStealer_076_16e34d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16e34d5b3836f196864a8efe804d8dcb5938801d29bed451a3b67dca6f7b0929"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 22:44:10"
  condition:
    hash.sha256(0, filesize) == "16e34d5b3836f196864a8efe804d8dcb5938801d29bed451a3b67dca6f7b0929"
}

rule MalwareBazaar_unknown_077_a3ade4b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3ade4b9e03e459a5955d68c52f8dbf893ce0c2bfb56c1c8b7415ecfb7ec9246"
    family = "unknown"
    file_name = "temp_1781774687144.apk"
    file_type = "apk"
    first_seen = "2026-07-02 22:38:50"
  condition:
    hash.sha256(0, filesize) == "a3ade4b9e03e459a5955d68c52f8dbf893ce0c2bfb56c1c8b7415ecfb7ec9246"
}

rule MalwareBazaar_unknown_078_d472e114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25"
    family = "unknown"
    file_name = "data.apk"
    file_type = "apk"
    first_seen = "2026-07-02 22:38:22"
  condition:
    hash.sha256(0, filesize) == "d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25"
}

rule MalwareBazaar_AsyncRAT_079_85ec7434
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85ec743443fe4830daddd95a454fc05b6434adf486a6889134b5d50c29570c9d"
    family = "AsyncRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 22:17:39"
  condition:
    hash.sha256(0, filesize) == "85ec743443fe4830daddd95a454fc05b6434adf486a6889134b5d50c29570c9d"
}

rule MalwareBazaar_SpyNote_080_dea11008
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e"
    family = "SpyNote"
    file_name = "decrypted_600520367292854360.apk"
    file_type = "apk"
    first_seen = "2026-07-02 22:17:24"
  condition:
    hash.sha256(0, filesize) == "dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e"
}

rule MalwareBazaar_WannaCry_081_7c4d1e3b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92"
    family = "WannaCry"
    file_name = "7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92"
    file_type = "exe"
    first_seen = "2026-07-02 22:15:27"
  condition:
    hash.sha256(0, filesize) == "7c4d1e3bff4c3d62adb8352b78e586b01eeba9e6d4b96715df89da84bae79c92"
}

rule MalwareBazaar_ValleyRAT_082_eeb2d44d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb2d44d0f86670ac2ee5e0b7aa44ec41b7be9962359f59ac21f736d7b0e7889"
    family = "ValleyRAT"
    file_name = "27d3039a8ca9acbcbc985b88f27720a8.exe"
    file_type = "exe"
    first_seen = "2026-07-02 22:15:11"
  condition:
    hash.sha256(0, filesize) == "eeb2d44d0f86670ac2ee5e0b7aa44ec41b7be9962359f59ac21f736d7b0e7889"
}

rule MalwareBazaar_unknown_083_1f30b62c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f30b62c19be5de98456ec6915f1618da92cab68f20bf36cf91473788437f87a"
    family = "unknown"
    file_name = "ۦۖ۫.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:35:27"
  condition:
    hash.sha256(0, filesize) == "1f30b62c19be5de98456ec6915f1618da92cab68f20bf36cf91473788437f87a"
}

rule MalwareBazaar_Prometei_084_be1d961b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f"
    family = "Prometei"
    file_name = "be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f"
    file_type = "elf"
    first_seen = "2026-07-02 21:34:54"
  condition:
    hash.sha256(0, filesize) == "be1d961b96fb27bd1410dbab08ac25086ee9f65782e9bab45f6fab3120bd672f"
}

rule MalwareBazaar_Prometei_085_ff825f04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943"
    family = "Prometei"
    file_name = "ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943"
    file_type = "exe"
    first_seen = "2026-07-02 21:34:23"
  condition:
    hash.sha256(0, filesize) == "ff825f043105b50df62b498b65c6c7632f2e7aab5efff1cdca49400e38bd2943"
}

rule MalwareBazaar_unknown_086_05a2da9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05a2da9df1b4aed78e16349c17443ccd83cb48ed9e38e38d0c0b6ce808a9c2a8"
    family = "unknown"
    file_name = "src_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:55"
  condition:
    hash.sha256(0, filesize) == "05a2da9df1b4aed78e16349c17443ccd83cb48ed9e38e38d0c0b6ce808a9c2a8"
}

rule MalwareBazaar_unknown_087_537f0875
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "537f08755139d0199fb1751068eb49a92b68e0d1dcadaf03758837c3832f99c5"
    family = "unknown"
    file_name = "res_obs_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:48"
  condition:
    hash.sha256(0, filesize) == "537f08755139d0199fb1751068eb49a92b68e0d1dcadaf03758837c3832f99c5"
}

rule MalwareBazaar_unknown_088_72f18d01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72f18d019123393ae610dd73b25e5f30a4945430f6f835700d6bdee19f566a30"
    family = "unknown"
    file_name = "output_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:42"
  condition:
    hash.sha256(0, filesize) == "72f18d019123393ae610dd73b25e5f30a4945430f6f835700d6bdee19f566a30"
}

rule MalwareBazaar_unknown_089_bf586ec8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bf586ec8ce8528d26ec491fa5864dc590cefae88da176246296bb849e226a0c8"
    family = "unknown"
    file_name = "entry_added_0.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:25"
  condition:
    hash.sha256(0, filesize) == "bf586ec8ce8528d26ec491fa5864dc590cefae88da176246296bb849e226a0c8"
}

rule MalwareBazaar_unknown_090_0bc98459
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0bc98459a42d1d0108a882671f4496f214f8a68400810b9e034cdd7212f5a4fa"
    family = "unknown"
    file_name = "apksigner6222202351320183515.apk"
    file_type = "apk"
    first_seen = "2026-07-02 21:15:08"
  condition:
    hash.sha256(0, filesize) == "0bc98459a42d1d0108a882671f4496f214f8a68400810b9e034cdd7212f5a4fa"
}

rule MalwareBazaar_Stealc_091_275035f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "275035f44dc9cf992964e3954ba0af5d09e0df6b5c1009befaaeb21408cc0bba"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 21:14:34"
  condition:
    hash.sha256(0, filesize) == "275035f44dc9cf992964e3954ba0af5d09e0df6b5c1009befaaeb21408cc0bba"
}

rule MalwareBazaar_unknown_092_42bf4581
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "42bf45811ef88b4cbbde334f34197beca2836a38a6d2ba45d7c9f4ec60937450"
    family = "unknown"
    file_name = "p"
    file_type = "sh"
    first_seen = "2026-07-02 20:21:07"
  condition:
    hash.sha256(0, filesize) == "42bf45811ef88b4cbbde334f34197beca2836a38a6d2ba45d7c9f4ec60937450"
}

rule MalwareBazaar_unknown_093_b634c8c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b634c8c0ec3a4d682630eed6ac1cc8d5e2b0481110121990edcb4e0df9867698"
    family = "unknown"
    file_name = "dogandcat(1).apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:13:12"
  condition:
    hash.sha256(0, filesize) == "b634c8c0ec3a4d682630eed6ac1cc8d5e2b0481110121990edcb4e0df9867698"
}

rule MalwareBazaar_unknown_094_f5b84a26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5b84a261a19b8066cb609124d97bc52df08f08f564d32358a15aaf511caf5e4"
    family = "unknown"
    file_name = "dogandcat.apk.signed.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:13:06"
  condition:
    hash.sha256(0, filesize) == "f5b84a261a19b8066cb609124d97bc52df08f08f564d32358a15aaf511caf5e4"
}

rule MalwareBazaar_unknown_095_cbc71b0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbc71b0bd3f94cb163a8ab106242aa7638aced10e7b8c4d6179bc7fc5ba649f2"
    family = "unknown"
    file_name = "dogandcat.apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:13:01"
  condition:
    hash.sha256(0, filesize) == "cbc71b0bd3f94cb163a8ab106242aa7638aced10e7b8c4d6179bc7fc5ba649f2"
}

rule MalwareBazaar_unknown_096_5cad494f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cad494f67808745489659cd077dce429fce364a673c44c9d238d14dcca81732"
    family = "unknown"
    file_name = "dog_patched.tmp.apk"
    file_type = "apk"
    first_seen = "2026-07-02 20:12:55"
  condition:
    hash.sha256(0, filesize) == "5cad494f67808745489659cd077dce429fce364a673c44c9d238d14dcca81732"
}

rule MalwareBazaar_unknown_097_580877c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "580877c7bf8d435f28741037a3e64dfefea32d9e594196e39308af80396596bd"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-02 20:06:47"
  condition:
    hash.sha256(0, filesize) == "580877c7bf8d435f28741037a3e64dfefea32d9e594196e39308af80396596bd"
}

rule MalwareBazaar_unknown_098_add9ff4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "add9ff4b6e73395939d91d9956fb79aae3ccf42522e8b5954d20a59f7f70ca5a"
    family = "unknown"
    file_name = "WSW0"
    file_type = "sh"
    first_seen = "2026-07-02 20:02:50"
  condition:
    hash.sha256(0, filesize) == "add9ff4b6e73395939d91d9956fb79aae3ccf42522e8b5954d20a59f7f70ca5a"
}

rule MalwareBazaar_unknown_099_4e6276cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d"
    family = "unknown"
    file_name = "libjson_script.so.0"
    file_type = "elf"
    first_seen = "2026-07-02 19:37:06"
  condition:
    hash.sha256(0, filesize) == "4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d"
}

rule MalwareBazaar_unknown_100_015a389e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "015a389e5c97ec1e545978359e19c08050ce2b3d23c88557ec9f4a540a4c6c51"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-02 19:34:09"
  condition:
    hash.sha256(0, filesize) == "015a389e5c97ec1e545978359e19c08050ce2b3d23c88557ec9f4a540a4c6c51"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-18

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 652 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 652 |
| Unique family labels | 8 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 84 |
| Mirai | 6 |
| JOMANGY | 4 |
| Vidar | 2 |
| ConnectWise | 1 |
| FleetDeck | 1 |
| RemusStealer | 1 |
| Gafgyt | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 69 |
| elf | 17 |
| unknown | 5 |
| sh | 4 |
| msi | 1 |
| iso | 1 |
| macho | 1 |
| js | 1 |
| jar | 1 |

## Per-Sample Analysis

### Sample 1: `163a8f4faf936123`

| Field | Value |
|---|---|
| SHA-256 | `163a8f4faf9361239e3ef1a5ddfaa28ff48afd5b9c5b4c17ffd92fa5c40b99e6` |
| Family label | `unknown` |
| File name | `s` |
| File type | `unknown` |
| First seen | `2026-09-18 04:45:31` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01a4a972fea2c3b137aac0b7661ad8fa` |
| SHA-256 | `163a8f4faf9361239e3ef1a5ddfaa28ff48afd5b9c5b4c17ffd92fa5c40b99e6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_163a8f4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163a8f4faf9361239e3ef1a5ddfaa28ff48afd5b9c5b4c17ffd92fa5c40b99e6"
    family = "unknown"
    file_name = "s"
    file_type = "unknown"
    first_seen = "2026-09-18 04:45:31"
  condition:
    hash.sha256(0, filesize) == "163a8f4faf9361239e3ef1a5ddfaa28ff48afd5b9c5b4c17ffd92fa5c40b99e6"
}
```

### Sample 2: `e0d4a52ba2159d4f`

| Field | Value |
|---|---|
| SHA-256 | `e0d4a52ba2159d4f8b9d4f95445f8431f30efae4dde32bf3be368ab9e1fd1333` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-18 04:33:16` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `512bc45d55bc3f2c013b2b647a3a03fd` |
| SHA-1 | `eecfb8d54a695453b11643576461971df82a7985` |
| SHA-256 | `e0d4a52ba2159d4f8b9d4f95445f8431f30efae4dde32bf3be368ab9e1fd1333` |
| SHA3-384 | `b353342d21f28482fdd6ca91ef5a078e8d53d74d0145380513a126351862a3ad765ed964a5f703aef8bba6c38e9527c2` |
| TLSH | `T18EC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:V8vCB+25j6es8ROl9FYpMSUpi+20qUpi+20YQX:V8l25JODd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_002_e0d4a52b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d4a52ba2159d4f8b9d4f95445f8431f30efae4dde32bf3be368ab9e1fd1333"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-18 04:33:16"
  condition:
    hash.sha256(0, filesize) == "e0d4a52ba2159d4f8b9d4f95445f8431f30efae4dde32bf3be368ab9e1fd1333"
}
```

### Sample 3: `28f89ed48119891e`

| Field | Value |
|---|---|
| SHA-256 | `28f89ed48119891e87c240e6238dec07c145fed79febe419d074b072e980c8bd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 04:32:44` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b840d61770fcf86b14bf57c32216ea52` |
| SHA-1 | `2091b67e6bd61ed775468de6eb73dc841928fb52` |
| SHA-256 | `28f89ed48119891e87c240e6238dec07c145fed79febe419d074b072e980c8bd` |
| SHA3-384 | `4c677d98d4d4a73627a55faefe95f7f3a8252eabd1f3d9d1e75bb84702aff8a4892868fecc170624f1af0a67f631e704` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12A62F796D9922F5DCE4FC0713A11FC78AD757690866568E3D7828D309EA39D000A4FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZIBgn:fKOe2/7c9sN3zfZR1m+RGAI6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_28f89ed4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28f89ed48119891e87c240e6238dec07c145fed79febe419d074b072e980c8bd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:32:44"
  condition:
    hash.sha256(0, filesize) == "28f89ed48119891e87c240e6238dec07c145fed79febe419d074b072e980c8bd"
}
```

### Sample 4: `ea600bdda77ebeaa`

| Field | Value |
|---|---|
| SHA-256 | `ea600bdda77ebeaa723eeecbe72babb251e3a9968eaa7fbf85d366deb7b50d03` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 04:29:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1384013fd79cb0c84f63417c81750d73` |
| SHA-1 | `458b5729511e6a2a4ab220d81d7bfc537b192358` |
| SHA-256 | `ea600bdda77ebeaa723eeecbe72babb251e3a9968eaa7fbf85d366deb7b50d03` |
| SHA3-384 | `4becb52d58a461f107573387849bb3770e5c56ec23dc6e6cbc6658e03709dcabb3c2ae64debff2924f25a10f85590545` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18D62D896D8922F6DDE8ED0703A11F838ED7033919A6969E3D7928C305DAB9D00124FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UEnBgn:fKOe2/7c9sN3zfZR1m+RGN6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_ea600bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea600bdda77ebeaa723eeecbe72babb251e3a9968eaa7fbf85d366deb7b50d03"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:29:41"
  condition:
    hash.sha256(0, filesize) == "ea600bdda77ebeaa723eeecbe72babb251e3a9968eaa7fbf85d366deb7b50d03"
}
```

### Sample 5: `30efde1102c51996`

| Field | Value |
|---|---|
| SHA-256 | `30efde1102c5199625e7c652dbebecf7e20d15fbb47c5863437871a94871e794` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 04:27:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09afd8fe046aae84a2595586d908b843` |
| SHA-1 | `e6f58fb0e467499c2e346f67128786409ef60c1e` |
| SHA-256 | `30efde1102c5199625e7c652dbebecf7e20d15fbb47c5863437871a94871e794` |
| SHA3-384 | `3293c6fb8b62afdf125f8c762cb98eb7669eb6b32a6113904e20c088435becc2209b02946f1bd915aa6c1fb75c61d889` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B162B88699A21F6CCE8E80707E11F938BD70769455656DE3D7D28C309EA39E01034EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UDBgCc:fKOe2/7c9sN3zfZR1m+RGI6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_30efde11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30efde1102c5199625e7c652dbebecf7e20d15fbb47c5863437871a94871e794"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:27:19"
  condition:
    hash.sha256(0, filesize) == "30efde1102c5199625e7c652dbebecf7e20d15fbb47c5863437871a94871e794"
}
```

### Sample 6: `0c3dc4409a00ea24`

| Field | Value |
|---|---|
| SHA-256 | `0c3dc4409a00ea240ed1a884e27cb7d38cc30524b7d7c1319121916cfa6a1d73` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 04:26:44` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d1700bbb9a43c2fc8a31b09b77bf696` |
| SHA-1 | `f9ad3393fa1a89c8f692c2b7cafd4d3d457b78fd` |
| SHA-256 | `0c3dc4409a00ea240ed1a884e27cb7d38cc30524b7d7c1319121916cfa6a1d73` |
| SHA3-384 | `d5f170c0cd74359958914393b003ae654cbd3ced52d46cb5a100262d113084389d7dd5ecc860a90dcc872f1d286bd1a0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19962D79AD9925F6CCE4EC0703E11FC78AD7536D0866999E3D7828C345DA39D40428FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UyRkfe:fKOe2/7c9sN3zfZR1m+RGhRq6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_0c3dc440
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c3dc4409a00ea240ed1a884e27cb7d38cc30524b7d7c1319121916cfa6a1d73"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:26:44"
  condition:
    hash.sha256(0, filesize) == "0c3dc4409a00ea240ed1a884e27cb7d38cc30524b7d7c1319121916cfa6a1d73"
}
```

### Sample 7: `065cb7480fdecd37`

| Field | Value |
|---|---|
| SHA-256 | `065cb7480fdecd37d37c4ec2ab0b4e7a9d5c97c33f913d08093270e6e4dd2578` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 04:20:53` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9325d06e0b6db362582f56827ee50e82` |
| SHA-1 | `851eef685f61ec134f5d12b4f567100a7a3e1551` |
| SHA-256 | `065cb7480fdecd37d37c4ec2ab0b4e7a9d5c97c33f913d08093270e6e4dd2578` |
| SHA3-384 | `95b8ee580204eabec944ff9333e20e48ec6db05200bf21574ca1561e4bf0d4c1edec946422dc802e5ed47d133ba4be1a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17162C8CAE8925F5DDE4E90703A11F9A87D743A908A6569F3DB828C3059B39D00524FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UQCIfe:fKOe2/7c9sN3zfZR1m+RGHf6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_065cb748
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "065cb7480fdecd37d37c4ec2ab0b4e7a9d5c97c33f913d08093270e6e4dd2578"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:20:53"
  condition:
    hash.sha256(0, filesize) == "065cb7480fdecd37d37c4ec2ab0b4e7a9d5c97c33f913d08093270e6e4dd2578"
}
```

### Sample 8: `afe27e538b4cb296`

| Field | Value |
|---|---|
| SHA-256 | `afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75` |
| Family label | `unknown` |
| File name | `afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75` |
| File type | `elf` |
| First seen | `2026-09-18 04:18:47` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e996a6355d4b1d4b7a8dae65f697721` |
| SHA-1 | `2de951ffb95cdf9414565ea1acf7cf5d7d13f40c` |
| SHA-256 | `afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75` |
| SHA3-384 | `0dcfb8ba24a50bb759f865cf836884a070f63423a2ce71d1b5a3c8f9c976fd428541fb8a5e4e29efee53c8e1773eac89` |
| TLSH | `T1D3A3122593230D1BC4392CFEB67BE7262D862E29284A805845B5E57B5FF708CE5F5313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw8:biMYFJvw6Yh0b1gKobtCGCmCj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_afe27e53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75"
    family = "unknown"
    file_name = "afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75"
    file_type = "elf"
    first_seen = "2026-09-18 04:18:47"
  condition:
    hash.sha256(0, filesize) == "afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75"
}
```

### Sample 9: `ee873e439c2bcf2d`

| Field | Value |
|---|---|
| SHA-256 | `ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db` |
| Family label | `unknown` |
| File name | `ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db` |
| File type | `elf` |
| First seen | `2026-09-18 04:18:42` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42e31ddee1215af84c64b77dcade7896` |
| SHA-1 | `b73792ffaa70aa6397ea82690f29e0bf453acc54` |
| SHA-256 | `ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db` |
| SHA3-384 | `a82250656e7684362d35ad597b87a88dab596286e5298f5609050ba0378da355a362761d8eee29b1b510e5298ace9e3c` |
| TLSH | `T158C3124AFF319C1B9F102DB32ADA5E8E9C6D7AAB41DBB4A878C1D14F47901CE3952214` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ1U:p3lOYoaja8xzx/0wsxzU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_ee873e43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db"
    family = "unknown"
    file_name = "ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db"
    file_type = "elf"
    first_seen = "2026-09-18 04:18:42"
  condition:
    hash.sha256(0, filesize) == "ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db"
}
```

### Sample 10: `72a021730c042cbd`

| Field | Value |
|---|---|
| SHA-256 | `72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d` |
| Family label | `Mirai` |
| File name | `72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d` |
| File type | `elf` |
| First seen | `2026-09-18 04:18:37` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cc98b88704d8e9639325e16aa93b100` |
| SHA-1 | `ae144659925c2092371fd0955788a694076ed887` |
| SHA-256 | `72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d` |
| SHA3-384 | `379715a521dfc60f319fd7593bab9e5591d4e94c797a007d2901e0e2d3103855babf558730ef685a46df36e89307c507` |
| TLSH | `T19F44298AFD81AF25D5C4267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOM:T2s/bW+UmJqBxAuaPRhVabEDSDP99zB+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_72a02173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d"
    family = "Mirai"
    file_name = "72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d"
    file_type = "elf"
    first_seen = "2026-09-18 04:18:37"
  condition:
    hash.sha256(0, filesize) == "72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d"
}
```

### Sample 11: `8e496e71da9fde5d`

| Field | Value |
|---|---|
| SHA-256 | `8e496e71da9fde5d3253b19ff8e1f12b82394b4267beee30d712dbe47767b96c` |
| Family label | `JOMANGY` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-09-18 04:15:45` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3528eea5cc0625aebcbeee0f4dbada0f` |
| SHA-1 | `b260780bc985fbf7b193bf85c24656ff8d924082` |
| SHA-256 | `8e496e71da9fde5d3253b19ff8e1f12b82394b4267beee30d712dbe47767b96c` |
| SHA3-384 | `fa37dba24fdcc3dc125b5f98b421b803ebca54acdf97336115812fc11c8791569b2d577159feb8491c4ed65abf594bb7` |
| TLSH | `T1FB136D6566843C24AE9988371D7E2F0CBDA983E5310851EDBFCB3CF58C49A9CE20971D` |
| SSDEEP | `768:5+6rDTPjHS9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:5Nr3jco` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_011_8e496e71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e496e71da9fde5d3253b19ff8e1f12b82394b4267beee30d712dbe47767b96c"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-18 04:15:45"
  condition:
    hash.sha256(0, filesize) == "8e496e71da9fde5d3253b19ff8e1f12b82394b4267beee30d712dbe47767b96c"
}
```

### Sample 12: `4a74ad41aaf0453c`

| Field | Value |
|---|---|
| SHA-256 | `4a74ad41aaf0453cd4f984912c695b7a1b763dee7665580a6900c8f79ff80072` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 04:05:12` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1ccd5d8a21ebcdc71810a9ed88e3f91` |
| SHA-1 | `ccb174ccbf9e07200b8a914d10cbef8268a5ea2d` |
| SHA-256 | `4a74ad41aaf0453cd4f984912c695b7a1b763dee7665580a6900c8f79ff80072` |
| SHA3-384 | `fbc2e6f165de5a1489205d708e2f03e450f287eea1b86ad2e702a7cafbc3bcc7b279eac9f9534476d7ff2a1724174564` |
| IMPHASH | `be77a47655c52492017a8d44e5572e98` |
| TLSH | `T1FE463A42A6975CEAC9D697B451972336B734FC648B395F3FA604CA301E53BD0AD2EB00` |
| SSDEEP | `98304:9mbEhURYtsEGHohqqv/ZgIrc9msn7gfybIHnwFbL9A1t8ncdmAmuTov1rYz59GBi:9mbE/tsEAW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_4a74ad41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a74ad41aaf0453cd4f984912c695b7a1b763dee7665580a6900c8f79ff80072"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:05:12"
  condition:
    hash.sha256(0, filesize) == "4a74ad41aaf0453cd4f984912c695b7a1b763dee7665580a6900c8f79ff80072"
}
```

### Sample 13: `09a78eff62566b90`

| Field | Value |
|---|---|
| SHA-256 | `09a78eff62566b906a4a41005e1841cee8b43da0d65633c56fb47d8ca6dbd9b9` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-18 04:01:34` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81e0993c73786b3fac45675403b7ecb9` |
| SHA-1 | `f5f675c7934af1a5973b4969e678529729db95bc` |
| SHA-256 | `09a78eff62566b906a4a41005e1841cee8b43da0d65633c56fb47d8ca6dbd9b9` |
| SHA3-384 | `ddcccf0f924e7f08482271510f5d0d8a77aa12a4715d2724df5bb700d4c80e85cb8cd8a05cc0521f862726ddd818a317` |
| TLSH | `T118C28D966A967C44BDC98A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACC618B1A` |
| SSDEEP | `768:t8vCB+25j6es8RQ9FYpMSUpi+20qUpi+20YQX:t8l25JWd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_013_09a78eff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09a78eff62566b906a4a41005e1841cee8b43da0d65633c56fb47d8ca6dbd9b9"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-18 04:01:34"
  condition:
    hash.sha256(0, filesize) == "09a78eff62566b906a4a41005e1841cee8b43da0d65633c56fb47d8ca6dbd9b9"
}
```

### Sample 14: `2f093f8d688bec29`

| Field | Value |
|---|---|
| SHA-256 | `2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3` |
| Family label | `ConnectWise` |
| File name | `2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3.msi` |
| File type | `msi` |
| First seen | `2026-09-18 03:58:08` |
| Reporter | `Tuxxin` |
| Tags | `ConnectWise, msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `48264648f9c57c41ce1dda7262bf7cad` |
| SHA-1 | `2169a21ac5dc32e881c1cc8c8bd1211ffe06467d` |
| SHA-256 | `2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3` |
| SHA3-384 | `6a523f104a03b50dc1d81a1e3f0aea72060a978bede71b835f93016640bf269bad542f92c3713b95cb3bcaff2ff96d84` |
| TLSH | `T133A6233267E8D425F1B60B3AEC3686B16A39BC10DF15C40F2364785D6972D81C6A37BB` |
| SSDEEP | `196608:6eq5KqDBCDkStMQEyeq5KqDBCDkSt3eq5KqDBCDkStseq5KqDBCDkSt:3q5VDBCDxMQEPq5VDBCDxOq5VDBCDxRT` |

#### Technical Assessment

- The sample is tracked as `ConnectWise` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ConnectWise_014_2f093f8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3"
    family = "ConnectWise"
    file_name = "2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3.msi"
    file_type = "msi"
    first_seen = "2026-09-18 03:58:08"
  condition:
    hash.sha256(0, filesize) == "2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3"
}
```

### Sample 15: `1dab32c614e9a97a`

| Field | Value |
|---|---|
| SHA-256 | `1dab32c614e9a97a25f8f04841b4ba9fe780369da1b043871b936e8f3c834891` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:54:00` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d36d52a9d1f6e260e67f3532141fae3` |
| SHA-1 | `809a7656fb99a991149906b81cd614d5ae7b4469` |
| SHA-256 | `1dab32c614e9a97a25f8f04841b4ba9fe780369da1b043871b936e8f3c834891` |
| SHA3-384 | `9c69a3fa295254ffcc420877be9dd1b8d1bb8ca249599e7cbae797a6e49e66ca5bd8482cdfa7f6b135be098561895fb0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A762A686D9921E9DCE4E90703A11F868797477A14A6A99E7E7C1CC306D639D01034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U4jBgn:fKOe2/7c9sN3zfZR1m+RGV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_1dab32c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dab32c614e9a97a25f8f04841b4ba9fe780369da1b043871b936e8f3c834891"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:54:00"
  condition:
    hash.sha256(0, filesize) == "1dab32c614e9a97a25f8f04841b4ba9fe780369da1b043871b936e8f3c834891"
}
```

### Sample 16: `aba4d4dd7ab62fea`

| Field | Value |
|---|---|
| SHA-256 | `aba4d4dd7ab62fea1849a1ef348bce68d68ce1f28e3b518436a46b8228940461` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:51:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c6e68a53aa2c7277ed6611e50e8e01e` |
| SHA-1 | `3bd1613ae1a10a0eed314a9ea8802f2c90c410a4` |
| SHA-256 | `aba4d4dd7ab62fea1849a1ef348bce68d68ce1f28e3b518436a46b8228940461` |
| SHA3-384 | `299e6303b1187adcc0564afd37362a53561265a5886210521524bace4dd3d639686ad81770df693b129153b5697bf1f5` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13162D796E8923EACDE8FD0F03A11FD78A97472A195655DE3E7C18D3949A38C04024FB9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UVUBgn:fKOe2/7c9sN3zfZR1m+RGV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_aba4d4dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba4d4dd7ab62fea1849a1ef348bce68d68ce1f28e3b518436a46b8228940461"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:51:27"
  condition:
    hash.sha256(0, filesize) == "aba4d4dd7ab62fea1849a1ef348bce68d68ce1f28e3b518436a46b8228940461"
}
```

### Sample 17: `b410d33efc86ced7`

| Field | Value |
|---|---|
| SHA-256 | `b410d33efc86ced799284522e3bebfe020e00f6203977a055225680b045856b9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:49:01` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c25aa100c3419f9c81bd10dd574f9d39` |
| SHA-1 | `d970037409fb226b95af5914a1d2db2ea91f1d0d` |
| SHA-256 | `b410d33efc86ced799284522e3bebfe020e00f6203977a055225680b045856b9` |
| SHA3-384 | `bd8159689cc75e0ed1b968f4bd4cba04045df9ee0ae97de89a9218551d3f19334eadbe6479508ce7c2a62f5b488fa6df` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18D62B58AD9A21A6CCE4F90703A11F978B9707690866599E3DB828C309EB39D11434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1T/BM:fKOe2/7c9sN3zfZR1m+RGUT/6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_b410d33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b410d33efc86ced799284522e3bebfe020e00f6203977a055225680b045856b9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:49:01"
  condition:
    hash.sha256(0, filesize) == "b410d33efc86ced799284522e3bebfe020e00f6203977a055225680b045856b9"
}
```

### Sample 18: `126a096e0e6a6c15`

| Field | Value |
|---|---|
| SHA-256 | `126a096e0e6a6c157fec7fe12ec37a93aba07b84118dcb60ec0693baab1deee3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:46:50` |
| Reporter | `Bitsight` |
| Tags | `368eb34be1e7e495c94952b194824099, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d28765ab460a26e699fce1a1d396f6f` |
| SHA-1 | `424aa218778a4d6203542c570174d9cd17b70031` |
| SHA-256 | `126a096e0e6a6c157fec7fe12ec37a93aba07b84118dcb60ec0693baab1deee3` |
| SHA3-384 | `5fed6e444ca47ab1ddaef5e7d4c2aede8653bdeab58d37c2f3de9f8c865e2efd7a5bfe24a419dc91b0e3762656adfe0c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A062FA86E8925F6DCE4F80703A11F878BDB03A95865569E3DB82CC315DA39D05428FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UlStzU:fKOe2/7c9sN3zfZR1m+RGiYd6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_126a096e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126a096e0e6a6c157fec7fe12ec37a93aba07b84118dcb60ec0693baab1deee3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:46:50"
  condition:
    hash.sha256(0, filesize) == "126a096e0e6a6c157fec7fe12ec37a93aba07b84118dcb60ec0693baab1deee3"
}
```

### Sample 19: `d4cee6760bf8b042`

| Field | Value |
|---|---|
| SHA-256 | `d4cee6760bf8b0420f3e49ac68e1a14f4ab804dbe317873901dcd734ca93f8af` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:44:19` |
| Reporter | `Bitsight` |
| Tags | `368eb34be1e7e495c94952b194824099, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3414907070d1d0c6356fc70d4ffc42f1` |
| SHA-1 | `461117945e4f1f3b8b8e55f3660f4a3a38b04ac8` |
| SHA-256 | `d4cee6760bf8b0420f3e49ac68e1a14f4ab804dbe317873901dcd734ca93f8af` |
| SHA3-384 | `1125b9e1dab661adb928d6ed156b9b8223afe31e9853bff244063748db47a08240cdb20a77721d406eea521621dd2eee` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F862C98AF8926E6CCE4E80707A21F8786D747694456559E3F7828C355DB38D00534FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UU2cse:fKOe2/7c9sN3zfZR1m+RGocs6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_d4cee676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4cee6760bf8b0420f3e49ac68e1a14f4ab804dbe317873901dcd734ca93f8af"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:44:19"
  condition:
    hash.sha256(0, filesize) == "d4cee6760bf8b0420f3e49ac68e1a14f4ab804dbe317873901dcd734ca93f8af"
}
```

### Sample 20: `a14fb55db0c9ba8c`

| Field | Value |
|---|---|
| SHA-256 | `a14fb55db0c9ba8c61603e6935a47f2d6d71c4856981532327eb36aae4b30809` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:42:27` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27ddb2a579f66a1c10eced8684b12474` |
| SHA-1 | `159f17e8b0e80e9766bf23725261b3f36b0d63cd` |
| SHA-256 | `a14fb55db0c9ba8c61603e6935a47f2d6d71c4856981532327eb36aae4b30809` |
| SHA3-384 | `6c78bcbec8050ede6984b0ed6240ffb3518113a0575ceb5a6a49e7cae91ab61694a73861c9dae82d5ac0b6818f98e651` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14D62C896D8922F6CDE4E80B03B11F86C6AB036D18B6569E3DB828C705F639D04574FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1+szu:fKOe2/7c9sN3zfZR1m+RGoz36C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_a14fb55d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14fb55db0c9ba8c61603e6935a47f2d6d71c4856981532327eb36aae4b30809"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:42:27"
  condition:
    hash.sha256(0, filesize) == "a14fb55db0c9ba8c61603e6935a47f2d6d71c4856981532327eb36aae4b30809"
}
```

### Sample 21: `987c42d48e9a78ed`

| Field | Value |
|---|---|
| SHA-256 | `987c42d48e9a78ed2ebc33b4d3b8dd6c1c17d01cd911ff6287fa5d878451b38d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:41:51` |
| Reporter | `Bitsight` |
| Tags | `368eb34be1e7e495c94952b194824099, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bca97cdabccc772eda721e6f9b39fb36` |
| SHA-1 | `f6006562ad8a59d27c309b358d89b71371d9240c` |
| SHA-256 | `987c42d48e9a78ed2ebc33b4d3b8dd6c1c17d01cd911ff6287fa5d878451b38d` |
| SHA3-384 | `9ac6dbea973ee4b501a58876ee1c9228399ff49899a924226a5609b411ec6dcb5bcfb8062a4732b380eda201b52b8b93` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F162D78AD8A22F6CDE8E90703B11F878AD74369186A599F3D7928C305DA79D04424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UMf2Ge:fKOe2/7c9sN3zfZR1m+RGn+G6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_987c42d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "987c42d48e9a78ed2ebc33b4d3b8dd6c1c17d01cd911ff6287fa5d878451b38d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:41:51"
  condition:
    hash.sha256(0, filesize) == "987c42d48e9a78ed2ebc33b4d3b8dd6c1c17d01cd911ff6287fa5d878451b38d"
}
```

### Sample 22: `cefa3f258164e668`

| Field | Value |
|---|---|
| SHA-256 | `cefa3f258164e6680c6c8f9c728d9dac1a429777f31ed5b2a14e39d6c9329e0f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:40:03` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74bc9cd9d4a288006fd8ffbfeae372cf` |
| SHA-1 | `11d48d9f15293121bbcaf77c82e5a2fcc7ae03a8` |
| SHA-256 | `cefa3f258164e6680c6c8f9c728d9dac1a429777f31ed5b2a14e39d6c9329e0f` |
| SHA3-384 | `40293d20c767b29ae1ddfcc8f82204b5ffee99f02c7731c7150f4c849f736858b2240f9909beeaac9bc33c2f51c2dc7b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FB62D696D9A22F9CDE4ED0703A11F868BD717290CA6659F7E7828C304DA39C14624FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UvCBBM:fKOe2/7c9sN3zfZR1m+RG7B6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_cefa3f25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cefa3f258164e6680c6c8f9c728d9dac1a429777f31ed5b2a14e39d6c9329e0f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:40:03"
  condition:
    hash.sha256(0, filesize) == "cefa3f258164e6680c6c8f9c728d9dac1a429777f31ed5b2a14e39d6c9329e0f"
}
```

### Sample 23: `70c2fa845ac0791b`

| Field | Value |
|---|---|
| SHA-256 | `70c2fa845ac0791b6281ef1107e9f0c6bc33c582e8c36087f8d3e921ad8ac772` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:19:16` |
| Reporter | `Bitsight` |
| Tags | `16660bde630116f363f759a4ac9d08fb, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4fc0f88f0c13ab1007b95390ec9bf715` |
| SHA-1 | `3a974f57c2b5fcc4447a1875d767296d608ad8dd` |
| SHA-256 | `70c2fa845ac0791b6281ef1107e9f0c6bc33c582e8c36087f8d3e921ad8ac772` |
| SHA3-384 | `f3dc658832020f59c0618d7d494e0f200a268bdc02a94bf120ad4ff9551c60668d3a857a9e0dcc2f053108c86ef608b2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A062C686D9A21F6CDE4E90703A12F878BD7072908A6659E3D7D28C245D639D00578EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UYLRTe:fKOe2/7c9sN3zfZR1m+RGHL7t6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_70c2fa84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c2fa845ac0791b6281ef1107e9f0c6bc33c582e8c36087f8d3e921ad8ac772"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:19:16"
  condition:
    hash.sha256(0, filesize) == "70c2fa845ac0791b6281ef1107e9f0c6bc33c582e8c36087f8d3e921ad8ac772"
}
```

### Sample 24: `8ec88910ab11d3a2`

| Field | Value |
|---|---|
| SHA-256 | `8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77` |
| Family label | `unknown` |
| File name | `8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77` |
| File type | `elf` |
| First seen | `2026-09-18 03:17:23` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a018faf219dd912f728d0293d85486a` |
| SHA-1 | `65a4790ff158351993f8af0b35f3486f118dbadc` |
| SHA-256 | `8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77` |
| SHA3-384 | `296b74c8a674daf7eda470d16454fe51123bc0fbe50c171cef82ecbde0c4f0462ba77bd9615037c9ba90c7b83cf90a9f` |
| TLSH | `T119B31251D3230D0FC42538FABA26E6162D872E79248A415D4AF9E57B4FB709CE9F2313` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lxF:biMYFJvw6Yh0b1gKobtCGCmCRlrX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_8ec88910
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77"
    family = "unknown"
    file_name = "8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77"
    file_type = "elf"
    first_seen = "2026-09-18 03:17:23"
  condition:
    hash.sha256(0, filesize) == "8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77"
}
```

### Sample 25: `59653f10e35db9aa`

| Field | Value |
|---|---|
| SHA-256 | `59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03` |
| Family label | `unknown` |
| File name | `59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03` |
| File type | `elf` |
| First seen | `2026-09-18 03:17:18` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `687d667d5f4c1d351af8a9ee20a37c90` |
| SHA-1 | `b100daba7781b42a643bf266f619a15f47306b13` |
| SHA-256 | `59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03` |
| SHA3-384 | `df4b9724622c634d1998600709b3f2e35d95fb3abd4a602eff7116a27beb25cfc0620e58b487ba5b9ed0c4d2be4cd194` |
| TLSH | `T1AFB3124AFF31980B9F4019B21ADA5E8EDC697B6B01CBB4A869C2904F57A11CD7D52218` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+Vs:phNlHuBafLeBtfCzpta8xlBIOdVo33` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_59653f10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03"
    family = "unknown"
    file_name = "59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03"
    file_type = "elf"
    first_seen = "2026-09-18 03:17:18"
  condition:
    hash.sha256(0, filesize) == "59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03"
}
```

### Sample 26: `54c7c2a37cc2bd52`

| Field | Value |
|---|---|
| SHA-256 | `54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8` |
| Family label | `Mirai` |
| File name | `54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8` |
| File type | `elf` |
| First seen | `2026-09-18 03:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a69a5f0d9ea27dab7dfbfd796a69f67` |
| SHA-1 | `866cf046cc3c0971f42b6093214e7f02b31f3517` |
| SHA-256 | `54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8` |
| SHA3-384 | `9693cba84c278317ca503322785d128905fd6daee6401f26740c579f93331658623028264917dd6c63eb32002d6358f4` |
| TLSH | `T130A3189ABCD19A5545D413BBBE6E818E330723B4D2DF7113DD041F18B6CA94F0E7AA82` |
| SSDEEP | `3072:T2s/ITo7WCkybotgsJ913DhrbW4UYSx7QpUiBB:T2s/gAWuboqsJ9xcJxspJBB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_54c7c2a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8"
    family = "Mirai"
    file_name = "54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8"
    file_type = "elf"
    first_seen = "2026-09-18 03:17:12"
  condition:
    hash.sha256(0, filesize) == "54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8"
}
```

### Sample 27: `bcd1d32f1f89f3fd`

| Field | Value |
|---|---|
| SHA-256 | `bcd1d32f1f89f3fd6a107874fe525c8536509f993921948c929ae24aeb870054` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:16:40` |
| Reporter | `Bitsight` |
| Tags | `16660bde630116f363f759a4ac9d08fb, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e1ada36f2469421f44a26025c85acdcc` |
| SHA-1 | `184fe2326632ea959f45f0c0da2b6b7dec74bfc8` |
| SHA-256 | `bcd1d32f1f89f3fd6a107874fe525c8536509f993921948c929ae24aeb870054` |
| SHA3-384 | `2f8b0e000079cc364dfe797dd9175cb36eb60cbe08d12e4e46b4f6eddad70aff31b52c992a9ddf42278ed21736657f3b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1DA62E796E8A22F5DCE4ED0703B11FC38BDB47695866599E3D7928C305EA78D00424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UHQrBM:fKOe2/7c9sN3zfZR1m+RGUG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_bcd1d32f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcd1d32f1f89f3fd6a107874fe525c8536509f993921948c929ae24aeb870054"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:16:40"
  condition:
    hash.sha256(0, filesize) == "bcd1d32f1f89f3fd6a107874fe525c8536509f993921948c929ae24aeb870054"
}
```

### Sample 28: `14f2f0266e4f480e`

| Field | Value |
|---|---|
| SHA-256 | `14f2f0266e4f480e2a38bb3f5ac46fe9f3662a07c59a499378527b348cd40019` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:14:59` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `42474c66889beb61c05b6eca9195e27f` |
| SHA-1 | `3ea3e55d232619e573d7219204db00a3b2b6a0a0` |
| SHA-256 | `14f2f0266e4f480e2a38bb3f5ac46fe9f3662a07c59a499378527b348cd40019` |
| SHA3-384 | `ef1759f18f3b2fcfe60ee1cd013bb9006ef066b69821f0a6f23e7c48e3cffb5785ed9591b11d742d86d16a0016c1ab6e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1AA62D586D8D22F5CEE4E80703A11FC287D7436929A65AAE7D7828C355AB39D00524EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U0oBgn:fKOe2/7c9sN3zfZR1m+RGO6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_14f2f026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14f2f0266e4f480e2a38bb3f5ac46fe9f3662a07c59a499378527b348cd40019"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:14:59"
  condition:
    hash.sha256(0, filesize) == "14f2f0266e4f480e2a38bb3f5ac46fe9f3662a07c59a499378527b348cd40019"
}
```

### Sample 29: `ba9f20f074d53852`

| Field | Value |
|---|---|
| SHA-256 | `ba9f20f074d5385224db8f0c114147a21cee9a8c327223230c97cf80b262f505` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:14:23` |
| Reporter | `Bitsight` |
| Tags | `16660bde630116f363f759a4ac9d08fb, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `081b282d3ae3f5e6659c5775fc19c167` |
| SHA-1 | `2c4eed06d55951bb5fb1632361a01152f00f14c4` |
| SHA-256 | `ba9f20f074d5385224db8f0c114147a21cee9a8c327223230c97cf80b262f505` |
| SHA3-384 | `111672f06a0b0b0d3ccd089bde1312a575fb1b9156cec8d101ff89889e32e293cdf2ced4f997676cfe68f6a965b78259` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12E62C68AE8A26F5DCE4E80703A11F878BDB5379486695DE3E7828C355D639D00124FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UTCPvm:fKOe2/7c9sN3zfZR1m+RGWA/6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_ba9f20f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba9f20f074d5385224db8f0c114147a21cee9a8c327223230c97cf80b262f505"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:14:23"
  condition:
    hash.sha256(0, filesize) == "ba9f20f074d5385224db8f0c114147a21cee9a8c327223230c97cf80b262f505"
}
```

### Sample 30: `ea7010ab863c15d2`

| Field | Value |
|---|---|
| SHA-256 | `ea7010ab863c15d2690780a5b2c8052b7cd654000d5a714f12c7d5b97440dae0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:12:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd27e639a169c0f4d421a0ec6f780407` |
| SHA-1 | `26f148d554a4b61e3c46bcf8f1328e4b675aeea2` |
| SHA-256 | `ea7010ab863c15d2690780a5b2c8052b7cd654000d5a714f12c7d5b97440dae0` |
| SHA3-384 | `07a2f1d9fbfadb6f3f21b34a6d3964cc5495e6464e712005ef6bd6bb4d3e6eb405ebcc00025684da63acc0dd579809ee` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14D62E886D8E25F7CDE4F80703A11F978AD7036949A66A9E7E7828C305DA39D00164FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46USWzBM:fKOe2/7c9sN3zfZR1m+RGi6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_ea7010ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea7010ab863c15d2690780a5b2c8052b7cd654000d5a714f12c7d5b97440dae0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:12:39"
  condition:
    hash.sha256(0, filesize) == "ea7010ab863c15d2690780a5b2c8052b7cd654000d5a714f12c7d5b97440dae0"
}
```

### Sample 31: `cecc81f8830b3ca7`

| Field | Value |
|---|---|
| SHA-256 | `cecc81f8830b3ca7b39a967be79e16bdccc113f2bde6e40f0a235e67e7e6af22` |
| Family label | `FleetDeck` |
| File name | `adobe-updater-003.exe` |
| File type | `exe` |
| First seen | `2026-09-18 03:12:16` |
| Reporter | `ppt_lol` |
| Tags | `exe, FleetDeck, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a9f3ecd70e3b3de60eab5292c6942945` |
| SHA-1 | `a09793bc5df8e7239f14d8393b79d4729665778d` |
| SHA-256 | `cecc81f8830b3ca7b39a967be79e16bdccc113f2bde6e40f0a235e67e7e6af22` |
| SHA3-384 | `20dc222a9d0700aa9cae36e0dde2717d858d05ff20c43dfdead073ea7b89e7e06ad5fd3b8fe94a4b4163ac9a7b1921a4` |
| IMPHASH | `9cbefe68f395e67356e2a5d8d1b285c0` |
| TLSH | `T1C416CF90FCDB54B5E603553158AB62BF2734AD094F31CBC7D6407BAEAC73AE10936229` |
| SSDEEP | `49152:xP0dfmVfyr+CU8D1i+7BN53NPyVzc9neiUM1kIq8HQ442lyXp8SnUIA26Yu2:xPt6Laeoi+0QFfXp4Oi2` |
| ICON-DHASH | `e4922945552992e4` |

#### Technical Assessment

- The sample is tracked as `FleetDeck` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_FleetDeck_031_cecc81f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cecc81f8830b3ca7b39a967be79e16bdccc113f2bde6e40f0a235e67e7e6af22"
    family = "FleetDeck"
    file_name = "adobe-updater-003.exe"
    file_type = "exe"
    first_seen = "2026-09-18 03:12:16"
  condition:
    hash.sha256(0, filesize) == "cecc81f8830b3ca7b39a967be79e16bdccc113f2bde6e40f0a235e67e7e6af22"
}
```

### Sample 32: `365583e0613b4e68`

| Field | Value |
|---|---|
| SHA-256 | `365583e0613b4e68379d2a3e897b6e01d681184335fcdbc6c980e7357ecf04bf` |
| Family label | `unknown` |
| File name | `20260914113129-CEF7FAF6EF7E12 (1).iso` |
| File type | `iso` |
| First seen | `2026-09-18 03:11:49` |
| Reporter | `ppt_lol` |
| Tags | `iso, SreenConnect` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b66c46d5bb3083aef03ed6d02962d94` |
| SHA-1 | `3a72e3214e6953dbfa765d2084133551f5dadbd7` |
| SHA-256 | `365583e0613b4e68379d2a3e897b6e01d681184335fcdbc6c980e7357ecf04bf` |
| SHA3-384 | `9ba8661d66143b2439edacb07912ff010ad39150af7bdee1191ff667570036b4985bdd3e3034977ca0be41e9022b7853` |
| TLSH | `T1A7766AF4AB808C32D42A183C4530D3B03F6EA9F05DA4969B67BB1D79CF216D2963161F` |
| SSDEEP | `12288:MPBaiLjpOp/PLs2ooyJLS4w9E/Ihu3RJen1k15:MJaAjoFES+/ICenen` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `iso`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_365583e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "365583e0613b4e68379d2a3e897b6e01d681184335fcdbc6c980e7357ecf04bf"
    family = "unknown"
    file_name = "20260914113129-CEF7FAF6EF7E12 (1).iso"
    file_type = "iso"
    first_seen = "2026-09-18 03:11:49"
  condition:
    hash.sha256(0, filesize) == "365583e0613b4e68379d2a3e897b6e01d681184335fcdbc6c980e7357ecf04bf"
}
```

### Sample 33: `525d26995e33a512`

| Field | Value |
|---|---|
| SHA-256 | `525d26995e33a51239499d755f02a84a01e5ec662d564336952012693da4949b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:10:22` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33a174ef3a03cecf208495d8d5ae1da0` |
| SHA-1 | `69cdc2acaddf82dca64db046c449825936d4d630` |
| SHA-256 | `525d26995e33a51239499d755f02a84a01e5ec662d564336952012693da4949b` |
| SHA3-384 | `c24cb7f8e62dd2687de29e9cf0408198ccf0d8bf34b7c70591c0d3e14f2a52093c451c4ff31aefac3f9f1bbb0ecddee0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15F62C896D8E21F9DCE4E80713A11F878AD70369486A9A9E3E7C28C355DA39D10434FFD` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGuLaaaaaaaaaeWy6C:fKOeOQOzUxwaaaaaaaaaI6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_525d2699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "525d26995e33a51239499d755f02a84a01e5ec662d564336952012693da4949b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:10:22"
  condition:
    hash.sha256(0, filesize) == "525d26995e33a51239499d755f02a84a01e5ec662d564336952012693da4949b"
}
```

### Sample 34: `6b74f08a084510ec`

| Field | Value |
|---|---|
| SHA-256 | `6b74f08a084510ecc7862fc3ff26b6f02209933be2239bbbe279dab2536d0421` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 03:07:58` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `147300d8f993b5c034bb38ad7de65bf2` |
| SHA-1 | `04d0b30453375b845082059029679ebeb10ad807` |
| SHA-256 | `6b74f08a084510ecc7862fc3ff26b6f02209933be2239bbbe279dab2536d0421` |
| SHA3-384 | `435eb5eef76279e09c3d78b23e611ea73c45904d76edc6d0c52dd652ae779ba15aa621d9ebb2679347137e311c606179` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D262E786E9B22F6CDE8E90703E21F968AD7472D0966559F3C7928C715DA39D00024FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UHBDMr:fKOe2/7c9sN3zfZR1m+RG6BD56C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_6b74f08a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b74f08a084510ecc7862fc3ff26b6f02209933be2239bbbe279dab2536d0421"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:07:58"
  condition:
    hash.sha256(0, filesize) == "6b74f08a084510ecc7862fc3ff26b6f02209933be2239bbbe279dab2536d0421"
}
```

### Sample 35: `e9e328bdef27c1cf`

| Field | Value |
|---|---|
| SHA-256 | `e9e328bdef27c1cfea4939140024f87ca909541222bf0d2ed1f56019295b764b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:58:46` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7449b12561772204b39d0a10ab16a111` |
| SHA-1 | `dbd43638c3df81682ccf86816da6a12f2960d611` |
| SHA-256 | `e9e328bdef27c1cfea4939140024f87ca909541222bf0d2ed1f56019295b764b` |
| SHA3-384 | `62c6e16202a2780a7f8b03b6de4c622b996bcf60dd383dc64af2e6d008624c2e5305ca55d408af723299c162d5616b64` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19D62B68798A21F5CCE4E81703A51F97CBDB0369086669DF3D7838C3499A39D04429FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UdBgCc:fKOe2/7c9sN3zfZR1m+RGe6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_e9e328bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9e328bdef27c1cfea4939140024f87ca909541222bf0d2ed1f56019295b764b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:58:46"
  condition:
    hash.sha256(0, filesize) == "e9e328bdef27c1cfea4939140024f87ca909541222bf0d2ed1f56019295b764b"
}
```

### Sample 36: `cc922fb8fe4d86f2`

| Field | Value |
|---|---|
| SHA-256 | `cc922fb8fe4d86f2cf1f3cfea0e45fbed8f5982c5a7ba26405d3ad6b5af2a7c0` |
| Family label | `unknown` |
| File name | `stage1_cc922fb8fe4d.zsh` |
| File type | `unknown` |
| First seen | `2026-09-18 02:35:23` |
| Reporter | `c4ffeine` |
| Tags | `aes, AMOS, ClickFix, dropper, Foxveil, macOS, zsh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58d6b34e0269a5f7b2e76be2c1d8f0f4` |
| SHA-256 | `cc922fb8fe4d86f2cf1f3cfea0e45fbed8f5982c5a7ba26405d3ad6b5af2a7c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_cc922fb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc922fb8fe4d86f2cf1f3cfea0e45fbed8f5982c5a7ba26405d3ad6b5af2a7c0"
    family = "unknown"
    file_name = "stage1_cc922fb8fe4d.zsh"
    file_type = "unknown"
    first_seen = "2026-09-18 02:35:23"
  condition:
    hash.sha256(0, filesize) == "cc922fb8fe4d86f2cf1f3cfea0e45fbed8f5982c5a7ba26405d3ad6b5af2a7c0"
}
```

### Sample 37: `f3b6962c49b361c6`

| Field | Value |
|---|---|
| SHA-256 | `f3b6962c49b361c63fe9d0af9a83e10a52133360117e4c8ac68272160a60edac` |
| Family label | `unknown` |
| File name | `macho_f3b6962c49b3.bin` |
| File type | `macho` |
| First seen | `2026-09-18 02:35:19` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, apph4, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9905cb6e295c26abccc8970121528289` |
| SHA-1 | `073e55ce137dd5fb7bb3a078b32c9acea8bdcce5` |
| SHA-256 | `f3b6962c49b361c63fe9d0af9a83e10a52133360117e4c8ac68272160a60edac` |
| SHA3-384 | `b425ad3da1cb82dd487211cb42d7f301b7b95f4eb1cf57fa55b0853d9a38a7ca758dab39a6cf7ebd7822dfa229257a66` |
| TLSH | `T133050200CF579096F88CE7313E2E4B334E6066A0CA8551DF67253E88AE763E3E56715E` |
| SSDEEP | `12288:eEEIGGrjngjrkv45vpYo97M34B4izSpgIauxJfNgfxkfSR/bwSD703gx:eEvTgjQ45vp5w3I+rxJlgfSSR/bdY3U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_f3b6962c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3b6962c49b361c63fe9d0af9a83e10a52133360117e4c8ac68272160a60edac"
    family = "unknown"
    file_name = "macho_f3b6962c49b3.bin"
    file_type = "macho"
    first_seen = "2026-09-18 02:35:19"
  condition:
    hash.sha256(0, filesize) == "f3b6962c49b361c63fe9d0af9a83e10a52133360117e4c8ac68272160a60edac"
}
```

### Sample 38: `13df107e0549aaa7`

| Field | Value |
|---|---|
| SHA-256 | `13df107e0549aaa781f0bd23cf64dedeefad302e479ab8b91212e4d84629c5ec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:32:01` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f09ab67954ed45ce31c5e5d735da928f` |
| SHA-1 | `ac44ce0c817ae6e851d7ee845e931b6ed2e605e4` |
| SHA-256 | `13df107e0549aaa781f0bd23cf64dedeefad302e479ab8b91212e4d84629c5ec` |
| SHA3-384 | `d3b635bf2ee5cf42ef2799e582c3e538379bc10440e17c94bdd31b4b9ea18b242615314f79e4f41ab19f36d6a6476bb0` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17062D78ADCA22F7CCE4FC0703A11F8A8697436D5966659E7D7828C304DB39D06464EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UsRFBM:fKOe2/7c9sN3zfZR1m+RGnf6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_13df107e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13df107e0549aaa781f0bd23cf64dedeefad302e479ab8b91212e4d84629c5ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:32:01"
  condition:
    hash.sha256(0, filesize) == "13df107e0549aaa781f0bd23cf64dedeefad302e479ab8b91212e4d84629c5ec"
}
```

### Sample 39: `b9fcea96ad78d54d`

| Field | Value |
|---|---|
| SHA-256 | `b9fcea96ad78d54d4b937c08518064b66866763f23000bbdbd8c383b16e6e461` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:31:02` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b214556a27a516c10e9129b0b80393dd` |
| SHA-1 | `4fa0b61198e873ede34f2950c8ed6927ed30eef9` |
| SHA-256 | `b9fcea96ad78d54d4b937c08518064b66866763f23000bbdbd8c383b16e6e461` |
| SHA3-384 | `a90cc2be7cef24721af7cdcd02fc8c349bd65449c86e61587270a3b2301dd702a35e775d39dfa15dc1a3c42dfce213e8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19262D586E9A22F6CDE4F80703B11F968BD747691866599E3D7828C315EA39D00434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UCzBgn:fKOe2/7c9sN3zfZR1m+RGT6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_b9fcea96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9fcea96ad78d54d4b937c08518064b66866763f23000bbdbd8c383b16e6e461"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:31:02"
  condition:
    hash.sha256(0, filesize) == "b9fcea96ad78d54d4b937c08518064b66866763f23000bbdbd8c383b16e6e461"
}
```

### Sample 40: `bbbcf6bb205f7e65`

| Field | Value |
|---|---|
| SHA-256 | `bbbcf6bb205f7e65744c08ba2fd237f390f0fe07790b3bcea8eba13d4a577f67` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:29:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `598b6021047bbf1763e86794e82c4fd4` |
| SHA-1 | `b647acb143a3f76094e85c06176cbe2ed3ac66ec` |
| SHA-256 | `bbbcf6bb205f7e65744c08ba2fd237f390f0fe07790b3bcea8eba13d4a577f67` |
| SHA3-384 | `518d6cdb1d0c23e1f692dae5df2cd56500a51fa29c4bcdafd00f9da2d5d51b87d696d062de3c48756010ed1c8e5d681b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14E62D7D6D8A22F5CDE4F81707A11F838ADB036908A6699E3D7878C3459A79D00534FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZBgCc:fKOe2/7c9sN3zfZR1m+RGy6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_bbbcf6bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbbcf6bb205f7e65744c08ba2fd237f390f0fe07790b3bcea8eba13d4a577f67"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:29:35"
  condition:
    hash.sha256(0, filesize) == "bbbcf6bb205f7e65744c08ba2fd237f390f0fe07790b3bcea8eba13d4a577f67"
}
```

### Sample 41: `32d160e6f6c628b3`

| Field | Value |
|---|---|
| SHA-256 | `32d160e6f6c628b3abf63646826f563590fe09d55b6519d4fc527f8817f5666a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:28:36` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `993abbf5a552c590cc4ec4ae80559247` |
| SHA-1 | `d93a41ee90fa762563b6227e72af6db92f7c9b4c` |
| SHA-256 | `32d160e6f6c628b3abf63646826f563590fe09d55b6519d4fc527f8817f5666a` |
| SHA3-384 | `1daea5cfc79cdf1e54a35481650ef00522c9db68e024f48e59ccef54b6440fa85947e509f9c51b74b5198e560d05ae0b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D362D786E8A22E9CDE4F80703A11F878BDB57690866699F7D7828C315DA39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U6gBgn:fKOe2/7c9sN3zfZR1m+RGPg6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_32d160e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32d160e6f6c628b3abf63646826f563590fe09d55b6519d4fc527f8817f5666a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:28:36"
  condition:
    hash.sha256(0, filesize) == "32d160e6f6c628b3abf63646826f563590fe09d55b6519d4fc527f8817f5666a"
}
```

### Sample 42: `e433b61491ac9db0`

| Field | Value |
|---|---|
| SHA-256 | `e433b61491ac9db00a0701863ff678bc010d8e380ce09f20034f80df02e301b8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:27:07` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c1a60995b1c3956c92753d49c698515` |
| SHA-1 | `f5723d0ebd6555432ddca23e736b531e353624fb` |
| SHA-256 | `e433b61491ac9db00a0701863ff678bc010d8e380ce09f20034f80df02e301b8` |
| SHA3-384 | `e643fa26fa3e6a7bd5c29bd0870f9480ace2c3034730d648fc0b49e59fb7b9e0ae280472b0d9278f91eb6b91ca06a763` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12362C68ADDA26F5CCE4E80707E11F978AD7076D08A6669E3D7828C3159A39D00464EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U/BgCc:fKOe2/7c9sN3zfZR1m+RGU6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_e433b614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e433b61491ac9db00a0701863ff678bc010d8e380ce09f20034f80df02e301b8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:27:07"
  condition:
    hash.sha256(0, filesize) == "e433b61491ac9db00a0701863ff678bc010d8e380ce09f20034f80df02e301b8"
}
```

### Sample 43: `e29932e6656a0a80`

| Field | Value |
|---|---|
| SHA-256 | `e29932e6656a0a80456a84fe90b3622cf9d66e66fca86cfe8c06dccd830ad2b2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:26:17` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26d7593704f777a0bbd1f719460df4d6` |
| SHA-1 | `c8894203e5860df2a2b985a2ab6a9f82917d075c` |
| SHA-256 | `e29932e6656a0a80456a84fe90b3622cf9d66e66fca86cfe8c06dccd830ad2b2` |
| SHA3-384 | `1d69d3d9791403060956bc4291592d21c24bf9a1d00ff21fc779b27a7fc1b97bd3d37a4755792d1ba952632349227e8d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A862E68AD8A22F6CCE4F80703A11F878BD7576958665ADE3D7828C355DA39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UASztx:fKOe2/7c9sN3zfZR1m+RGhghYz6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_e29932e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e29932e6656a0a80456a84fe90b3622cf9d66e66fca86cfe8c06dccd830ad2b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:26:17"
  condition:
    hash.sha256(0, filesize) == "e29932e6656a0a80456a84fe90b3622cf9d66e66fca86cfe8c06dccd830ad2b2"
}
```

### Sample 44: `25adb48419bdf28d`

| Field | Value |
|---|---|
| SHA-256 | `25adb48419bdf28da15fa043c5c2473ffade5853e0efa7922165ff18614fd527` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:23:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15f10ed5fc677e7141964459c6987e0c` |
| SHA-1 | `300dbb833a841c702d674af7e1eb85db8ad9a232` |
| SHA-256 | `25adb48419bdf28da15fa043c5c2473ffade5853e0efa7922165ff18614fd527` |
| SHA3-384 | `a886fe7ffc8f638e68612df13978b6dcceb957c727b19b82d3ba00d7af7cf6e6d8e942f609856def31117b5c1dc33912` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19262E7C6DC921F5DDE4E80703B21FC286EB17290C92569E7DB828D355AA39C14074FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U3BnBM:fKOe2/7c9sN3zfZR1m+RG4Bn6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_25adb484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25adb48419bdf28da15fa043c5c2473ffade5853e0efa7922165ff18614fd527"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:23:39"
  condition:
    hash.sha256(0, filesize) == "25adb48419bdf28da15fa043c5c2473ffade5853e0efa7922165ff18614fd527"
}
```

### Sample 45: `8b7ec973dc5f5b11`

| Field | Value |
|---|---|
| SHA-256 | `8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef` |
| Family label | `unknown` |
| File name | `8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef` |
| File type | `elf` |
| First seen | `2026-09-18 02:18:49` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7c9bf92f3740579191920212ba083083` |
| SHA-1 | `8910f0a460f99b0f672e511beeb8e4fc39f4f34b` |
| SHA-256 | `8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef` |
| SHA3-384 | `f86b8ccedbff21ada0f033b132a0b9f1fea7193a9a7641e8a8ceb31b32d7e8dd35f754230448f28f58175a63bf60701f` |
| TLSH | `T1B793026693230C4AC4392CFAB566D7263E8A2B28284B409845B5F57E5FF31CCE5F5323` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z/:biMYFJvw6Yh0b1gKobtCGCP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_8b7ec973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef"
    family = "unknown"
    file_name = "8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef"
    file_type = "elf"
    first_seen = "2026-09-18 02:18:49"
  condition:
    hash.sha256(0, filesize) == "8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef"
}
```

### Sample 46: `39e38e0e5365d490`

| Field | Value |
|---|---|
| SHA-256 | `39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b` |
| Family label | `Mirai` |
| File name | `39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b` |
| File type | `elf` |
| First seen | `2026-09-18 02:18:43` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba53c4d7ccb43b428fa868740d0654f8` |
| SHA-1 | `3d0ce64d8aaef6f0057efad6a35fba424ac89e3d` |
| SHA-256 | `39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b` |
| SHA3-384 | `b347a35d3d46ff5f14ca08860e3505275173ed330cad7ec0eda12f4cf356e755c95f69df61400f1526a7f1dc722e2212` |
| TLSH | `T14844398AFD80AF25D5C526BBFE2F428A331317B8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJt:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_39e38e0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b"
    family = "Mirai"
    file_name = "39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b"
    file_type = "elf"
    first_seen = "2026-09-18 02:18:43"
  condition:
    hash.sha256(0, filesize) == "39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b"
}
```

### Sample 47: `4b4ad532ad81d4c0`

| Field | Value |
|---|---|
| SHA-256 | `4b4ad532ad81d4c07f7de4b68007c7f569b972515b61304037feef29c06b2a22` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:16:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb0a84b0a62247fc4a710ab9705d12a1` |
| SHA-1 | `1bc5a91c9462b1badad4d2d85acd8be121ee326d` |
| SHA-256 | `4b4ad532ad81d4c07f7de4b68007c7f569b972515b61304037feef29c06b2a22` |
| SHA3-384 | `6badecdfa54069d321b4f9c780f1bf84bc77798e66d4b3dad5faef84207e49571311eaf593bc1c4179dbe4aafeb2e96a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10662E98AE9921F6DDE4F80703A11F8797A74769086A699E3D7828C305DA39C01424FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UugRBM:fKOe2/7c9sN3zfZR1m+RGoR6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_4b4ad532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b4ad532ad81d4c07f7de4b68007c7f569b972515b61304037feef29c06b2a22"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:16:41"
  condition:
    hash.sha256(0, filesize) == "4b4ad532ad81d4c07f7de4b68007c7f569b972515b61304037feef29c06b2a22"
}
```

### Sample 48: `3a2d59a1f90b7a74`

| Field | Value |
|---|---|
| SHA-256 | `3a2d59a1f90b7a74d2d358266e88e21c148f2c2979eabbeb64d23569e887545e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:14:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3349bb91ee4404d4c911a826806e41fb` |
| SHA-1 | `eedd16c17b892d91ab75c8bd8a5900c29cba2c6e` |
| SHA-256 | `3a2d59a1f90b7a74d2d358266e88e21c148f2c2979eabbeb64d23569e887545e` |
| SHA3-384 | `bcae17761261c830d4c9a9c1b3444812f53ce12c36220a4fd4854baaca6e93cc1bebca4a65a9f30be2e7a29546ee3e6b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16B62C686D9A22F5DCE4E80707B11FC78AEB53690866569F7E7878C245DA39C00434EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UkkBgn:fKOe2/7c9sN3zfZR1m+RGlk6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_3a2d59a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2d59a1f90b7a74d2d358266e88e21c148f2c2979eabbeb64d23569e887545e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:14:08"
  condition:
    hash.sha256(0, filesize) == "3a2d59a1f90b7a74d2d358266e88e21c148f2c2979eabbeb64d23569e887545e"
}
```

### Sample 49: `c556be826963de2d`

| Field | Value |
|---|---|
| SHA-256 | `c556be826963de2d9c75ef07cb15cdd54c8ae081cd23699b38c53a6eb93df89e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:11:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ddd372ff33e2f8af859eec5c783f827` |
| SHA-1 | `8125a22791c50bb4aca8ec04b1c1049b04a4a00f` |
| SHA-256 | `c556be826963de2d9c75ef07cb15cdd54c8ae081cd23699b38c53a6eb93df89e` |
| SHA3-384 | `ef8c3764f45dd970c9cf82a31fcef4bd5c93217630e9fe26f21a602dd0d04958401f9895fe3c2dad5d4d96148ea3ef38` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D962C586D9A22F6CCE4FC0703A12F838B97436D486659AE3D7C28C355DA39D01424FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuxjBM:fKOe2/7c9sN3zfZR1m+RGb6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_c556be82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c556be826963de2d9c75ef07cb15cdd54c8ae081cd23699b38c53a6eb93df89e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:11:39"
  condition:
    hash.sha256(0, filesize) == "c556be826963de2d9c75ef07cb15cdd54c8ae081cd23699b38c53a6eb93df89e"
}
```

### Sample 50: `dd9d85265cc6ebcd`

| Field | Value |
|---|---|
| SHA-256 | `dd9d85265cc6ebcd449731ca971d37bafd6382c41ceeea083bdbb00e693122e4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:02:48` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96a115e8f76ba2a8b1cd11666d9e2d4b` |
| SHA-1 | `8ce953b71d85252936c1d6ca740da62a7f3fc28c` |
| SHA-256 | `dd9d85265cc6ebcd449731ca971d37bafd6382c41ceeea083bdbb00e693122e4` |
| SHA3-384 | `2985cab9611ad7dd296263b66b1bf5c768b3e217213b2bb7102c7ec1a35fcc19eab8ce4e9df8ed367098317bf304b6db` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D962E887E8925F6CDE4E80707B11F838AD7036908626A9E3D7C18D315DA38D25574FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U5pMBM:fKOe2/7c9sN3zfZR1m+RG4q6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_dd9d8526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd9d85265cc6ebcd449731ca971d37bafd6382c41ceeea083bdbb00e693122e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:02:48"
  condition:
    hash.sha256(0, filesize) == "dd9d85265cc6ebcd449731ca971d37bafd6382c41ceeea083bdbb00e693122e4"
}
```

### Sample 51: `ad733ae1b12eca7d`

| Field | Value |
|---|---|
| SHA-256 | `ad733ae1b12eca7dca5058a99520bbb179548d61cadb7ac87c5d76c9c2a4ff71` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-18 02:02:42` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ccc9a66b5e5bf02d8554fa3deebae642` |
| SHA-1 | `a0f3d7e65795da40b9112eb1b2596bbaf05f9656` |
| SHA-256 | `ad733ae1b12eca7dca5058a99520bbb179548d61cadb7ac87c5d76c9c2a4ff71` |
| SHA3-384 | `9f46712721470036be59beebb87251a82fc7dfd9dec037432a5302735a4e17f38d15a3104b2af299445ad441cc9a48dd` |
| TLSH | `T1C8C27C966E867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:78vCB+25j6es8Rq9FYpMSUpi+20qUpi+20YQX:78l25Jcd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_051_ad733ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad733ae1b12eca7dca5058a99520bbb179548d61cadb7ac87c5d76c9c2a4ff71"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-18 02:02:42"
  condition:
    hash.sha256(0, filesize) == "ad733ae1b12eca7dca5058a99520bbb179548d61cadb7ac87c5d76c9c2a4ff71"
}
```

### Sample 52: `990d9914843669db`

| Field | Value |
|---|---|
| SHA-256 | `990d9914843669dbf47e67b57456d5b81e9639f561b4c21f2ec74906840ec7a4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:02:26` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a416d2770eddffb30f4a91380b0f40d` |
| SHA-1 | `84c323c4acfb65e5d00773fa7c14851f3162492c` |
| SHA-256 | `990d9914843669dbf47e67b57456d5b81e9639f561b4c21f2ec74906840ec7a4` |
| SHA3-384 | `37c1065215469a86b3e6a3a4d1afdcf2e7528eab541a24397cce651b7086a2d3fd4cb41984370a0659e99501c265b096` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12262C89AE8922F5DCE4F80B03B11F838BD7476D5896999E3D7928C745DA39D00024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UatBgn:fKOe2/7c9sN3zfZR1m+RG/6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_990d9914
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "990d9914843669dbf47e67b57456d5b81e9639f561b4c21f2ec74906840ec7a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:02:26"
  condition:
    hash.sha256(0, filesize) == "990d9914843669dbf47e67b57456d5b81e9639f561b4c21f2ec74906840ec7a4"
}
```

### Sample 53: `08877bbceb3707d8`

| Field | Value |
|---|---|
| SHA-256 | `08877bbceb3707d89a0a1945ab86b46d35cc4418a667e07e3405fe8031c49e58` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:01:38` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `44947dae4b585c3de9af704aba747e75` |
| SHA-1 | `ed8b7ee93ff4f826b28061e95c12717cb2c966f2` |
| SHA-256 | `08877bbceb3707d89a0a1945ab86b46d35cc4418a667e07e3405fe8031c49e58` |
| SHA3-384 | `efa1421db405f66fbda4d6caf2e564e62820459fecfc889dde2e12b56fc08cad6411534c52a6f3aba8b8333c60aea8af` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D462E896DAE11EADCE4F80713B20F878A97477A1566699E3D7C28C305EA39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UuPaJk:fKOe2/7c9sN3zfZR1m+RGhPaT6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_08877bbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08877bbceb3707d89a0a1945ab86b46d35cc4418a667e07e3405fe8031c49e58"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:01:38"
  condition:
    hash.sha256(0, filesize) == "08877bbceb3707d89a0a1945ab86b46d35cc4418a667e07e3405fe8031c49e58"
}
```

### Sample 54: `61a36d4ff07091d0`

| Field | Value |
|---|---|
| SHA-256 | `61a36d4ff07091d061ed569eef0fad3e4ca16b6fbde7d687a73ece2beb6389b4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:00:12` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77d43bc4d7020a20d9ff1db9c3caee54` |
| SHA-1 | `836f3cb1e49f7c17ef568418d1fd4b499f0ea1af` |
| SHA-256 | `61a36d4ff07091d061ed569eef0fad3e4ca16b6fbde7d687a73ece2beb6389b4` |
| SHA3-384 | `47146e960a6aaf8d7e9bc69d7075b91944e99e8b0bca6573f3dc5dfc4887e326fa7c4b7753b49049cedb8ca1555247df` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19562C58AD8E22B7CDE4F80713B51FA38BD71769087665DF3DB828C3459A39D14024EB9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U3BgCc:fKOe2/7c9sN3zfZR1m+RGo6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_61a36d4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61a36d4ff07091d061ed569eef0fad3e4ca16b6fbde7d687a73ece2beb6389b4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:00:12"
  condition:
    hash.sha256(0, filesize) == "61a36d4ff07091d061ed569eef0fad3e4ca16b6fbde7d687a73ece2beb6389b4"
}
```

### Sample 55: `2b7d1106e7f8c2d0`

| Field | Value |
|---|---|
| SHA-256 | `2b7d1106e7f8c2d0bd11dc879e7fe585d040b8f095f08bc43159bc679a0000d0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 02:00:03` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95f0c240bffe4b476e2cffc3e1479b99` |
| SHA-1 | `637ac2231c05e911b138d4a210132fde4a3a9396` |
| SHA-256 | `2b7d1106e7f8c2d0bd11dc879e7fe585d040b8f095f08bc43159bc679a0000d0` |
| SHA3-384 | `3d4c0577e2cdf6b5d89ae31f0b585ce604f9fc0cdd115e19ed3dc3b8ecddd92ab0b768ee2c2c332403d215b5bf9c931d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11E62C796DD922E5DDE4E80703B11F8786DB5729086665EE7D7C28C305DA39D00428EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46US4rBM:fKOe2/7c9sN3zfZR1m+RGls6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_2b7d1106
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b7d1106e7f8c2d0bd11dc879e7fe585d040b8f095f08bc43159bc679a0000d0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:00:03"
  condition:
    hash.sha256(0, filesize) == "2b7d1106e7f8c2d0bd11dc879e7fe585d040b8f095f08bc43159bc679a0000d0"
}
```

### Sample 56: `b07c47d2ff7ac642`

| Field | Value |
|---|---|
| SHA-256 | `b07c47d2ff7ac6425434b6a9ba200823b9a104a4f614c3b5326528d4b0d8c221` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:58:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c1dc55aec7d98bc9d22bfb12b1e1f7f` |
| SHA-1 | `834925b1c2e8dda782bd0d6594f0816c5d2f0e35` |
| SHA-256 | `b07c47d2ff7ac6425434b6a9ba200823b9a104a4f614c3b5326528d4b0d8c221` |
| SHA3-384 | `a81ad3082e50f91ec6bb85c59531962af42befdefe2ecfb21f5fa1c8cd64206606f21ca2846f2ec8f3b65b9a305ca0cd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17B62C68AD9E35F6CCE4E90707A11F828B9B436E4896659E3D796CC304AA39D00434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uc2hBM:fKOe2/7c9sN3zfZR1m+RG72h6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_b07c47d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b07c47d2ff7ac6425434b6a9ba200823b9a104a4f614c3b5326528d4b0d8c221"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:58:19"
  condition:
    hash.sha256(0, filesize) == "b07c47d2ff7ac6425434b6a9ba200823b9a104a4f614c3b5326528d4b0d8c221"
}
```

### Sample 57: `19334979afe2d89b`

| Field | Value |
|---|---|
| SHA-256 | `19334979afe2d89b6a494f25af129048de7c228cda2f266b4356da20ae7b4d5c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:57:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf7c9c3a1a7804cc0a3574c3d0c4836a` |
| SHA-1 | `ff545274c3ec3746882f22c53f84a87c4aac92f8` |
| SHA-256 | `19334979afe2d89b6a494f25af129048de7c228cda2f266b4356da20ae7b4d5c` |
| SHA3-384 | `609bbf4a09cbf69760069388b74ecbb80a7ab30f72ac3f6d4a51cd702ed12eacd09cad340466654629dfa6ecfe26c2f6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A462E896E9D12EACCE8E80703A21FC78AD717694865959F7C7928C305EA39D04438FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UDBgCc:fKOe2/7c9sN3zfZR1m+RGk6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_19334979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19334979afe2d89b6a494f25af129048de7c228cda2f266b4356da20ae7b4d5c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:57:47"
  condition:
    hash.sha256(0, filesize) == "19334979afe2d89b6a494f25af129048de7c228cda2f266b4356da20ae7b4d5c"
}
```

### Sample 58: `d4137be5ad4d7930`

| Field | Value |
|---|---|
| SHA-256 | `d4137be5ad4d79301a66b4e756ec8c0f8cb481e016e5c3075dcdac5096691ba4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:57:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e69fa273fbc0603b621e6d9cbb84b0e` |
| SHA-1 | `40db8faaf2f4a165473c0268263d66574ad0b2f7` |
| SHA-256 | `d4137be5ad4d79301a66b4e756ec8c0f8cb481e016e5c3075dcdac5096691ba4` |
| SHA3-384 | `6db46a54b2d8ba7fcc66c6825d83fb66e86b80360b43afdf58d97773d12e554694b204c7541d664ded0f33982870bdf6` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E862F89AD8A25F5CCE4E90703B52FA78BDB43291896599E7C7928C345DA38D00038FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZBGwX:fKOe2/7c9sN3zfZR1m+RGEd26C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_d4137be5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4137be5ad4d79301a66b4e756ec8c0f8cb481e016e5c3075dcdac5096691ba4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:57:35"
  condition:
    hash.sha256(0, filesize) == "d4137be5ad4d79301a66b4e756ec8c0f8cb481e016e5c3075dcdac5096691ba4"
}
```

### Sample 59: `0e8aa7f4ea502014`

| Field | Value |
|---|---|
| SHA-256 | `0e8aa7f4ea5020141b57f52438bcaf8e46c004e38b7a7de1f8527e8cdfb937bd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:46:48` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb3c47fc035775ee13f5026b60b59817` |
| SHA-1 | `90f69305ca4db57e6a7bd574d36e3dbe0a356864` |
| SHA-256 | `0e8aa7f4ea5020141b57f52438bcaf8e46c004e38b7a7de1f8527e8cdfb937bd` |
| SHA3-384 | `51b4cee653ce0aee2a45574424c34511b7c842cda3697a883ad40281a3e16c73b746abd2f4325612cd95641065bdcdd8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12B62D58AE9A32FACDE4F80703A51F838BD747294866559E3D7828C314EA39D10534FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UgBgCc:fKOe2/7c9sN3zfZR1m+RGX6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_0e8aa7f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8aa7f4ea5020141b57f52438bcaf8e46c004e38b7a7de1f8527e8cdfb937bd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:46:48"
  condition:
    hash.sha256(0, filesize) == "0e8aa7f4ea5020141b57f52438bcaf8e46c004e38b7a7de1f8527e8cdfb937bd"
}
```

### Sample 60: `72e4b18a842191ce`

| Field | Value |
|---|---|
| SHA-256 | `72e4b18a842191ce7087bed05fc4106364f99280c4e7c27859e11e79f9781963` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:44:24` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e0ddf430c0a06a27de68570a07cff21` |
| SHA-1 | `79a66da3f29866e37f492047fc03d95544809487` |
| SHA-256 | `72e4b18a842191ce7087bed05fc4106364f99280c4e7c27859e11e79f9781963` |
| SHA3-384 | `e8947bd868179841bb2b1b8f033dee88da453b14123da4b4a08dbd79a285d13f5de55075f202caaf0f1022ec2c9838ab` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15662C786D8A22E5CCE4E90707E21F878797032E086669DE3DB96CC3559A79E10434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UBBgCc:fKOe2/7c9sN3zfZR1m+RGK6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_72e4b18a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72e4b18a842191ce7087bed05fc4106364f99280c4e7c27859e11e79f9781963"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:44:24"
  condition:
    hash.sha256(0, filesize) == "72e4b18a842191ce7087bed05fc4106364f99280c4e7c27859e11e79f9781963"
}
```

### Sample 61: `4f375117095db078`

| Field | Value |
|---|---|
| SHA-256 | `4f375117095db078e4fa3828bbfb82e686f69574ee8802a4b1daab9e7e031dd2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:31:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f4cea5ee1fa470abc5479849474a961` |
| SHA-1 | `b300bdd0158158889a13252e28597c65cf808f63` |
| SHA-256 | `4f375117095db078e4fa3828bbfb82e686f69574ee8802a4b1daab9e7e031dd2` |
| SHA3-384 | `6efdcbcfa68b6ad843a99bc1ef0b19489160dbfd436be2948316a770362597b2a0ef39767f9c79446e8e649c4b7018ff` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18162C687EAD22F5CEE4FC0717A11F8786E7036908A6599F7D7C28C345DA38E10424EB9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGEy333333333sy6C:fKOeOQOzUxEy333333333P6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_4f375117
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f375117095db078e4fa3828bbfb82e686f69574ee8802a4b1daab9e7e031dd2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:31:41"
  condition:
    hash.sha256(0, filesize) == "4f375117095db078e4fa3828bbfb82e686f69574ee8802a4b1daab9e7e031dd2"
}
```

### Sample 62: `dddef12b126dc995`

| Field | Value |
|---|---|
| SHA-256 | `dddef12b126dc995cba706ca84c3f0f79ec1eacc61a5fc05ab0b564cadc76e3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:27:40` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2c46ec64094d7a82a6daf3b93724f8a` |
| SHA-1 | `6e349f260f4dcfd7490e578d65bf0f2a1b72dfa1` |
| SHA-256 | `dddef12b126dc995cba706ca84c3f0f79ec1eacc61a5fc05ab0b564cadc76e3e` |
| SHA3-384 | `a93a14c6b4b048bb29a9f9db43df30ce474e2769ef1a3adfddc065e7b25c0e7346efeb4a0eada7d83c79ac95d5888320` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F062D686E9A21F6CDE4E80713B21F978AE7076D4876569E7D7828C305DA39D00424FFE` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGmVVVVVVVVVVVVVVVVVVVVVVU6C:fKOeOQOzUxmVVVVVVVVVVVVVVVVVVVVJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_dddef12b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dddef12b126dc995cba706ca84c3f0f79ec1eacc61a5fc05ab0b564cadc76e3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:27:40"
  condition:
    hash.sha256(0, filesize) == "dddef12b126dc995cba706ca84c3f0f79ec1eacc61a5fc05ab0b564cadc76e3e"
}
```

### Sample 63: `9b7382cf25d7d745`

| Field | Value |
|---|---|
| SHA-256 | `9b7382cf25d7d7459166276de94c21439eb0dae47babaf08b7f6115b1e5fc8b7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:25:15` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cfb1ce7f985aacbaac7df227351714c7` |
| SHA-1 | `d1678241df989822bac6cbc57b868a14446aebd9` |
| SHA-256 | `9b7382cf25d7d7459166276de94c21439eb0dae47babaf08b7f6115b1e5fc8b7` |
| SHA3-384 | `8128cd07f833b809eec6aa7131779e02f1e5885fe2a5ca1cce2db89a2e33d7162dbb626166d7b4753e4b61874de260f9` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17262C78AD8A22F6CCE4FD0703A11F878ADB036958A6699E7D7D2CC305D639D00524FBD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJFgBM:fKOe2/7c9sN3zfZR1m+RGkg6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_9b7382cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b7382cf25d7d7459166276de94c21439eb0dae47babaf08b7f6115b1e5fc8b7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:25:15"
  condition:
    hash.sha256(0, filesize) == "9b7382cf25d7d7459166276de94c21439eb0dae47babaf08b7f6115b1e5fc8b7"
}
```

### Sample 64: `c3df8dfb912fc17f`

| Field | Value |
|---|---|
| SHA-256 | `c3df8dfb912fc17fb564a11c918a4ca19c36d2b7df0efb8efb76e6851699352c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:21:13` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33a1e84a6647a47bbd12b89d855d37a1` |
| SHA-1 | `9822464103ea308b69779532b28edd9e4e9ad80a` |
| SHA-256 | `c3df8dfb912fc17fb564a11c918a4ca19c36d2b7df0efb8efb76e6851699352c` |
| SHA3-384 | `c83676164af15d83dbfac49296bd7eb299a51d3cf28c6b4fe01241cf1cbe8e627b65ff01de4f25ba23d056b848a71707` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13D62C496E9A36E9CDE8F80703E11F978BDB43690866659E3D7828C3459A38D10034FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UVkBgn:fKOe2/7c9sN3zfZR1m+RGJ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_c3df8dfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3df8dfb912fc17fb564a11c918a4ca19c36d2b7df0efb8efb76e6851699352c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:21:13"
  condition:
    hash.sha256(0, filesize) == "c3df8dfb912fc17fb564a11c918a4ca19c36d2b7df0efb8efb76e6851699352c"
}
```

### Sample 65: `2d176f7c7efa92ec`

| Field | Value |
|---|---|
| SHA-256 | `2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5` |
| Family label | `unknown` |
| File name | `2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5` |
| File type | `elf` |
| First seen | `2026-09-18 01:19:46` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, x64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7e7e9814a504aa78681821edd9915ce` |
| SHA-1 | `c337620d903113f8b237d7ef722bc6fc6d2016cf` |
| SHA-256 | `2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5` |
| SHA3-384 | `d543d940dff8f45b3ce22b3c0ee53045c8ba649e0613351bb8545f4824b17427368f45edfe90278b277c1101490d92e4` |
| TLSH | `T1802413DCAF1898CDCB7D437D70A0FD66DBC1604A9B47E900A868A6E463EE5F0B542C74` |
| SSDEEP | `6144:levDQFy6EeZakLY/mWFbQpH6IwQwkK4rs/rI0qj:lertoZakLSHFhOKOj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_2d176f7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5"
    family = "unknown"
    file_name = "2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:46"
  condition:
    hash.sha256(0, filesize) == "2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5"
}
```

### Sample 66: `798f72019b2b81af`

| Field | Value |
|---|---|
| SHA-256 | `798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2` |
| Family label | `unknown` |
| File name | `798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2` |
| File type | `elf` |
| First seen | `2026-09-18 01:19:41` |
| Reporter | `aLittleBitGrey` |
| Tags | `aarch64, cowrie, elf, honeypot` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d0a0d73b21fded59970567f131b59e1` |
| SHA-1 | `83f5759a90f454659229ab00b6964e2e657b451c` |
| SHA-256 | `798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2` |
| SHA3-384 | `ce822c0ac8ed8aed1eee3f118f5c5d7672b91b99ae9514be570fb80c2a644a20a90abc3850667964fc8a9d0178d1d51d` |
| TLSH | `T187B423F5D20D4D65F18BFB6E1A895008F60CD549E6114CB62734AACFE4A787CF222C6B` |
| SSDEEP | `12288:qRc6T2fuRJ5avCPJfVMP7+0/veOGtqU4HMGQNIAMkNg3o:sc6qWRqqRfVMP7Cft/U1QNlMo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_798f7201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2"
    family = "unknown"
    file_name = "798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:41"
  condition:
    hash.sha256(0, filesize) == "798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2"
}
```

### Sample 67: `9b36220ec9117783`

| Field | Value |
|---|---|
| SHA-256 | `9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40` |
| Family label | `unknown` |
| File name | `9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40` |
| File type | `elf` |
| First seen | `2026-09-18 01:19:35` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c056bb2fcc033aebed5783607117a19d` |
| SHA-1 | `dd490d3d83a97f8ce0cb066a298e12cb2f8ce591` |
| SHA-256 | `9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40` |
| SHA3-384 | `2a603133391d5fd7b17da5a71d0b0624c27e79492d196d40ed3c9cbcd987614c2c45858e34906c99ffb54d4533f80434` |
| TLSH | `T16AC3125293221C4BC43538FABE16E6162D862E79248E405C46F5E77A5FB7088EEF1363` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4Dx1lx7:biMYFJvw6Yh0b1gKobtCGCmCRlrR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_9b36220e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40"
    family = "unknown"
    file_name = "9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:35"
  condition:
    hash.sha256(0, filesize) == "9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40"
}
```

### Sample 68: `47247191db3a3c71`

| Field | Value |
|---|---|
| SHA-256 | `47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0` |
| Family label | `unknown` |
| File name | `47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0` |
| File type | `elf` |
| First seen | `2026-09-18 01:19:30` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `876fc321d965ee4773c99426968694ef` |
| SHA-1 | `31929ce2d969e3cdd19450be172dcbfd319c7c8c` |
| SHA-256 | `47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0` |
| SHA3-384 | `8e4fee14475d187ae227afb9876224bb5330201ba714162ebd02a249ab0ae3980503bce18e9b26f8cf45dbc886e0be2f` |
| TLSH | `T11ED3124AEF369C1ECF401EB22ADB5F8E9C6D796B41CBF4A4B9C5818F13A01C97912215` |
| SSDEEP | `3072:phNlHuBafLeBtfCzpta8xlBIOdVo3/4sxLJ10xir:p3lOYoaja8xzx/0wsxzSir` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_47247191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0"
    family = "unknown"
    file_name = "47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:30"
  condition:
    hash.sha256(0, filesize) == "47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0"
}
```

### Sample 69: `1bf756538fa9bffc`

| Field | Value |
|---|---|
| SHA-256 | `1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d` |
| Family label | `Mirai` |
| File name | `1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d` |
| File type | `elf` |
| First seen | `2026-09-18 01:19:25` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `781ef00a56ae4b52ccdffabd8e5f27d6` |
| SHA-1 | `26753d89cb6e96822585f64f1b27227a3d820161` |
| SHA-256 | `1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d` |
| SHA3-384 | `97d313928f73c5ab350db106e023c0e863d329160105ee37ef8e2c02a78fe6e32cfb59cd2c020eb872224b94cbea5209` |
| TLSH | `T18224298AFC81AF5596C126BBFE2E418A331317B8D2EE71129D145F2477CA94F0F3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqS:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_1bf75653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d"
    family = "Mirai"
    file_name = "1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:25"
  condition:
    hash.sha256(0, filesize) == "1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d"
}
```

### Sample 70: `e696334a71375d10`

| Field | Value |
|---|---|
| SHA-256 | `e696334a71375d10625a19fd8ceb269c5503db069d0ff0ac8d9c5854ffa2bbfc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:18:57` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1166411eac9ecbef1f2bc2a7ed6c51e4` |
| SHA-1 | `700333ab29b1f450e32151063de00acc5456d7ca` |
| SHA-256 | `e696334a71375d10625a19fd8ceb269c5503db069d0ff0ac8d9c5854ffa2bbfc` |
| SHA3-384 | `357cd34a53e50f2d7ab0d732d1e20609ab0daa7f8d051ef99c833ecbf4af27b4954b2b5933a681e04858ae3697389a46` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14462B586E9D26F6CCE4E80703A11F8386DB176A186665DE3D7C28D3059A78D04628EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U/BgCc:fKOe2/7c9sN3zfZR1m+RGQ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_e696334a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e696334a71375d10625a19fd8ceb269c5503db069d0ff0ac8d9c5854ffa2bbfc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:18:57"
  condition:
    hash.sha256(0, filesize) == "e696334a71375d10625a19fd8ceb269c5503db069d0ff0ac8d9c5854ffa2bbfc"
}
```

### Sample 71: `144e1a620a7d257e`

| Field | Value |
|---|---|
| SHA-256 | `144e1a620a7d257e7b17ae16da658d015ebca4336dc603d67e0f2c80f9cdafcd` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-18 01:16:36` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c87ce41fccd56958dfbdb6463f93626` |
| SHA-256 | `144e1a620a7d257e7b17ae16da658d015ebca4336dc603d67e0f2c80f9cdafcd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_144e1a62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "144e1a620a7d257e7b17ae16da658d015ebca4336dc603d67e0f2c80f9cdafcd"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-18 01:16:36"
  condition:
    hash.sha256(0, filesize) == "144e1a620a7d257e7b17ae16da658d015ebca4336dc603d67e0f2c80f9cdafcd"
}
```

### Sample 72: `f190633ec16ecb1f`

| Field | Value |
|---|---|
| SHA-256 | `f190633ec16ecb1f0f070c26f258a278d51bb86842dbe0f75c00d0ff0f178300` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:16:22` |
| Reporter | `Bitsight` |
| Tags | `7fb9ce94a5b4ca72f31a746cc2c6134d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1257d893c92aa388cd0d308763f45b1b` |
| SHA-1 | `74d930e8487db0261f21f78c8cf72e1f99690e69` |
| SHA-256 | `f190633ec16ecb1f0f070c26f258a278d51bb86842dbe0f75c00d0ff0f178300` |
| SHA3-384 | `21123cfb02928435ed881ae4aeb98f86598e2cb9171aeb0d5b46da00d9bae5d509dfc9028c18b9fb8ad21693fca87980` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FB62D596DC936F6CCE4F91703A11F838ADB5B294866599E3DB828C304EA39D04024EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UEBgCc:fKOe2/7c9sN3zfZR1m+RGX6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_f190633e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f190633ec16ecb1f0f070c26f258a278d51bb86842dbe0f75c00d0ff0f178300"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:16:22"
  condition:
    hash.sha256(0, filesize) == "f190633ec16ecb1f0f070c26f258a278d51bb86842dbe0f75c00d0ff0f178300"
}
```

### Sample 73: `021d369e92976960`

| Field | Value |
|---|---|
| SHA-256 | `021d369e929769603851acade92af051024192b69a28dca96569a4327449a005` |
| Family label | `unknown` |
| File name | `Kohzan Maru VI Full Vessel Q88.js` |
| File type | `js` |
| First seen | `2026-09-18 01:14:35` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d10758dfe63b53428795ff54200cc546` |
| SHA-1 | `812e1ab4913c4d5849a80bfe3f88f7e1f2228c99` |
| SHA-256 | `021d369e929769603851acade92af051024192b69a28dca96569a4327449a005` |
| SHA3-384 | `ac6927cf8ff3bf672a6dc7c25313b83ec1a8a6d2723ec6d6be8c9430a9787d54a578722a8bdd41790b12613546125146` |
| TLSH | `T132D5E8F263EFFA8A1D057B2D940CA6680F6EC4522D95E99090CB05C590CF5FF24C9DAE` |
| SSDEEP | `49152:1Ik7bwNC9hqn9bPuATwTcGlFWqxA3hjFL+t//LQQNi9bScUnn9bwz2koCQprl6h5:S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_021d369e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021d369e929769603851acade92af051024192b69a28dca96569a4327449a005"
    family = "unknown"
    file_name = "Kohzan Maru VI Full Vessel Q88.js"
    file_type = "js"
    first_seen = "2026-09-18 01:14:35"
  condition:
    hash.sha256(0, filesize) == "021d369e929769603851acade92af051024192b69a28dca96569a4327449a005"
}
```

### Sample 74: `a7487d01ab276b28`

| Field | Value |
|---|---|
| SHA-256 | `a7487d01ab276b2817463cdb4bb8547c0fa0b750d3a123cf770a2db63ba82e00` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:12:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0740937ab067ed5abec7c74952de935c` |
| SHA-1 | `392d2adbd3dae57cfdcf4798c73aae82dfafd475` |
| SHA-256 | `a7487d01ab276b2817463cdb4bb8547c0fa0b750d3a123cf770a2db63ba82e00` |
| SHA3-384 | `903cbba539c3999339786dccba6652b44dc7f47a6083bb10fc03c668d0647248c62b12adbe620bf8718f7a3d3570c994` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E462C786D8D25F6CCE8E90707E11F878B9B436919979DDE7DB829C3049A39E00424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Ur+Bgn:fKOe2/7c9sN3zfZR1m+RGB6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_a7487d01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7487d01ab276b2817463cdb4bb8547c0fa0b750d3a123cf770a2db63ba82e00"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:12:49"
  condition:
    hash.sha256(0, filesize) == "a7487d01ab276b2817463cdb4bb8547c0fa0b750d3a123cf770a2db63ba82e00"
}
```

### Sample 75: `f6aceea08cc26303`

| Field | Value |
|---|---|
| SHA-256 | `f6aceea08cc263030f0f4233076308602239b3cb19527fa3372dfec5b785ddbc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:10:21` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0379c0eea08a2c2c98be3bb74e477d46` |
| SHA-1 | `e5b441a7493da9393af3d7ef863d6edb8d93f167` |
| SHA-256 | `f6aceea08cc263030f0f4233076308602239b3cb19527fa3372dfec5b785ddbc` |
| SHA3-384 | `8a62b3120df85c070771a2bc928a25feaafb70fb9284ad02280ff7b3ef7d0f1a1c33fbf1576b24f96fdd785284ddd77e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B162C6C6D8A26E5CDE4FC0703E11FC78B97432D19A6659E3D7828C315AA39E00574FB9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uh8WMe:fKOe2/7c9sN3zfZR1m+RGyM6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_f6aceea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6aceea08cc263030f0f4233076308602239b3cb19527fa3372dfec5b785ddbc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:10:21"
  condition:
    hash.sha256(0, filesize) == "f6aceea08cc263030f0f4233076308602239b3cb19527fa3372dfec5b785ddbc"
}
```

### Sample 76: `f526c366d758781f`

| Field | Value |
|---|---|
| SHA-256 | `f526c366d758781f0185c788e2a6d52780b83bda3c3e5bf9c4c5938a05338685` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:08:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1a201b1122ed4cbd920e9636aef5625` |
| SHA-1 | `5ad90ade62b3d694e9b312e0c4be026e5fb2cb48` |
| SHA-256 | `f526c366d758781f0185c788e2a6d52780b83bda3c3e5bf9c4c5938a05338685` |
| SHA3-384 | `0179b44c77e28b5e2403118d02a226acef8b2039e62365452400495cfe2f7c8b1e942f37cdc5199d010cbf93df03874c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T11762E786D8E26FADDE4E80703B11F868B9743AD1962569E7D7928C305DA38D00538FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uqh7BM:fKOe2/7c9sN3zfZR1m+RGl76C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_f526c366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f526c366d758781f0185c788e2a6d52780b83bda3c3e5bf9c4c5938a05338685"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:08:41"
  condition:
    hash.sha256(0, filesize) == "f526c366d758781f0185c788e2a6d52780b83bda3c3e5bf9c4c5938a05338685"
}
```

### Sample 77: `9d0444f496a57b73`

| Field | Value |
|---|---|
| SHA-256 | `9d0444f496a57b73dd27e4c384c89871d0534b0fdd84a3743727013899ff67ee` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:06:04` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11d89d85c7b2d24ac4ca4d7cc0d9ecab` |
| SHA-1 | `62b2ff516f9c0e488b2303191c32cf1f245739bd` |
| SHA-256 | `9d0444f496a57b73dd27e4c384c89871d0534b0fdd84a3743727013899ff67ee` |
| SHA3-384 | `ec60843903cae8fe240ce10d5a11b7ab0b3b2dbcc000416f6e6d2e9faa0e66ccf9a7c2a5923e3cf3591b30c183944018` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12D62E687D8A22F6CDE8E80707A11F878BD7536959A255CE7D7828C315DA39D00434FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UNc/BM:fKOe2/7c9sN3zfZR1m+RGYc/6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_9d0444f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d0444f496a57b73dd27e4c384c89871d0534b0fdd84a3743727013899ff67ee"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:06:04"
  condition:
    hash.sha256(0, filesize) == "9d0444f496a57b73dd27e4c384c89871d0534b0fdd84a3743727013899ff67ee"
}
```

### Sample 78: `70e6b909f8850bbf`

| Field | Value |
|---|---|
| SHA-256 | `70e6b909f8850bbfcd0915af762f97eb9315ad11bb9abf77ef0bde400ea09d38` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 01:03:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2ad23ece156ef6e38abee39df8f7cc8b` |
| SHA-1 | `eb4a9ebcb9234b32687cf4b1ca2e22a1006f96f1` |
| SHA-256 | `70e6b909f8850bbfcd0915af762f97eb9315ad11bb9abf77ef0bde400ea09d38` |
| SHA3-384 | `732d2aca455eb013d87905134bffc91b439ff3f043a8f969e5fad1cc1e08b78ed9052baa5c2dc6fb1e6f41ba83ca0d14` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14D62C686D8D22E5CDE4E90B03B11FC786D79B691856A99F7D7C29C305EA39D00034EF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGHfJJJJJJJJJJ6C:fKOeOQOzUxP6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_70e6b909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e6b909f8850bbfcd0915af762f97eb9315ad11bb9abf77ef0bde400ea09d38"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:03:39"
  condition:
    hash.sha256(0, filesize) == "70e6b909f8850bbfcd0915af762f97eb9315ad11bb9abf77ef0bde400ea09d38"
}
```

### Sample 79: `76753bdffb071b3c`

| Field | Value |
|---|---|
| SHA-256 | `76753bdffb071b3cc77c3b7edad8693910f4682448325d0bbd84db96fc04e16f` |
| Family label | `unknown` |
| File name | `Offmeta.exe` |
| File type | `exe` |
| First seen | `2026-09-18 00:49:36` |
| Reporter | `NyxIndius` |
| Tags | `exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06573dd9a2cec38ab6496d5d29756704` |
| SHA-1 | `61aae6c6d2302ccbf2596da84017ce59c6e4c860` |
| SHA-256 | `76753bdffb071b3cc77c3b7edad8693910f4682448325d0bbd84db96fc04e16f` |
| SHA3-384 | `1c38123e5777573c1ab0ac9215065cac8fb4af13653a181f21c43096365829f2cf1b0a398f516f43e0565c08c9e85849` |
| IMPHASH | `b34f154ec913d2d2c435cbd644e91687` |
| TLSH | `T14818332DE670765FE6A167BFAC4141DB930E5C57019701AA2C3F74E60E308E8F91DA2B` |
| SSDEEP | `1572864:KejOYf1Wh54eBDoYaInao6duNjPt1a2C2Uh2Qr9xuTJdpdbqK037:K4oh5DBMQadduhF1a2Cfr9ImK037` |
| ICON-DHASH | `b2a89c96a2cada72` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_76753bdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76753bdffb071b3cc77c3b7edad8693910f4682448325d0bbd84db96fc04e16f"
    family = "unknown"
    file_name = "Offmeta.exe"
    file_type = "exe"
    first_seen = "2026-09-18 00:49:36"
  condition:
    hash.sha256(0, filesize) == "76753bdffb071b3cc77c3b7edad8693910f4682448325d0bbd84db96fc04e16f"
}
```

### Sample 80: `7e383b920652b95b`

| Field | Value |
|---|---|
| SHA-256 | `7e383b920652b95b476a8021657086cb1dd01204d1f5771b5e010e4150827c08` |
| Family label | `unknown` |
| File name | `Boostraptl_v72.5.944.exe` |
| File type | `exe` |
| First seen | `2026-09-18 00:47:43` |
| Reporter | `NyxIndius` |
| Tags | `exe, golang, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2af6c08adc887c602f2799dd06769310` |
| SHA-1 | `af5ab20fed25a7a8b8eaef8cabb4153031737d9f` |
| SHA-256 | `7e383b920652b95b476a8021657086cb1dd01204d1f5771b5e010e4150827c08` |
| SHA3-384 | `3f0665444148cc05a010e5693b23bcaad0e70805a59995e0dc9dc2e769beeb23410d57dd17abe18a88a322d9fa968922` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1D9567E03766818E9E4569A38C1B75293EA25B88CCB3532E32E4175342F3B7D07BF6794` |
| SSDEEP | `49152:I5HVIyIMR8p7tMV5zmcNrjdwHPXQFIQ2cENjhRn/PfqfiCpvL1TKWuuieO6fY5hX:I73MqdmPXYgzyju0OEpW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_7e383b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e383b920652b95b476a8021657086cb1dd01204d1f5771b5e010e4150827c08"
    family = "unknown"
    file_name = "Boostraptl_v72.5.944.exe"
    file_type = "exe"
    first_seen = "2026-09-18 00:47:43"
  condition:
    hash.sha256(0, filesize) == "7e383b920652b95b476a8021657086cb1dd01204d1f5771b5e010e4150827c08"
}
```

### Sample 81: `acea2c08fdeb1e84`

| Field | Value |
|---|---|
| SHA-256 | `acea2c08fdeb1e84ab024b981cddfdb43d8a741ae64f27e69ae857ed755aea3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:38:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8652a758d112815979d679d3909b5e01` |
| SHA-1 | `c3066371d19aec42282437c31ca64547070540ce` |
| SHA-256 | `acea2c08fdeb1e84ab024b981cddfdb43d8a741ae64f27e69ae857ed755aea3e` |
| SHA3-384 | `66c78e7d0493e579f47d6e6e7e560dce4083f754007f1b545ac4b1b970fd4833a4fa8e1bd26341fae32ff5d80081a0e2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17F62C7D6E8921F6DCE8EC0707E51F8786D74729489A569E3D7C18C315EA39D00124EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UVJBgn:fKOe2/7c9sN3zfZR1m+RGc6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_acea2c08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acea2c08fdeb1e84ab024b981cddfdb43d8a741ae64f27e69ae857ed755aea3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:38:50"
  condition:
    hash.sha256(0, filesize) == "acea2c08fdeb1e84ab024b981cddfdb43d8a741ae64f27e69ae857ed755aea3e"
}
```

### Sample 82: `16def544b709273b`

| Field | Value |
|---|---|
| SHA-256 | `16def544b709273b2c6f6bae2f90b5768544ddd8bec10ecdf3bc9fc3bde29c53` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:36:21` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd394ba65cfb8a27f29eb6e44b0fe20b` |
| SHA-1 | `ccd8c30ee8e6cddbeea0ef94cfd0beb319e2170a` |
| SHA-256 | `16def544b709273b2c6f6bae2f90b5768544ddd8bec10ecdf3bc9fc3bde29c53` |
| SHA3-384 | `45c419a5d0e0662293354fa35eefdff05984796028f1babffddf9fe03e43df99d35c7a3bdfaf538a6ec8cedc842cb032` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A262C596E8E21F5CDE4E80703A11F838BDB936D4A6659DF7D7928C2059A38D04034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UP643e:fKOe2/7c9sN3zfZR1m+RGw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_16def544
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16def544b709273b2c6f6bae2f90b5768544ddd8bec10ecdf3bc9fc3bde29c53"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:36:21"
  condition:
    hash.sha256(0, filesize) == "16def544b709273b2c6f6bae2f90b5768544ddd8bec10ecdf3bc9fc3bde29c53"
}
```

### Sample 83: `5d7a5af64d1939c3`

| Field | Value |
|---|---|
| SHA-256 | `5d7a5af64d1939c33baa8569e27a270649776bbd82423259f436af80a0132b95` |
| Family label | `RemusStealer` |
| File name | `Velocity Executor.exe` |
| File type | `exe` |
| First seen | `2026-09-18 00:33:29` |
| Reporter | `NyxIndius` |
| Tags | `exe, golang, RemusStealer, signed, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c94aad39878d0b1a1a78ef31916208f8` |
| SHA-1 | `3e65b521301433f9773ea92ee10d6deb39c00dd5` |
| SHA-256 | `5d7a5af64d1939c33baa8569e27a270649776bbd82423259f436af80a0132b95` |
| SHA3-384 | `56410326a7e9c91bd1e826fa7f0c37dad65de30f90bb082579df53a349d4c3038f0a26ef0ff389d5a90dc28899c08ad9` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T1045649076B6402E9C856C738D57A0262AA74BC0CDF7972E72D51B1702FB67C1B9B8F48` |
| SSDEEP | `49152:2DUfA7T4igC7YR/TtuoyaB9btbjab528ic2nX5lj3lEOnamLjic4zo2HGRh41mMH:ohU37iObr0K9qCMJBQy2p7c` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_083_5d7a5af6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7a5af64d1939c33baa8569e27a270649776bbd82423259f436af80a0132b95"
    family = "RemusStealer"
    file_name = "Velocity Executor.exe"
    file_type = "exe"
    first_seen = "2026-09-18 00:33:29"
  condition:
    hash.sha256(0, filesize) == "5d7a5af64d1939c33baa8569e27a270649776bbd82423259f436af80a0132b95"
}
```

### Sample 84: `a0821fb6aa72d6d7`

| Field | Value |
|---|---|
| SHA-256 | `a0821fb6aa72d6d7d7c2b55010c6418c0d5eb1036a9a775a788f54356738e06d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:31:24` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5faa85465594d7ed3304d83e2f020bc` |
| SHA-1 | `3cc72a701d2e9701b5e26681d204542c5a3c556c` |
| SHA-256 | `a0821fb6aa72d6d7d7c2b55010c6418c0d5eb1036a9a775a788f54356738e06d` |
| SHA3-384 | `e78d79f636708c1a454e59e99a58a8174f5b917dee96b178b5bc94413e21e5fface52b38e77feb41b22ce111a5d69b6d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16F62A78ADCB22F5CCE4E80B03A12FC6C69B576A4866699F3D7828D315D679D00434EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UM+Bgn:fKOe2/7c9sN3zfZR1m+RGj+6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_a0821fb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0821fb6aa72d6d7d7c2b55010c6418c0d5eb1036a9a775a788f54356738e06d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:31:24"
  condition:
    hash.sha256(0, filesize) == "a0821fb6aa72d6d7d7c2b55010c6418c0d5eb1036a9a775a788f54356738e06d"
}
```

### Sample 85: `bd244d809b1adb13`

| Field | Value |
|---|---|
| SHA-256 | `bd244d809b1adb130f75e2d167642e63e5669683b2e276e46a4ff0236552f3af` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:30:52` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5728f99beeb74b7b4046f73ffa343b21` |
| SHA-1 | `cde210c41b70a3395679da5b5f22380382c3815b` |
| SHA-256 | `bd244d809b1adb130f75e2d167642e63e5669683b2e276e46a4ff0236552f3af` |
| SHA3-384 | `b62b51faf0ef0bb3eb9bdd3bc6c37a3d194e60510cdf37210c5cfb5638daf2b456e4454e8fbd9e10c1979dcf713d4536` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E762D78BD8D25F5CCE4E80703E11FC28A97936E49AA569E3D7A28C305DA3CD14124EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uj8Bgn:fKOe2/7c9sN3zfZR1m+RGO86C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_bd244d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd244d809b1adb130f75e2d167642e63e5669683b2e276e46a4ff0236552f3af"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:30:52"
  condition:
    hash.sha256(0, filesize) == "bd244d809b1adb130f75e2d167642e63e5669683b2e276e46a4ff0236552f3af"
}
```

### Sample 86: `92161fd217f9c765`

| Field | Value |
|---|---|
| SHA-256 | `92161fd217f9c765c955caedd74d478cf0f163db3ce8c804099ef91f2db7c4e9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:28:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7eb0a4316053549ae591f3654fe20d4c` |
| SHA-1 | `9f01d6496df7c8f29e7e0db869e977bf22250edb` |
| SHA-256 | `92161fd217f9c765c955caedd74d478cf0f163db3ce8c804099ef91f2db7c4e9` |
| SHA3-384 | `4745d2cfba37c2a9898da61ea1b138c6ebbf3a4159d46b3877920c38968fb0cc04d67bba2b014679d370ad68762679d2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17062D78AD9A29E5CCE8E80703B11F93CBDB0369086655DE7D7828C345EA39D04434FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UeFBgn:fKOe2/7c9sN3zfZR1m+RGF6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_92161fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92161fd217f9c765c955caedd74d478cf0f163db3ce8c804099ef91f2db7c4e9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:28:30"
  condition:
    hash.sha256(0, filesize) == "92161fd217f9c765c955caedd74d478cf0f163db3ce8c804099ef91f2db7c4e9"
}
```

### Sample 87: `bbd9b532605bbf6f`

| Field | Value |
|---|---|
| SHA-256 | `bbd9b532605bbf6fa55a23d2d4e452bec5a58b8a1e830ac9e5e6c8fdea256ddc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:26:03` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae382c1d94883b71524b431ccd8bf19d` |
| SHA-1 | `bc2287e425647b8d56f90b74bfc7140fc9903d94` |
| SHA-256 | `bbd9b532605bbf6fa55a23d2d4e452bec5a58b8a1e830ac9e5e6c8fdea256ddc` |
| SHA3-384 | `2a4292ac46dec2677975100dfe63d7d9f4eab4e85f2fbb85ce547c2c6db4979d983bf9932125081458dd7353ba024db2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1DF62B58AD8A22F5CCE4E90703A11F97DAD78769086656DE3D7828C355DB39D00838FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UZBgCc:fKOe2/7c9sN3zfZR1m+RGG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_bbd9b532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd9b532605bbf6fa55a23d2d4e452bec5a58b8a1e830ac9e5e6c8fdea256ddc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:26:03"
  condition:
    hash.sha256(0, filesize) == "bbd9b532605bbf6fa55a23d2d4e452bec5a58b8a1e830ac9e5e6c8fdea256ddc"
}
```

### Sample 88: `e08b76509c1bc5f3`

| Field | Value |
|---|---|
| SHA-256 | `e08b76509c1bc5f335514d60b800cdc377628580926f1706182e9365ce101acc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:25:24` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `367fb5138fa3f33f37090d425e097d14` |
| SHA-1 | `e9818d67ad90c67f25bfc5b0f80b2bc5bea1da8c` |
| SHA-256 | `e08b76509c1bc5f335514d60b800cdc377628580926f1706182e9365ce101acc` |
| SHA3-384 | `b3ca7b427a504a2cc29737b1eecc5cbbe63f53e66fc4c7bffdfb9fb4c51ab57431e8d0681593de487dd988cc694527c9` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E962E686D9E22F6CCE4F80703A11F978BE753290966959E3C7928C345DA39D00025FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UMBBgn:fKOe2/7c9sN3zfZR1m+RGXB6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_e08b7650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e08b76509c1bc5f335514d60b800cdc377628580926f1706182e9365ce101acc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:25:24"
  condition:
    hash.sha256(0, filesize) == "e08b76509c1bc5f335514d60b800cdc377628580926f1706182e9365ce101acc"
}
```

### Sample 89: `77a084844c142fe4`

| Field | Value |
|---|---|
| SHA-256 | `77a084844c142fe493a266eb5436463a58372c349618dc4d47d4974d81ae60b0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:25:20` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e527a147adc2d3700e52994ee842cbd5` |
| SHA-1 | `b01fb653593d4341aaeb70b6eed326922271f851` |
| SHA-256 | `77a084844c142fe493a266eb5436463a58372c349618dc4d47d4974d81ae60b0` |
| SHA3-384 | `3a79a7c8a296429b88c31c39f9078a2b581f747a4b46745c09ca9324a5e6aecc9879e0eff407b0ab3fd3378df74db403` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17162C88AE8A21F5DEE4E80703F11F878ADB436D08A65A9E3D7828C3159679D04474FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46URBgCc:fKOe2/7c9sN3zfZR1m+RGq6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_77a08484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a084844c142fe493a266eb5436463a58372c349618dc4d47d4974d81ae60b0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:25:20"
  condition:
    hash.sha256(0, filesize) == "77a084844c142fe493a266eb5436463a58372c349618dc4d47d4974d81ae60b0"
}
```

### Sample 90: `3d092dbefd730679`

| Field | Value |
|---|---|
| SHA-256 | `3d092dbefd730679b28eba8d0fa5e480d6a17acae9dd082c61827af393e59c54` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-18 00:22:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ef210d019b47dc40a9719003e373bf4` |
| SHA-1 | `c511716a4037d790a26f8fb2d9431a98d3d6de08` |
| SHA-256 | `3d092dbefd730679b28eba8d0fa5e480d6a17acae9dd082c61827af393e59c54` |
| SHA3-384 | `213dd8f37c9ffea02de00644ef01124220abea9c8a685b9a63310dc81dbb70dad84660f79dbfbd63fa6ec4a31233db65` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C462B68AE8D25EACDE4F90703B21F8B869703291D95959E7D7828C205EB39D10024FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UVFtS8:fKOe2/7c9sN3zfZR1m+RGUs16C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_3d092dbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d092dbefd730679b28eba8d0fa5e480d6a17acae9dd082c61827af393e59c54"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:22:50"
  condition:
    hash.sha256(0, filesize) == "3d092dbefd730679b28eba8d0fa5e480d6a17acae9dd082c61827af393e59c54"
}
```

### Sample 91: `ab5fa95c81e6e464`

| Field | Value |
|---|---|
| SHA-256 | `ab5fa95c81e6e464ff673cf7eb4d22d1e0d51ee77b6a23a67b353d91f3ec17a7` |
| Family label | `unknown` |
| File name | `mod.jar` |
| File type | `jar` |
| First seen | `2026-09-18 00:22:13` |
| Reporter | `GhostTypes` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19f5f88ecd47c940729aaa7067ec452c` |
| SHA-1 | `785a82c71467e17efa70e74edf4aa8f924dcfbe8` |
| SHA-256 | `ab5fa95c81e6e464ff673cf7eb4d22d1e0d51ee77b6a23a67b353d91f3ec17a7` |
| SHA3-384 | `a8d1db1b64c17e23acb1fcf918b360ff0280e08fdb91f27bed92aa4fd47de5fd4750c01791e9523ec61ebfc7333fb336` |
| TLSH | `T1877423794A45A0EEFED5D27303C85F57E3C28BD50B5F20E1161E2E8E42BDB6CA2D4854` |
| SSDEEP | `6144:X3CLmuPwDizmySHr6jTHZV7veAwxzx1Qnvokso010piDN7IzxnOWjFLbQ4Oh//F8:4muYDhHe/nbTwxd+nwkN010pI7IzNJ5x` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_ab5fa95c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab5fa95c81e6e464ff673cf7eb4d22d1e0d51ee77b6a23a67b353d91f3ec17a7"
    family = "unknown"
    file_name = "mod.jar"
    file_type = "jar"
    first_seen = "2026-09-18 00:22:13"
  condition:
    hash.sha256(0, filesize) == "ab5fa95c81e6e464ff673cf7eb4d22d1e0d51ee77b6a23a67b353d91f3ec17a7"
}
```

### Sample 92: `75c3b612e533e9d4`

| Field | Value |
|---|---|
| SHA-256 | `75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af` |
| Family label | `Mirai` |
| File name | `75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af` |
| File type | `elf` |
| First seen | `2026-09-18 00:18:25` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5949e9b0d2db9dd6ed2a13d18ec0322a` |
| SHA-1 | `5b79878a1d1cd0ee6ddec9844f44887b6ac154a0` |
| SHA-256 | `75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af` |
| SHA3-384 | `0b61fc00f2dbcb2dae8504bdb41f3a2d092c3a81ddf44416b3a9862e97b66ed2ab9a2a46ef392cb221900a3f2fd0a925` |
| TLSH | `T153A30221D3230D4AC4353CFEBA26E7152D862E69248A415D49F5E9B74FB708CE9F5322` |
| SSDEEP | `1536:XtBTX941eYF8NblpuvnwanQ3zWYq40LZ51g6DobtaeSGPKNkJt6Z2wFZw4DxN:biMYFJvw6Yh0b1gKobtCGCmCRlN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_75c3b612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af"
    family = "Mirai"
    file_name = "75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af"
    file_type = "elf"
    first_seen = "2026-09-18 00:18:25"
  condition:
    hash.sha256(0, filesize) == "75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af"
}
```

### Sample 93: `e0b9f7ed09792f94`

| Field | Value |
|---|---|
| SHA-256 | `e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501` |
| Family label | `unknown` |
| File name | `e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501` |
| File type | `elf` |
| First seen | `2026-09-18 00:18:20` |
| Reporter | `aLittleBitGrey` |
| Tags | `cowrie, elf, honeypot, mips` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d764750cbd8f125f4ee4b05e57390ed6` |
| SHA-1 | `db951e75922ed6c58615cbc7fefc6e01a098cca3` |
| SHA-256 | `e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501` |
| SHA3-384 | `6e79f66078292f2790da7060c855543cf090d57c6218f40e585f64fc2ca97c3d357fb518ceabab8607f628cbc7ed631f` |
| TLSH | `T1BCB3124EFF319C1B9F5019B316DA5E8E9C6D7BAB01DBB4A869C2C14F47A00CE7D52218` |
| SSDEEP | `1536:pxpJNlEYvXndUt/afLuZmVelu9eoCtcCCzNbC4RWC0CQFW3RLlNCzgb0OmfPn+Vj:phNlHuBafLeBtfCzpta8xlBIOdVo3/4H` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_e0b9f7ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501"
    family = "unknown"
    file_name = "e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501"
    file_type = "elf"
    first_seen = "2026-09-18 00:18:20"
  condition:
    hash.sha256(0, filesize) == "e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501"
}
```

### Sample 94: `61ff97114baf276c`

| Field | Value |
|---|---|
| SHA-256 | `61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9` |
| Family label | `Mirai` |
| File name | `61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9` |
| File type | `elf` |
| First seen | `2026-09-18 00:18:14` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f059dc979105c8604067425e1ab8b9e9` |
| SHA-1 | `9cbe4989d987344fcb0c7552b446e3e0e7bdef67` |
| SHA-256 | `61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9` |
| SHA3-384 | `42e8b6dab40b4c9b93b18dc6c156b4639a723be0212f22a9af00aa0c1654cb9912a5b9e7d00b08a545b3e43ee88c20d3` |
| TLSH | `T1D914198AFC81AF5586D127BBFE2E418A331317B8D2EE71129D145F2477CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKq1:T2s/bW+UmJqBxAuaPRhVabEDSDP99zB6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_61ff9711
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9"
    family = "Mirai"
    file_name = "61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9"
    file_type = "elf"
    first_seen = "2026-09-18 00:18:14"
  condition:
    hash.sha256(0, filesize) == "61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9"
}
```

### Sample 95: `36122302ffb5502d`

| Field | Value |
|---|---|
| SHA-256 | `36122302ffb5502ddaccfb01d7c87ca2aacf570e2be41ead200cb17e2ae0f08e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `unknown` |
| First seen | `2026-09-18 00:16:22` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-StealC, worker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fc9ecdd2a43d2cf211917d6d19642ec` |
| SHA-256 | `36122302ffb5502ddaccfb01d7c87ca2aacf570e2be41ead200cb17e2ae0f08e` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_36122302
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36122302ffb5502ddaccfb01d7c87ca2aacf570e2be41ead200cb17e2ae0f08e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-18 00:16:22"
  condition:
    hash.sha256(0, filesize) == "36122302ffb5502ddaccfb01d7c87ca2aacf570e2be41ead200cb17e2ae0f08e"
}
```

### Sample 96: `799a1a163336fe71`

| Field | Value |
|---|---|
| SHA-256 | `799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379` |
| Family label | `Vidar` |
| File name | `799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379.bin` |
| File type | `exe` |
| First seen | `2026-09-18 00:10:45` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd9e8f376fbf650c01598a93872d4993` |
| SHA-1 | `84aaaf46edb3794a6ecc2f12e48ff61e68b3d608` |
| SHA-256 | `799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379` |
| SHA3-384 | `c8fa5ced260d5d2e1ab2a0b228e9126d3e8bed2fe17a608808353ef67174fb9966ea79091b0b7cd515a5c649395babc8` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1A5D65C03B7A852E0C5C5DE34D5AB4327AA287C8DCB3032B36E162EB56F79BD41678750` |
| SSDEEP | `49152:PFdj2yhipiR3d4/W/exkNjFYrYz8caeR01wXRpPigKXKuxJfZLNd9ueu5TVoty4/:8+3d4O/jlREyuxJxLNd9ueu59HIi4` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_096_799a1a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379"
    family = "Vidar"
    file_name = "799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379.bin"
    file_type = "exe"
    first_seen = "2026-09-18 00:10:45"
  condition:
    hash.sha256(0, filesize) == "799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379"
}
```

### Sample 97: `bb235a6362fcfa8c`

| Field | Value |
|---|---|
| SHA-256 | `bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55` |
| Family label | `Vidar` |
| File name | `bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55.bin` |
| File type | `exe` |
| First seen | `2026-09-18 00:10:42` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `364e81db581c349d85b4d3d8dcd7092a` |
| SHA-1 | `89593e25883b3b89441678a249d5d453a55cae72` |
| SHA-256 | `bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55` |
| SHA3-384 | `88318721cef8e793616dd82896e38b7298d0648b9d0bfc42341acb02dd6b9fa795c65370f6d5ee70a7fb4c114f00009b` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T147E65C07660441E8E8A2E37CE07F02B15976FC4CE33136A71E9AB4B47EB6BD565B4B10` |
| SSDEEP | `98304:Edo0dZlVJ+traft3uVovi/qcrF7zRmteJgmjWk:EOkZvg5aft3TK/L71hKfk` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_097_bb235a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55"
    family = "Vidar"
    file_name = "bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55.bin"
    file_type = "exe"
    first_seen = "2026-09-18 00:10:42"
  condition:
    hash.sha256(0, filesize) == "bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55"
}
```

### Sample 98: `dcdf5d22f008a726`

| Field | Value |
|---|---|
| SHA-256 | `dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b` |
| Family label | `unknown` |
| File name | `dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b.bin` |
| File type | `exe` |
| First seen | `2026-09-18 00:10:39` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9cf484f6dd5817ed37b1ef43b2fefaf` |
| SHA-1 | `7909ba29012893512abe9c0fb20aa6f54e956590` |
| SHA-256 | `dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b` |
| SHA3-384 | `d400a395e5e2ac86e62e05c182c74a7e06a9fca1c6c38997d225c48258a68bf7b8a9b36990611398bee6267353b56389` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T16428330BBC5502D8C166DE39857693A2BA74BC45CB3573E72E90A2781F397C25F3AB10` |
| SSDEEP | `1572864:zVpY0SL+njWiyTK6ZLETUmcXE/KcsytcDfnar3FSRlWMrXepeslrwlwXmUeXGTd6:zb8+qiyHL87/K1EcD8IrWMCpesa+U8No` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_dcdf5d22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b"
    family = "unknown"
    file_name = "dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b.bin"
    file_type = "exe"
    first_seen = "2026-09-18 00:10:39"
  condition:
    hash.sha256(0, filesize) == "dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b"
}
```

### Sample 99: `10d34be7098171c1`

| Field | Value |
|---|---|
| SHA-256 | `10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df` |
| Family label | `unknown` |
| File name | `10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df.bin` |
| File type | `unknown` |
| First seen | `2026-09-18 00:08:45` |
| Reporter | `Birdo` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `809484f32334bd9fbe1ac0bad9fba597` |
| SHA-256 | `10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_10d34be7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df"
    family = "unknown"
    file_name = "10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df.bin"
    file_type = "unknown"
    first_seen = "2026-09-18 00:08:45"
  condition:
    hash.sha256(0, filesize) == "10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df"
}
```

### Sample 100: `3a37758233921a30`

| Field | Value |
|---|---|
| SHA-256 | `3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b` |
| Family label | `Gafgyt` |
| File name | `p-p.c-.Sakura` |
| File type | `elf` |
| First seen | `2026-09-17 23:46:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d03a8db5507dfff3538bc0711c3d45d1` |
| SHA-1 | `e4ed96feaa991da51e0923382082a1e6d22edef1` |
| SHA-256 | `3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b` |
| SHA3-384 | `0d8850f08b93938a0f14cd26cd7d32800ea1c8c3693752ae5aa6c4b074fd7ee4309cc05860be0ac85368b02ab2d22005` |
| TLSH | `T169C30A44F941872BC2E327BAE78E438D3B315A9497DB332569386EF42FC17982D29530` |
| TELFHASH | `t1b3210d0371faca292bb356346cb842f112956a233391be71bf1dc4c494370027974ecb` |
| SSDEEP | `3072:0mTe1c/r2e7rC8fVjhin3b0BPz5bNmbAAQVhPRtXJfo:j/r2e7rjfjinGrmbAAQVhPRtXJfo` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_100_3a377582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b"
    family = "Gafgyt"
    file_name = "p-p.c-.Sakura"
    file_type = "elf"
    first_seen = "2026-09-17 23:46:04"
  condition:
    hash.sha256(0, filesize) == "3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b"
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
 * Generated: 2026-09-18T04:52:00.115860+00:00
 */

rule MalwareBazaar_unknown_001_163a8f4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "163a8f4faf9361239e3ef1a5ddfaa28ff48afd5b9c5b4c17ffd92fa5c40b99e6"
    family = "unknown"
    file_name = "s"
    file_type = "unknown"
    first_seen = "2026-09-18 04:45:31"
  condition:
    hash.sha256(0, filesize) == "163a8f4faf9361239e3ef1a5ddfaa28ff48afd5b9c5b4c17ffd92fa5c40b99e6"
}

rule MalwareBazaar_JOMANGY_002_e0d4a52b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0d4a52ba2159d4f8b9d4f95445f8431f30efae4dde32bf3be368ab9e1fd1333"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-18 04:33:16"
  condition:
    hash.sha256(0, filesize) == "e0d4a52ba2159d4f8b9d4f95445f8431f30efae4dde32bf3be368ab9e1fd1333"
}

rule MalwareBazaar_unknown_003_28f89ed4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28f89ed48119891e87c240e6238dec07c145fed79febe419d074b072e980c8bd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:32:44"
  condition:
    hash.sha256(0, filesize) == "28f89ed48119891e87c240e6238dec07c145fed79febe419d074b072e980c8bd"
}

rule MalwareBazaar_unknown_004_ea600bdd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea600bdda77ebeaa723eeecbe72babb251e3a9968eaa7fbf85d366deb7b50d03"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:29:41"
  condition:
    hash.sha256(0, filesize) == "ea600bdda77ebeaa723eeecbe72babb251e3a9968eaa7fbf85d366deb7b50d03"
}

rule MalwareBazaar_unknown_005_30efde11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30efde1102c5199625e7c652dbebecf7e20d15fbb47c5863437871a94871e794"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:27:19"
  condition:
    hash.sha256(0, filesize) == "30efde1102c5199625e7c652dbebecf7e20d15fbb47c5863437871a94871e794"
}

rule MalwareBazaar_unknown_006_0c3dc440
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c3dc4409a00ea240ed1a884e27cb7d38cc30524b7d7c1319121916cfa6a1d73"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:26:44"
  condition:
    hash.sha256(0, filesize) == "0c3dc4409a00ea240ed1a884e27cb7d38cc30524b7d7c1319121916cfa6a1d73"
}

rule MalwareBazaar_unknown_007_065cb748
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "065cb7480fdecd37d37c4ec2ab0b4e7a9d5c97c33f913d08093270e6e4dd2578"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:20:53"
  condition:
    hash.sha256(0, filesize) == "065cb7480fdecd37d37c4ec2ab0b4e7a9d5c97c33f913d08093270e6e4dd2578"
}

rule MalwareBazaar_unknown_008_afe27e53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75"
    family = "unknown"
    file_name = "afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75"
    file_type = "elf"
    first_seen = "2026-09-18 04:18:47"
  condition:
    hash.sha256(0, filesize) == "afe27e538b4cb2962b6589c8ce081bc27ec53f95707962e2bb7e2fbdbb995d75"
}

rule MalwareBazaar_unknown_009_ee873e43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db"
    family = "unknown"
    file_name = "ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db"
    file_type = "elf"
    first_seen = "2026-09-18 04:18:42"
  condition:
    hash.sha256(0, filesize) == "ee873e439c2bcf2dbadad850e64acd895d231e5d1c8e9e0b6d0ff261e9a407db"
}

rule MalwareBazaar_Mirai_010_72a02173
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d"
    family = "Mirai"
    file_name = "72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d"
    file_type = "elf"
    first_seen = "2026-09-18 04:18:37"
  condition:
    hash.sha256(0, filesize) == "72a021730c042cbd4d557ab0ca3387aa8230a9c026217f51c4c93b75c057287d"
}

rule MalwareBazaar_JOMANGY_011_8e496e71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e496e71da9fde5d3253b19ff8e1f12b82394b4267beee30d712dbe47767b96c"
    family = "JOMANGY"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-09-18 04:15:45"
  condition:
    hash.sha256(0, filesize) == "8e496e71da9fde5d3253b19ff8e1f12b82394b4267beee30d712dbe47767b96c"
}

rule MalwareBazaar_unknown_012_4a74ad41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a74ad41aaf0453cd4f984912c695b7a1b763dee7665580a6900c8f79ff80072"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 04:05:12"
  condition:
    hash.sha256(0, filesize) == "4a74ad41aaf0453cd4f984912c695b7a1b763dee7665580a6900c8f79ff80072"
}

rule MalwareBazaar_JOMANGY_013_09a78eff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09a78eff62566b906a4a41005e1841cee8b43da0d65633c56fb47d8ca6dbd9b9"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-18 04:01:34"
  condition:
    hash.sha256(0, filesize) == "09a78eff62566b906a4a41005e1841cee8b43da0d65633c56fb47d8ca6dbd9b9"
}

rule MalwareBazaar_ConnectWise_014_2f093f8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3"
    family = "ConnectWise"
    file_name = "2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3.msi"
    file_type = "msi"
    first_seen = "2026-09-18 03:58:08"
  condition:
    hash.sha256(0, filesize) == "2f093f8d688bec29b1944ece953d4b60c428388152ddf12d973343750db93aa3"
}

rule MalwareBazaar_unknown_015_1dab32c6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dab32c614e9a97a25f8f04841b4ba9fe780369da1b043871b936e8f3c834891"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:54:00"
  condition:
    hash.sha256(0, filesize) == "1dab32c614e9a97a25f8f04841b4ba9fe780369da1b043871b936e8f3c834891"
}

rule MalwareBazaar_unknown_016_aba4d4dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aba4d4dd7ab62fea1849a1ef348bce68d68ce1f28e3b518436a46b8228940461"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:51:27"
  condition:
    hash.sha256(0, filesize) == "aba4d4dd7ab62fea1849a1ef348bce68d68ce1f28e3b518436a46b8228940461"
}

rule MalwareBazaar_unknown_017_b410d33e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b410d33efc86ced799284522e3bebfe020e00f6203977a055225680b045856b9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:49:01"
  condition:
    hash.sha256(0, filesize) == "b410d33efc86ced799284522e3bebfe020e00f6203977a055225680b045856b9"
}

rule MalwareBazaar_unknown_018_126a096e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126a096e0e6a6c157fec7fe12ec37a93aba07b84118dcb60ec0693baab1deee3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:46:50"
  condition:
    hash.sha256(0, filesize) == "126a096e0e6a6c157fec7fe12ec37a93aba07b84118dcb60ec0693baab1deee3"
}

rule MalwareBazaar_unknown_019_d4cee676
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4cee6760bf8b0420f3e49ac68e1a14f4ab804dbe317873901dcd734ca93f8af"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:44:19"
  condition:
    hash.sha256(0, filesize) == "d4cee6760bf8b0420f3e49ac68e1a14f4ab804dbe317873901dcd734ca93f8af"
}

rule MalwareBazaar_unknown_020_a14fb55d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14fb55db0c9ba8c61603e6935a47f2d6d71c4856981532327eb36aae4b30809"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:42:27"
  condition:
    hash.sha256(0, filesize) == "a14fb55db0c9ba8c61603e6935a47f2d6d71c4856981532327eb36aae4b30809"
}

rule MalwareBazaar_unknown_021_987c42d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "987c42d48e9a78ed2ebc33b4d3b8dd6c1c17d01cd911ff6287fa5d878451b38d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:41:51"
  condition:
    hash.sha256(0, filesize) == "987c42d48e9a78ed2ebc33b4d3b8dd6c1c17d01cd911ff6287fa5d878451b38d"
}

rule MalwareBazaar_unknown_022_cefa3f25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cefa3f258164e6680c6c8f9c728d9dac1a429777f31ed5b2a14e39d6c9329e0f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:40:03"
  condition:
    hash.sha256(0, filesize) == "cefa3f258164e6680c6c8f9c728d9dac1a429777f31ed5b2a14e39d6c9329e0f"
}

rule MalwareBazaar_unknown_023_70c2fa84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70c2fa845ac0791b6281ef1107e9f0c6bc33c582e8c36087f8d3e921ad8ac772"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:19:16"
  condition:
    hash.sha256(0, filesize) == "70c2fa845ac0791b6281ef1107e9f0c6bc33c582e8c36087f8d3e921ad8ac772"
}

rule MalwareBazaar_unknown_024_8ec88910
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77"
    family = "unknown"
    file_name = "8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77"
    file_type = "elf"
    first_seen = "2026-09-18 03:17:23"
  condition:
    hash.sha256(0, filesize) == "8ec88910ab11d3a2e7ed3a9aa1e111d503ddfc5e77065a41383936f015ea6f77"
}

rule MalwareBazaar_unknown_025_59653f10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03"
    family = "unknown"
    file_name = "59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03"
    file_type = "elf"
    first_seen = "2026-09-18 03:17:18"
  condition:
    hash.sha256(0, filesize) == "59653f10e35db9aa30f0a720a05c3c0da79511da422cec85be558b1d223e8a03"
}

rule MalwareBazaar_Mirai_026_54c7c2a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8"
    family = "Mirai"
    file_name = "54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8"
    file_type = "elf"
    first_seen = "2026-09-18 03:17:12"
  condition:
    hash.sha256(0, filesize) == "54c7c2a37cc2bd52274855235cf84d9cbc4a5e4b8d5cfdc1dbd07f9b38bb33f8"
}

rule MalwareBazaar_unknown_027_bcd1d32f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bcd1d32f1f89f3fd6a107874fe525c8536509f993921948c929ae24aeb870054"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:16:40"
  condition:
    hash.sha256(0, filesize) == "bcd1d32f1f89f3fd6a107874fe525c8536509f993921948c929ae24aeb870054"
}

rule MalwareBazaar_unknown_028_14f2f026
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14f2f0266e4f480e2a38bb3f5ac46fe9f3662a07c59a499378527b348cd40019"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:14:59"
  condition:
    hash.sha256(0, filesize) == "14f2f0266e4f480e2a38bb3f5ac46fe9f3662a07c59a499378527b348cd40019"
}

rule MalwareBazaar_unknown_029_ba9f20f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba9f20f074d5385224db8f0c114147a21cee9a8c327223230c97cf80b262f505"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:14:23"
  condition:
    hash.sha256(0, filesize) == "ba9f20f074d5385224db8f0c114147a21cee9a8c327223230c97cf80b262f505"
}

rule MalwareBazaar_unknown_030_ea7010ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea7010ab863c15d2690780a5b2c8052b7cd654000d5a714f12c7d5b97440dae0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:12:39"
  condition:
    hash.sha256(0, filesize) == "ea7010ab863c15d2690780a5b2c8052b7cd654000d5a714f12c7d5b97440dae0"
}

rule MalwareBazaar_FleetDeck_031_cecc81f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cecc81f8830b3ca7b39a967be79e16bdccc113f2bde6e40f0a235e67e7e6af22"
    family = "FleetDeck"
    file_name = "adobe-updater-003.exe"
    file_type = "exe"
    first_seen = "2026-09-18 03:12:16"
  condition:
    hash.sha256(0, filesize) == "cecc81f8830b3ca7b39a967be79e16bdccc113f2bde6e40f0a235e67e7e6af22"
}

rule MalwareBazaar_unknown_032_365583e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "365583e0613b4e68379d2a3e897b6e01d681184335fcdbc6c980e7357ecf04bf"
    family = "unknown"
    file_name = "20260914113129-CEF7FAF6EF7E12 (1).iso"
    file_type = "iso"
    first_seen = "2026-09-18 03:11:49"
  condition:
    hash.sha256(0, filesize) == "365583e0613b4e68379d2a3e897b6e01d681184335fcdbc6c980e7357ecf04bf"
}

rule MalwareBazaar_unknown_033_525d2699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "525d26995e33a51239499d755f02a84a01e5ec662d564336952012693da4949b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:10:22"
  condition:
    hash.sha256(0, filesize) == "525d26995e33a51239499d755f02a84a01e5ec662d564336952012693da4949b"
}

rule MalwareBazaar_unknown_034_6b74f08a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b74f08a084510ecc7862fc3ff26b6f02209933be2239bbbe279dab2536d0421"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 03:07:58"
  condition:
    hash.sha256(0, filesize) == "6b74f08a084510ecc7862fc3ff26b6f02209933be2239bbbe279dab2536d0421"
}

rule MalwareBazaar_unknown_035_e9e328bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9e328bdef27c1cfea4939140024f87ca909541222bf0d2ed1f56019295b764b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:58:46"
  condition:
    hash.sha256(0, filesize) == "e9e328bdef27c1cfea4939140024f87ca909541222bf0d2ed1f56019295b764b"
}

rule MalwareBazaar_unknown_036_cc922fb8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc922fb8fe4d86f2cf1f3cfea0e45fbed8f5982c5a7ba26405d3ad6b5af2a7c0"
    family = "unknown"
    file_name = "stage1_cc922fb8fe4d.zsh"
    file_type = "unknown"
    first_seen = "2026-09-18 02:35:23"
  condition:
    hash.sha256(0, filesize) == "cc922fb8fe4d86f2cf1f3cfea0e45fbed8f5982c5a7ba26405d3ad6b5af2a7c0"
}

rule MalwareBazaar_unknown_037_f3b6962c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3b6962c49b361c63fe9d0af9a83e10a52133360117e4c8ac68272160a60edac"
    family = "unknown"
    file_name = "macho_f3b6962c49b3.bin"
    file_type = "macho"
    first_seen = "2026-09-18 02:35:19"
  condition:
    hash.sha256(0, filesize) == "f3b6962c49b361c63fe9d0af9a83e10a52133360117e4c8ac68272160a60edac"
}

rule MalwareBazaar_unknown_038_13df107e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13df107e0549aaa781f0bd23cf64dedeefad302e479ab8b91212e4d84629c5ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:32:01"
  condition:
    hash.sha256(0, filesize) == "13df107e0549aaa781f0bd23cf64dedeefad302e479ab8b91212e4d84629c5ec"
}

rule MalwareBazaar_unknown_039_b9fcea96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b9fcea96ad78d54d4b937c08518064b66866763f23000bbdbd8c383b16e6e461"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:31:02"
  condition:
    hash.sha256(0, filesize) == "b9fcea96ad78d54d4b937c08518064b66866763f23000bbdbd8c383b16e6e461"
}

rule MalwareBazaar_unknown_040_bbbcf6bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbbcf6bb205f7e65744c08ba2fd237f390f0fe07790b3bcea8eba13d4a577f67"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:29:35"
  condition:
    hash.sha256(0, filesize) == "bbbcf6bb205f7e65744c08ba2fd237f390f0fe07790b3bcea8eba13d4a577f67"
}

rule MalwareBazaar_unknown_041_32d160e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32d160e6f6c628b3abf63646826f563590fe09d55b6519d4fc527f8817f5666a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:28:36"
  condition:
    hash.sha256(0, filesize) == "32d160e6f6c628b3abf63646826f563590fe09d55b6519d4fc527f8817f5666a"
}

rule MalwareBazaar_unknown_042_e433b614
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e433b61491ac9db00a0701863ff678bc010d8e380ce09f20034f80df02e301b8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:27:07"
  condition:
    hash.sha256(0, filesize) == "e433b61491ac9db00a0701863ff678bc010d8e380ce09f20034f80df02e301b8"
}

rule MalwareBazaar_unknown_043_e29932e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e29932e6656a0a80456a84fe90b3622cf9d66e66fca86cfe8c06dccd830ad2b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:26:17"
  condition:
    hash.sha256(0, filesize) == "e29932e6656a0a80456a84fe90b3622cf9d66e66fca86cfe8c06dccd830ad2b2"
}

rule MalwareBazaar_unknown_044_25adb484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25adb48419bdf28da15fa043c5c2473ffade5853e0efa7922165ff18614fd527"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:23:39"
  condition:
    hash.sha256(0, filesize) == "25adb48419bdf28da15fa043c5c2473ffade5853e0efa7922165ff18614fd527"
}

rule MalwareBazaar_unknown_045_8b7ec973
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef"
    family = "unknown"
    file_name = "8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef"
    file_type = "elf"
    first_seen = "2026-09-18 02:18:49"
  condition:
    hash.sha256(0, filesize) == "8b7ec973dc5f5b1123c0ffaea513f54727120b86baf70871380b59871dfa60ef"
}

rule MalwareBazaar_Mirai_046_39e38e0e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b"
    family = "Mirai"
    file_name = "39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b"
    file_type = "elf"
    first_seen = "2026-09-18 02:18:43"
  condition:
    hash.sha256(0, filesize) == "39e38e0e5365d490cd105e5e814aa9af6503f8ebf90c6cfa24fb43ad77b2431b"
}

rule MalwareBazaar_unknown_047_4b4ad532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b4ad532ad81d4c07f7de4b68007c7f569b972515b61304037feef29c06b2a22"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:16:41"
  condition:
    hash.sha256(0, filesize) == "4b4ad532ad81d4c07f7de4b68007c7f569b972515b61304037feef29c06b2a22"
}

rule MalwareBazaar_unknown_048_3a2d59a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2d59a1f90b7a74d2d358266e88e21c148f2c2979eabbeb64d23569e887545e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:14:08"
  condition:
    hash.sha256(0, filesize) == "3a2d59a1f90b7a74d2d358266e88e21c148f2c2979eabbeb64d23569e887545e"
}

rule MalwareBazaar_unknown_049_c556be82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c556be826963de2d9c75ef07cb15cdd54c8ae081cd23699b38c53a6eb93df89e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:11:39"
  condition:
    hash.sha256(0, filesize) == "c556be826963de2d9c75ef07cb15cdd54c8ae081cd23699b38c53a6eb93df89e"
}

rule MalwareBazaar_unknown_050_dd9d8526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd9d85265cc6ebcd449731ca971d37bafd6382c41ceeea083bdbb00e693122e4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:02:48"
  condition:
    hash.sha256(0, filesize) == "dd9d85265cc6ebcd449731ca971d37bafd6382c41ceeea083bdbb00e693122e4"
}

rule MalwareBazaar_JOMANGY_051_ad733ae1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad733ae1b12eca7dca5058a99520bbb179548d61cadb7ac87c5d76c9c2a4ff71"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-18 02:02:42"
  condition:
    hash.sha256(0, filesize) == "ad733ae1b12eca7dca5058a99520bbb179548d61cadb7ac87c5d76c9c2a4ff71"
}

rule MalwareBazaar_unknown_052_990d9914
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "990d9914843669dbf47e67b57456d5b81e9639f561b4c21f2ec74906840ec7a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:02:26"
  condition:
    hash.sha256(0, filesize) == "990d9914843669dbf47e67b57456d5b81e9639f561b4c21f2ec74906840ec7a4"
}

rule MalwareBazaar_unknown_053_08877bbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08877bbceb3707d89a0a1945ab86b46d35cc4418a667e07e3405fe8031c49e58"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:01:38"
  condition:
    hash.sha256(0, filesize) == "08877bbceb3707d89a0a1945ab86b46d35cc4418a667e07e3405fe8031c49e58"
}

rule MalwareBazaar_unknown_054_61a36d4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61a36d4ff07091d061ed569eef0fad3e4ca16b6fbde7d687a73ece2beb6389b4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:00:12"
  condition:
    hash.sha256(0, filesize) == "61a36d4ff07091d061ed569eef0fad3e4ca16b6fbde7d687a73ece2beb6389b4"
}

rule MalwareBazaar_unknown_055_2b7d1106
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2b7d1106e7f8c2d0bd11dc879e7fe585d040b8f095f08bc43159bc679a0000d0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 02:00:03"
  condition:
    hash.sha256(0, filesize) == "2b7d1106e7f8c2d0bd11dc879e7fe585d040b8f095f08bc43159bc679a0000d0"
}

rule MalwareBazaar_unknown_056_b07c47d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b07c47d2ff7ac6425434b6a9ba200823b9a104a4f614c3b5326528d4b0d8c221"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:58:19"
  condition:
    hash.sha256(0, filesize) == "b07c47d2ff7ac6425434b6a9ba200823b9a104a4f614c3b5326528d4b0d8c221"
}

rule MalwareBazaar_unknown_057_19334979
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19334979afe2d89b6a494f25af129048de7c228cda2f266b4356da20ae7b4d5c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:57:47"
  condition:
    hash.sha256(0, filesize) == "19334979afe2d89b6a494f25af129048de7c228cda2f266b4356da20ae7b4d5c"
}

rule MalwareBazaar_unknown_058_d4137be5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4137be5ad4d79301a66b4e756ec8c0f8cb481e016e5c3075dcdac5096691ba4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:57:35"
  condition:
    hash.sha256(0, filesize) == "d4137be5ad4d79301a66b4e756ec8c0f8cb481e016e5c3075dcdac5096691ba4"
}

rule MalwareBazaar_unknown_059_0e8aa7f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e8aa7f4ea5020141b57f52438bcaf8e46c004e38b7a7de1f8527e8cdfb937bd"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:46:48"
  condition:
    hash.sha256(0, filesize) == "0e8aa7f4ea5020141b57f52438bcaf8e46c004e38b7a7de1f8527e8cdfb937bd"
}

rule MalwareBazaar_unknown_060_72e4b18a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72e4b18a842191ce7087bed05fc4106364f99280c4e7c27859e11e79f9781963"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:44:24"
  condition:
    hash.sha256(0, filesize) == "72e4b18a842191ce7087bed05fc4106364f99280c4e7c27859e11e79f9781963"
}

rule MalwareBazaar_unknown_061_4f375117
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f375117095db078e4fa3828bbfb82e686f69574ee8802a4b1daab9e7e031dd2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:31:41"
  condition:
    hash.sha256(0, filesize) == "4f375117095db078e4fa3828bbfb82e686f69574ee8802a4b1daab9e7e031dd2"
}

rule MalwareBazaar_unknown_062_dddef12b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dddef12b126dc995cba706ca84c3f0f79ec1eacc61a5fc05ab0b564cadc76e3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:27:40"
  condition:
    hash.sha256(0, filesize) == "dddef12b126dc995cba706ca84c3f0f79ec1eacc61a5fc05ab0b564cadc76e3e"
}

rule MalwareBazaar_unknown_063_9b7382cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b7382cf25d7d7459166276de94c21439eb0dae47babaf08b7f6115b1e5fc8b7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:25:15"
  condition:
    hash.sha256(0, filesize) == "9b7382cf25d7d7459166276de94c21439eb0dae47babaf08b7f6115b1e5fc8b7"
}

rule MalwareBazaar_unknown_064_c3df8dfb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3df8dfb912fc17fb564a11c918a4ca19c36d2b7df0efb8efb76e6851699352c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:21:13"
  condition:
    hash.sha256(0, filesize) == "c3df8dfb912fc17fb564a11c918a4ca19c36d2b7df0efb8efb76e6851699352c"
}

rule MalwareBazaar_unknown_065_2d176f7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5"
    family = "unknown"
    file_name = "2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:46"
  condition:
    hash.sha256(0, filesize) == "2d176f7c7efa92ec6abb362deb95cb25fa857394c7e08f48a3d3c3dae488d7d5"
}

rule MalwareBazaar_unknown_066_798f7201
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2"
    family = "unknown"
    file_name = "798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:41"
  condition:
    hash.sha256(0, filesize) == "798f72019b2b81afe2d797e6b33cf3422c8227ba5908a54b58a75791a1be32f2"
}

rule MalwareBazaar_unknown_067_9b36220e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40"
    family = "unknown"
    file_name = "9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:35"
  condition:
    hash.sha256(0, filesize) == "9b36220ec911778359a9cd5cfe13e3798f67bdaf93da307dff4a443ea6e1cb40"
}

rule MalwareBazaar_unknown_068_47247191
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0"
    family = "unknown"
    file_name = "47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:30"
  condition:
    hash.sha256(0, filesize) == "47247191db3a3c7128582d8228f6545045f16d46a32e0a39a65fb933e4229dc0"
}

rule MalwareBazaar_Mirai_069_1bf75653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d"
    family = "Mirai"
    file_name = "1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d"
    file_type = "elf"
    first_seen = "2026-09-18 01:19:25"
  condition:
    hash.sha256(0, filesize) == "1bf756538fa9bffc9ddef216959184bea242d1ebbefa3dad78bacf48c92f999d"
}

rule MalwareBazaar_unknown_070_e696334a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e696334a71375d10625a19fd8ceb269c5503db069d0ff0ac8d9c5854ffa2bbfc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:18:57"
  condition:
    hash.sha256(0, filesize) == "e696334a71375d10625a19fd8ceb269c5503db069d0ff0ac8d9c5854ffa2bbfc"
}

rule MalwareBazaar_unknown_071_144e1a62
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "144e1a620a7d257e7b17ae16da658d015ebca4336dc603d67e0f2c80f9cdafcd"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-18 01:16:36"
  condition:
    hash.sha256(0, filesize) == "144e1a620a7d257e7b17ae16da658d015ebca4336dc603d67e0f2c80f9cdafcd"
}

rule MalwareBazaar_unknown_072_f190633e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f190633ec16ecb1f0f070c26f258a278d51bb86842dbe0f75c00d0ff0f178300"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:16:22"
  condition:
    hash.sha256(0, filesize) == "f190633ec16ecb1f0f070c26f258a278d51bb86842dbe0f75c00d0ff0f178300"
}

rule MalwareBazaar_unknown_073_021d369e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "021d369e929769603851acade92af051024192b69a28dca96569a4327449a005"
    family = "unknown"
    file_name = "Kohzan Maru VI Full Vessel Q88.js"
    file_type = "js"
    first_seen = "2026-09-18 01:14:35"
  condition:
    hash.sha256(0, filesize) == "021d369e929769603851acade92af051024192b69a28dca96569a4327449a005"
}

rule MalwareBazaar_unknown_074_a7487d01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7487d01ab276b2817463cdb4bb8547c0fa0b750d3a123cf770a2db63ba82e00"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:12:49"
  condition:
    hash.sha256(0, filesize) == "a7487d01ab276b2817463cdb4bb8547c0fa0b750d3a123cf770a2db63ba82e00"
}

rule MalwareBazaar_unknown_075_f6aceea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6aceea08cc263030f0f4233076308602239b3cb19527fa3372dfec5b785ddbc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:10:21"
  condition:
    hash.sha256(0, filesize) == "f6aceea08cc263030f0f4233076308602239b3cb19527fa3372dfec5b785ddbc"
}

rule MalwareBazaar_unknown_076_f526c366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f526c366d758781f0185c788e2a6d52780b83bda3c3e5bf9c4c5938a05338685"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:08:41"
  condition:
    hash.sha256(0, filesize) == "f526c366d758781f0185c788e2a6d52780b83bda3c3e5bf9c4c5938a05338685"
}

rule MalwareBazaar_unknown_077_9d0444f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d0444f496a57b73dd27e4c384c89871d0534b0fdd84a3743727013899ff67ee"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:06:04"
  condition:
    hash.sha256(0, filesize) == "9d0444f496a57b73dd27e4c384c89871d0534b0fdd84a3743727013899ff67ee"
}

rule MalwareBazaar_unknown_078_70e6b909
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70e6b909f8850bbfcd0915af762f97eb9315ad11bb9abf77ef0bde400ea09d38"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 01:03:39"
  condition:
    hash.sha256(0, filesize) == "70e6b909f8850bbfcd0915af762f97eb9315ad11bb9abf77ef0bde400ea09d38"
}

rule MalwareBazaar_unknown_079_76753bdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "76753bdffb071b3cc77c3b7edad8693910f4682448325d0bbd84db96fc04e16f"
    family = "unknown"
    file_name = "Offmeta.exe"
    file_type = "exe"
    first_seen = "2026-09-18 00:49:36"
  condition:
    hash.sha256(0, filesize) == "76753bdffb071b3cc77c3b7edad8693910f4682448325d0bbd84db96fc04e16f"
}

rule MalwareBazaar_unknown_080_7e383b92
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e383b920652b95b476a8021657086cb1dd01204d1f5771b5e010e4150827c08"
    family = "unknown"
    file_name = "Boostraptl_v72.5.944.exe"
    file_type = "exe"
    first_seen = "2026-09-18 00:47:43"
  condition:
    hash.sha256(0, filesize) == "7e383b920652b95b476a8021657086cb1dd01204d1f5771b5e010e4150827c08"
}

rule MalwareBazaar_unknown_081_acea2c08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acea2c08fdeb1e84ab024b981cddfdb43d8a741ae64f27e69ae857ed755aea3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:38:50"
  condition:
    hash.sha256(0, filesize) == "acea2c08fdeb1e84ab024b981cddfdb43d8a741ae64f27e69ae857ed755aea3e"
}

rule MalwareBazaar_unknown_082_16def544
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16def544b709273b2c6f6bae2f90b5768544ddd8bec10ecdf3bc9fc3bde29c53"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:36:21"
  condition:
    hash.sha256(0, filesize) == "16def544b709273b2c6f6bae2f90b5768544ddd8bec10ecdf3bc9fc3bde29c53"
}

rule MalwareBazaar_RemusStealer_083_5d7a5af6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d7a5af64d1939c33baa8569e27a270649776bbd82423259f436af80a0132b95"
    family = "RemusStealer"
    file_name = "Velocity Executor.exe"
    file_type = "exe"
    first_seen = "2026-09-18 00:33:29"
  condition:
    hash.sha256(0, filesize) == "5d7a5af64d1939c33baa8569e27a270649776bbd82423259f436af80a0132b95"
}

rule MalwareBazaar_unknown_084_a0821fb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0821fb6aa72d6d7d7c2b55010c6418c0d5eb1036a9a775a788f54356738e06d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:31:24"
  condition:
    hash.sha256(0, filesize) == "a0821fb6aa72d6d7d7c2b55010c6418c0d5eb1036a9a775a788f54356738e06d"
}

rule MalwareBazaar_unknown_085_bd244d80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd244d809b1adb130f75e2d167642e63e5669683b2e276e46a4ff0236552f3af"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:30:52"
  condition:
    hash.sha256(0, filesize) == "bd244d809b1adb130f75e2d167642e63e5669683b2e276e46a4ff0236552f3af"
}

rule MalwareBazaar_unknown_086_92161fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92161fd217f9c765c955caedd74d478cf0f163db3ce8c804099ef91f2db7c4e9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:28:30"
  condition:
    hash.sha256(0, filesize) == "92161fd217f9c765c955caedd74d478cf0f163db3ce8c804099ef91f2db7c4e9"
}

rule MalwareBazaar_unknown_087_bbd9b532
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd9b532605bbf6fa55a23d2d4e452bec5a58b8a1e830ac9e5e6c8fdea256ddc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:26:03"
  condition:
    hash.sha256(0, filesize) == "bbd9b532605bbf6fa55a23d2d4e452bec5a58b8a1e830ac9e5e6c8fdea256ddc"
}

rule MalwareBazaar_unknown_088_e08b7650
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e08b76509c1bc5f335514d60b800cdc377628580926f1706182e9365ce101acc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:25:24"
  condition:
    hash.sha256(0, filesize) == "e08b76509c1bc5f335514d60b800cdc377628580926f1706182e9365ce101acc"
}

rule MalwareBazaar_unknown_089_77a08484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77a084844c142fe493a266eb5436463a58372c349618dc4d47d4974d81ae60b0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:25:20"
  condition:
    hash.sha256(0, filesize) == "77a084844c142fe493a266eb5436463a58372c349618dc4d47d4974d81ae60b0"
}

rule MalwareBazaar_unknown_090_3d092dbe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d092dbefd730679b28eba8d0fa5e480d6a17acae9dd082c61827af393e59c54"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-18 00:22:50"
  condition:
    hash.sha256(0, filesize) == "3d092dbefd730679b28eba8d0fa5e480d6a17acae9dd082c61827af393e59c54"
}

rule MalwareBazaar_unknown_091_ab5fa95c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ab5fa95c81e6e464ff673cf7eb4d22d1e0d51ee77b6a23a67b353d91f3ec17a7"
    family = "unknown"
    file_name = "mod.jar"
    file_type = "jar"
    first_seen = "2026-09-18 00:22:13"
  condition:
    hash.sha256(0, filesize) == "ab5fa95c81e6e464ff673cf7eb4d22d1e0d51ee77b6a23a67b353d91f3ec17a7"
}

rule MalwareBazaar_Mirai_092_75c3b612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af"
    family = "Mirai"
    file_name = "75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af"
    file_type = "elf"
    first_seen = "2026-09-18 00:18:25"
  condition:
    hash.sha256(0, filesize) == "75c3b612e533e9d4b3773398dfe342f71014527385d9a16bff8ac7bc4bb236af"
}

rule MalwareBazaar_unknown_093_e0b9f7ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501"
    family = "unknown"
    file_name = "e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501"
    file_type = "elf"
    first_seen = "2026-09-18 00:18:20"
  condition:
    hash.sha256(0, filesize) == "e0b9f7ed09792f94b2787762fe7e5857b57f177b5f950a88b094bb99445e9501"
}

rule MalwareBazaar_Mirai_094_61ff9711
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9"
    family = "Mirai"
    file_name = "61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9"
    file_type = "elf"
    first_seen = "2026-09-18 00:18:14"
  condition:
    hash.sha256(0, filesize) == "61ff97114baf276c23f2d4ea0bc0847e2c6b08ce17a0f0e62c494ccd3fd2c9a9"
}

rule MalwareBazaar_unknown_095_36122302
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "36122302ffb5502ddaccfb01d7c87ca2aacf570e2be41ead200cb17e2ae0f08e"
    family = "unknown"
    file_name = "file"
    file_type = "unknown"
    first_seen = "2026-09-18 00:16:22"
  condition:
    hash.sha256(0, filesize) == "36122302ffb5502ddaccfb01d7c87ca2aacf570e2be41ead200cb17e2ae0f08e"
}

rule MalwareBazaar_Vidar_096_799a1a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379"
    family = "Vidar"
    file_name = "799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379.bin"
    file_type = "exe"
    first_seen = "2026-09-18 00:10:45"
  condition:
    hash.sha256(0, filesize) == "799a1a163336fe71ae4d743a4e1547b9bf2b7112fbc23dfdaa1f41f5a477b379"
}

rule MalwareBazaar_Vidar_097_bb235a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55"
    family = "Vidar"
    file_name = "bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55.bin"
    file_type = "exe"
    first_seen = "2026-09-18 00:10:42"
  condition:
    hash.sha256(0, filesize) == "bb235a6362fcfa8c29211dd988f114db355a5c5025cdcb21cb26bce82d28cf55"
}

rule MalwareBazaar_unknown_098_dcdf5d22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b"
    family = "unknown"
    file_name = "dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b.bin"
    file_type = "exe"
    first_seen = "2026-09-18 00:10:39"
  condition:
    hash.sha256(0, filesize) == "dcdf5d22f008a72622dd1bebf29dcd0652e58296030bfc274b6331a85d276b2b"
}

rule MalwareBazaar_unknown_099_10d34be7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df"
    family = "unknown"
    file_name = "10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df.bin"
    file_type = "unknown"
    first_seen = "2026-09-18 00:08:45"
  condition:
    hash.sha256(0, filesize) == "10d34be7098171c16e2d7b23a1c567150a9a4e6eb820d8798e12258720f224df"
}

rule MalwareBazaar_Gafgyt_100_3a377582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b"
    family = "Gafgyt"
    file_name = "p-p.c-.Sakura"
    file_type = "elf"
    first_seen = "2026-09-17 23:46:04"
  condition:
    hash.sha256(0, filesize) == "3a37758233921a3022659d0e1dfc62d61c990cd8e787512939dad90bb443203b"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-09-21

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 671 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 671 |
| Unique family labels | 6 |
| Unique file types | 7 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 68 |
| Mirai | 28 |
| JOMANGY | 1 |
| Gafgyt | 1 |
| Formbook | 1 |
| Snowlight | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 60 |
| elf | 32 |
| js | 3 |
| macho | 2 |
| sh | 1 |
| unknown | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `832f4c6ca7b9b61b`

| Field | Value |
|---|---|
| SHA-256 | `832f4c6ca7b9b61b3a8063355c71f96e5b18e1bfd209df3cd3570b55e5144b4f` |
| Family label | `unknown` |
| File name | `BOOKING_CONFIRMATION.js` |
| File type | `js` |
| First seen | `2026-09-21 05:01:52` |
| Reporter | `ppt_lol` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c58bdff2dd06fe997d2ac959c9c2557c` |
| SHA-1 | `2671234f516c6b79f93bd189bd6ac39d2087ee28` |
| SHA-256 | `832f4c6ca7b9b61b3a8063355c71f96e5b18e1bfd209df3cd3570b55e5144b4f` |
| SHA3-384 | `5ea41394bb27c75a8d87fbe08814e55280c67c264ca4162b10aec0b1ec354161ec33ecfa52cafc555eb7b8e02e6e9a8d` |
| TLSH | `T12A36844F7DF52A30D3528E6B29D519002E7EB2B94CB2E19A59D870370A6382CE4DD7F1` |
| SSDEEP | `12288:60CV/w+0dhgCnxbOKokMBGLmgF22wds/uZeWfjI95TSdS1wZ/IemrXgcuBKpRuep:X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_832f4c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "832f4c6ca7b9b61b3a8063355c71f96e5b18e1bfd209df3cd3570b55e5144b4f"
    family = "unknown"
    file_name = "BOOKING_CONFIRMATION.js"
    file_type = "js"
    first_seen = "2026-09-21 05:01:52"
  condition:
    hash.sha256(0, filesize) == "832f4c6ca7b9b61b3a8063355c71f96e5b18e1bfd209df3cd3570b55e5144b4f"
}
```

### Sample 2: `c6b30fe33b4891fe`

| Field | Value |
|---|---|
| SHA-256 | `c6b30fe33b4891fecabf2d2b5577f994a60fb1e4002923accf1c4f5cffad0eec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:55:46` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `042e22185816c2493d65b7d9cb7b1924` |
| SHA-1 | `896a292843d1c702df4709c8bc50e34c9223c16f` |
| SHA-256 | `c6b30fe33b4891fecabf2d2b5577f994a60fb1e4002923accf1c4f5cffad0eec` |
| SHA3-384 | `178ec8756e6d8416ff08d8e647e92741bee1fbb06ed3a0c6d4522152504703c9a15d67e6fee2455abf951c0196a23a6e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A962D786D9D26F9CDE4F81703A11F878BDB0B6918A6559E3D7828C345DA39E00824FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UkxUle:fKOe2/7c9sN3zfZR1m+RGRi6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_c6b30fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6b30fe33b4891fecabf2d2b5577f994a60fb1e4002923accf1c4f5cffad0eec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:55:46"
  condition:
    hash.sha256(0, filesize) == "c6b30fe33b4891fecabf2d2b5577f994a60fb1e4002923accf1c4f5cffad0eec"
}
```

### Sample 3: `39d16f7d08302fa1`

| Field | Value |
|---|---|
| SHA-256 | `39d16f7d08302fa1bccaf9ebb474115b22c531cb6975e2b416811ddcedde4a83` |
| Family label | `Mirai` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-09-21 04:54:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f72df07d86afeb2524733def02a7e280` |
| SHA-1 | `8dbfc020874e44fc71efb1d6f1dde10eddf684fa` |
| SHA-256 | `39d16f7d08302fa1bccaf9ebb474115b22c531cb6975e2b416811ddcedde4a83` |
| SHA3-384 | `582546bf0c5461de1ded0dbc6b0102a9362165881dbdeb593764481a127ef02623f7606cfce9233df221a5bc21dc7751` |
| TLSH | `T169356C633731CF65E355C27005F3CA51AAD520A31AE2409AB36CC3287A61A6E7D5FFE4` |
| TELFHASH | `t15ea002161885c61d573b9f189ce9064610831c33fc6d3d665e5cde558525405065cca7` |
| SSDEEP | `24576:R6u3xnG40oaDNWxkFioOi1pjg+QUUxuHnYDd:RBA40oaDN1Xpc+FUxuH4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_39d16f7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39d16f7d08302fa1bccaf9ebb474115b22c531cb6975e2b416811ddcedde4a83"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-21 04:54:53"
  condition:
    hash.sha256(0, filesize) == "39d16f7d08302fa1bccaf9ebb474115b22c531cb6975e2b416811ddcedde4a83"
}
```

### Sample 4: `7f50def548a0e26e`

| Field | Value |
|---|---|
| SHA-256 | `7f50def548a0e26eb6ef0ab431df93a103c12e2a9066d95b4e9951e86709d39f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:53:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c0114618da135f7d707cf004dc4b7f66` |
| SHA-1 | `d8d093fceeed9531e2dc1a22d69c8dcf7ef81c5c` |
| SHA-256 | `7f50def548a0e26eb6ef0ab431df93a103c12e2a9066d95b4e9951e86709d39f` |
| SHA3-384 | `ec1a1832db238a633731e9c647b64f4b89534edafe5cf53d62e6ce45fb0ffd69b884c8816b198522f53008f91201c549` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1E062E687D8A22E6CCE4E80707E21FD79B97536E086259AE7DB82CD345D639C05024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UdaDBM:fKOe2/7c9sN3zfZR1m+RGak6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_7f50def5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f50def548a0e26eb6ef0ab431df93a103c12e2a9066d95b4e9951e86709d39f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:53:19"
  condition:
    hash.sha256(0, filesize) == "7f50def548a0e26eb6ef0ab431df93a103c12e2a9066d95b4e9951e86709d39f"
}
```

### Sample 5: `aaa8da8dfe2aaa51`

| Field | Value |
|---|---|
| SHA-256 | `aaa8da8dfe2aaa513916b12137ad6141f451ebf7cbe578830fc1bb4ae2008d94` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:27:31` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a34badf28a0ccd4da8c455463e5d3207` |
| SHA-1 | `c7880ac996099d11b1ce02f10e377c51c92f1769` |
| SHA-256 | `aaa8da8dfe2aaa513916b12137ad6141f451ebf7cbe578830fc1bb4ae2008d94` |
| SHA3-384 | `b58647b117cd380370abed7a0b0123a62de8ecc279884774ce7bc257489798acfcc6744cfd0bb05c85b283bc480bbf88` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14062C586ECA22F5DCE8F80713B11F928B97176E0C66559E3D7C28C315AA39D014A4EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Up8Bgn:fKOe2/7c9sN3zfZR1m+RGh6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_aaa8da8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaa8da8dfe2aaa513916b12137ad6141f451ebf7cbe578830fc1bb4ae2008d94"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:27:31"
  condition:
    hash.sha256(0, filesize) == "aaa8da8dfe2aaa513916b12137ad6141f451ebf7cbe578830fc1bb4ae2008d94"
}
```

### Sample 6: `85924fefcfbbbd26`

| Field | Value |
|---|---|
| SHA-256 | `85924fefcfbbbd26057dc4d5ffd65557f7af612b9481e8b4a0b6b7b13a0fe330` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:25:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8211d6b062607815c480c49c8ee3d6f` |
| SHA-1 | `b8bcf20f97e0294105c95dc0d5374051911e4431` |
| SHA-256 | `85924fefcfbbbd26057dc4d5ffd65557f7af612b9481e8b4a0b6b7b13a0fe330` |
| SHA3-384 | `58dc9eb729a427d8b5c43449fac0dc12c9a08e0ef6bc2f5590aa2b13b73027669a0aa0698aad005fe532db93055dc5bd` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1AC62B796D9E26BACDE4E80703E11F838BE7476A0866599E3D7828C3459A39D04434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1AA1e:fKOe2/7c9sN3zfZR1m+RGwZ16C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_85924fef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85924fefcfbbbd26057dc4d5ffd65557f7af612b9481e8b4a0b6b7b13a0fe330"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:25:30"
  condition:
    hash.sha256(0, filesize) == "85924fefcfbbbd26057dc4d5ffd65557f7af612b9481e8b4a0b6b7b13a0fe330"
}
```

### Sample 7: `07f263b0b93461f7`

| Field | Value |
|---|---|
| SHA-256 | `07f263b0b93461f778a0e22ae977be22d8d64b88619aa48af018aed984875a6e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:24:32` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c65a187c2ca6d41db72af793dc42c153` |
| SHA-1 | `6bf3b7257aeac8ef607c81902968834057a4096e` |
| SHA-256 | `07f263b0b93461f778a0e22ae977be22d8d64b88619aa48af018aed984875a6e` |
| SHA3-384 | `8a27887c5c4c9a70e14e1bb4879fe410c97ee959efe75111eddaf8d9b8555aebe7cadb3b78725ca1a35c882bf8cd313c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B662B586D8A22F5CDE4F90B03A12FC78BD7876908A6599E3D7C28C315DA39D01424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UL5spe:fKOe2/7c9sN3zfZR1m+RGsWp6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_07f263b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f263b0b93461f778a0e22ae977be22d8d64b88619aa48af018aed984875a6e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:24:32"
  condition:
    hash.sha256(0, filesize) == "07f263b0b93461f778a0e22ae977be22d8d64b88619aa48af018aed984875a6e"
}
```

### Sample 8: `1730d47f22d4f74d`

| Field | Value |
|---|---|
| SHA-256 | `1730d47f22d4f74dcb5fb9bbc9e532fbba0d276b2a0cda6c931bf3c091af7a4d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:23:09` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e4d9d56f0e5919d7566590439e98168` |
| SHA-1 | `ed5e4e77eb52b40bbe1eef2a61162744ad2b85fe` |
| SHA-256 | `1730d47f22d4f74dcb5fb9bbc9e532fbba0d276b2a0cda6c931bf3c091af7a4d` |
| SHA3-384 | `4161d113f3761cfc318f31e00cf86c04a3ed84b4ff873cbca3493e7439f1d85d27f07ac8c841cf4c296c1320a8acdb55` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14262C786DCE21E9CDE4E80703B11FC786D7136A04A6569E3E7828C315DA38D14068FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U62r1H:fKOe2/7c9sN3zfZR1m+RGr96C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_1730d47f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1730d47f22d4f74dcb5fb9bbc9e532fbba0d276b2a0cda6c931bf3c091af7a4d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:23:09"
  condition:
    hash.sha256(0, filesize) == "1730d47f22d4f74dcb5fb9bbc9e532fbba0d276b2a0cda6c931bf3c091af7a4d"
}
```

### Sample 9: `98cd84c33f0d90b0`

| Field | Value |
|---|---|
| SHA-256 | `98cd84c33f0d90b0b81f9d7a4c359d56477c9579dc5ee62a18c5a9484ad184f6` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:21:36` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76ba1d027bec462b182bfd2f07c67c9a` |
| SHA-1 | `6c06868bdbc37adfde31848dc7d666fd479aed20` |
| SHA-256 | `98cd84c33f0d90b0b81f9d7a4c359d56477c9579dc5ee62a18c5a9484ad184f6` |
| SHA3-384 | `6feeb50efd81a681edf874fb27dbf78516362632708a0272f2df9fcca54953d8980b0a911f5fc817bcfe510f36472000` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16E62D886D8926FACCE4E80B03A12F878B9B0369489559DF3D7828D315AF39D11434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UfBgCc:fKOe2/7c9sN3zfZR1m+RGs6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_98cd84c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98cd84c33f0d90b0b81f9d7a4c359d56477c9579dc5ee62a18c5a9484ad184f6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:21:36"
  condition:
    hash.sha256(0, filesize) == "98cd84c33f0d90b0b81f9d7a4c359d56477c9579dc5ee62a18c5a9484ad184f6"
}
```

### Sample 10: `62630f2aa61b5ccf`

| Field | Value |
|---|---|
| SHA-256 | `62630f2aa61b5ccf9a13d150fbf68e9b67cf8cb0eddc16249313804a33273b11` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:21:23` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb892b3ca6930cdf5f17fff220a10ce9` |
| SHA-1 | `9726d7bc30abefa2ad0c984e1fd809a4b82866d7` |
| SHA-256 | `62630f2aa61b5ccf9a13d150fbf68e9b67cf8cb0eddc16249313804a33273b11` |
| SHA3-384 | `30444000a5b3388027b3c8f2225058cd8d9089abb2544f49333d9c7d307197f115bed0b146be4f78525381419a0d61d7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1A662D78AD9A27F5CCE4E80703A11FC38BD747A94866599E3DB82CC3159A39D14234FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46US9Bgn:fKOe2/7c9sN3zfZR1m+RGz96C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_62630f2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62630f2aa61b5ccf9a13d150fbf68e9b67cf8cb0eddc16249313804a33273b11"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:21:23"
  condition:
    hash.sha256(0, filesize) == "62630f2aa61b5ccf9a13d150fbf68e9b67cf8cb0eddc16249313804a33273b11"
}
```

### Sample 11: `a3d4b9a22aecc1d9`

| Field | Value |
|---|---|
| SHA-256 | `a3d4b9a22aecc1d9b3ddaff2587434c89a708c0495700efedcfdefb00ac1eb6b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:20:37` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b311a3b1fe39ba64283fbf73384fc399` |
| SHA-1 | `b2efea0615b9883346a164092518338327f72d9d` |
| SHA-256 | `a3d4b9a22aecc1d9b3ddaff2587434c89a708c0495700efedcfdefb00ac1eb6b` |
| SHA3-384 | `4ec0c5ca6509effb0057b0406202a986f6ecd5858014250d7687974989667749f9c2883d28425d723fd9fbcd9539cd2e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17762D596D8A22F5CCE4E80703B11FC68AD747AD196659DE3C7C2CC219DA39E20474EBD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Us9qje:fKOe2/7c9sN3zfZR1m+RGXqj6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_a3d4b9a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3d4b9a22aecc1d9b3ddaff2587434c89a708c0495700efedcfdefb00ac1eb6b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:20:37"
  condition:
    hash.sha256(0, filesize) == "a3d4b9a22aecc1d9b3ddaff2587434c89a708c0495700efedcfdefb00ac1eb6b"
}
```

### Sample 12: `9e7d77c7df21abcd`

| Field | Value |
|---|---|
| SHA-256 | `9e7d77c7df21abcdf0ff7a6f78c9fa47084f070306b6286fccc2c7a8199b1c56` |
| Family label | `unknown` |
| File name | `1` |
| File type | `elf` |
| First seen | `2026-09-21 04:19:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5f14db94cc538d1500ba6e6304cd36c` |
| SHA-1 | `8c419251710d849fcef09979245783708e2aa710` |
| SHA-256 | `9e7d77c7df21abcdf0ff7a6f78c9fa47084f070306b6286fccc2c7a8199b1c56` |
| SHA3-384 | `f73ec8568cb18772c0361e7366c160b9e1fee9842d90f45867c6da30edfa62b7435488d0739754728a086d1819bc9bf0` |
| TLSH | `T1337423A9D13B94D0C7107F7540A1D640C3627AC4F0AACE799ED362DCCBF2AE92934D66` |
| SSDEEP | `6144:6x0hW6fCKje2IhKAUPcb8ftii8LQF54WE0eM14SRB02FQwL:6xavqhKuc4W4YJKuS2hL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_9e7d77c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e7d77c7df21abcdf0ff7a6f78c9fa47084f070306b6286fccc2c7a8199b1c56"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-21 04:19:55"
  condition:
    hash.sha256(0, filesize) == "9e7d77c7df21abcdf0ff7a6f78c9fa47084f070306b6286fccc2c7a8199b1c56"
}
```

### Sample 13: `16f03091a93bf25c`

| Field | Value |
|---|---|
| SHA-256 | `16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074` |
| Family label | `Mirai` |
| File name | `16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074` |
| File type | `elf` |
| First seen | `2026-09-21 04:18:05` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `707f78571ddedab18d93296421ad5c6a` |
| SHA-1 | `48fded3ad4152577de213c9d4bd8351652441a49` |
| SHA-256 | `16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074` |
| SHA3-384 | `3b7887b02e14d549c73ff0f4e879e4bc6bea2d098bc09486f26d7fe7327c7e5d45b1fa412403968098dc9a148fef5286` |
| TLSH | `T1E4543A8AFD81AE25D5C122BBFE2F428A331317B8D2EB71129D145F2476CA94F0F7A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_16f03091
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074"
    family = "Mirai"
    file_name = "16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074"
    file_type = "elf"
    first_seen = "2026-09-21 04:18:05"
  condition:
    hash.sha256(0, filesize) == "16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074"
}
```

### Sample 14: `9087e723c9aea3ec`

| Field | Value |
|---|---|
| SHA-256 | `9087e723c9aea3ec4d8fca4c410fe41941b8eb158dccff432b8973332ed51ddc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 04:16:39` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eac6cc78bb6003bb9eb7388c461eca4e` |
| SHA-1 | `6965897fdf5d8afd70bd8945f5de7600a74cac73` |
| SHA-256 | `9087e723c9aea3ec4d8fca4c410fe41941b8eb158dccff432b8973332ed51ddc` |
| SHA3-384 | `63e880fba063ee791d88aaf0b02c643d5171d758442f955bba87a1bd3ffb50354f15e2e354709750a6f86c09e6dd9448` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15062C986E8925F5CDE4E80B03A11F868BD707A908A5699F3D782CC3D5D639D00429FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U0HmBM:fKOe2/7c9sN3zfZR1m+RGbHm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_9087e723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9087e723c9aea3ec4d8fca4c410fe41941b8eb158dccff432b8973332ed51ddc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:16:39"
  condition:
    hash.sha256(0, filesize) == "9087e723c9aea3ec4d8fca4c410fe41941b8eb158dccff432b8973332ed51ddc"
}
```

### Sample 15: `fb6ffe4171a0af5f`

| Field | Value |
|---|---|
| SHA-256 | `fb6ffe4171a0af5f7a30b978c55aa35ce00e4ee1cbf253b432a907f5c8cc7ac1` |
| Family label | `Mirai` |
| File name | `bot.aarch64` |
| File type | `elf` |
| First seen | `2026-09-21 04:08:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a682d1ee129a46bf3bf13cd6ee347f50` |
| SHA-1 | `5802c1e15a8ac1f984370ac3c355734539da9363` |
| SHA-256 | `fb6ffe4171a0af5f7a30b978c55aa35ce00e4ee1cbf253b432a907f5c8cc7ac1` |
| SHA3-384 | `234ba6fcb4481af3efa3cb93934aa1ececaa00c971b09fd8117b9d1c75699eb751d9a541bfe2dbc40640c7b40e61e10a` |
| TLSH | `T14D356C5DFE4F3C47D2C6F23DDB4A82F47127B098D62310A725C2034DE689D998F6299A` |
| TELFHASH | `t1a1a011020880820c02bbab228ca8038a20828833e82a3ea22e0cea80082000802888a2` |
| SSDEEP | `12288:eFe29N36cNJ5K+qDMYUaHqMNzr1RthJ5k8qPTVUB7k1R5Tdga5hi6kFKHsZsY8Wh:utNsM2HqUzrXgXKETdgHFTSwIvskwv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_fb6ffe41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb6ffe4171a0af5f7a30b978c55aa35ce00e4ee1cbf253b432a907f5c8cc7ac1"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-21 04:08:31"
  condition:
    hash.sha256(0, filesize) == "fb6ffe4171a0af5f7a30b978c55aa35ce00e4ee1cbf253b432a907f5c8cc7ac1"
}
```

### Sample 16: `c34b31ba33e12ab9`

| Field | Value |
|---|---|
| SHA-256 | `c34b31ba33e12ab9251b02574514a81aa6d7ca974f8b8bb87b193695be69506c` |
| Family label | `JOMANGY` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-09-21 04:07:25` |
| Reporter | `abuse_ch` |
| Tags | `JOMANGY, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e4e080a03af5c33da253abe769086ae` |
| SHA-1 | `a0c89a2cb5744e7b3ce0c9f898855a7cfd7edf15` |
| SHA-256 | `c34b31ba33e12ab9251b02574514a81aa6d7ca974f8b8bb87b193695be69506c` |
| SHA3-384 | `63fce76a11db7b0c642aa32db122b119d1ae14c1261ae87f892b5b75c6910c9bb757cf4e11475ee4257f29c5c8d0f741` |
| TLSH | `T18FC27D956A867C44BEC94A3E4CBD2B0D6DF5C3E1324942AC3D8B3C719C15FACD618B1A` |
| SSDEEP | `768:j8vCB+25j6es8RW9FYpMSUpi+20qUpi+20YQX:j8l25JAd2QX` |

#### Technical Assessment

- The sample is tracked as `JOMANGY` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_JOMANGY_016_c34b31ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34b31ba33e12ab9251b02574514a81aa6d7ca974f8b8bb87b193695be69506c"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-21 04:07:25"
  condition:
    hash.sha256(0, filesize) == "c34b31ba33e12ab9251b02574514a81aa6d7ca974f8b8bb87b193695be69506c"
}
```

### Sample 17: `f160f29ffe64663d`

| Field | Value |
|---|---|
| SHA-256 | `f160f29ffe64663daeaa7f669eb6a2f67624d7c1308069aa57c2219a714dbf16` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 03:50:58` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6ebc6efe43cfc5bbce05bbb2decfe68` |
| SHA-1 | `d69426e5d0d5e215579f9937bc4d0c610d3e0c4e` |
| SHA-256 | `f160f29ffe64663daeaa7f669eb6a2f67624d7c1308069aa57c2219a714dbf16` |
| SHA3-384 | `02d144824a0fc8ecfdbf81d83dcaefc9a2b41dbb8d4015afe106c2bb984500abb9c93a552edc24a11d7e2ca6f203e6ac` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D162C596D8A25F6CCE4FC0703A11F938ADB4369096699EF3D7828D345DA39D08424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U5xUOe:fKOe2/7c9sN3zfZR1m+RGCUO6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_f160f29f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f160f29ffe64663daeaa7f669eb6a2f67624d7c1308069aa57c2219a714dbf16"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:50:58"
  condition:
    hash.sha256(0, filesize) == "f160f29ffe64663daeaa7f669eb6a2f67624d7c1308069aa57c2219a714dbf16"
}
```

### Sample 18: `8bca9dae858b5f85`

| Field | Value |
|---|---|
| SHA-256 | `8bca9dae858b5f859dfe7e2b196d9abf874ab6c2cc99ae2fdb645d8efba54ccb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 03:48:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b5445be4beed7280329d62d8d3058ff0` |
| SHA-1 | `c282ad5e801665d57fa7a3b1a4a8e5bc0fa4c69d` |
| SHA-256 | `8bca9dae858b5f859dfe7e2b196d9abf874ab6c2cc99ae2fdb645d8efba54ccb` |
| SHA3-384 | `843cdd66e29f66adfcbe21be3f1f39ade1d556fa11c0a140adace01a0012b12f3357527325ddf5f2fe326978346cfcda` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1BE62E78AE9E26F5CCE4F8070BA51F968AD70329089295DE7D7868C315DA39C00174FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UizBgn:fKOe2/7c9sN3zfZR1m+RGZ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_8bca9dae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bca9dae858b5f859dfe7e2b196d9abf874ab6c2cc99ae2fdb645d8efba54ccb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:48:35"
  condition:
    hash.sha256(0, filesize) == "8bca9dae858b5f859dfe7e2b196d9abf874ab6c2cc99ae2fdb645d8efba54ccb"
}
```

### Sample 19: `a4f7714bb8c1e6ff`

| Field | Value |
|---|---|
| SHA-256 | `a4f7714bb8c1e6ff6c5b6205f5c9da818e3c9625d51457669c9b6a673c43375d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 03:46:03` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62e28fbbce4cd8185658a6ea9026865f` |
| SHA-1 | `f312f9e547b8a18c011031ebb34ab2599bf21aa6` |
| SHA-256 | `a4f7714bb8c1e6ff6c5b6205f5c9da818e3c9625d51457669c9b6a673c43375d` |
| SHA3-384 | `22a9e9d2af1b675500e46fb670e2fb6df23ceb3160bcff181169d4249fa9968f6fb5a4263d63e5e2541c136ada23e6f7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19062D78AE8E22F9CCE4ED0703A11F929ADB03791856579F3D7828C715DA39D04424EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U89GBM:fKOe2/7c9sN3zfZR1m+RGv9G6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_a4f7714b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4f7714bb8c1e6ff6c5b6205f5c9da818e3c9625d51457669c9b6a673c43375d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:46:03"
  condition:
    hash.sha256(0, filesize) == "a4f7714bb8c1e6ff6c5b6205f5c9da818e3c9625d51457669c9b6a673c43375d"
}
```

### Sample 20: `45ce428e16e0a892`

| Field | Value |
|---|---|
| SHA-256 | `45ce428e16e0a892f74371a4ce4c909bc738e88da9af93c9ef9165f793e48e12` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 03:42:34` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47569ff0e0676acee5f8589e739ff903` |
| SHA-1 | `cc369066cc7d2c374a847025dbe0b33cc40a32b8` |
| SHA-256 | `45ce428e16e0a892f74371a4ce4c909bc738e88da9af93c9ef9165f793e48e12` |
| SHA3-384 | `ee7c4be3dfd08e9d8289b010f901d77288abc0cbe6edf67a546e2e7ff45c5f48355dd95f7f603c2f3f6d466ce75c3394` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19A62D69AE9D21FACDE4E80703A11F868AD7476A486655DE3D7828C708DA39D04134EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UkVmBM:fKOe2/7c9sN3zfZR1m+RGBVm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_45ce428e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ce428e16e0a892f74371a4ce4c909bc738e88da9af93c9ef9165f793e48e12"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:42:34"
  condition:
    hash.sha256(0, filesize) == "45ce428e16e0a892f74371a4ce4c909bc738e88da9af93c9ef9165f793e48e12"
}
```

### Sample 21: `d25b957a739dfafc`

| Field | Value |
|---|---|
| SHA-256 | `d25b957a739dfafc72a3a73a7faa2de7364d16611e712f3b688a79d8e740ef7c` |
| Family label | `Gafgyt` |
| File name | `i-5.8-6.Sakura` |
| File type | `elf` |
| First seen | `2026-09-21 03:41:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e80d72752188e968e6fbbb325fb2e1c` |
| SHA-1 | `aa3c0e3c336fd998d3a38b005148561e1d81157a` |
| SHA-256 | `d25b957a739dfafc72a3a73a7faa2de7364d16611e712f3b688a79d8e740ef7c` |
| SHA3-384 | `d624f80c41d01b2f1e4fef47a6373eddc1eba344005b253366913a7704605621b1feccc533c191d0242cbe587f522588` |
| TLSH | `T1C5A3F896F800DFB7F40AE67604D34B24B670BBE14E532622731739A6AE762D53823F45` |
| TELFHASH | `t13611d04270b6891d2bb659245cbc42b5165536236381be75bf0ec5c45537002ba79e8b` |
| SSDEEP | `3072:Vgdr2vIBAxMyAOLRcftchOemuxVqDr78fz1e:Vgdr2vIRyAYcOhOemuxVqDr78fz1e` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_021_d25b957a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d25b957a739dfafc72a3a73a7faa2de7364d16611e712f3b688a79d8e740ef7c"
    family = "Gafgyt"
    file_name = "i-5.8-6.Sakura"
    file_type = "elf"
    first_seen = "2026-09-21 03:41:27"
  condition:
    hash.sha256(0, filesize) == "d25b957a739dfafc72a3a73a7faa2de7364d16611e712f3b688a79d8e740ef7c"
}
```

### Sample 22: `b85cffcb640a1a5d`

| Field | Value |
|---|---|
| SHA-256 | `b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7` |
| Family label | `Mirai` |
| File name | `b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7` |
| File type | `elf` |
| First seen | `2026-09-21 03:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f4c445651a4684703fd833a73efa959` |
| SHA-1 | `2a34d8b2e07301269c186a5151d57f0e33359fc8` |
| SHA-256 | `b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7` |
| SHA3-384 | `48ea06ff9b70ccba6cd243c2cdfb2001a1d6c53d87b16fd75132e5ebd7ac7733a5e837f5798353c80702b9bd6f50f21a` |
| TLSH | `T12073F886BC919A9655D423BBBE6E85CE330323B8D2DF7103DD055F18B6CA84F0E76942` |
| SSDEEP | `1536:CMn12A//SrRftY97WARbIcbboW+zLsYtJ913DhrPDysX+4if3LEVwjUW:T2s/ITo7WCkybotgsJ913DhrbW4UYSL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_b85cffcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7"
    family = "Mirai"
    file_name = "b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7"
    file_type = "elf"
    first_seen = "2026-09-21 03:17:12"
  condition:
    hash.sha256(0, filesize) == "b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7"
}
```

### Sample 23: `9737530cbf7a92cf`

| Field | Value |
|---|---|
| SHA-256 | `9737530cbf7a92cf261dd1c875b8ee18cc32797aa5852eb4395ba06552dd7dd3` |
| Family label | `unknown` |
| File name | `Utils.exe` |
| File type | `exe` |
| First seen | `2026-09-21 03:10:19` |
| Reporter | `Alex_sev` |
| Tags | `exe, generic, kryptik` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7ac4df54f78ffafffaf68e5122ff6c2` |
| SHA-1 | `d05841e44c2e7ee651b940ad7871e852a645dd5a` |
| SHA-256 | `9737530cbf7a92cf261dd1c875b8ee18cc32797aa5852eb4395ba06552dd7dd3` |
| SHA3-384 | `d280aa7c6dc128af044b4892fcae1fefdd73f979c771eb7963fc004833b1761c9a22825a4c25753581dba35ff77f3e1f` |
| IMPHASH | `2e33a544f54ef773efa81545fd112848` |
| TLSH | `T1D2A501E9A87246D9E01F4FB8689932463C0ED969CE07DECE506FD1A579EE3710724C0E` |
| SSDEEP | `49152:85+Z/e+2b42HVfx7cQgJmriR0zKiXJhuGgxeCXZ:6nj4237cruKcJhYxeCXZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_9737530c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9737530cbf7a92cf261dd1c875b8ee18cc32797aa5852eb4395ba06552dd7dd3"
    family = "unknown"
    file_name = "Utils.exe"
    file_type = "exe"
    first_seen = "2026-09-21 03:10:19"
  condition:
    hash.sha256(0, filesize) == "9737530cbf7a92cf261dd1c875b8ee18cc32797aa5852eb4395ba06552dd7dd3"
}
```

### Sample 24: `080c5b27e2d8a2b1`

| Field | Value |
|---|---|
| SHA-256 | `080c5b27e2d8a2b13d5cda93ee502b767bc43e787df95899ace6f27ed9c1dd22` |
| Family label | `unknown` |
| File name | `wso.exe` |
| File type | `exe` |
| First seen | `2026-09-21 03:09:30` |
| Reporter | `Alex_sev` |
| Tags | `dapato, exe, kryptik` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebfc1f913f7b2868056542f3a605cd0a` |
| SHA-1 | `361dea3a7ae7a057f340f2006b8be071d345c14c` |
| SHA-256 | `080c5b27e2d8a2b13d5cda93ee502b767bc43e787df95899ace6f27ed9c1dd22` |
| SHA3-384 | `6b0edfb222753267be2405d6113096a2016e63e71ee417544b07ef873431a0c53028ae911fbe4f685042a68f1005ab7a` |
| IMPHASH | `f4f47bcfe83c73d3ee12b59621c22cb6` |
| TLSH | `T1D0D502C22431567ED1CE7A3CA54981EAFD0E8873E78454B352D716817BEA1F20F786B2` |
| SSDEEP | `49152:Q0raKSG7gXvmYtw40qEb5MU/EZp+2b42HVfx7cQgJmriR0zKiXJhuGgxeCXvHyT:Q0raKS3XvmYtw40j5MGELj4237cruKcT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_080c5b27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "080c5b27e2d8a2b13d5cda93ee502b767bc43e787df95899ace6f27ed9c1dd22"
    family = "unknown"
    file_name = "wso.exe"
    file_type = "exe"
    first_seen = "2026-09-21 03:09:30"
  condition:
    hash.sha256(0, filesize) == "080c5b27e2d8a2b13d5cda93ee502b767bc43e787df95899ace6f27ed9c1dd22"
}
```

### Sample 25: `30e5af4d627069f7`

| Field | Value |
|---|---|
| SHA-256 | `30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9` |
| Family label | `Formbook` |
| File name | `Penawaran RFQ Terlampir 2026.pdf.js` |
| File type | `js` |
| First seen | `2026-09-21 03:08:36` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8cc62058f9448e5f9795c961754e7541` |
| SHA-1 | `1c2a9c403d3f7e4cecbcc11ed3afe783faf277b7` |
| SHA-256 | `30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9` |
| SHA3-384 | `7c44b8f04618f2cc528613953cdc50ab9813161c36f0453cdbced12bce1ac5fced28fc709a4f62b60d419d15ffab1f39` |
| TLSH | `T115A22E114D927440933763BE722BB8E1EB764A2B02402C5BB87CB944EFB6D09DDD4DB9` |
| SSDEEP | `384:5gVcr/U8XTm7+bCzYaOfScN80cQe6oA08Wjah7md14mRaxl5sf3Dy0xHeOgbMciu:5vr/UZ7sCzYaOfScN80cQe6oA08WjahJ` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_025_30e5af4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9"
    family = "Formbook"
    file_name = "Penawaran RFQ Terlampir 2026.pdf.js"
    file_type = "js"
    first_seen = "2026-09-21 03:08:36"
  condition:
    hash.sha256(0, filesize) == "30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9"
}
```

### Sample 26: `f47f3fba888e9c79`

| Field | Value |
|---|---|
| SHA-256 | `f47f3fba888e9c798d9f5b9115b31aabf844cb0202a5253956dcb7b9940e5c3e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 03:08:15` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9427f7338ba930b4d99d07152dbed0b1` |
| SHA-1 | `caa945c8ccc45b7b63a923458decbfe41ee376df` |
| SHA-256 | `f47f3fba888e9c798d9f5b9115b31aabf844cb0202a5253956dcb7b9940e5c3e` |
| SHA3-384 | `ae8ae49f34a2034ee971ba5fcc7a82fcc73b94494ccd59ac98fd0f7cc1fc3a64df1d48f23ae24736e9b808bd6cffa482` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F262C686D8926F5DCE4F80703A51FC68BE7476A585299DE3D7828D3199B38D08034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UUhwBM:fKOe2/7c9sN3zfZR1m+RGHw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_f47f3fba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47f3fba888e9c798d9f5b9115b31aabf844cb0202a5253956dcb7b9940e5c3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:08:15"
  condition:
    hash.sha256(0, filesize) == "f47f3fba888e9c798d9f5b9115b31aabf844cb0202a5253956dcb7b9940e5c3e"
}
```

### Sample 27: `a28aa61cc3ef70a1`

| Field | Value |
|---|---|
| SHA-256 | `a28aa61cc3ef70a11cf1e1b41b2a7df5cac1842577af1885152d9e31a6b1d619` |
| Family label | `unknown` |
| File name | `NEW_MV_TBN_Order_Quotation_Form.js` |
| File type | `js` |
| First seen | `2026-09-21 02:45:48` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08016f27415bd9d92e80f275e2e0cb19` |
| SHA-1 | `95322bcdc108063ee0e1f4b11c6590916955177a` |
| SHA-256 | `a28aa61cc3ef70a11cf1e1b41b2a7df5cac1842577af1885152d9e31a6b1d619` |
| SHA3-384 | `7725095b56c6eec0f2af9ba68940a3c7f9f7fa0859487633ebb47457f184cd61026a5ed051aef048766df5a5e84f264d` |
| TLSH | `T18AE5E5A766DD61876C0DB3452654A98D0B29C7E22FD1F7D0A0DB0A989C0F0196EE0F7F` |
| SSDEEP | `49152:jD6kzN6LV90Vl7pxNQUlfCV5LYLRzWPK1NtiziaTEbXmtKgtzciPB1ozuVTm:V` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_a28aa61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a28aa61cc3ef70a11cf1e1b41b2a7df5cac1842577af1885152d9e31a6b1d619"
    family = "unknown"
    file_name = "NEW_MV_TBN_Order_Quotation_Form.js"
    file_type = "js"
    first_seen = "2026-09-21 02:45:48"
  condition:
    hash.sha256(0, filesize) == "a28aa61cc3ef70a11cf1e1b41b2a7df5cac1842577af1885152d9e31a6b1d619"
}
```

### Sample 28: `894dd68a9891238e`

| Field | Value |
|---|---|
| SHA-256 | `894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f` |
| Family label | `unknown` |
| File name | `894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f` |
| File type | `elf` |
| First seen | `2026-09-21 02:40:56` |
| Reporter | `c2hunter` |
| Tags | `elf, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b236d555bf1cf96614597501a48207ad` |
| SHA-1 | `c7f7b6687acbfbb7784f817df6500c9ad7bb0c79` |
| SHA-256 | `894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f` |
| SHA3-384 | `15d0751ec9d1bba5bceae93fdfe2209057cb1bad99abff6a80edaa4ca6b5aaed9ac2b0f2f6ae50f4a11a16abeda712bd` |
| TLSH | `T135842386D04B4EE7FE0BB9FAC48DCEBB64059064B54CBD026E8A22A7571EC97145770C` |
| SSDEEP | `6144:4gMD5E2D8j1k28GmNTYC52kVb2dk7US7PvvJpruH+Q7tE70mgGvzH94st7Pu:5MD5fD8ji3GmN8wL45SDHJZuH+Q7M0xd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_894dd68a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f"
    family = "unknown"
    file_name = "894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f"
    file_type = "elf"
    first_seen = "2026-09-21 02:40:56"
  condition:
    hash.sha256(0, filesize) == "894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f"
}
```

### Sample 29: `09ee8454d25becc2`

| Field | Value |
|---|---|
| SHA-256 | `09ee8454d25becc292fb33b33c85554df1ff4d70d780c210633682c904e52fb1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:31:42` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bc5fed9baf3020ab0a7343411b24d9a` |
| SHA-1 | `e94cb66d6df61bf7b802b5a6351df0c4ec992cd5` |
| SHA-256 | `09ee8454d25becc292fb33b33c85554df1ff4d70d780c210633682c904e52fb1` |
| SHA3-384 | `a4d23dd22b149b51d8a37a4f1db933f51d92741b1f9be3f46d111ec904f5220ebeb4231351a8d54e8d84704ea27ac58f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19062C586D8A62F5ECE4F80713B11F878BD7536909A6659E3D7C68C204DB39C08428FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UimSSi:fKOe2/7c9sN3zfZR1m+RG/e6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_09ee8454
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09ee8454d25becc292fb33b33c85554df1ff4d70d780c210633682c904e52fb1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:31:42"
  condition:
    hash.sha256(0, filesize) == "09ee8454d25becc292fb33b33c85554df1ff4d70d780c210633682c904e52fb1"
}
```

### Sample 30: `3f41859451acb64c`

| Field | Value |
|---|---|
| SHA-256 | `3f41859451acb64cb101290e361714bc8e2ed6bc937a977c79473a6b59094756` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:29:13` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f3fb4ec25d61fbee3e0aaa7300ee4f3` |
| SHA-1 | `9ccc646d7e2ec009b15525f127f1cebd4f334fea` |
| SHA-256 | `3f41859451acb64cb101290e361714bc8e2ed6bc937a977c79473a6b59094756` |
| SHA3-384 | `734942456dacb1776ebb1d7cc2cb841a9f52691c893ad0c99436bdad184bb742798039713e43a443b2afcba510722d27` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12B62C48AEDE26A6CDF4E90703A11F878ADB03690866559F3E7828C3059A3DD14064FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UrMSBM:fKOe2/7c9sN3zfZR1m+RGgMS6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_3f418594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f41859451acb64cb101290e361714bc8e2ed6bc937a977c79473a6b59094756"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:29:13"
  condition:
    hash.sha256(0, filesize) == "3f41859451acb64cb101290e361714bc8e2ed6bc937a977c79473a6b59094756"
}
```

### Sample 31: `c87126d88769d219`

| Field | Value |
|---|---|
| SHA-256 | `c87126d88769d2198f18d1a376c2eb88b88a9555feb58fb0908ad19927290d7b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:26:47` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `503b396ab46c16f45e034072648d3600` |
| SHA-1 | `e9dda4dffca49916acc9f77a4daedda479c45447` |
| SHA-256 | `c87126d88769d2198f18d1a376c2eb88b88a9555feb58fb0908ad19927290d7b` |
| SHA3-384 | `f56597361ba75a75331660847f5b87b46717eb2c813aac779b6a404805ffd38a3fefbb55cd4bffe751c1550b98523ecf` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10C62D686DCA27E6DCE4F80703B11F939A97572E4862659E7D7C28C3059B39D04428EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UdK/BM:fKOe2/7c9sN3zfZR1m+RG6A6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_c87126d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c87126d88769d2198f18d1a376c2eb88b88a9555feb58fb0908ad19927290d7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:26:47"
  condition:
    hash.sha256(0, filesize) == "c87126d88769d2198f18d1a376c2eb88b88a9555feb58fb0908ad19927290d7b"
}
```

### Sample 32: `a1b85fa1f3f58a03`

| Field | Value |
|---|---|
| SHA-256 | `a1b85fa1f3f58a0315506a8187b8292fbf51fb82d38f842a847cac21a57fb34e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:26:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f8a29dd220dafdcc870d0e6a414b6a8` |
| SHA-1 | `d4b6a18f5d0b879aecaec64b86ffce3769b1f760` |
| SHA-256 | `a1b85fa1f3f58a0315506a8187b8292fbf51fb82d38f842a847cac21a57fb34e` |
| SHA3-384 | `3bebf5f353916ab30179dca30e97c5d0fdfb8f7f11624d36d94a3a7828ac6b5ed08639e462d3b3e845c0e9e5d5bb554d` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14E62F786D8A62F6CCE8E90707A10FD78AD743290966658FBE7828D306D639D04534FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UvUbym:fKOe2/7c9sN3zfZR1m+RGdOVN6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_a1b85fa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1b85fa1f3f58a0315506a8187b8292fbf51fb82d38f842a847cac21a57fb34e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:26:35"
  condition:
    hash.sha256(0, filesize) == "a1b85fa1f3f58a0315506a8187b8292fbf51fb82d38f842a847cac21a57fb34e"
}
```

### Sample 33: `fa9a0761f85ab411`

| Field | Value |
|---|---|
| SHA-256 | `fa9a0761f85ab411c81874cd873d6d4e0bb0a539437043b96066d1e456af020c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:24:05` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afdd595d8581ec24d90dbf27bb3e4679` |
| SHA-1 | `aaead7330e64df3bfc60de4078a463062995a441` |
| SHA-256 | `fa9a0761f85ab411c81874cd873d6d4e0bb0a539437043b96066d1e456af020c` |
| SHA3-384 | `26b892a9f28aae000ed8f3fd733873db255257c4653932c5a17018330c0ef081a19543ca91049f790724a8e7dffba411` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15862D78AD9921E5DDE8F90B03A11F8687D7036E195A9A9E3DB828D3449B3DD04024FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UiMLBM:fKOe2/7c9sN3zfZR1m+RGrML6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_fa9a0761
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa9a0761f85ab411c81874cd873d6d4e0bb0a539437043b96066d1e456af020c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:24:05"
  condition:
    hash.sha256(0, filesize) == "fa9a0761f85ab411c81874cd873d6d4e0bb0a539437043b96066d1e456af020c"
}
```

### Sample 34: `4f859aeb12bd1611`

| Field | Value |
|---|---|
| SHA-256 | `4f859aeb12bd1611b86143b8754b5cb7f631015894df20f0881bc43f996ec67e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:21:22` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `112f330563fd74c9cd7b696fd32c5136` |
| SHA-1 | `bd349f583a06e5310cd3d0e58e8df9e48f28a6e0` |
| SHA-256 | `4f859aeb12bd1611b86143b8754b5cb7f631015894df20f0881bc43f996ec67e` |
| SHA3-384 | `77e0b3dfca830dac7aedfe6a283671c6b7c05fede315d87aa3c8478e11fb7bb9336480d70ee67a74672efb4c67ec2365` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18962D89AD9A21F9CDE8E80707E22F9787D707694866599E3D7828C305EA39D04034FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UvBgCc:fKOe2/7c9sN3zfZR1m+RGA6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_4f859aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f859aeb12bd1611b86143b8754b5cb7f631015894df20f0881bc43f996ec67e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:21:22"
  condition:
    hash.sha256(0, filesize) == "4f859aeb12bd1611b86143b8754b5cb7f631015894df20f0881bc43f996ec67e"
}
```

### Sample 35: `e1ee8d5c020d3b80`

| Field | Value |
|---|---|
| SHA-256 | `e1ee8d5c020d3b8016b46f68cf7c8f146232500dfff8ac478805d3dbb545ff75` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:21:13` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf6579157d74ea716c25c6a38f1f060c` |
| SHA-1 | `4d402b02ed55388ae4aa1c60101b063922c6499a` |
| SHA-256 | `e1ee8d5c020d3b8016b46f68cf7c8f146232500dfff8ac478805d3dbb545ff75` |
| SHA3-384 | `d3a6408dba977e2fceac9bd95e0ba9708d08f49b30417f9c246a2e0553d43d905797f4739909f231661d1e1b00974a72` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C162C686E8A22EACCE4EC0703B51F878AD7437958A6659F7D7828C745DA39C00124EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uc9n2e:fKOe2/7c9sN3zfZR1m+RGO6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_e1ee8d5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1ee8d5c020d3b8016b46f68cf7c8f146232500dfff8ac478805d3dbb545ff75"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:21:13"
  condition:
    hash.sha256(0, filesize) == "e1ee8d5c020d3b8016b46f68cf7c8f146232500dfff8ac478805d3dbb545ff75"
}
```

### Sample 36: `5a554cc0cc86575e`

| Field | Value |
|---|---|
| SHA-256 | `5a554cc0cc86575e0f3e07d384ba4e83871d5a03333c67170bb0b946bf38844d` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:19:50` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ee1385100d3ecb3924f5063ac83262c` |
| SHA-1 | `46d5cc2161e3e472fcb89e6f49896fa18c8155c6` |
| SHA-256 | `5a554cc0cc86575e0f3e07d384ba4e83871d5a03333c67170bb0b946bf38844d` |
| SHA3-384 | `8ceab62ac5cc06728b06a5cae19fc161a44048518050a18d003f52457f19d5a5218d80488d62abc990149b73dcc5c070` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15E62E78AE8A26E6CDE4FC0B03A10FD79AD753690462559E3C7C2CC215EB78C14434FB9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U0vBgn:fKOe2/7c9sN3zfZR1m+RGd6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_5a554cc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a554cc0cc86575e0f3e07d384ba4e83871d5a03333c67170bb0b946bf38844d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:19:50"
  condition:
    hash.sha256(0, filesize) == "5a554cc0cc86575e0f3e07d384ba4e83871d5a03333c67170bb0b946bf38844d"
}
```

### Sample 37: `839d4344f0e6b396`

| Field | Value |
|---|---|
| SHA-256 | `839d4344f0e6b396467df570011971897acfca4aee37011fb64ade9338ecfb81` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:17:19` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4c1a95803a0d5da95e5f1ae79e50375` |
| SHA-1 | `0ad8483737a2b86a6ba71d1a9959f0731eea5a46` |
| SHA-256 | `839d4344f0e6b396467df570011971897acfca4aee37011fb64ade9338ecfb81` |
| SHA3-384 | `cc2dae93edddeebe0cedc9f7194b0bd40715318a2149c26f3752a68d8bd9d4364455d83abd8be5d10caf23372b4de69a` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17F62B79AD8A12F5CCE4F80707A11FE686DB436D0856669E3DB82CC3099A39D05534FFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UahsYe:fKOe2/7c9sN3zfZR1m+RGt6Y6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_839d4344
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839d4344f0e6b396467df570011971897acfca4aee37011fb64ade9338ecfb81"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:17:19"
  condition:
    hash.sha256(0, filesize) == "839d4344f0e6b396467df570011971897acfca4aee37011fb64ade9338ecfb81"
}
```

### Sample 38: `c8e651f556522788`

| Field | Value |
|---|---|
| SHA-256 | `c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b` |
| Family label | `Mirai` |
| File name | `c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b` |
| File type | `elf` |
| First seen | `2026-09-21 02:17:12` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a9b27075cec379d35e2777cc533a132` |
| SHA-1 | `eb1c25bfa143c16d29027df75e8ad3885f3e8877` |
| SHA-256 | `c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b` |
| SHA3-384 | `ccc89495fbf6c707fec9d4105569c09e5f6a117e55b63e88214075c68f66bda7ed08dc52937c686c54af601f959caa34` |
| TLSH | `T19614198AFC81AF5596C127BBFE2E418A331317B8D2EE71129D145F2477CA94F0E3A542` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqf:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_c8e651f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b"
    family = "Mirai"
    file_name = "c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b"
    file_type = "elf"
    first_seen = "2026-09-21 02:17:12"
  condition:
    hash.sha256(0, filesize) == "c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b"
}
```

### Sample 39: `66a99c73398040b1`

| Field | Value |
|---|---|
| SHA-256 | `66a99c73398040b11ce75f839ba2ff705aa12df7405006bf8328e00204beaf1b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:17:08` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60f37ef660fa58f9cc619dfba2a889ad` |
| SHA-1 | `6734a5b7cf84f57294046fefcddf85fe84a7ea41` |
| SHA-256 | `66a99c73398040b11ce75f839ba2ff705aa12df7405006bf8328e00204beaf1b` |
| SHA3-384 | `3c3d3b631feca944fd0413b3d0f9fe03bb24ca5a9ec348e6705354b21605a53a9202067d6f95cd5a644335f8ef8416a7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18762D896D8A21FADDE4F80717A21FC38ADB236904A565DE3D7C28C305D678D00424FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uf51Be:fKOe2/7c9sN3zfZR1m+RGUB6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_66a99c73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66a99c73398040b11ce75f839ba2ff705aa12df7405006bf8328e00204beaf1b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:17:08"
  condition:
    hash.sha256(0, filesize) == "66a99c73398040b11ce75f839ba2ff705aa12df7405006bf8328e00204beaf1b"
}
```

### Sample 40: `7ac1c753b75182d5`

| Field | Value |
|---|---|
| SHA-256 | `7ac1c753b75182d5d6300904e7ea31e313df4b20c1709ce4cb19168880778e77` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:16:52` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f5b67eebff3824d778032f286cb4f6f` |
| SHA-1 | `d083e783de295b12aec94a956136c8a4ee831f94` |
| SHA-256 | `7ac1c753b75182d5d6300904e7ea31e313df4b20c1709ce4cb19168880778e77` |
| SHA3-384 | `b9552907ee3c3c8e4787bed2d170fd7b9c9b23a2f73ab17607b48a580f607720ad064aebb61d6cf564f2f0b6fe64819b` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1DC62D796D8922F5CDE8ED0703A11F939ADB0769086665AE3DB82CC305DB79E01434EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U55sfe:fKOe2/7c9sN3zfZR1m+RGhf6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_7ac1c753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac1c753b75182d5d6300904e7ea31e313df4b20c1709ce4cb19168880778e77"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:16:52"
  condition:
    hash.sha256(0, filesize) == "7ac1c753b75182d5d6300904e7ea31e313df4b20c1709ce4cb19168880778e77"
}
```

### Sample 41: `1dfbe4d756e4a424`

| Field | Value |
|---|---|
| SHA-256 | `1dfbe4d756e4a424f51a012250ddbdd7da05070146676302275118ebc2c24f1e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:16:03` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fe365cfe03734ca88996c17378f89ef` |
| SHA-1 | `fe2574a83b3076c2d03de18ad6e5dd83db7f234c` |
| SHA-256 | `1dfbe4d756e4a424f51a012250ddbdd7da05070146676302275118ebc2c24f1e` |
| SHA3-384 | `0111206d50125dbfdefbaf9afb8bbb30b47785cdec2671ea6d10678532891e9d7fec2bfc8398baf06e234737a6be2267` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16362E786E8A22F6CDE8E80703A11F978BD757690866599F3D7928C305EA39D00134FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UD5XeG:fKOe2/7c9sN3zfZR1m+RGM5+b6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_1dfbe4d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dfbe4d756e4a424f51a012250ddbdd7da05070146676302275118ebc2c24f1e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:16:03"
  condition:
    hash.sha256(0, filesize) == "1dfbe4d756e4a424f51a012250ddbdd7da05070146676302275118ebc2c24f1e"
}
```

### Sample 42: `d459fd61bfd71fd4`

| Field | Value |
|---|---|
| SHA-256 | `d459fd61bfd71fd434eff7ae4ff4dcb7201c334861bde1452112ac130e12cd58` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:14:54` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `328b891d69722811d51149188fdc711e` |
| SHA-1 | `704c4e95b74051400404be3ed36cd45fdf4e4df7` |
| SHA-256 | `d459fd61bfd71fd434eff7ae4ff4dcb7201c334861bde1452112ac130e12cd58` |
| SHA3-384 | `847066391142e7005f6991c67bec6f7abe03904349b63951e597a2e30486da1350de1b60f3c467c3ca25e4598e4bdc01` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16562D68AD8E25F7CCE4E80703F51F878A9B53694966699E3D7828C215DA78C00534FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UtBgCc:fKOe2/7c9sN3zfZR1m+RGi6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d459fd61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d459fd61bfd71fd434eff7ae4ff4dcb7201c334861bde1452112ac130e12cd58"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:14:54"
  condition:
    hash.sha256(0, filesize) == "d459fd61bfd71fd434eff7ae4ff4dcb7201c334861bde1452112ac130e12cd58"
}
```

### Sample 43: `c8fdd6050c30252b`

| Field | Value |
|---|---|
| SHA-256 | `c8fdd6050c30252ba672b0284963a3e1ace14b0e9588fe347415f4f02e4e5db1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:14:52` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cde0e904f2100e981aed08a8723116f1` |
| SHA-1 | `84756abc47846a0ba4a30b9f8bec0d2d437a7e44` |
| SHA-256 | `c8fdd6050c30252ba672b0284963a3e1ace14b0e9588fe347415f4f02e4e5db1` |
| SHA3-384 | `bb4b05dc78c03c2d69e8e819a888bf2852394df8290ca32eb198ecf21967be127876507eb2df449452f589569b578383` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14962C79AD8926F6CDE4FD0703A11F868BEB836909565ADE3D7918C315DA39D00034EFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U5fgBM:fKOe2/7c9sN3zfZR1m+RGwo6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_c8fdd605
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8fdd6050c30252ba672b0284963a3e1ace14b0e9588fe347415f4f02e4e5db1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:14:52"
  condition:
    hash.sha256(0, filesize) == "c8fdd6050c30252ba672b0284963a3e1ace14b0e9588fe347415f4f02e4e5db1"
}
```

### Sample 44: `46b913adb2c7e0d8`

| Field | Value |
|---|---|
| SHA-256 | `46b913adb2c7e0d8e7b93ecb3ca164bd6a25b0482ad78cf4462ecf9da5ae205e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:13:28` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e4c06d214706fc79a26533050496b90` |
| SHA-1 | `2e1d293980c7b5e5a91082681e089ba5977453aa` |
| SHA-256 | `46b913adb2c7e0d8e7b93ecb3ca164bd6a25b0482ad78cf4462ecf9da5ae205e` |
| SHA3-384 | `20be5e8283d9efff0f855cec6e07aa793d107cbd4ac0f616c37ce7e0325bea44ce04eff5c2b86007c2464d3af20ab273` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19B62D59AD9A22F5DDE4F80703A11F838BD7536908A6699F7D7828C315EA39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UYXKJn:fKOe2/7c9sN3zfZR1m+RGV/6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_46b913ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b913adb2c7e0d8e7b93ecb3ca164bd6a25b0482ad78cf4462ecf9da5ae205e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:13:28"
  condition:
    hash.sha256(0, filesize) == "46b913adb2c7e0d8e7b93ecb3ca164bd6a25b0482ad78cf4462ecf9da5ae205e"
}
```

### Sample 45: `52d682c52b8acbb1`

| Field | Value |
|---|---|
| SHA-256 | `52d682c52b8acbb14822592ead2b398f164398e72009f81524ed35469ff124d0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:11:54` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7aff1aac4bd4dd54dd9916574bfd17ae` |
| SHA-1 | `69e469dfad201d082a5ee433e7a59e376b2f0396` |
| SHA-256 | `52d682c52b8acbb14822592ead2b398f164398e72009f81524ed35469ff124d0` |
| SHA3-384 | `015d013f09d9b7b34a88deec371672181af3d1dfd83ddb89e436288df7f3174617da86cbdc0826a1c2f68a5372e03cc7` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18862C59AE8922F6DEE4FC0703A21F9787E747790965598E3D7C28C705AA39D00024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UeMMM5:fKOe2/7c9sN3zfZR1m+RGgq6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_52d682c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d682c52b8acbb14822592ead2b398f164398e72009f81524ed35469ff124d0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:11:54"
  condition:
    hash.sha256(0, filesize) == "52d682c52b8acbb14822592ead2b398f164398e72009f81524ed35469ff124d0"
}
```

### Sample 46: `cd87c73901bd8201`

| Field | Value |
|---|---|
| SHA-256 | `cd87c73901bd82017779f218e7efa0047a4f2c73b6c61e72c1a7c0d37d2f77a1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:09:28` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8314ae947a3378db149556f576531780` |
| SHA-1 | `3d45450b6dc14d6462bf8827783a9d6e6fc1a3bd` |
| SHA-256 | `cd87c73901bd82017779f218e7efa0047a4f2c73b6c61e72c1a7c0d37d2f77a1` |
| SHA3-384 | `65d58c091447f2f144292abb4492cec2754e90f339fb79d5a1814c3eb7f2f1d6dca694b7465bfe9e94aeaa23caebef8e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B462E687D9A25E5DDE8E80717B02FC38AE7836A09A655DE3C7C2CC7549638C00124FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UmBgCc:fKOe2/7c9sN3zfZR1m+RGJ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_cd87c739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd87c73901bd82017779f218e7efa0047a4f2c73b6c61e72c1a7c0d37d2f77a1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:09:28"
  condition:
    hash.sha256(0, filesize) == "cd87c73901bd82017779f218e7efa0047a4f2c73b6c61e72c1a7c0d37d2f77a1"
}
```

### Sample 47: `be4662165b56e3d3`

| Field | Value |
|---|---|
| SHA-256 | `be4662165b56e3d3b03e5cde83a8720d4af5a3a167952c1b7aefba1951078108` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 02:07:01` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3fb632e81be69f543095a3e520d7063` |
| SHA-1 | `d4c9fb89c74d0053fdfa641fdc3279e123012019` |
| SHA-256 | `be4662165b56e3d3b03e5cde83a8720d4af5a3a167952c1b7aefba1951078108` |
| SHA3-384 | `7a39de89b2e77d5d59bac2327dfc33ce23706fc6c4e297bfa3bcf37a19596847b532760dd4cde32146c5e482b5508bae` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T13B62C486ECE22F5CCE4F80703A11F878A9B53691866959E7DB838C355AA79C04434EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UhcBgn:fKOe2/7c9sN3zfZR1m+RG+c6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_be466216
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be4662165b56e3d3b03e5cde83a8720d4af5a3a167952c1b7aefba1951078108"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:07:01"
  condition:
    hash.sha256(0, filesize) == "be4662165b56e3d3b03e5cde83a8720d4af5a3a167952c1b7aefba1951078108"
}
```

### Sample 48: `ddc1d03f03ef7d82`

| Field | Value |
|---|---|
| SHA-256 | `ddc1d03f03ef7d821a8cfe5efe4220d791d07796a4a49a379893f4201e0155d4` |
| Family label | `unknown` |
| File name | `dq0hf4.exe` |
| File type | `exe` |
| First seen | `2026-09-21 01:54:24` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78a3def2ef757153d63ffa45de947d1f` |
| SHA-1 | `688caebddaeb509e6e930ae44bdbacf48fbe5d5f` |
| SHA-256 | `ddc1d03f03ef7d821a8cfe5efe4220d791d07796a4a49a379893f4201e0155d4` |
| SHA3-384 | `a2b52325cd5fd667c254c554a272b75ec6139a2e53c4e82172a52f0e02a03bafd063f2a9ffd4600e2af4d738d15309fc` |
| IMPHASH | `c2d457ad8ac36fc9f18d45bffcd450c2` |
| TLSH | `T111A65B4738D510A4D499E739C4BB53207E78BC8EC73263972F54AA781F60BD29839FA4` |
| SSDEEP | `196608:aDrIX8spybUV8diHw3oBZJJH4kVWeuaXuOYr4O3k:HIk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_ddc1d03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddc1d03f03ef7d821a8cfe5efe4220d791d07796a4a49a379893f4201e0155d4"
    family = "unknown"
    file_name = "dq0hf4.exe"
    file_type = "exe"
    first_seen = "2026-09-21 01:54:24"
  condition:
    hash.sha256(0, filesize) == "ddc1d03f03ef7d821a8cfe5efe4220d791d07796a4a49a379893f4201e0155d4"
}
```

### Sample 49: `5fabab3dc7f8b73e`

| Field | Value |
|---|---|
| SHA-256 | `5fabab3dc7f8b73ee1343b01ea9e3d7802a41d12e9a03b1c80f66b72b98fd3fa` |
| Family label | `unknown` |
| File name | `macho_5fabab3dc7f8.bin` |
| File type | `macho` |
| First seen | `2026-09-21 01:51:36` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3cbbd7dd060fe026e591901f5439a7f6` |
| SHA-1 | `583194f58e1d68b65e0d7de904d6de1316799a22` |
| SHA-256 | `5fabab3dc7f8b73ee1343b01ea9e3d7802a41d12e9a03b1c80f66b72b98fd3fa` |
| SHA3-384 | `d6263d86bd9c922946e95690f002058ed161dce10f3f18a365372b4952d58c957486c73aaf895cb3f5bd2b0171281eda` |
| TLSH | `T1DC050100CE665995F5CCDA312A6F47334E20BAB0828551CE63A65EC89F353F3E52F35A` |
| SSDEEP | `24576:IbL10UCja7gnjjtW4KVyvkAijWrg91PxSwUfA:iqZmBXGA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_5fabab3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fabab3dc7f8b73ee1343b01ea9e3d7802a41d12e9a03b1c80f66b72b98fd3fa"
    family = "unknown"
    file_name = "macho_5fabab3dc7f8.bin"
    file_type = "macho"
    first_seen = "2026-09-21 01:51:36"
  condition:
    hash.sha256(0, filesize) == "5fabab3dc7f8b73ee1343b01ea9e3d7802a41d12e9a03b1c80f66b72b98fd3fa"
}
```

### Sample 50: `0541bb4f2c603677`

| Field | Value |
|---|---|
| SHA-256 | `0541bb4f2c603677627f379c588dc8f0407f713e5290886bb2c86001d404ad23` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:47:31` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fbcc994a057e315dece6cab3d50158af` |
| SHA-1 | `7c52fc0f2840aa7a9990056fd2463013903e2dad` |
| SHA-256 | `0541bb4f2c603677627f379c588dc8f0407f713e5290886bb2c86001d404ad23` |
| SHA3-384 | `2ae3aa1044384cdb0f1c05ad7dcf9b1103d9cea8a56be71658bcf1065091540d1efba695624b071fa24efda7811f0efc` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T12D62D78AE8A22F6CDE8F90703A11F978BD7536918A6559E7D7828C355DA38D00034FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U+ClTe:fKOe2/7c9sN3zfZR1m+RGbm6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_0541bb4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0541bb4f2c603677627f379c588dc8f0407f713e5290886bb2c86001d404ad23"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:47:31"
  condition:
    hash.sha256(0, filesize) == "0541bb4f2c603677627f379c588dc8f0407f713e5290886bb2c86001d404ad23"
}
```

### Sample 51: `731d654a1ee57491`

| Field | Value |
|---|---|
| SHA-256 | `731d654a1ee574915dbf0011b9749b5393a2e4fb84f64686a7a838e4ad6dd766` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:45:09` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `07b50b21a9494b9d38a446bd9a6617ae` |
| SHA-1 | `a1dfc4862c675d84cf9da4ae0a44c22dc84058ce` |
| SHA-256 | `731d654a1ee574915dbf0011b9749b5393a2e4fb84f64686a7a838e4ad6dd766` |
| SHA3-384 | `834e976e8a1eeafcf6b71cb2a228aeb486eb49d8958bf52e9965d1ac3351fbaa8ce6a169d95ed876177b08d891559076` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15C62E786D8E22F6CDE4E80703B11F978BDB536948A6599E3D7928C305DA39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uc2T8s:fKOe2/7c9sN3zfZR1m+RG4To6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_731d654a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731d654a1ee574915dbf0011b9749b5393a2e4fb84f64686a7a838e4ad6dd766"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:45:09"
  condition:
    hash.sha256(0, filesize) == "731d654a1ee574915dbf0011b9749b5393a2e4fb84f64686a7a838e4ad6dd766"
}
```

### Sample 52: `a8c1ff106b081834`

| Field | Value |
|---|---|
| SHA-256 | `a8c1ff106b08183461fef576642b6c8a9386a437c6e6fefd1daa7ff6838eade7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:42:36` |
| Reporter | `Bitsight` |
| Tags | `0f81469cc7638ba7c82eaddbd6b3c20a, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c430aeb83cf97476d499b16138b1401` |
| SHA-1 | `22db002301da6b7f53c3981edfda9fc34d3ec5d1` |
| SHA-256 | `a8c1ff106b08183461fef576642b6c8a9386a437c6e6fefd1daa7ff6838eade7` |
| SHA3-384 | `33e660ae4819a56434af311cdd313c6dabc53ec69b499db5f0d8a0ce9972c6d6a753014230192a3e4a29a95505182ac2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T16362D686E8E22F9CDE4F80703E11F878ADB57691866569E7D7828C355EA38D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UC7xpR:fKOe2/7c9sN3zfZR1m+RGXQ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_a8c1ff10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c1ff106b08183461fef576642b6c8a9386a437c6e6fefd1daa7ff6838eade7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:42:36"
  condition:
    hash.sha256(0, filesize) == "a8c1ff106b08183461fef576642b6c8a9386a437c6e6fefd1daa7ff6838eade7"
}
```

### Sample 53: `a37649842a47b845`

| Field | Value |
|---|---|
| SHA-256 | `a37649842a47b8456a763c1b4878d08ea7ecee0ea861db2d7588f99f7e180cda` |
| Family label | `unknown` |
| File name | `dred` |
| File type | `unknown` |
| First seen | `2026-09-21 01:39:57` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10e92cfb8e3bd97b7386e1a5e6f7dfb3` |
| SHA-256 | `a37649842a47b8456a763c1b4878d08ea7ecee0ea861db2d7588f99f7e180cda` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_a3764984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a37649842a47b8456a763c1b4878d08ea7ecee0ea861db2d7588f99f7e180cda"
    family = "unknown"
    file_name = "dred"
    file_type = "unknown"
    first_seen = "2026-09-21 01:39:57"
  condition:
    hash.sha256(0, filesize) == "a37649842a47b8456a763c1b4878d08ea7ecee0ea861db2d7588f99f7e180cda"
}
```

### Sample 54: `cb6bf19586f74326`

| Field | Value |
|---|---|
| SHA-256 | `cb6bf19586f74326a26c7dd76305e236abe4b49de6ee71453299bc9ec65b9939` |
| Family label | `Mirai` |
| File name | `bot.x86_64` |
| File type | `elf` |
| First seen | `2026-09-21 01:39:56` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cd48a2a764b093e3a18ff03e0ca09a0` |
| SHA-1 | `12ee4e9424acf80ef90fc1260771a1061650b51d` |
| SHA-256 | `cb6bf19586f74326a26c7dd76305e236abe4b49de6ee71453299bc9ec65b9939` |
| SHA3-384 | `e871cd01a1e79c4c8483104c01ec5febbe5a6f2586b9bcad6983ec407795a6eb6b2418dba6263ac84db82b72162ccb27` |
| TLSH | `T1EA355C5BB2A374BCC557C430439BDA72BD35B46502226E7FA5C4DB302E26E602729F72` |
| TELFHASH | `t1e6e15cb44bf934f1a6e6e910a352f0f549771c2966ec35f11522ad98ef84fc10c7682b` |
| SSDEEP | `24576:xm8Drkx462+FnmjtfEPzRB0proqwgepxn7HYc9:xHD+462JfErRGoDgept74c9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_cb6bf195
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb6bf19586f74326a26c7dd76305e236abe4b49de6ee71453299bc9ec65b9939"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-21 01:39:56"
  condition:
    hash.sha256(0, filesize) == "cb6bf19586f74326a26c7dd76305e236abe4b49de6ee71453299bc9ec65b9939"
}
```

### Sample 55: `0766787a6a5d07b2`

| Field | Value |
|---|---|
| SHA-256 | `0766787a6a5d07b2900e2237bf33bf87ec68c9c5dec7f6b065cadc4badb8fb88` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:39:49` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `050c6f93b4d5187ed8e859af3a9acdd0` |
| SHA-1 | `dca7bc3a98700bde724676df5fb678613af58019` |
| SHA-256 | `0766787a6a5d07b2900e2237bf33bf87ec68c9c5dec7f6b065cadc4badb8fb88` |
| SHA3-384 | `1fae34f650683bd5be2ce34ab9b66b246745432cdaf06a17894a6265322d54b339b49e84f8f2c01e45bb5ce9c8b6f3d8` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19F62C68AE9A22E6CCE8EC0703A11F9786D7532D0866699E7D7D28C314DA38D01435EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U/OA7e:fKOe2/7c9sN3zfZR1m+RGAOo6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_0766787a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0766787a6a5d07b2900e2237bf33bf87ec68c9c5dec7f6b065cadc4badb8fb88"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:39:49"
  condition:
    hash.sha256(0, filesize) == "0766787a6a5d07b2900e2237bf33bf87ec68c9c5dec7f6b065cadc4badb8fb88"
}
```

### Sample 56: `c2aa2004111b9d8a`

| Field | Value |
|---|---|
| SHA-256 | `c2aa2004111b9d8a44daab4f58b2a2a3abc9fc313cf6a19d31cf4c750ba09ad8` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:38:05` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb926fa983448486b8229ed0a7989d97` |
| SHA-1 | `b12130bc9aeba7a500c18b7f6080736b55e263dd` |
| SHA-256 | `c2aa2004111b9d8a44daab4f58b2a2a3abc9fc313cf6a19d31cf4c750ba09ad8` |
| SHA3-384 | `455c60bfe17a1645e29969d7b53812a2c20104b1033a2748932aed65d7e6d36ad58ea2999d8cd5852feee58863b1a07f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14F62E686D8A26F5DEE8E80713A11F838AD7136D0862599F3D7828C345DA78D24534FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UGRvr7:fKOe2/7c9sN3zfZR1m+RGtrr6jQ+6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_c2aa2004
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2aa2004111b9d8a44daab4f58b2a2a3abc9fc313cf6a19d31cf4c750ba09ad8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:38:05"
  condition:
    hash.sha256(0, filesize) == "c2aa2004111b9d8a44daab4f58b2a2a3abc9fc313cf6a19d31cf4c750ba09ad8"
}
```

### Sample 57: `498b21cb71c948c5`

| Field | Value |
|---|---|
| SHA-256 | `498b21cb71c948c579b9c5732adf167c3899a162d8660058be750881fa1234b2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:37:26` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a634e0a37cd5e50b6dbd87c55a531fb` |
| SHA-1 | `a1b300e262446dd9540bca060659879476186568` |
| SHA-256 | `498b21cb71c948c579b9c5732adf167c3899a162d8660058be750881fa1234b2` |
| SHA3-384 | `f05bfd966d12285005a5a23a67dc22cca46968d7cd01c7c512af300bcff9c86c57eefc64d57e8e3b8092fa61ddef6857` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1FF62D78AE9D22F6CCE4ED0703A11F9387E7476948A5699E3D7C28C305DA7AD00534EBD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UWd92q:fKOe2/7c9sN3zfZR1m+RGLvQ6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_498b21cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "498b21cb71c948c579b9c5732adf167c3899a162d8660058be750881fa1234b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:37:26"
  condition:
    hash.sha256(0, filesize) == "498b21cb71c948c579b9c5732adf167c3899a162d8660058be750881fa1234b2"
}
```

### Sample 58: `14eadb08f490f786`

| Field | Value |
|---|---|
| SHA-256 | `14eadb08f490f786db8002704cfcd4241a421017f9b7f65099977a685c40cec5` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:35:35` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb7faab3e3895007f59abbf89960565e` |
| SHA-1 | `78a9dbbd5ce33f9ed59a1b1e84c00668a2dab658` |
| SHA-256 | `14eadb08f490f786db8002704cfcd4241a421017f9b7f65099977a685c40cec5` |
| SHA3-384 | `619734ba8bf9a305e2eaad8269be346e91fc6d23b56a6e3842ff296c5449b17941d5b9fb7a639900ff9ac6e861ea15d1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14C62B586D8A22F5EDE8E90703E11F8B8B9707690C67559E3D7C28C355DA39D40428EBE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46Uz/+BM:fKOe2/7c9sN3zfZR1m+RGc+6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_14eadb08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14eadb08f490f786db8002704cfcd4241a421017f9b7f65099977a685c40cec5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:35:35"
  condition:
    hash.sha256(0, filesize) == "14eadb08f490f786db8002704cfcd4241a421017f9b7f65099977a685c40cec5"
}
```

### Sample 59: `2bb36d4cb0ee3275`

| Field | Value |
|---|---|
| SHA-256 | `2bb36d4cb0ee32753b23d3f95e0324870711d6c85ff901bbc8de68b23f419db7` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:34:51` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d62e349a1c7c61ddcd2496fb0ef7dc1` |
| SHA-1 | `cfc8f6578d7c13b0d313b34d804083a957ab55dd` |
| SHA-256 | `2bb36d4cb0ee32753b23d3f95e0324870711d6c85ff901bbc8de68b23f419db7` |
| SHA3-384 | `109cccfed346feb49b2b3943fa6ecede101d9282cffce3e4a854842dfaacd1259ab80f59e0e1cbaf89e9ec83212cc3eb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1C262C78AD9A21F6DCE4F80703A11F878BDB036E0966699F3D7818C3159B39D04525FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJyLen:fKOe2/7c9sN3zfZR1m+RGlSG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_2bb36d4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bb36d4cb0ee32753b23d3f95e0324870711d6c85ff901bbc8de68b23f419db7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:34:51"
  condition:
    hash.sha256(0, filesize) == "2bb36d4cb0ee32753b23d3f95e0324870711d6c85ff901bbc8de68b23f419db7"
}
```

### Sample 60: `e86adbad6c3d13dd`

| Field | Value |
|---|---|
| SHA-256 | `e86adbad6c3d13ddab441084a6568f08bd7b72fd68de68fda6d46a560afb9a97` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:21:16` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae868d95553cf332b071da74cb60c0f6` |
| SHA-1 | `559f5756f92637e13a20192ad7523672d8d08c4e` |
| SHA-256 | `e86adbad6c3d13ddab441084a6568f08bd7b72fd68de68fda6d46a560afb9a97` |
| SHA3-384 | `ec94a7315609de2ace40a7fecf969af2452a368a4ee9e05c960f920f17bc2e38a5ca1f38f309d7eb1c359b4fa0d87230` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EE62C78AD9A2AF5CCE4ED0703F11F8686DB13A91866569E3D7828C345DA79D01034EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UI9aFp:fKOe2/7c9sN3zfZR1m+RG99v6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_e86adbad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e86adbad6c3d13ddab441084a6568f08bd7b72fd68de68fda6d46a560afb9a97"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:21:16"
  condition:
    hash.sha256(0, filesize) == "e86adbad6c3d13ddab441084a6568f08bd7b72fd68de68fda6d46a560afb9a97"
}
```

### Sample 61: `9eb24cbcd482418d`

| Field | Value |
|---|---|
| SHA-256 | `9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed` |
| Family label | `Mirai` |
| File name | `9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed` |
| File type | `elf` |
| First seen | `2026-09-21 01:19:22` |
| Reporter | `aLittleBitGrey` |
| Tags | `arm, cowrie, elf, honeypot, mirai, mozi, torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `618cb7dda81ae71c0be3857e92b20c74` |
| SHA-1 | `55b24acf3bcc8767683b7ed88147303791f7dbd4` |
| SHA-256 | `9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed` |
| SHA3-384 | `13e8a9bfa69a6de8d917b6e51bcfc5a9a894dce522291e6224a968d017c4ce6550424c9c0c43f2cbca5eeae41bd0bbe7` |
| TLSH | `T1B744398AFD80AF25D5C5267BFE2F428A33131BB8D2EB71129D145F24768A94F0F3A541` |
| SSDEEP | `6144:T2s/gAWuboqsJ9xcJxspJBqQgTuaJZRhVabE5wKSDP99zBa77oNsKqqfPqOJ:T2s/bW+UmJqBxAuaPRhVabEDSDP99zBT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_9eb24cbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed"
    family = "Mirai"
    file_name = "9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed"
    file_type = "elf"
    first_seen = "2026-09-21 01:19:22"
  condition:
    hash.sha256(0, filesize) == "9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed"
}
```

### Sample 62: `0f5e1dbcd1904061`

| Field | Value |
|---|---|
| SHA-256 | `0f5e1dbcd1904061d0f1d967ab43f8a441e8dabbda4179e0717e2aefdf6afb1a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:19:17` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6293474a6be361c394a94ef5a5fb85f` |
| SHA-1 | `d7d8a4760a390023f64d6097b9e72c20d35ae259` |
| SHA-256 | `0f5e1dbcd1904061d0f1d967ab43f8a441e8dabbda4179e0717e2aefdf6afb1a` |
| SHA3-384 | `11e04b6d4c206399ddebfad94a2a9d7b061f7662fd07230261211b09b89c325c060f9c22f6d864c99ca5d7a1b2bcf9f2` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1D762C487E8A22FADCE4E80703A11F938BD7432909A6569F7D7929D305DA79D00424EF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGNAAAAAAAAAAAAAAAAAAAAAAAAn6C:fKOeOQOzUxNAAAAAAAAAAAAAAAAAAAAy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_0f5e1dbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f5e1dbcd1904061d0f1d967ab43f8a441e8dabbda4179e0717e2aefdf6afb1a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:19:17"
  condition:
    hash.sha256(0, filesize) == "0f5e1dbcd1904061d0f1d967ab43f8a441e8dabbda4179e0717e2aefdf6afb1a"
}
```

### Sample 63: `61957e253c812ff8`

| Field | Value |
|---|---|
| SHA-256 | `61957e253c812ff892dcfe3959a766c1dad06866534ae4ad22c8b100b83519d3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:19:17` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6222bca79428b725724b49f26bcb8646` |
| SHA-1 | `493bcd14c9364f0b568e238b76587c8ae886f5e4` |
| SHA-256 | `61957e253c812ff892dcfe3959a766c1dad06866534ae4ad22c8b100b83519d3` |
| SHA3-384 | `03f2a682a42cafb021e55a8e8bbca338310c11734f569c6f0dfce5f2acb8d001150d81e9ca07350c059e8d9c6df1d376` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14A62C78AD9926F6CDE4EC0703F11F878AD747690CA6A99F7D7828D305E639D00024EF9` |
| SSDEEP | `384:fKOe2/7c9sN3zfZR1m+RGLm3GGGGGGGGGj6C:fKOeOQOzUxL36` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_61957e25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61957e253c812ff892dcfe3959a766c1dad06866534ae4ad22c8b100b83519d3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:19:17"
  condition:
    hash.sha256(0, filesize) == "61957e253c812ff892dcfe3959a766c1dad06866534ae4ad22c8b100b83519d3"
}
```

### Sample 64: `dd00defe265bd901`

| Field | Value |
|---|---|
| SHA-256 | `dd00defe265bd901fe466a7832acbe0c6d957a6ca309b6a211ddc17076a14461` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:17:31` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebefa0caff29954431f947343058fc96` |
| SHA-1 | `708481301e3b5e0e7988d8aa112ed7bd495e73d8` |
| SHA-256 | `dd00defe265bd901fe466a7832acbe0c6d957a6ca309b6a211ddc17076a14461` |
| SHA3-384 | `eb7409cec183b9d29900d61ee5a6a285c4062fed02080fd8e093bd8ecf2574b363de0905539cea7653c242aa2ffa3320` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T19E62C886ECD25E9CDE4E80703A21F83CAD727694866569E3D7818D315D639D00534EFA` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UexvBM:fKOe2/7c9sN3zfZR1m+RGh6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_dd00defe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd00defe265bd901fe466a7832acbe0c6d957a6ca309b6a211ddc17076a14461"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:17:31"
  condition:
    hash.sha256(0, filesize) == "dd00defe265bd901fe466a7832acbe0c6d957a6ca309b6a211ddc17076a14461"
}
```

### Sample 65: `a93532d58650bf02`

| Field | Value |
|---|---|
| SHA-256 | `a93532d58650bf020c997d4d2abc2fbf00a078537063c9de9e14bf8aa4df8046` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:16:53` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a07e10c38d66f00fc80c28f079385466` |
| SHA-1 | `1e19d0a86cb3f6e80b70d3e39f08609d2acb4a82` |
| SHA-256 | `a93532d58650bf020c997d4d2abc2fbf00a078537063c9de9e14bf8aa4df8046` |
| SHA3-384 | `8f06fc1b16f0afe611e1b9444d29f2dff9ff64b19bd6eea01c6f648653e839389154e342cf4e58a617d7cd6bd98c18af` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15362C48AD9A26F6CCE4E80703A11F92CBDF17690866969E3D7928C305DA3DD00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UHYBgn:fKOe2/7c9sN3zfZR1m+RGuY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_a93532d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a93532d58650bf020c997d4d2abc2fbf00a078537063c9de9e14bf8aa4df8046"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:16:53"
  condition:
    hash.sha256(0, filesize) == "a93532d58650bf020c997d4d2abc2fbf00a078537063c9de9e14bf8aa4df8046"
}
```

### Sample 66: `13feea8b62c25c3f`

| Field | Value |
|---|---|
| SHA-256 | `13feea8b62c25c3f0fc396565d0ab40874a497cd90398fd9296eccf59586174b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:16:51` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `209fbadb04b525bfb5108bd3f0705299` |
| SHA-1 | `8040315aa1f8cccd83d2b0b009db592e9c52a57d` |
| SHA-256 | `13feea8b62c25c3f0fc396565d0ab40874a497cd90398fd9296eccf59586174b` |
| SHA3-384 | `3f7c5f7245207d64a12ab08edd76e7247f227a896f9d4b0d6adf0d193bc8d6f121f522f74b26498f030707db8f3564e1` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F462D69AD9A22F6DDE4E80703A11F938B97432909A695DF3D7828C345D638D90035FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UwBgCc:fKOe2/7c9sN3zfZR1m+RGT6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_13feea8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13feea8b62c25c3f0fc396565d0ab40874a497cd90398fd9296eccf59586174b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:16:51"
  condition:
    hash.sha256(0, filesize) == "13feea8b62c25c3f0fc396565d0ab40874a497cd90398fd9296eccf59586174b"
}
```

### Sample 67: `369aab05bae5fa73`

| Field | Value |
|---|---|
| SHA-256 | `369aab05bae5fa73828e94d7aaab5bed42fb18b10236535a7f47570631bf43b1` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:16:41` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3635387a18bf1200ec9db448b29c255` |
| SHA-1 | `0938ce5e1d27b53380d12a86399e96589e480214` |
| SHA-256 | `369aab05bae5fa73828e94d7aaab5bed42fb18b10236535a7f47570631bf43b1` |
| SHA3-384 | `075002154339639aeea36e235c272aa29266e23b6e35f64bcac3cbde29fa19ef9cdc521c4616d3fdc371358f0dfc1d85` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1B962C586D9E26F6CDE4F80703B11F968ADB47AD08A6559E7D782CC309DA39D10024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UJF2rt:fKOe2/7c9sN3zfZR1m+RGgF2rk6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_369aab05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "369aab05bae5fa73828e94d7aaab5bed42fb18b10236535a7f47570631bf43b1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:16:41"
  condition:
    hash.sha256(0, filesize) == "369aab05bae5fa73828e94d7aaab5bed42fb18b10236535a7f47570631bf43b1"
}
```

### Sample 68: `cae0697aa8c68dd3`

| Field | Value |
|---|---|
| SHA-256 | `cae0697aa8c68dd3e83129bfa1d2e92fa2011912b774aa98dee6ca8d16a677ec` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:15:14` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd85357578202d939e8fc80280974d1e` |
| SHA-1 | `c53fd26294044762f9b0b67b39b9a05aeebb0d66` |
| SHA-256 | `cae0697aa8c68dd3e83129bfa1d2e92fa2011912b774aa98dee6ca8d16a677ec` |
| SHA3-384 | `87f8de29ad38efd1805883045c8a58f74bcbe50932797e736ce445cf249fe8669b8fc34f95cd248e6255f7a0477df8e3` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T15F62D5C6EDE22F6CDE8E80703A11F8287D707292866599F3D7868C215DA79D00024FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UbYmHe:fKOe2/7c9sN3zfZR1m+RGkb6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_cae0697a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae0697aa8c68dd3e83129bfa1d2e92fa2011912b774aa98dee6ca8d16a677ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:15:14"
  condition:
    hash.sha256(0, filesize) == "cae0697aa8c68dd3e83129bfa1d2e92fa2011912b774aa98dee6ca8d16a677ec"
}
```

### Sample 69: `3ff11eae1e8b38d9`

| Field | Value |
|---|---|
| SHA-256 | `3ff11eae1e8b38d9d1724c92f013fa00c4a8644649674b91f3bd9960acabfa33` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:14:24` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ba1ae8db840603c8f88682c0c82ef27` |
| SHA-1 | `de4908a446e37421eeb159fdf2c41f1083f2861d` |
| SHA-256 | `3ff11eae1e8b38d9d1724c92f013fa00c4a8644649674b91f3bd9960acabfa33` |
| SHA3-384 | `677132a7b25c8f44e5de68e13448feaa2f6ad99a0142137ff089de61422573cda993dea74008bade070210579999a815` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10162E68AD8D22E6CEE4E91707A11F828BDB4369486659DE3DB828D345DF38D00434FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UF+Bgn:fKOe2/7c9sN3zfZR1m+RGv6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_3ff11eae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ff11eae1e8b38d9d1724c92f013fa00c4a8644649674b91f3bd9960acabfa33"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:14:24"
  condition:
    hash.sha256(0, filesize) == "3ff11eae1e8b38d9d1724c92f013fa00c4a8644649674b91f3bd9960acabfa33"
}
```

### Sample 70: `89a8d6df68ed3e73`

| Field | Value |
|---|---|
| SHA-256 | `89a8d6df68ed3e7313935363c9468af937604dcae0a06c24f78c11a8e0b2f095` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:14:02` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0dd352c95d3b31c984dd6059b850f01e` |
| SHA-1 | `3df229ef50929172e996315cfdc64e0641dc9bfa` |
| SHA-256 | `89a8d6df68ed3e7313935363c9468af937604dcae0a06c24f78c11a8e0b2f095` |
| SHA3-384 | `ea2c86b70eb932b01239268469112e570fca59e726ca058f036bc5c3bb17c2bc7b25d5e61296c020b25b0e5136143c3c` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18762D686D9A32F5DEE4FC0703A21F878AE7132D9866599E7C7828D245DA39D00424FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UywBgn:fKOe2/7c9sN3zfZR1m+RGzw6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_89a8d6df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89a8d6df68ed3e7313935363c9468af937604dcae0a06c24f78c11a8e0b2f095"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:14:02"
  condition:
    hash.sha256(0, filesize) == "89a8d6df68ed3e7313935363c9468af937604dcae0a06c24f78c11a8e0b2f095"
}
```

### Sample 71: `2c94c07af82326a2`

| Field | Value |
|---|---|
| SHA-256 | `2c94c07af82326a289f7a983a1a76323f5a0860b728bd390e8ba8d0e754da7d3` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:12:26` |
| Reporter | `Bitsight` |
| Tags | `03c288afc2626e195437231037ade40b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `78e5038c4c3bb43fffd3b71794fafb4e` |
| SHA-1 | `3a39367fc6abb02f47eb4c31fe7a46109e7c2959` |
| SHA-256 | `2c94c07af82326a289f7a983a1a76323f5a0860b728bd390e8ba8d0e754da7d3` |
| SHA3-384 | `5c3400898197d7024683fea558f7155bf7c9f53d63bd55cbb723a6bc6829b21dc6ce6eb558d0a21d73ba99503f0c3863` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1EF62E78AD8A22F6CDE4E80B03A52F838BD74369089655DF3D7928C345DA78D11524FFE` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UwEGBM:fKOe2/7c9sN3zfZR1m+RGgG6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_2c94c07a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c94c07af82326a289f7a983a1a76323f5a0860b728bd390e8ba8d0e754da7d3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:12:26"
  condition:
    hash.sha256(0, filesize) == "2c94c07af82326a289f7a983a1a76323f5a0860b728bd390e8ba8d0e754da7d3"
}
```

### Sample 72: `7acfc5d3321a2253`

| Field | Value |
|---|---|
| SHA-256 | `7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f` |
| Family label | `unknown` |
| File name | `7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f.bin` |
| File type | `zip` |
| First seen | `2026-09-21 01:09:58` |
| Reporter | `Tuxxin` |
| Tags | `zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c48585da123d09bc56c48f4c69e53592` |
| SHA-1 | `ec6265b5913f0110853916dcf0a57bb0a4766e4d` |
| SHA-256 | `7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f` |
| SHA3-384 | `581a3eb252b046c81c908f38be22ebcb9b487b6bbd08238d505361af123a1791835f6d2ea3d3b3f4be72d63865fa89ee` |
| TLSH | `T16D641264630A146EC7E265125AAE808A3FCDDE0CA14FD8CB5D81971C539046CF6BE7AF` |
| SSDEEP | `6144:jelVcZr4DJYUEHlrQcFyzmqYUoOv2HeuREaEXLSqDJY4E3lPQGTOzMqmUoGpyHNB:j06cYRHl0rGGv2HeHpXL3Yt3lofa+pyj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_7acfc5d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f"
    family = "unknown"
    file_name = "7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f.bin"
    file_type = "zip"
    first_seen = "2026-09-21 01:09:58"
  condition:
    hash.sha256(0, filesize) == "7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f"
}
```

### Sample 73: `fef726f1f0c5243f`

| Field | Value |
|---|---|
| SHA-256 | `fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c` |
| Family label | `Mirai` |
| File name | `fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c.elf` |
| File type | `elf` |
| First seen | `2026-09-21 01:09:51` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1293c4a3b91ed25aac03bef2ec7bf25` |
| SHA-1 | `c7843a85f95f2bb6ae8cc8803096060034406061` |
| SHA-256 | `fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c` |
| SHA3-384 | `76c798ec9356177e27dbf80c742b1a57f6a91ba065980909b246f43324a23d7b6fe74b2d00d337d254f472cb1bff1807` |
| TLSH | `T1CC125147A2D1CE7FC8E813384457122472BBD47ADFA29713060C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5WlTTej6TNJ9VvNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTyTTfTpV7dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_fef726f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c"
    family = "Mirai"
    file_name = "fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:09:51"
  condition:
    hash.sha256(0, filesize) == "fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c"
}
```

### Sample 74: `b8ab8a050e34c800`

| Field | Value |
|---|---|
| SHA-256 | `b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133` |
| Family label | `Mirai` |
| File name | `b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133.elf` |
| File type | `elf` |
| First seen | `2026-09-21 01:09:47` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b2fda0b5ea761b1a0084915088d3331` |
| SHA-1 | `7f19264b07290b901a4ea563c341d88789e6aa7d` |
| SHA-256 | `b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133` |
| SHA3-384 | `23a744fb1d27b309bffd815f3a043b40d6377bed5fc2277657c103e51190528add1640477eb78df6dec8c82d7ee85f6e` |
| TLSH | `T1C4E16207E2D5CD72D8CD133847931749213AC86EAB83EF03650C1AA9EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFY146pwz7cSym4S2ofahbpZiQ:fsue7cHJyFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_b8ab8a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133"
    family = "Mirai"
    file_name = "b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:09:47"
  condition:
    hash.sha256(0, filesize) == "b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133"
}
```

### Sample 75: `a44dddd9f780261c`

| Field | Value |
|---|---|
| SHA-256 | `a44dddd9f780261cebeb54162f26bffb6e85811928a36ff78b7f9c2975093e0b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:09:00` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `917a2f42b5137be7a5694c9fae909ab9` |
| SHA-1 | `9d31930c2b59ecd082abbc8ee71cec515b024392` |
| SHA-256 | `a44dddd9f780261cebeb54162f26bffb6e85811928a36ff78b7f9c2975093e0b` |
| SHA3-384 | `ad0d2440108341a23ee373bc5eaa1e4dcfd24c3fdee5329b01877629e57f921b9f996477aefad0131821e6cba579d3f3` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T17762E586D8E22F5CCE4E90703B11FA2CED753690966599E3D7828C365EA3CE10524FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1HBgn:fKOe2/7c9sN3zfZR1m+RGgH6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_a44dddd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a44dddd9f780261cebeb54162f26bffb6e85811928a36ff78b7f9c2975093e0b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:09:00"
  condition:
    hash.sha256(0, filesize) == "a44dddd9f780261cebeb54162f26bffb6e85811928a36ff78b7f9c2975093e0b"
}
```

### Sample 76: `3e1641122d009db6`

| Field | Value |
|---|---|
| SHA-256 | `3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa` |
| Family label | `Snowlight` |
| File name | `3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa.elf` |
| File type | `elf` |
| First seen | `2026-09-21 01:08:59` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe76dc8af53e1f4f5fa118e679683f48` |
| SHA-1 | `196b0499ea53be6f4b0e1647c673fe52f41eb86c` |
| SHA-256 | `3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa` |
| SHA3-384 | `d1868c11e64802616c27213f14c8d9420424fec3a8ccfdc155847525adcb679844b9a967bede527561dd5ab10e5cd9c0` |
| TLSH | `T19DE17117E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw38Jheuhih5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbsJhA/Zz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_076_3e164112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa"
    family = "Snowlight"
    file_name = "3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:08:59"
  condition:
    hash.sha256(0, filesize) == "3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa"
}
```

### Sample 77: `9c1a4318df911281`

| Field | Value |
|---|---|
| SHA-256 | `9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6` |
| Family label | `Mirai` |
| File name | `9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6.elf` |
| File type | `elf` |
| First seen | `2026-09-21 01:08:55` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `233a647d0c3062b6e3c6fcd8b98e564c` |
| SHA-1 | `87f988262b04c7d974bc7ab8f7da721cc3cc4b28` |
| SHA-256 | `9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6` |
| SHA3-384 | `a5dc57ac180dbd1329e3f223cbd964247bb2ba0030efe492093e4f0ee918525cb49ddb5be718d295784a681e3b950a0a` |
| TLSH | `T109E16207E2D5CE72D8CD133847931749213AC86EAB83AF03650C5999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFp146Hwz7cSym4S2ofahbpZiQ:fsue7ccJQFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_9c1a4318
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6"
    family = "Mirai"
    file_name = "9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:08:55"
  condition:
    hash.sha256(0, filesize) == "9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6"
}
```

### Sample 78: `a031852c5688f26a`

| Field | Value |
|---|---|
| SHA-256 | `a031852c5688f26aab531cca341576bc1098727320199e0f5bb3bd2a6caff94b` |
| Family label | `Mirai` |
| File name | `Space.arm7` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e2f8602fdfdbc0ad783829d18a06c90` |
| SHA-1 | `04aa03063f92c71b0c5e430767d122f889cc16bf` |
| SHA-256 | `a031852c5688f26aab531cca341576bc1098727320199e0f5bb3bd2a6caff94b` |
| SHA3-384 | `4d461be7fa8977effe34a5673a143a1c7e516384dea24543a6bf77ddbade786888efa80e2d4d9f8e298028b51e3b2491` |
| TLSH | `T183F33A46F6418B13C0D61779BA9F424533239BA4E3DB73069928BFF43F8279A0E67905` |
| TELFHASH | `t1f821f071133645146a71caa88decb7b2052887122385ff33ef3ac8dc5809095e939c0f` |
| SSDEEP | `3072:62bmltngzA0BJaq/xGP40Gv/KYZ+W9L6MjccDjyoM/9Hc03:pbmltSJaq/xGPu/H+wL6OccDj1M/9803` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_a031852c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a031852c5688f26aab531cca341576bc1098727320199e0f5bb3bd2a6caff94b"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:39"
  condition:
    hash.sha256(0, filesize) == "a031852c5688f26aab531cca341576bc1098727320199e0f5bb3bd2a6caff94b"
}
```

### Sample 79: `b4cea7e82069bca6`

| Field | Value |
|---|---|
| SHA-256 | `b4cea7e82069bca6d19f51e04362b13adb9ada4d9564779bff961e936e11531d` |
| Family label | `Mirai` |
| File name | `Space.x86_64` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b0c92d91bbb2543d3396e6938788a65` |
| SHA-1 | `b7b48b258330321726e237038eccfa6e992790f8` |
| SHA-256 | `b4cea7e82069bca6d19f51e04362b13adb9ada4d9564779bff961e936e11531d` |
| SHA3-384 | `ce00cbc188287eb3c454de37a4e23cc8e9ecde576eb73c00a4c826db6130bb71e2eea0fc9c0f79d8f1e5b94d52f6c3d3` |
| TLSH | `T197733A17BA4080FEC899C43843BABA36DC7274FE1379725A17D4FE366D55E601E29C84` |
| TELFHASH | `t1ad2145b039590da0f0ebe468b305e1561d391a6004e2b8f3d9b790f3eb517870db5427` |
| SSDEEP | `1536:DeuIZobG3QEWYAIb/+w4HnC+8l8Anzcf8:quIZTAEzAIf4HT8l8Azcf8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_b4cea7e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4cea7e82069bca6d19f51e04362b13adb9ada4d9564779bff961e936e11531d"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:36"
  condition:
    hash.sha256(0, filesize) == "b4cea7e82069bca6d19f51e04362b13adb9ada4d9564779bff961e936e11531d"
}
```

### Sample 80: `e7804767a5e607b1`

| Field | Value |
|---|---|
| SHA-256 | `e7804767a5e607b192396a919226a5b6aa64f8078f4c5b63e4569a2de23a8531` |
| Family label | `Mirai` |
| File name | `Space.arm6` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c626816e62c53225cb53ca7e7eb346ef` |
| SHA-1 | `4adacea9e39be5a0007103a305ef352758d2f3b4` |
| SHA-256 | `e7804767a5e607b192396a919226a5b6aa64f8078f4c5b63e4569a2de23a8531` |
| SHA3-384 | `0c44c4f35fc166cf032799ba5b2ae4610946a7a6da29048803cedeeabd6e454ed586dd80fb38b0e1d28f3288632834d6` |
| TLSH | `T1DF83185AF8814B21D5C512BAFA1E164E331307FCE3DE72239E24AF7037CA51B0E6A855` |
| TELFHASH | `t1ac012090098939cda4b88f6580dd75297a6d3876fc32183a8fa3b71a81236d72739409` |
| SSDEEP | `1536:mpnQQmY6CpD2sAKv7iszt1BREBfSHJkaU6n3coIhriX4NidwT7245zYtN:Ym0D2ymQE5SHJkaUdG4NidwTa4V0N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_e7804767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7804767a5e607b192396a919226a5b6aa64f8078f4c5b63e4569a2de23a8531"
    family = "Mirai"
    file_name = "Space.arm6"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:34"
  condition:
    hash.sha256(0, filesize) == "e7804767a5e607b192396a919226a5b6aa64f8078f4c5b63e4569a2de23a8531"
}
```

### Sample 81: `1b6c2dd0d3b6b01e`

| Field | Value |
|---|---|
| SHA-256 | `1b6c2dd0d3b6b01efda1a44ca63ce4168129b0ef3e415f96ba1d7af77aad20b7` |
| Family label | `Mirai` |
| File name | `Space.arm5` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a08bf4ab6a40117f3c04fd57425524c6` |
| SHA-1 | `27a64122d267d879434187dc3be61afbd90a349c` |
| SHA-256 | `1b6c2dd0d3b6b01efda1a44ca63ce4168129b0ef3e415f96ba1d7af77aad20b7` |
| SHA3-384 | `190edee097d0c1125d05d82e42269417f428f32d4895fbf388ff9ae2a3e491b2621ac39113b8c9973480ff7221394c28` |
| TLSH | `T169132946FCC24A3FC2C013BAA66E5A4E3761E3E5D2CB760B9E54577136C620F1D2AD80` |
| TELFHASH | `t1e4e06840fc755e1854e76570dcdc47b095012223606a4b20cf55dae0883f110e30ce4d` |
| SSDEEP | `768:DO2bf2SHD3pDi9ZbyE2h44Gi6ZQqQdMOFUZWJdzBNewGoOw:DiSHDUJn2hPq4dMOSWd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_1b6c2dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b6c2dd0d3b6b01efda1a44ca63ce4168129b0ef3e415f96ba1d7af77aad20b7"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:32"
  condition:
    hash.sha256(0, filesize) == "1b6c2dd0d3b6b01efda1a44ca63ce4168129b0ef3e415f96ba1d7af77aad20b7"
}
```

### Sample 82: `f3011161d8bd6ca8`

| Field | Value |
|---|---|
| SHA-256 | `f3011161d8bd6ca8cfb7221d69bcfd2e094d5fda28c09a6069a036c8a6931bae` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 01:04:30` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a2b719536d65f30b8044b6e0c39ea54` |
| SHA-1 | `d559baec3b858fd2ebc19cc4a49f669e00cb118b` |
| SHA-256 | `f3011161d8bd6ca8cfb7221d69bcfd2e094d5fda28c09a6069a036c8a6931bae` |
| SHA3-384 | `a024665b1bc3298384ea1123eb7ea8083e00ff481a7633663fba2979c5e8d614c444dd654324d15455db061725e2c61f` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T10162C586EDA22FADDE4F80703B11FC287D757290866669E3D7828C3159A79D00634EF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1YBgn:fKOe2/7c9sN3zfZR1m+RGYY6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_f3011161
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3011161d8bd6ca8cfb7221d69bcfd2e094d5fda28c09a6069a036c8a6931bae"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:04:30"
  condition:
    hash.sha256(0, filesize) == "f3011161d8bd6ca8cfb7221d69bcfd2e094d5fda28c09a6069a036c8a6931bae"
}
```

### Sample 83: `84afbce29ba3d166`

| Field | Value |
|---|---|
| SHA-256 | `84afbce29ba3d166d549ba14dc919fe5edde84dd2c0314ece3cdf5f40f68c37c` |
| Family label | `Mirai` |
| File name | `Space.arm` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e37bfe219d6e0a138e73278790336ce4` |
| SHA-1 | `f4353761580b542849ef5020166d267c205c3ca6` |
| SHA-256 | `84afbce29ba3d166d549ba14dc919fe5edde84dd2c0314ece3cdf5f40f68c37c` |
| SHA3-384 | `2279503131a370d39eaad5179cffe984815854242bd7d10f451718ebcc93b243fb749854c1a0068d673a90580a63aae2` |
| TLSH | `T144733A56FC814A23C6C1127BFB6E468D3B2653E8E2DA72039E259F3133C751B0D6B895` |
| TELFHASH | `t1bf4143b1e7b40bdc67c0c704c24a9265aeb4316d771034a38b2d978b92d3bc1b11e42b` |
| SSDEEP | `1536:WB/VU93ilj19ZBpG1atb2tA+qhx9Qf8vN6:WB/VBBpG1atvRRN6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_84afbce2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84afbce29ba3d166d549ba14dc919fe5edde84dd2c0314ece3cdf5f40f68c37c"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:30"
  condition:
    hash.sha256(0, filesize) == "84afbce29ba3d166d549ba14dc919fe5edde84dd2c0314ece3cdf5f40f68c37c"
}
```

### Sample 84: `a2863d10f67f1c6a`

| Field | Value |
|---|---|
| SHA-256 | `a2863d10f67f1c6a2e9b55bfdd972d9e316f796e9be516bfe9f3cda8316caca8` |
| Family label | `Mirai` |
| File name | `Space.x86` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c588236c9e12f411815509a5ecb89df` |
| SHA-1 | `dbaa99b63d42bf7648431c033b2d8abedb432f0b` |
| SHA-256 | `a2863d10f67f1c6a2e9b55bfdd972d9e316f796e9be516bfe9f3cda8316caca8` |
| SHA3-384 | `fc7d1348b665deceeb6fc42e6f4c0f88bba905476129a3bbefe2b458b5b2a4c3fdce3474e3f1fc2763c8e397dcab4429` |
| TLSH | `T1A1634BC9F983D5B6F8970930107AAF639DB3D6BE21A8DA43C3B45536AD12502F412E6C` |
| TELFHASH | `t121214cf75e1e48e8f3c4a840c35eaa55192ad677086136e445b2ccd036e7dc194bdc39` |
| SSDEEP | `1536:TtWvgqAC7sTb6vF7lOvZOWsIyq3XkZSQn:TtDqAC7sn6NJOvwfIyq8n` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_a2863d10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2863d10f67f1c6a2e9b55bfdd972d9e316f796e9be516bfe9f3cda8316caca8"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:26"
  condition:
    hash.sha256(0, filesize) == "a2863d10f67f1c6a2e9b55bfdd972d9e316f796e9be516bfe9f3cda8316caca8"
}
```

### Sample 85: `b3c25fc4ff0b36f9`

| Field | Value |
|---|---|
| SHA-256 | `b3c25fc4ff0b36f9e2d227667cce1b67195eb1ee155045f11dfe046abcb76fcf` |
| Family label | `Mirai` |
| File name | `Space.arm7` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5e4174fb3f9b81402868631118e5445` |
| SHA-1 | `2281dd2aa1f10340a40cf10cfe7776b51794604c` |
| SHA-256 | `b3c25fc4ff0b36f9e2d227667cce1b67195eb1ee155045f11dfe046abcb76fcf` |
| SHA3-384 | `3a9a8467e439688dd87edcaf61753367734f919155e1f9f82632b1d21a28abbe23ac48f17b49fd62ed198a7f48bf0475` |
| TLSH | `T1AC530250E80A89F7F3606BF49CB1E907E9A96BB4B9454841107CF12880F7A41B97E78B` |
| SSDEEP | `1536:JVQgIB+iQv0pfhr5T3eI6Jj6f0rWLNM5Tfv83KJJSFkr:JVIB+iQv0pfbTONJj6MaLeTX83Kckr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_b3c25fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3c25fc4ff0b36f9e2d227667cce1b67195eb1ee155045f11dfe046abcb76fcf"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:12"
  condition:
    hash.sha256(0, filesize) == "b3c25fc4ff0b36f9e2d227667cce1b67195eb1ee155045f11dfe046abcb76fcf"
}
```

### Sample 86: `a4fad26f865fe4a7`

| Field | Value |
|---|---|
| SHA-256 | `a4fad26f865fe4a7397bc21094c45def5e6fe6ab332f379380c3e7a316e86d92` |
| Family label | `Mirai` |
| File name | `Space.x86_64` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1de792f099ad122a780201040da0db50` |
| SHA-1 | `917114ab1f4bbc0aa53d9b145103537d2577b02e` |
| SHA-256 | `a4fad26f865fe4a7397bc21094c45def5e6fe6ab332f379380c3e7a316e86d92` |
| SHA3-384 | `6f139e015942d8a764db6fda0fd5bc1cbcd029e4782c63a9a2d30b5ca7b5ab5acab27b86625d7409c788236b2f0e6c63` |
| TLSH | `T1D0F2F1DBD23FC4B9ED3741B32668C39831A5A0C7A90917A20A9D537F4DA363D2944BC1` |
| SSDEEP | `768:Wkjvsa/voIrDuWYZHmqtdE4lNlsqC9h0+oNYXlL+Bq+TaO9OsV723NAZl1QxUx0c:NzHz5i5lbEDoNeCwCYWMZO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_a4fad26f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4fad26f865fe4a7397bc21094c45def5e6fe6ab332f379380c3e7a316e86d92"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:11"
  condition:
    hash.sha256(0, filesize) == "a4fad26f865fe4a7397bc21094c45def5e6fe6ab332f379380c3e7a316e86d92"
}
```

### Sample 87: `efc1ac998c9be84b`

| Field | Value |
|---|---|
| SHA-256 | `efc1ac998c9be84b72fb26cce3a51931e460319cd662ae9097cdb5c776bdbe92` |
| Family label | `Mirai` |
| File name | `Space.arm6` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbc4b5443a733680fc59646d44ea54eb` |
| SHA-1 | `8df7c17945056a398a38f9072cd4a07fefc75e6a` |
| SHA-256 | `efc1ac998c9be84b72fb26cce3a51931e460319cd662ae9097cdb5c776bdbe92` |
| SHA3-384 | `3bbdb1e041517060b617c80811c99779433e4f0809ec4fb74d69fc98bb3f99c1e49424c6310cc9aa68d35b404d117a0c` |
| TLSH | `T13D03F2751364A8D3ADA0347A6DA405CDFFA0437AE3F735A24A38486DC3BA2442CB47C7` |
| SSDEEP | `768:UGPjXBOTsh1ewTyMdi6myAysX+9LVfSFAL330uhWLpNuL9q3UEL99:BLYCNlAHX+BVf5jknLVL/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_efc1ac99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc1ac998c9be84b72fb26cce3a51931e460319cd662ae9097cdb5c776bdbe92"
    family = "Mirai"
    file_name = "Space.arm6"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:09"
  condition:
    hash.sha256(0, filesize) == "efc1ac998c9be84b72fb26cce3a51931e460319cd662ae9097cdb5c776bdbe92"
}
```

### Sample 88: `75596ce797ee68d6`

| Field | Value |
|---|---|
| SHA-256 | `75596ce797ee68d6ba16058f70eddbf7915299d1938c5f871dcda536d6f6d2d0` |
| Family label | `Mirai` |
| File name | `Space.arm5` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b8d22e06c47aba6ab6637dbd981baa0` |
| SHA-1 | `37cfac1e311d07b45c25fabbdd82f72e466fe80f` |
| SHA-256 | `75596ce797ee68d6ba16058f70eddbf7915299d1938c5f871dcda536d6f6d2d0` |
| SHA3-384 | `0c1af28300372ee9f6915cb118dd69a2e17e88fc60aff93949fb66832465a4fc02b8a51ef5c817c2916c867c4e29d725` |
| TLSH | `T18392D0A085C3B876C5308C34B3F987937767CFBFC2E23997962043A4654319E42BDA45` |
| SSDEEP | `384:sGTgbm9lMrpGyeqOyNP1QBFLj/VlVuiCF+RWoirhymdGUop5htc:7gjplNtQBpPVdCcRKs3UozLc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_75596ce7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75596ce797ee68d6ba16058f70eddbf7915299d1938c5f871dcda536d6f6d2d0"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:08"
  condition:
    hash.sha256(0, filesize) == "75596ce797ee68d6ba16058f70eddbf7915299d1938c5f871dcda536d6f6d2d0"
}
```

### Sample 89: `31921683c81079a6`

| Field | Value |
|---|---|
| SHA-256 | `31921683c81079a60502a35e6b4ec4f9afe34276a9229a2685ee4f2daa2d46f6` |
| Family label | `Mirai` |
| File name | `Space.arm` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf1c9a1b8984595ba3455a8d70b4cf05` |
| SHA-1 | `49f41b5858f05a457bc6cc045ef7f4bb7ec2ed66` |
| SHA-256 | `31921683c81079a60502a35e6b4ec4f9afe34276a9229a2685ee4f2daa2d46f6` |
| SHA3-384 | `a110263d0658f928b09e3d3dd23d387bb8f008705f03980f6f9cc032b918d9855c65f5a571109dde3bb8d404204455cd` |
| TLSH | `T191F2F1203011B9E4E6A0453BDF7996C6E3AE82A59193351D5A2503FEA48F6C295FC3E3` |
| SSDEEP | `768:qQKd4TIv86wHqEGBFePMdayb0zDWX5pq2PvAsws3Uoz0:qQKSIbtYMHaDy5p/PvLlz0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_31921683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31921683c81079a60502a35e6b4ec4f9afe34276a9229a2685ee4f2daa2d46f6"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:07"
  condition:
    hash.sha256(0, filesize) == "31921683c81079a60502a35e6b4ec4f9afe34276a9229a2685ee4f2daa2d46f6"
}
```

### Sample 90: `0fb25f6e2b685d8f`

| Field | Value |
|---|---|
| SHA-256 | `0fb25f6e2b685d8f8b1843b8d11e0ac81be09a498010ebf87aac1a4d6a3e42f3` |
| Family label | `Mirai` |
| File name | `Space.sh4` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52d120ecea0d74682d75de27efd9a5ed` |
| SHA-1 | `2dfdfd63781e5498b36057a0eebbff5bf3c5d01c` |
| SHA-256 | `0fb25f6e2b685d8f8b1843b8d11e0ac81be09a498010ebf87aac1a4d6a3e42f3` |
| SHA3-384 | `f74cb32ad17bead1f0ecdbeaaf2641590550d0f5d0f16e54fbaa9fcefcc42cc43f83b42c68b3c11d01877df025dd6f8d` |
| TLSH | `T190639E16D8211899C286C5B4B1ECCE3A1B13A5C063837EF7566AC3B5A067D9CF849FF4` |
| SSDEEP | `1536:Qaw/uMkOts9CWQ1KcTlh7BTRLzCIMpCtPKxu:QZVkwsQWQccnxRLz0GCxu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_0fb25f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fb25f6e2b685d8f8b1843b8d11e0ac81be09a498010ebf87aac1a4d6a3e42f3"
    family = "Mirai"
    file_name = "Space.sh4"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:06"
  condition:
    hash.sha256(0, filesize) == "0fb25f6e2b685d8f8b1843b8d11e0ac81be09a498010ebf87aac1a4d6a3e42f3"
}
```

### Sample 91: `7412bbd1ce42b879`

| Field | Value |
|---|---|
| SHA-256 | `7412bbd1ce42b8799cd74063e95b4870f26f75e4b0b4d3367b067398835124be` |
| Family label | `Mirai` |
| File name | `Space.x86` |
| File type | `elf` |
| First seen | `2026-09-21 01:04:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee3aa5a2a13d9870d2c11e1bba34e48e` |
| SHA-1 | `88635e5b72c628f9c7eceeacc2645515ed045d06` |
| SHA-256 | `7412bbd1ce42b8799cd74063e95b4870f26f75e4b0b4d3367b067398835124be` |
| SHA3-384 | `bf0f1ba0e9bb71c595c2c4abae4b9866ad36d0d0f9f98c6cdd2ea4902a3cdb0cc42471e36371890843f69435d2991cdd` |
| TLSH | `T12DF2E103868AC792FA2E0339BCDDBD4D0951535DBB926821DB94E1734484F1E8E3E2DB` |
| SSDEEP | `768:LzbGjwng3vdOXjjYNAEiuWD2ILrm1Xey6aEyeRI7bxYtcTnbcuyD7UHQRjB:fdnA0Y7EjmQCd7bxYYnouy8Hyd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_7412bbd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7412bbd1ce42b8799cd74063e95b4870f26f75e4b0b4d3367b067398835124be"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:05"
  condition:
    hash.sha256(0, filesize) == "7412bbd1ce42b8799cd74063e95b4870f26f75e4b0b4d3367b067398835124be"
}
```

### Sample 92: `6b3f3cef5349a61f`

| Field | Value |
|---|---|
| SHA-256 | `6b3f3cef5349a61f3ffe1631e01a7ff4fe28f1ee2e8e3e0fdf4c81b42036196d` |
| Family label | `Mirai` |
| File name | `Space.mips` |
| File type | `elf` |
| First seen | `2026-09-21 01:03:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11870a0f1a90c8d7bf5897e343b2db1c` |
| SHA-1 | `55f9eca75f976dfaf1dbcbebcb22c93e658c1973` |
| SHA-256 | `6b3f3cef5349a61f3ffe1631e01a7ff4fe28f1ee2e8e3e0fdf4c81b42036196d` |
| SHA3-384 | `41a7f7b372ab44620f9e562fe1fdbee8e0db53d53c9de45905a414580af3ff9bf6c8b080abe80e52727802880c548522` |
| TLSH | `T198A3B44D7E318FBEFBEC823447B39A12A65927D533E1C585D2ADD2011E7024E681FBA4` |
| TELFHASH | `t11a117c18893812f097751c9d6bedff76e6a130cf4a265e378d00f85eaa2dd425e00c1c` |
| SSDEEP | `1536:WpaZOuT/Q30SQXa1r3J62yqPy/RWLW0edmpwjeqNY0:lZzTJa1rZ62yqPy/ULWzjeqNP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_6b3f3cef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b3f3cef5349a61f3ffe1631e01a7ff4fe28f1ee2e8e3e0fdf4c81b42036196d"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:17"
  condition:
    hash.sha256(0, filesize) == "6b3f3cef5349a61f3ffe1631e01a7ff4fe28f1ee2e8e3e0fdf4c81b42036196d"
}
```

### Sample 93: `0dcd1d1183936c90`

| Field | Value |
|---|---|
| SHA-256 | `0dcd1d1183936c9035f2cb9cba8d2eefa12531b9625b9ce6f8dba3ba1fafaf5c` |
| Family label | `Mirai` |
| File name | `Space.m68k` |
| File type | `elf` |
| First seen | `2026-09-21 01:03:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5014551ccc9d75840b4cdc808fbdf917` |
| SHA-1 | `8fdc93c2c30e45b9eb6bf7ee1e22e4328cdfc89d` |
| SHA-256 | `0dcd1d1183936c9035f2cb9cba8d2eefa12531b9625b9ce6f8dba3ba1fafaf5c` |
| SHA3-384 | `20e0b3eedf8122eab824b90082358b01ee3c045ead0066ed637927f330b1975a14324605fb84cfc6ecddb8611287a4ee` |
| TLSH | `T1FE83198BF800DD7DF80FDAB74453490EB931E3910A931A377767BDA7AC721A14826E85` |
| SSDEEP | `1536:XQOjxmw2V2xAYV8afTybJYxYAhJ6r48980jTUhtIpu1HHr+t2c9I/bz0pz:XQO4QfTVdhJ6rk/tCupy9I/P0pz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_0dcd1d11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dcd1d1183936c9035f2cb9cba8d2eefa12531b9625b9ce6f8dba3ba1fafaf5c"
    family = "Mirai"
    file_name = "Space.m68k"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:05"
  condition:
    hash.sha256(0, filesize) == "0dcd1d1183936c9035f2cb9cba8d2eefa12531b9625b9ce6f8dba3ba1fafaf5c"
}
```

### Sample 94: `a6a895a12575751e`

| Field | Value |
|---|---|
| SHA-256 | `a6a895a12575751e60ac5b1fa76c969c3beba983330c01941150a07d3b7c0891` |
| Family label | `Mirai` |
| File name | `Space.spc` |
| File type | `elf` |
| First seen | `2026-09-21 01:03:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `701fd54d78336fe2a908bc425072f33b` |
| SHA-1 | `9bf11d64c979e81f031afc92e3931b05eb90621a` |
| SHA-256 | `a6a895a12575751e60ac5b1fa76c969c3beba983330c01941150a07d3b7c0891` |
| SHA3-384 | `fb16850d44a6f4d07220182d33af99c3da91a1893116fc339f179e65ba68ef5b557b968f51eb3e91ee46671d79301417` |
| TLSH | `T170734B31F939092BC0D4917A61F74723B5F297CA20A8861F3E720F9DBF615403A57AB9` |
| SSDEEP | `1536:U2kN6QCXbqt5guvvF7tR7SYm5BHxS1H1tT7fT:HhilL7SYOBR27fT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_a6a895a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6a895a12575751e60ac5b1fa76c969c3beba983330c01941150a07d3b7c0891"
    family = "Mirai"
    file_name = "Space.spc"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:04"
  condition:
    hash.sha256(0, filesize) == "a6a895a12575751e60ac5b1fa76c969c3beba983330c01941150a07d3b7c0891"
}
```

### Sample 95: `f976a3b51c470d22`

| Field | Value |
|---|---|
| SHA-256 | `f976a3b51c470d22f5129bb5930dadc7447d0ae383c4d90bc3c1a2e00e252658` |
| Family label | `Mirai` |
| File name | `Space.mips` |
| File type | `elf` |
| First seen | `2026-09-21 01:03:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `32caec6bbbeb54014b7b11e623a621a6` |
| SHA-1 | `7bfe732361376f5ada515e89882e6a38eda6903f` |
| SHA-256 | `f976a3b51c470d22f5129bb5930dadc7447d0ae383c4d90bc3c1a2e00e252658` |
| SHA3-384 | `1375ec118ce2123d54c383d6747ee5c932ddfd85ae8ff684dabf4cc0dc93d1b6646622c8998d4356d9aef310b31a9bdc` |
| TLSH | `T13803F1A6BD300899EEBDD0B80FDC0B215DA80F6594560D2679D3E3539FE3075348AAED` |
| SSDEEP | `768:kyI187beFSc+RX4qCw7kwGDGRfHBENJwjJJgGlzDpbuR1JC:kyf7beMbIqCw7jcGXOGj7VJu0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_f976a3b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f976a3b51c470d22f5129bb5930dadc7447d0ae383c4d90bc3c1a2e00e252658"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:03"
  condition:
    hash.sha256(0, filesize) == "f976a3b51c470d22f5129bb5930dadc7447d0ae383c4d90bc3c1a2e00e252658"
}
```

### Sample 96: `e4ca83ae8c8c4f62`

| Field | Value |
|---|---|
| SHA-256 | `e4ca83ae8c8c4f6263f7f43550b1dd7dc0b2d8852fe6602234553916a0d4e6ca` |
| Family label | `Mirai` |
| File name | `Space.arc` |
| File type | `elf` |
| First seen | `2026-09-21 01:03:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15b0a7b77ba68ee05a86a9f78743fce4` |
| SHA-1 | `5254b5643169fc5e8fba4cee164bb88cb692564d` |
| SHA-256 | `e4ca83ae8c8c4f6263f7f43550b1dd7dc0b2d8852fe6602234553916a0d4e6ca` |
| SHA3-384 | `4e80a045191c5c65b82d883f7f8336b8d1787972b2a4eee5c8b257629a032cf2ad52308eaf5b6052ccd0ba370e0567b3` |
| TLSH | `T148B3AEEBF64725A2C85243F013C79FCE3E232291AE57A4E76C1E267B15760DB1D06B81` |
| SSDEEP | `1536:hkc9afIgfD3zS0aRGGTlRl3xHFpexJ6jngJP/LWe:OfIq3u0ZEnl5FpdngJPq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_e4ca83ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4ca83ae8c8c4f6263f7f43550b1dd7dc0b2d8852fe6602234553916a0d4e6ca"
    family = "Mirai"
    file_name = "Space.arc"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:02"
  condition:
    hash.sha256(0, filesize) == "e4ca83ae8c8c4f6263f7f43550b1dd7dc0b2d8852fe6602234553916a0d4e6ca"
}
```

### Sample 97: `8f0332933d8f2400`

| Field | Value |
|---|---|
| SHA-256 | `8f0332933d8f240083e9ff173852177f45b48372a6df64a22dc577d3b120b89a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 00:46:44` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e15cf40af58e78a8cfb9c608a930ecfa` |
| SHA-1 | `8e7d1803e6a333e60f8fcbd3c04ace7561b233bf` |
| SHA-256 | `8f0332933d8f240083e9ff173852177f45b48372a6df64a22dc577d3b120b89a` |
| SHA3-384 | `1da67066e6ea07dc595bf7609192555b5b1fc68a611c436b09266cd8110ae6a70772d05b1a1cf9dde9ea30fb642e1c72` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T18462D786E9A25F5ECE4F80B03A11F838A97077D58A265DE3D7928C7549A39D00434EFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U13Bgn:fKOe2/7c9sN3zfZR1m+RGk36C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_8f033293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0332933d8f240083e9ff173852177f45b48372a6df64a22dc577d3b120b89a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 00:46:44"
  condition:
    hash.sha256(0, filesize) == "8f0332933d8f240083e9ff173852177f45b48372a6df64a22dc577d3b120b89a"
}
```

### Sample 98: `f2cd69b0448ff01b`

| Field | Value |
|---|---|
| SHA-256 | `f2cd69b0448ff01b89adcf5670f38e1f66da6861564e32a395facc156fcc3d89` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 00:44:25` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb6246fb501314bb93f99f3a02b27ff8` |
| SHA-1 | `6e5c56fc3403737785ea1b6848c6a8064dc23f33` |
| SHA-256 | `f2cd69b0448ff01b89adcf5670f38e1f66da6861564e32a395facc156fcc3d89` |
| SHA3-384 | `61c0b93255f314e9a468d48a486d28fc4d534555445ddfaec791e328d5e00f334a140da34e0eaf5a9f6917677b23156e` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T14B62D686D8A26F5CDE8F80703A11FC38BE7436908A6569E7D7928D345DA79C10038FF9` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46U1BgCc:fKOe2/7c9sN3zfZR1m+RGK6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_f2cd69b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2cd69b0448ff01b89adcf5670f38e1f66da6861564e32a395facc156fcc3d89"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 00:44:25"
  condition:
    hash.sha256(0, filesize) == "f2cd69b0448ff01b89adcf5670f38e1f66da6861564e32a395facc156fcc3d89"
}
```

### Sample 99: `0d0ee878ce80bba9`

| Field | Value |
|---|---|
| SHA-256 | `0d0ee878ce80bba959f48fbf1d3220b135ad18625eeb62aa89a6a16c3308fdda` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-09-21 00:42:01` |
| Reporter | `Bitsight` |
| Tags | `5a4378fb90db39f09c7b18d1f314e645, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `298c7a63092957ca5dd1d823d086dd2d` |
| SHA-1 | `5b3d4e5afe79a653d059812943f966fb4e2841cc` |
| SHA-256 | `0d0ee878ce80bba959f48fbf1d3220b135ad18625eeb62aa89a6a16c3308fdda` |
| SHA3-384 | `a587c6ff208854cd2aa22f2dbb1371b0cd383429bb6a47c8b6ef5942e165e7d6977f5b0ffcd6e028d36c45caa88a3fdb` |
| IMPHASH | `c64a9aaa58707c34f0569020880351cb` |
| TLSH | `T1F162C68BD8A22E5CDE4F90713A11F978A97472A096A65DE3D792CC305AA39D00434FFD` |
| SSDEEP | `192:fqHOoLPoHeVQBNBY0fidcj3wJLsN3AAK8BzvTt1NpkAm1paLsehDPP0B46UB38nc:fKOe2/7c9sN3zfZR1m+RGDV6C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_0d0ee878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0ee878ce80bba959f48fbf1d3220b135ad18625eeb62aa89a6a16c3308fdda"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 00:42:01"
  condition:
    hash.sha256(0, filesize) == "0d0ee878ce80bba959f48fbf1d3220b135ad18625eeb62aa89a6a16c3308fdda"
}
```

### Sample 100: `c254bf1cd9ab1496`

| Field | Value |
|---|---|
| SHA-256 | `c254bf1cd9ab1496ad01785ed181bd6e314534bb1f079a4bc4616b40a8fd62ee` |
| Family label | `unknown` |
| File name | `macho_c254bf1cd9ab.bin` |
| File type | `macho` |
| First seen | `2026-09-21 00:41:55` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `891e75f66f5c7bc7b7db86bdbb205a89` |
| SHA-1 | `6dc47ffd0340b36e6ca5a00e71e2a7f79a1215c9` |
| SHA-256 | `c254bf1cd9ab1496ad01785ed181bd6e314534bb1f079a4bc4616b40a8fd62ee` |
| SHA3-384 | `7c16b288ab9b511ae07ce081fcfe5925c6cedca08b0815f154949cec26ce0fc288ef0960382bde9c816a9d1afc41fefc` |
| TLSH | `T1AC15F100CEA554AAF48CEB311B2A0B33DE21B9548B85A2DF13553EC89D363D3E96735D` |
| SSDEEP | `24576:YEjmnBcKvWZytslk3/lEooY7I0JUtWnolI:1mvlE0/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_c254bf1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c254bf1cd9ab1496ad01785ed181bd6e314534bb1f079a4bc4616b40a8fd62ee"
    family = "unknown"
    file_name = "macho_c254bf1cd9ab.bin"
    file_type = "macho"
    first_seen = "2026-09-21 00:41:55"
  condition:
    hash.sha256(0, filesize) == "c254bf1cd9ab1496ad01785ed181bd6e314534bb1f079a4bc4616b40a8fd62ee"
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
 * Generated: 2026-09-21T05:06:11.031695+00:00
 */

rule MalwareBazaar_unknown_001_832f4c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "832f4c6ca7b9b61b3a8063355c71f96e5b18e1bfd209df3cd3570b55e5144b4f"
    family = "unknown"
    file_name = "BOOKING_CONFIRMATION.js"
    file_type = "js"
    first_seen = "2026-09-21 05:01:52"
  condition:
    hash.sha256(0, filesize) == "832f4c6ca7b9b61b3a8063355c71f96e5b18e1bfd209df3cd3570b55e5144b4f"
}

rule MalwareBazaar_unknown_002_c6b30fe3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6b30fe33b4891fecabf2d2b5577f994a60fb1e4002923accf1c4f5cffad0eec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:55:46"
  condition:
    hash.sha256(0, filesize) == "c6b30fe33b4891fecabf2d2b5577f994a60fb1e4002923accf1c4f5cffad0eec"
}

rule MalwareBazaar_Mirai_003_39d16f7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39d16f7d08302fa1bccaf9ebb474115b22c531cb6975e2b416811ddcedde4a83"
    family = "Mirai"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-09-21 04:54:53"
  condition:
    hash.sha256(0, filesize) == "39d16f7d08302fa1bccaf9ebb474115b22c531cb6975e2b416811ddcedde4a83"
}

rule MalwareBazaar_unknown_004_7f50def5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f50def548a0e26eb6ef0ab431df93a103c12e2a9066d95b4e9951e86709d39f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:53:19"
  condition:
    hash.sha256(0, filesize) == "7f50def548a0e26eb6ef0ab431df93a103c12e2a9066d95b4e9951e86709d39f"
}

rule MalwareBazaar_unknown_005_aaa8da8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aaa8da8dfe2aaa513916b12137ad6141f451ebf7cbe578830fc1bb4ae2008d94"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:27:31"
  condition:
    hash.sha256(0, filesize) == "aaa8da8dfe2aaa513916b12137ad6141f451ebf7cbe578830fc1bb4ae2008d94"
}

rule MalwareBazaar_unknown_006_85924fef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85924fefcfbbbd26057dc4d5ffd65557f7af612b9481e8b4a0b6b7b13a0fe330"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:25:30"
  condition:
    hash.sha256(0, filesize) == "85924fefcfbbbd26057dc4d5ffd65557f7af612b9481e8b4a0b6b7b13a0fe330"
}

rule MalwareBazaar_unknown_007_07f263b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f263b0b93461f778a0e22ae977be22d8d64b88619aa48af018aed984875a6e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:24:32"
  condition:
    hash.sha256(0, filesize) == "07f263b0b93461f778a0e22ae977be22d8d64b88619aa48af018aed984875a6e"
}

rule MalwareBazaar_unknown_008_1730d47f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1730d47f22d4f74dcb5fb9bbc9e532fbba0d276b2a0cda6c931bf3c091af7a4d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:23:09"
  condition:
    hash.sha256(0, filesize) == "1730d47f22d4f74dcb5fb9bbc9e532fbba0d276b2a0cda6c931bf3c091af7a4d"
}

rule MalwareBazaar_unknown_009_98cd84c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98cd84c33f0d90b0b81f9d7a4c359d56477c9579dc5ee62a18c5a9484ad184f6"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:21:36"
  condition:
    hash.sha256(0, filesize) == "98cd84c33f0d90b0b81f9d7a4c359d56477c9579dc5ee62a18c5a9484ad184f6"
}

rule MalwareBazaar_unknown_010_62630f2a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62630f2aa61b5ccf9a13d150fbf68e9b67cf8cb0eddc16249313804a33273b11"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:21:23"
  condition:
    hash.sha256(0, filesize) == "62630f2aa61b5ccf9a13d150fbf68e9b67cf8cb0eddc16249313804a33273b11"
}

rule MalwareBazaar_unknown_011_a3d4b9a2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3d4b9a22aecc1d9b3ddaff2587434c89a708c0495700efedcfdefb00ac1eb6b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:20:37"
  condition:
    hash.sha256(0, filesize) == "a3d4b9a22aecc1d9b3ddaff2587434c89a708c0495700efedcfdefb00ac1eb6b"
}

rule MalwareBazaar_unknown_012_9e7d77c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e7d77c7df21abcdf0ff7a6f78c9fa47084f070306b6286fccc2c7a8199b1c56"
    family = "unknown"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-09-21 04:19:55"
  condition:
    hash.sha256(0, filesize) == "9e7d77c7df21abcdf0ff7a6f78c9fa47084f070306b6286fccc2c7a8199b1c56"
}

rule MalwareBazaar_Mirai_013_16f03091
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074"
    family = "Mirai"
    file_name = "16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074"
    file_type = "elf"
    first_seen = "2026-09-21 04:18:05"
  condition:
    hash.sha256(0, filesize) == "16f03091a93bf25c5f206c41bc41e2a238c1c55a3750ce9335e818dda6486074"
}

rule MalwareBazaar_unknown_014_9087e723
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9087e723c9aea3ec4d8fca4c410fe41941b8eb158dccff432b8973332ed51ddc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 04:16:39"
  condition:
    hash.sha256(0, filesize) == "9087e723c9aea3ec4d8fca4c410fe41941b8eb158dccff432b8973332ed51ddc"
}

rule MalwareBazaar_Mirai_015_fb6ffe41
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fb6ffe4171a0af5f7a30b978c55aa35ce00e4ee1cbf253b432a907f5c8cc7ac1"
    family = "Mirai"
    file_name = "bot.aarch64"
    file_type = "elf"
    first_seen = "2026-09-21 04:08:31"
  condition:
    hash.sha256(0, filesize) == "fb6ffe4171a0af5f7a30b978c55aa35ce00e4ee1cbf253b432a907f5c8cc7ac1"
}

rule MalwareBazaar_JOMANGY_016_c34b31ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c34b31ba33e12ab9251b02574514a81aa6d7ca974f8b8bb87b193695be69506c"
    family = "JOMANGY"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-09-21 04:07:25"
  condition:
    hash.sha256(0, filesize) == "c34b31ba33e12ab9251b02574514a81aa6d7ca974f8b8bb87b193695be69506c"
}

rule MalwareBazaar_unknown_017_f160f29f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f160f29ffe64663daeaa7f669eb6a2f67624d7c1308069aa57c2219a714dbf16"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:50:58"
  condition:
    hash.sha256(0, filesize) == "f160f29ffe64663daeaa7f669eb6a2f67624d7c1308069aa57c2219a714dbf16"
}

rule MalwareBazaar_unknown_018_8bca9dae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8bca9dae858b5f859dfe7e2b196d9abf874ab6c2cc99ae2fdb645d8efba54ccb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:48:35"
  condition:
    hash.sha256(0, filesize) == "8bca9dae858b5f859dfe7e2b196d9abf874ab6c2cc99ae2fdb645d8efba54ccb"
}

rule MalwareBazaar_unknown_019_a4f7714b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4f7714bb8c1e6ff6c5b6205f5c9da818e3c9625d51457669c9b6a673c43375d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:46:03"
  condition:
    hash.sha256(0, filesize) == "a4f7714bb8c1e6ff6c5b6205f5c9da818e3c9625d51457669c9b6a673c43375d"
}

rule MalwareBazaar_unknown_020_45ce428e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45ce428e16e0a892f74371a4ce4c909bc738e88da9af93c9ef9165f793e48e12"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:42:34"
  condition:
    hash.sha256(0, filesize) == "45ce428e16e0a892f74371a4ce4c909bc738e88da9af93c9ef9165f793e48e12"
}

rule MalwareBazaar_Gafgyt_021_d25b957a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d25b957a739dfafc72a3a73a7faa2de7364d16611e712f3b688a79d8e740ef7c"
    family = "Gafgyt"
    file_name = "i-5.8-6.Sakura"
    file_type = "elf"
    first_seen = "2026-09-21 03:41:27"
  condition:
    hash.sha256(0, filesize) == "d25b957a739dfafc72a3a73a7faa2de7364d16611e712f3b688a79d8e740ef7c"
}

rule MalwareBazaar_Mirai_022_b85cffcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7"
    family = "Mirai"
    file_name = "b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7"
    file_type = "elf"
    first_seen = "2026-09-21 03:17:12"
  condition:
    hash.sha256(0, filesize) == "b85cffcb640a1a5d096ec5e3533aa7467ff1ce94a912c1ff71fec3e59194d5e7"
}

rule MalwareBazaar_unknown_023_9737530c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9737530cbf7a92cf261dd1c875b8ee18cc32797aa5852eb4395ba06552dd7dd3"
    family = "unknown"
    file_name = "Utils.exe"
    file_type = "exe"
    first_seen = "2026-09-21 03:10:19"
  condition:
    hash.sha256(0, filesize) == "9737530cbf7a92cf261dd1c875b8ee18cc32797aa5852eb4395ba06552dd7dd3"
}

rule MalwareBazaar_unknown_024_080c5b27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "080c5b27e2d8a2b13d5cda93ee502b767bc43e787df95899ace6f27ed9c1dd22"
    family = "unknown"
    file_name = "wso.exe"
    file_type = "exe"
    first_seen = "2026-09-21 03:09:30"
  condition:
    hash.sha256(0, filesize) == "080c5b27e2d8a2b13d5cda93ee502b767bc43e787df95899ace6f27ed9c1dd22"
}

rule MalwareBazaar_Formbook_025_30e5af4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9"
    family = "Formbook"
    file_name = "Penawaran RFQ Terlampir 2026.pdf.js"
    file_type = "js"
    first_seen = "2026-09-21 03:08:36"
  condition:
    hash.sha256(0, filesize) == "30e5af4d627069f7c7cf541a309bdd30050cf6f21232e6ad2aeeb4210053b8a9"
}

rule MalwareBazaar_unknown_026_f47f3fba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47f3fba888e9c798d9f5b9115b31aabf844cb0202a5253956dcb7b9940e5c3e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 03:08:15"
  condition:
    hash.sha256(0, filesize) == "f47f3fba888e9c798d9f5b9115b31aabf844cb0202a5253956dcb7b9940e5c3e"
}

rule MalwareBazaar_unknown_027_a28aa61c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a28aa61cc3ef70a11cf1e1b41b2a7df5cac1842577af1885152d9e31a6b1d619"
    family = "unknown"
    file_name = "NEW_MV_TBN_Order_Quotation_Form.js"
    file_type = "js"
    first_seen = "2026-09-21 02:45:48"
  condition:
    hash.sha256(0, filesize) == "a28aa61cc3ef70a11cf1e1b41b2a7df5cac1842577af1885152d9e31a6b1d619"
}

rule MalwareBazaar_unknown_028_894dd68a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f"
    family = "unknown"
    file_name = "894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f"
    file_type = "elf"
    first_seen = "2026-09-21 02:40:56"
  condition:
    hash.sha256(0, filesize) == "894dd68a9891238e6eab5b520b6c86806896f8b4c4aead221308ae9b0ef10a7f"
}

rule MalwareBazaar_unknown_029_09ee8454
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09ee8454d25becc292fb33b33c85554df1ff4d70d780c210633682c904e52fb1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:31:42"
  condition:
    hash.sha256(0, filesize) == "09ee8454d25becc292fb33b33c85554df1ff4d70d780c210633682c904e52fb1"
}

rule MalwareBazaar_unknown_030_3f418594
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f41859451acb64cb101290e361714bc8e2ed6bc937a977c79473a6b59094756"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:29:13"
  condition:
    hash.sha256(0, filesize) == "3f41859451acb64cb101290e361714bc8e2ed6bc937a977c79473a6b59094756"
}

rule MalwareBazaar_unknown_031_c87126d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c87126d88769d2198f18d1a376c2eb88b88a9555feb58fb0908ad19927290d7b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:26:47"
  condition:
    hash.sha256(0, filesize) == "c87126d88769d2198f18d1a376c2eb88b88a9555feb58fb0908ad19927290d7b"
}

rule MalwareBazaar_unknown_032_a1b85fa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1b85fa1f3f58a0315506a8187b8292fbf51fb82d38f842a847cac21a57fb34e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:26:35"
  condition:
    hash.sha256(0, filesize) == "a1b85fa1f3f58a0315506a8187b8292fbf51fb82d38f842a847cac21a57fb34e"
}

rule MalwareBazaar_unknown_033_fa9a0761
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fa9a0761f85ab411c81874cd873d6d4e0bb0a539437043b96066d1e456af020c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:24:05"
  condition:
    hash.sha256(0, filesize) == "fa9a0761f85ab411c81874cd873d6d4e0bb0a539437043b96066d1e456af020c"
}

rule MalwareBazaar_unknown_034_4f859aeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f859aeb12bd1611b86143b8754b5cb7f631015894df20f0881bc43f996ec67e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:21:22"
  condition:
    hash.sha256(0, filesize) == "4f859aeb12bd1611b86143b8754b5cb7f631015894df20f0881bc43f996ec67e"
}

rule MalwareBazaar_unknown_035_e1ee8d5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e1ee8d5c020d3b8016b46f68cf7c8f146232500dfff8ac478805d3dbb545ff75"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:21:13"
  condition:
    hash.sha256(0, filesize) == "e1ee8d5c020d3b8016b46f68cf7c8f146232500dfff8ac478805d3dbb545ff75"
}

rule MalwareBazaar_unknown_036_5a554cc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a554cc0cc86575e0f3e07d384ba4e83871d5a03333c67170bb0b946bf38844d"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:19:50"
  condition:
    hash.sha256(0, filesize) == "5a554cc0cc86575e0f3e07d384ba4e83871d5a03333c67170bb0b946bf38844d"
}

rule MalwareBazaar_unknown_037_839d4344
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "839d4344f0e6b396467df570011971897acfca4aee37011fb64ade9338ecfb81"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:17:19"
  condition:
    hash.sha256(0, filesize) == "839d4344f0e6b396467df570011971897acfca4aee37011fb64ade9338ecfb81"
}

rule MalwareBazaar_Mirai_038_c8e651f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b"
    family = "Mirai"
    file_name = "c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b"
    file_type = "elf"
    first_seen = "2026-09-21 02:17:12"
  condition:
    hash.sha256(0, filesize) == "c8e651f5565227886697c458949501a93e05eedbd47da2e8113df0233267682b"
}

rule MalwareBazaar_unknown_039_66a99c73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66a99c73398040b11ce75f839ba2ff705aa12df7405006bf8328e00204beaf1b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:17:08"
  condition:
    hash.sha256(0, filesize) == "66a99c73398040b11ce75f839ba2ff705aa12df7405006bf8328e00204beaf1b"
}

rule MalwareBazaar_unknown_040_7ac1c753
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ac1c753b75182d5d6300904e7ea31e313df4b20c1709ce4cb19168880778e77"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:16:52"
  condition:
    hash.sha256(0, filesize) == "7ac1c753b75182d5d6300904e7ea31e313df4b20c1709ce4cb19168880778e77"
}

rule MalwareBazaar_unknown_041_1dfbe4d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dfbe4d756e4a424f51a012250ddbdd7da05070146676302275118ebc2c24f1e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:16:03"
  condition:
    hash.sha256(0, filesize) == "1dfbe4d756e4a424f51a012250ddbdd7da05070146676302275118ebc2c24f1e"
}

rule MalwareBazaar_unknown_042_d459fd61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d459fd61bfd71fd434eff7ae4ff4dcb7201c334861bde1452112ac130e12cd58"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:14:54"
  condition:
    hash.sha256(0, filesize) == "d459fd61bfd71fd434eff7ae4ff4dcb7201c334861bde1452112ac130e12cd58"
}

rule MalwareBazaar_unknown_043_c8fdd605
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8fdd6050c30252ba672b0284963a3e1ace14b0e9588fe347415f4f02e4e5db1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:14:52"
  condition:
    hash.sha256(0, filesize) == "c8fdd6050c30252ba672b0284963a3e1ace14b0e9588fe347415f4f02e4e5db1"
}

rule MalwareBazaar_unknown_044_46b913ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "46b913adb2c7e0d8e7b93ecb3ca164bd6a25b0482ad78cf4462ecf9da5ae205e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:13:28"
  condition:
    hash.sha256(0, filesize) == "46b913adb2c7e0d8e7b93ecb3ca164bd6a25b0482ad78cf4462ecf9da5ae205e"
}

rule MalwareBazaar_unknown_045_52d682c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "52d682c52b8acbb14822592ead2b398f164398e72009f81524ed35469ff124d0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:11:54"
  condition:
    hash.sha256(0, filesize) == "52d682c52b8acbb14822592ead2b398f164398e72009f81524ed35469ff124d0"
}

rule MalwareBazaar_unknown_046_cd87c739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd87c73901bd82017779f218e7efa0047a4f2c73b6c61e72c1a7c0d37d2f77a1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:09:28"
  condition:
    hash.sha256(0, filesize) == "cd87c73901bd82017779f218e7efa0047a4f2c73b6c61e72c1a7c0d37d2f77a1"
}

rule MalwareBazaar_unknown_047_be466216
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be4662165b56e3d3b03e5cde83a8720d4af5a3a167952c1b7aefba1951078108"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 02:07:01"
  condition:
    hash.sha256(0, filesize) == "be4662165b56e3d3b03e5cde83a8720d4af5a3a167952c1b7aefba1951078108"
}

rule MalwareBazaar_unknown_048_ddc1d03f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddc1d03f03ef7d821a8cfe5efe4220d791d07796a4a49a379893f4201e0155d4"
    family = "unknown"
    file_name = "dq0hf4.exe"
    file_type = "exe"
    first_seen = "2026-09-21 01:54:24"
  condition:
    hash.sha256(0, filesize) == "ddc1d03f03ef7d821a8cfe5efe4220d791d07796a4a49a379893f4201e0155d4"
}

rule MalwareBazaar_unknown_049_5fabab3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5fabab3dc7f8b73ee1343b01ea9e3d7802a41d12e9a03b1c80f66b72b98fd3fa"
    family = "unknown"
    file_name = "macho_5fabab3dc7f8.bin"
    file_type = "macho"
    first_seen = "2026-09-21 01:51:36"
  condition:
    hash.sha256(0, filesize) == "5fabab3dc7f8b73ee1343b01ea9e3d7802a41d12e9a03b1c80f66b72b98fd3fa"
}

rule MalwareBazaar_unknown_050_0541bb4f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0541bb4f2c603677627f379c588dc8f0407f713e5290886bb2c86001d404ad23"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:47:31"
  condition:
    hash.sha256(0, filesize) == "0541bb4f2c603677627f379c588dc8f0407f713e5290886bb2c86001d404ad23"
}

rule MalwareBazaar_unknown_051_731d654a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731d654a1ee574915dbf0011b9749b5393a2e4fb84f64686a7a838e4ad6dd766"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:45:09"
  condition:
    hash.sha256(0, filesize) == "731d654a1ee574915dbf0011b9749b5393a2e4fb84f64686a7a838e4ad6dd766"
}

rule MalwareBazaar_unknown_052_a8c1ff10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8c1ff106b08183461fef576642b6c8a9386a437c6e6fefd1daa7ff6838eade7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:42:36"
  condition:
    hash.sha256(0, filesize) == "a8c1ff106b08183461fef576642b6c8a9386a437c6e6fefd1daa7ff6838eade7"
}

rule MalwareBazaar_unknown_053_a3764984
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a37649842a47b8456a763c1b4878d08ea7ecee0ea861db2d7588f99f7e180cda"
    family = "unknown"
    file_name = "dred"
    file_type = "unknown"
    first_seen = "2026-09-21 01:39:57"
  condition:
    hash.sha256(0, filesize) == "a37649842a47b8456a763c1b4878d08ea7ecee0ea861db2d7588f99f7e180cda"
}

rule MalwareBazaar_Mirai_054_cb6bf195
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb6bf19586f74326a26c7dd76305e236abe4b49de6ee71453299bc9ec65b9939"
    family = "Mirai"
    file_name = "bot.x86_64"
    file_type = "elf"
    first_seen = "2026-09-21 01:39:56"
  condition:
    hash.sha256(0, filesize) == "cb6bf19586f74326a26c7dd76305e236abe4b49de6ee71453299bc9ec65b9939"
}

rule MalwareBazaar_unknown_055_0766787a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0766787a6a5d07b2900e2237bf33bf87ec68c9c5dec7f6b065cadc4badb8fb88"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:39:49"
  condition:
    hash.sha256(0, filesize) == "0766787a6a5d07b2900e2237bf33bf87ec68c9c5dec7f6b065cadc4badb8fb88"
}

rule MalwareBazaar_unknown_056_c2aa2004
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2aa2004111b9d8a44daab4f58b2a2a3abc9fc313cf6a19d31cf4c750ba09ad8"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:38:05"
  condition:
    hash.sha256(0, filesize) == "c2aa2004111b9d8a44daab4f58b2a2a3abc9fc313cf6a19d31cf4c750ba09ad8"
}

rule MalwareBazaar_unknown_057_498b21cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "498b21cb71c948c579b9c5732adf167c3899a162d8660058be750881fa1234b2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:37:26"
  condition:
    hash.sha256(0, filesize) == "498b21cb71c948c579b9c5732adf167c3899a162d8660058be750881fa1234b2"
}

rule MalwareBazaar_unknown_058_14eadb08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "14eadb08f490f786db8002704cfcd4241a421017f9b7f65099977a685c40cec5"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:35:35"
  condition:
    hash.sha256(0, filesize) == "14eadb08f490f786db8002704cfcd4241a421017f9b7f65099977a685c40cec5"
}

rule MalwareBazaar_unknown_059_2bb36d4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2bb36d4cb0ee32753b23d3f95e0324870711d6c85ff901bbc8de68b23f419db7"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:34:51"
  condition:
    hash.sha256(0, filesize) == "2bb36d4cb0ee32753b23d3f95e0324870711d6c85ff901bbc8de68b23f419db7"
}

rule MalwareBazaar_unknown_060_e86adbad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e86adbad6c3d13ddab441084a6568f08bd7b72fd68de68fda6d46a560afb9a97"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:21:16"
  condition:
    hash.sha256(0, filesize) == "e86adbad6c3d13ddab441084a6568f08bd7b72fd68de68fda6d46a560afb9a97"
}

rule MalwareBazaar_Mirai_061_9eb24cbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed"
    family = "Mirai"
    file_name = "9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed"
    file_type = "elf"
    first_seen = "2026-09-21 01:19:22"
  condition:
    hash.sha256(0, filesize) == "9eb24cbcd482418db3c787ab26d378b7d88d783c589473358210668810c22aed"
}

rule MalwareBazaar_unknown_062_0f5e1dbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f5e1dbcd1904061d0f1d967ab43f8a441e8dabbda4179e0717e2aefdf6afb1a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:19:17"
  condition:
    hash.sha256(0, filesize) == "0f5e1dbcd1904061d0f1d967ab43f8a441e8dabbda4179e0717e2aefdf6afb1a"
}

rule MalwareBazaar_unknown_063_61957e25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61957e253c812ff892dcfe3959a766c1dad06866534ae4ad22c8b100b83519d3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:19:17"
  condition:
    hash.sha256(0, filesize) == "61957e253c812ff892dcfe3959a766c1dad06866534ae4ad22c8b100b83519d3"
}

rule MalwareBazaar_unknown_064_dd00defe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd00defe265bd901fe466a7832acbe0c6d957a6ca309b6a211ddc17076a14461"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:17:31"
  condition:
    hash.sha256(0, filesize) == "dd00defe265bd901fe466a7832acbe0c6d957a6ca309b6a211ddc17076a14461"
}

rule MalwareBazaar_unknown_065_a93532d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a93532d58650bf020c997d4d2abc2fbf00a078537063c9de9e14bf8aa4df8046"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:16:53"
  condition:
    hash.sha256(0, filesize) == "a93532d58650bf020c997d4d2abc2fbf00a078537063c9de9e14bf8aa4df8046"
}

rule MalwareBazaar_unknown_066_13feea8b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13feea8b62c25c3f0fc396565d0ab40874a497cd90398fd9296eccf59586174b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:16:51"
  condition:
    hash.sha256(0, filesize) == "13feea8b62c25c3f0fc396565d0ab40874a497cd90398fd9296eccf59586174b"
}

rule MalwareBazaar_unknown_067_369aab05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "369aab05bae5fa73828e94d7aaab5bed42fb18b10236535a7f47570631bf43b1"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:16:41"
  condition:
    hash.sha256(0, filesize) == "369aab05bae5fa73828e94d7aaab5bed42fb18b10236535a7f47570631bf43b1"
}

rule MalwareBazaar_unknown_068_cae0697a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cae0697aa8c68dd3e83129bfa1d2e92fa2011912b774aa98dee6ca8d16a677ec"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:15:14"
  condition:
    hash.sha256(0, filesize) == "cae0697aa8c68dd3e83129bfa1d2e92fa2011912b774aa98dee6ca8d16a677ec"
}

rule MalwareBazaar_unknown_069_3ff11eae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ff11eae1e8b38d9d1724c92f013fa00c4a8644649674b91f3bd9960acabfa33"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:14:24"
  condition:
    hash.sha256(0, filesize) == "3ff11eae1e8b38d9d1724c92f013fa00c4a8644649674b91f3bd9960acabfa33"
}

rule MalwareBazaar_unknown_070_89a8d6df
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89a8d6df68ed3e7313935363c9468af937604dcae0a06c24f78c11a8e0b2f095"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:14:02"
  condition:
    hash.sha256(0, filesize) == "89a8d6df68ed3e7313935363c9468af937604dcae0a06c24f78c11a8e0b2f095"
}

rule MalwareBazaar_unknown_071_2c94c07a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c94c07af82326a289f7a983a1a76323f5a0860b728bd390e8ba8d0e754da7d3"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:12:26"
  condition:
    hash.sha256(0, filesize) == "2c94c07af82326a289f7a983a1a76323f5a0860b728bd390e8ba8d0e754da7d3"
}

rule MalwareBazaar_unknown_072_7acfc5d3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f"
    family = "unknown"
    file_name = "7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f.bin"
    file_type = "zip"
    first_seen = "2026-09-21 01:09:58"
  condition:
    hash.sha256(0, filesize) == "7acfc5d3321a2253420d30e60d8a2900ce16142e8e0f94a88e87d796187ddc1f"
}

rule MalwareBazaar_Mirai_073_fef726f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c"
    family = "Mirai"
    file_name = "fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:09:51"
  condition:
    hash.sha256(0, filesize) == "fef726f1f0c5243f8aa0a59dca4e5647c11f2bc20198193962f38d00d5bb186c"
}

rule MalwareBazaar_Mirai_074_b8ab8a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133"
    family = "Mirai"
    file_name = "b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:09:47"
  condition:
    hash.sha256(0, filesize) == "b8ab8a050e34c8004a32b78c8908d454ef211387e3ba015710ccd425903a7133"
}

rule MalwareBazaar_unknown_075_a44dddd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a44dddd9f780261cebeb54162f26bffb6e85811928a36ff78b7f9c2975093e0b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:09:00"
  condition:
    hash.sha256(0, filesize) == "a44dddd9f780261cebeb54162f26bffb6e85811928a36ff78b7f9c2975093e0b"
}

rule MalwareBazaar_Snowlight_076_3e164112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa"
    family = "Snowlight"
    file_name = "3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:08:59"
  condition:
    hash.sha256(0, filesize) == "3e1641122d009db660fbff4261cc7206890e12470f86dbec77ff8769514530aa"
}

rule MalwareBazaar_Mirai_077_9c1a4318
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6"
    family = "Mirai"
    file_name = "9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6.elf"
    file_type = "elf"
    first_seen = "2026-09-21 01:08:55"
  condition:
    hash.sha256(0, filesize) == "9c1a4318df911281fd7b6971c7fd0e022ebe310b7c49381c6b89ef23ad9551e6"
}

rule MalwareBazaar_Mirai_078_a031852c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a031852c5688f26aab531cca341576bc1098727320199e0f5bb3bd2a6caff94b"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:39"
  condition:
    hash.sha256(0, filesize) == "a031852c5688f26aab531cca341576bc1098727320199e0f5bb3bd2a6caff94b"
}

rule MalwareBazaar_Mirai_079_b4cea7e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b4cea7e82069bca6d19f51e04362b13adb9ada4d9564779bff961e936e11531d"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:36"
  condition:
    hash.sha256(0, filesize) == "b4cea7e82069bca6d19f51e04362b13adb9ada4d9564779bff961e936e11531d"
}

rule MalwareBazaar_Mirai_080_e7804767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7804767a5e607b192396a919226a5b6aa64f8078f4c5b63e4569a2de23a8531"
    family = "Mirai"
    file_name = "Space.arm6"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:34"
  condition:
    hash.sha256(0, filesize) == "e7804767a5e607b192396a919226a5b6aa64f8078f4c5b63e4569a2de23a8531"
}

rule MalwareBazaar_Mirai_081_1b6c2dd0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b6c2dd0d3b6b01efda1a44ca63ce4168129b0ef3e415f96ba1d7af77aad20b7"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:32"
  condition:
    hash.sha256(0, filesize) == "1b6c2dd0d3b6b01efda1a44ca63ce4168129b0ef3e415f96ba1d7af77aad20b7"
}

rule MalwareBazaar_unknown_082_f3011161
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f3011161d8bd6ca8cfb7221d69bcfd2e094d5fda28c09a6069a036c8a6931bae"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 01:04:30"
  condition:
    hash.sha256(0, filesize) == "f3011161d8bd6ca8cfb7221d69bcfd2e094d5fda28c09a6069a036c8a6931bae"
}

rule MalwareBazaar_Mirai_083_84afbce2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84afbce29ba3d166d549ba14dc919fe5edde84dd2c0314ece3cdf5f40f68c37c"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:30"
  condition:
    hash.sha256(0, filesize) == "84afbce29ba3d166d549ba14dc919fe5edde84dd2c0314ece3cdf5f40f68c37c"
}

rule MalwareBazaar_Mirai_084_a2863d10
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a2863d10f67f1c6a2e9b55bfdd972d9e316f796e9be516bfe9f3cda8316caca8"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:26"
  condition:
    hash.sha256(0, filesize) == "a2863d10f67f1c6a2e9b55bfdd972d9e316f796e9be516bfe9f3cda8316caca8"
}

rule MalwareBazaar_Mirai_085_b3c25fc4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3c25fc4ff0b36f9e2d227667cce1b67195eb1ee155045f11dfe046abcb76fcf"
    family = "Mirai"
    file_name = "Space.arm7"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:12"
  condition:
    hash.sha256(0, filesize) == "b3c25fc4ff0b36f9e2d227667cce1b67195eb1ee155045f11dfe046abcb76fcf"
}

rule MalwareBazaar_Mirai_086_a4fad26f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a4fad26f865fe4a7397bc21094c45def5e6fe6ab332f379380c3e7a316e86d92"
    family = "Mirai"
    file_name = "Space.x86_64"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:11"
  condition:
    hash.sha256(0, filesize) == "a4fad26f865fe4a7397bc21094c45def5e6fe6ab332f379380c3e7a316e86d92"
}

rule MalwareBazaar_Mirai_087_efc1ac99
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efc1ac998c9be84b72fb26cce3a51931e460319cd662ae9097cdb5c776bdbe92"
    family = "Mirai"
    file_name = "Space.arm6"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:09"
  condition:
    hash.sha256(0, filesize) == "efc1ac998c9be84b72fb26cce3a51931e460319cd662ae9097cdb5c776bdbe92"
}

rule MalwareBazaar_Mirai_088_75596ce7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75596ce797ee68d6ba16058f70eddbf7915299d1938c5f871dcda536d6f6d2d0"
    family = "Mirai"
    file_name = "Space.arm5"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:08"
  condition:
    hash.sha256(0, filesize) == "75596ce797ee68d6ba16058f70eddbf7915299d1938c5f871dcda536d6f6d2d0"
}

rule MalwareBazaar_Mirai_089_31921683
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "31921683c81079a60502a35e6b4ec4f9afe34276a9229a2685ee4f2daa2d46f6"
    family = "Mirai"
    file_name = "Space.arm"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:07"
  condition:
    hash.sha256(0, filesize) == "31921683c81079a60502a35e6b4ec4f9afe34276a9229a2685ee4f2daa2d46f6"
}

rule MalwareBazaar_Mirai_090_0fb25f6e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0fb25f6e2b685d8f8b1843b8d11e0ac81be09a498010ebf87aac1a4d6a3e42f3"
    family = "Mirai"
    file_name = "Space.sh4"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:06"
  condition:
    hash.sha256(0, filesize) == "0fb25f6e2b685d8f8b1843b8d11e0ac81be09a498010ebf87aac1a4d6a3e42f3"
}

rule MalwareBazaar_Mirai_091_7412bbd1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7412bbd1ce42b8799cd74063e95b4870f26f75e4b0b4d3367b067398835124be"
    family = "Mirai"
    file_name = "Space.x86"
    file_type = "elf"
    first_seen = "2026-09-21 01:04:05"
  condition:
    hash.sha256(0, filesize) == "7412bbd1ce42b8799cd74063e95b4870f26f75e4b0b4d3367b067398835124be"
}

rule MalwareBazaar_Mirai_092_6b3f3cef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b3f3cef5349a61f3ffe1631e01a7ff4fe28f1ee2e8e3e0fdf4c81b42036196d"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:17"
  condition:
    hash.sha256(0, filesize) == "6b3f3cef5349a61f3ffe1631e01a7ff4fe28f1ee2e8e3e0fdf4c81b42036196d"
}

rule MalwareBazaar_Mirai_093_0dcd1d11
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0dcd1d1183936c9035f2cb9cba8d2eefa12531b9625b9ce6f8dba3ba1fafaf5c"
    family = "Mirai"
    file_name = "Space.m68k"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:05"
  condition:
    hash.sha256(0, filesize) == "0dcd1d1183936c9035f2cb9cba8d2eefa12531b9625b9ce6f8dba3ba1fafaf5c"
}

rule MalwareBazaar_Mirai_094_a6a895a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6a895a12575751e60ac5b1fa76c969c3beba983330c01941150a07d3b7c0891"
    family = "Mirai"
    file_name = "Space.spc"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:04"
  condition:
    hash.sha256(0, filesize) == "a6a895a12575751e60ac5b1fa76c969c3beba983330c01941150a07d3b7c0891"
}

rule MalwareBazaar_Mirai_095_f976a3b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f976a3b51c470d22f5129bb5930dadc7447d0ae383c4d90bc3c1a2e00e252658"
    family = "Mirai"
    file_name = "Space.mips"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:03"
  condition:
    hash.sha256(0, filesize) == "f976a3b51c470d22f5129bb5930dadc7447d0ae383c4d90bc3c1a2e00e252658"
}

rule MalwareBazaar_Mirai_096_e4ca83ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4ca83ae8c8c4f6263f7f43550b1dd7dc0b2d8852fe6602234553916a0d4e6ca"
    family = "Mirai"
    file_name = "Space.arc"
    file_type = "elf"
    first_seen = "2026-09-21 01:03:02"
  condition:
    hash.sha256(0, filesize) == "e4ca83ae8c8c4f6263f7f43550b1dd7dc0b2d8852fe6602234553916a0d4e6ca"
}

rule MalwareBazaar_unknown_097_8f033293
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f0332933d8f240083e9ff173852177f45b48372a6df64a22dc577d3b120b89a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 00:46:44"
  condition:
    hash.sha256(0, filesize) == "8f0332933d8f240083e9ff173852177f45b48372a6df64a22dc577d3b120b89a"
}

rule MalwareBazaar_unknown_098_f2cd69b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2cd69b0448ff01b89adcf5670f38e1f66da6861564e32a395facc156fcc3d89"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 00:44:25"
  condition:
    hash.sha256(0, filesize) == "f2cd69b0448ff01b89adcf5670f38e1f66da6861564e32a395facc156fcc3d89"
}

rule MalwareBazaar_unknown_099_0d0ee878
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0ee878ce80bba959f48fbf1d3220b135ad18625eeb62aa89a6a16c3308fdda"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-09-21 00:42:01"
  condition:
    hash.sha256(0, filesize) == "0d0ee878ce80bba959f48fbf1d3220b135ad18625eeb62aa89a6a16c3308fdda"
}

rule MalwareBazaar_unknown_100_c254bf1c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c254bf1cd9ab1496ad01785ed181bd6e314534bb1f079a4bc4616b40a8fd62ee"
    family = "unknown"
    file_name = "macho_c254bf1cd9ab.bin"
    file_type = "macho"
    first_seen = "2026-09-21 00:41:55"
  condition:
    hash.sha256(0, filesize) == "c254bf1cd9ab1496ad01785ed181bd6e314534bb1f079a4bc4616b40a8fd62ee"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

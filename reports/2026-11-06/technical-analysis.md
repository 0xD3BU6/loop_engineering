# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-06

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
| Unique family labels | 10 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 72 |
| Gafgyt | 10 |
| Mirai | 7 |
| DarkCoreRAT | 2 |
| WARDENStealer | 2 |
| Prometei | 2 |
| VShell | 2 |
| DDoSAgent | 1 |
| QuasarRAT | 1 |
| AveMariaRAT | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| macho | 51 |
| elf | 27 |
| exe | 15 |
| js | 3 |
| pl | 1 |
| sh | 1 |
| ps1 | 1 |
| apk | 1 |

## Per-Sample Analysis

### Sample 1: `32fa7a24cd9b8691`

| Field | Value |
|---|---|
| SHA-256 | `32fa7a24cd9b8691c1965aa788d1c93e3b923404c4d33b73e8474b7e8bbfa939` |
| Family label | `DarkCoreRAT` |
| File name | `042538776d6c16f7f63e679b1b9dc0b3.exe` |
| File type | `exe` |
| First seen | `2026-11-06 06:56:04` |
| Reporter | `abuse_ch` |
| Tags | `DarkCoreRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `042538776d6c16f7f63e679b1b9dc0b3` |
| SHA-1 | `682814ffe7e0836204998af29b5556135cdcc5ea` |
| SHA-256 | `32fa7a24cd9b8691c1965aa788d1c93e3b923404c4d33b73e8474b7e8bbfa939` |
| SHA3-384 | `eb314f5fd0114860df4661719abdb0b0e9b99f18df7c0298cf2ab1109db660d69a257007771c2452b6a27cce25e707b0` |
| IMPHASH | `fa603ca7f70ad2414bada75903057bda` |
| TLSH | `T1ADD49D58F6A401EDE27AC274CE479613F7B2B8491374A9EF03E089761F272A1473E761` |
| SSDEEP | `6144:g73ORchAJSBuOAItKDfAd2oEJhwefq3abLYeyNEWGNSK/B99fSdj6Ahx5Xg2vm5C:9SBuOASUJ3fqKP5y8pBOxVfmuJLV5` |

#### Technical Assessment

- The sample is tracked as `DarkCoreRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCoreRAT_001_32fa7a24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32fa7a24cd9b8691c1965aa788d1c93e3b923404c4d33b73e8474b7e8bbfa939"
    family = "DarkCoreRAT"
    file_name = "042538776d6c16f7f63e679b1b9dc0b3.exe"
    file_type = "exe"
    first_seen = "2026-11-06 06:56:04"
  condition:
    hash.sha256(0, filesize) == "32fa7a24cd9b8691c1965aa788d1c93e3b923404c4d33b73e8474b7e8bbfa939"
}
```

### Sample 2: `d51e0e128839839b`

| Field | Value |
|---|---|
| SHA-256 | `d51e0e128839839b7caf0d96cd6b082e2dd23f32a52da5fd1d9fadefca5f9e87` |
| Family label | `DarkCoreRAT` |
| File name | `3e26f226cc8699617fc8a7e24f100edf.exe` |
| File type | `exe` |
| First seen | `2026-11-06 06:54:54` |
| Reporter | `abuse_ch` |
| Tags | `DarkCoreRAT, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e26f226cc8699617fc8a7e24f100edf` |
| SHA-1 | `872575946a1eece5581ed38679b1230ecc4714a3` |
| SHA-256 | `d51e0e128839839b7caf0d96cd6b082e2dd23f32a52da5fd1d9fadefca5f9e87` |
| SHA3-384 | `46fa1886ac8e644697d5013eb06575caf1812a427ca071304e04de241693a5d0d5ba3d8941ea735946e27bc02ee151f6` |
| IMPHASH | `263e14d1de5c081e38c849d034683bab` |
| TLSH | `T195C48D14B6A412F9E177C674CE578513FBB27C491370A9EB03E089A72F236A15B3EB11` |
| SSDEEP | `6144:EO+dYsYt0KmTUkMnn1xGVauPHY2nvzD9Kf13TuTMGVQl8cpj4a4FuXY6X69j:WfUkMnn1xG4uVnvz5Kf13SIO3C4L0q9` |

#### Technical Assessment

- The sample is tracked as `DarkCoreRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DarkCoreRAT_002_d51e0e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51e0e128839839b7caf0d96cd6b082e2dd23f32a52da5fd1d9fadefca5f9e87"
    family = "DarkCoreRAT"
    file_name = "3e26f226cc8699617fc8a7e24f100edf.exe"
    file_type = "exe"
    first_seen = "2026-11-06 06:54:54"
  condition:
    hash.sha256(0, filesize) == "d51e0e128839839b7caf0d96cd6b082e2dd23f32a52da5fd1d9fadefca5f9e87"
}
```

### Sample 3: `3f6e9fd9ad8b6d65`

| Field | Value |
|---|---|
| SHA-256 | `3f6e9fd9ad8b6d6561407e284ee202b96f850a46d037572c8f4425bb8706f5d8` |
| Family label | `WARDENStealer` |
| File name | `1.exe` |
| File type | `exe` |
| First seen | `2026-11-06 06:51:36` |
| Reporter | `ghozt` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fae9113eabfb5012cfe92abfe76f3ed9` |
| SHA-1 | `3603def88daf183946a796315c5a8dbc066b8874` |
| SHA-256 | `3f6e9fd9ad8b6d6561407e284ee202b96f850a46d037572c8f4425bb8706f5d8` |
| SHA3-384 | `d15b0b3b9f1955a717c867da8615b271ca00acdc62dba2e7bd6341fbaec103d077ce7cf197c14e8dc77378d1919f8e16` |
| IMPHASH | `6ea024fc0b98336c202d3cc39c5f3509` |
| TLSH | `T1BA456D5ADFCB6CBCF4D6D8B496065B10E3B0D01B14F36692162E21B7C765210ABFAF09` |
| SSDEEP | `12288:9uZj6+Z28/KexqycNiJSPu0uqzil82NZv4uvdkbZm5qjZ+F5FUbIVzsm7/:9oOlDySiJscqOS2NVhakkjZ+F5F8m7/` |
| ICON-DHASH | `0816706969710600` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_003_3f6e9fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f6e9fd9ad8b6d6561407e284ee202b96f850a46d037572c8f4425bb8706f5d8"
    family = "WARDENStealer"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-11-06 06:51:36"
  condition:
    hash.sha256(0, filesize) == "3f6e9fd9ad8b6d6561407e284ee202b96f850a46d037572c8f4425bb8706f5d8"
}
```

### Sample 4: `bde4d2d549d4fd55`

| Field | Value |
|---|---|
| SHA-256 | `bde4d2d549d4fd5550e22f0b820246556f51b413420420697700a1f5f0982d53` |
| Family label | `unknown` |
| File name | `0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806` |
| File type | `elf` |
| First seen | `2026-11-06 06:49:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d3f0012dcffce81f112e7b902b544e20` |
| SHA-1 | `37f5020eb988fd6b3fd13bb657f353cb98af1f51` |
| SHA-256 | `bde4d2d549d4fd5550e22f0b820246556f51b413420420697700a1f5f0982d53` |
| SHA3-384 | `6c55209a735f793fd479d608725cc0d6c78447150da81e16756c7d9835ef23d48b46799d44872922a2e661627ba19637` |
| TLSH | `T141C73343FCD21594D4AFA330C9A64127BB757C490B7823D32A90B7382F3A7E0A976B55` |
| TELFHASH | `t17b227c7248bd74b5b696da11f362b4b896331cf567f838b15027a894efc1e801ce6837` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `1572864:l6LAQL0tdoXufzRe1DeTCREMzHMMpfEzpWNNu+MB:aLL0tdoYVe1D7MsszpWNgXB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_bde4d2d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde4d2d549d4fd5550e22f0b820246556f51b413420420697700a1f5f0982d53"
    family = "unknown"
    file_name = "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
    file_type = "elf"
    first_seen = "2026-11-06 06:49:34"
  condition:
    hash.sha256(0, filesize) == "bde4d2d549d4fd5550e22f0b820246556f51b413420420697700a1f5f0982d53"
}
```

### Sample 5: `8d23f427a29a0d20`

| Field | Value |
|---|---|
| SHA-256 | `8d23f427a29a0d2010097c8066901e026e81c41163672cbb5e522942786d1091` |
| Family label | `unknown` |
| File name | `022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42` |
| File type | `elf` |
| First seen | `2026-11-06 06:49:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce5ac0fbd5d4cf695444f46a78012519` |
| SHA-1 | `e800f5248e1075ed72e7905735c769f099a7df59` |
| SHA-256 | `8d23f427a29a0d2010097c8066901e026e81c41163672cbb5e522942786d1091` |
| SHA3-384 | `165b19ae9da43f10f89168db64f826382c6c928e4e12c38a2ba46e86c64fa2c4a33cfb09a1be4d9585f873dd16d6741e` |
| TLSH | `T191D60103B8E61CA4C8FAD27085668226EA71B84D0B7563DF5790B7342F337F14A76B94` |
| TELFHASH | `t19262fd75497c74b5b2a7c961f362b4b4e6331cb563f838b01063b981efd4e811caa867` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `393216:jAtmmuKibA0P8nv6OCIHJDeP/0V7kuE3Vk:MbVRum6PIH9q/0V7kuE3Vk` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_8d23f427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d23f427a29a0d2010097c8066901e026e81c41163672cbb5e522942786d1091"
    family = "unknown"
    file_name = "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
    file_type = "elf"
    first_seen = "2026-11-06 06:49:21"
  condition:
    hash.sha256(0, filesize) == "8d23f427a29a0d2010097c8066901e026e81c41163672cbb5e522942786d1091"
}
```

### Sample 6: `b5105b0b23e27232`

| Field | Value |
|---|---|
| SHA-256 | `b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5` |
| Family label | `unknown` |
| File name | `b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5` |
| File type | `pl` |
| First seen | `2026-11-06 06:43:21` |
| Reporter | `ArchonLabs` |
| Tags | `ddos, dropper, honeypot, pl, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `401f7ecb154d527903aab71162048eee` |
| SHA-1 | `29e54ce1a0a42c66c62c0e4d44239d3ae758b90b` |
| SHA-256 | `b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5` |
| SHA3-384 | `0c299a9b9de240c1a86fe00dee2bc3326c9441896f9a1951e2528bdbef280bd04d1996a51d8e267d477cf8c195a44474` |
| TLSH | `T1D0C2844919E34952A3B7F0761BDED4187A5BC1974B0DDE207DAC42D6BF90039D2F8AC8` |
| SSDEEP | `384:hsxqHe4XDp2fv6Mf8JSN6WWabfd43+yZzB3lx:hsx+e4XDp2fv5f8J7WWARy1B3z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `pl`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_b5105b0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5"
    family = "unknown"
    file_name = "b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5"
    file_type = "pl"
    first_seen = "2026-11-06 06:43:21"
  condition:
    hash.sha256(0, filesize) == "b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5"
}
```

### Sample 7: `0d44deb0f7a325ee`

| Field | Value |
|---|---|
| SHA-256 | `0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806` |
| Family label | `unknown` |
| File name | `0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806` |
| File type | `elf` |
| First seen | `2026-11-06 06:43:17` |
| Reporter | `ArchonLabs` |
| Tags | `elf, garble, golang, honeypot, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5a8d5a419a4b066b751a37bedd463b5` |
| SHA-1 | `10fc7408f0bf7e1753aa635d3d2e6feabc0dbfbe` |
| SHA-256 | `0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806` |
| SHA3-384 | `54f3d048439cebd53717f34cd49bc44dab4f53c37c75a4c945d972ab91e7e97d24a35aca531646ebaa51824dc392cbad` |
| TLSH | `T155C7330BDCC68ED5E10D7932BB46C62687ACADACA762070B75005EB6FC171405EF26F9` |
| SSDEEP | `1572864:y6LAQL0tdoXufzRe1DeTCREMzHMMpfEzpWNNu+MX:1LL0tdoYVe1D7MsszpWNgXX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_0d44deb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
    family = "unknown"
    file_name = "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
    file_type = "elf"
    first_seen = "2026-11-06 06:43:17"
  condition:
    hash.sha256(0, filesize) == "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
}
```

### Sample 8: `6e11016d0f4e3e0b`

| Field | Value |
|---|---|
| SHA-256 | `6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264` |
| Family label | `Mirai` |
| File name | `6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264` |
| File type | `elf` |
| First seen | `2026-11-06 06:43:05` |
| Reporter | `ArchonLabs` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `952cac002a7c45bbc30916b18279f5da` |
| SHA-1 | `77dd5a9facb81216d7df9e730ae55d598969b5ee` |
| SHA-256 | `6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264` |
| SHA3-384 | `1339b7d074943c5e7362600fdc014fece06ef77cb9cf5f742fb2cd166e5a408e8110ab88d683ca1cf2b58d126b1e20bd` |
| TLSH | `T189A67C5BB6F358ECC09EC430476FD5536A31B8A40231797B3A84AA342E77E60576EF21` |
| TELFHASH | `t1ee2232b48ad939b1a2e5ca8de373b1f59a7304f266f834b44126bd42dfd1dc10c5a81e` |
| SSDEEP | `98304:SErlpwHRUdukfzX09Twc0oBdrqmTE8lPE/zmW7dJcOoICFPeI/SweqiyzNWx9C2F:q2zmywjzNaROCcD9XiA6q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_6e11016d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264"
    family = "Mirai"
    file_name = "6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264"
    file_type = "elf"
    first_seen = "2026-11-06 06:43:05"
  condition:
    hash.sha256(0, filesize) == "6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264"
}
```

### Sample 9: `40d3cd162165639c`

| Field | Value |
|---|---|
| SHA-256 | `40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3` |
| Family label | `unknown` |
| File name | `40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3` |
| File type | `elf` |
| First seen | `2026-11-06 06:43:01` |
| Reporter | `ArchonLabs` |
| Tags | `CoinMiner, elf, honeypot, NBMiner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eaebe7ab1bd73df599bc78d7db841d89` |
| SHA-1 | `7778ec10c0920c8488f2ea95d730e87cc99438a7` |
| SHA-256 | `40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3` |
| SHA3-384 | `6245f56315ff56709960bb10ffbfb0d52b43469ac25d462ee211f8a90c7b151c5ad5c48f4a7a0a7fe6bbcfb1a2ece738` |
| TLSH | `T124B67C73905334D9E5A88DB4D11416526DBC388B5738A3CBBAC471F667BABE48E38730` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQ9:cqYUQuVDt0TZEy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_40d3cd16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3"
    family = "unknown"
    file_name = "40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3"
    file_type = "elf"
    first_seen = "2026-11-06 06:43:01"
  condition:
    hash.sha256(0, filesize) == "40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3"
}
```

### Sample 10: `022b8f9010612de6`

| Field | Value |
|---|---|
| SHA-256 | `022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42` |
| Family label | `unknown` |
| File name | `022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42` |
| File type | `elf` |
| First seen | `2026-11-06 06:42:54` |
| Reporter | `ArchonLabs` |
| Tags | `elf, honeypot, rootkit, ssh-backdoor, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb03625896f1523fcc82fc7057109281` |
| SHA-1 | `5387679cbdad2d9470c9619d6ece76c0bfabd771` |
| SHA-256 | `022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42` |
| SHA3-384 | `253ac7a8eae8c603b6fbe8cdfdc7e881970fc65b1fa2fd13c710ce763b430704bcdf4ab75c87e1764a01c48f1c816de4` |
| TLSH | `T169B633FEAE0F186A953DE5554E1D942DAC23688DF38A0D9A9D79C7CBCBC08073611BC1` |
| SSDEEP | `196608:lb22C4vXtcLyYhHztMsL+LACOZOLfH4c8F6x8NMhSlnt+t4igTrEYFDro5OZ52u1:lb22nvmLyyztMsLUACrbH4FF6+NCSj0Y` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_022b8f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
    family = "unknown"
    file_name = "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
    file_type = "elf"
    first_seen = "2026-11-06 06:42:54"
  condition:
    hash.sha256(0, filesize) == "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
}
```

### Sample 11: `9b1a249f9a599cea`

| Field | Value |
|---|---|
| SHA-256 | `9b1a249f9a599cea72da14f6a09aefaf8af3933e5c1a4c2c4a3208cdc951a163` |
| Family label | `unknown` |
| File name | `install.sh` |
| File type | `sh` |
| First seen | `2026-11-06 06:26:32` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70158a896b9f6b69ac4f9be7acaee14f` |
| SHA-1 | `d4d8a954360eb1321063455a0c30e67418fb1671` |
| SHA-256 | `9b1a249f9a599cea72da14f6a09aefaf8af3933e5c1a4c2c4a3208cdc951a163` |
| SHA3-384 | `9816fb791afb05d49ed1d2050b3ed4eb810a924c2d8c6c4d4b8263bb1937a25dcc578f5c8493102b4f4fa01fbaa11acf` |
| TLSH | `T13DA151EBF0BC9E313598452DBCDD65515A8E193B22A03804F49FB8085FBD825B17EB74` |
| SSDEEP | `96:okeJ0i3bItxGvBn1IPHcSHwzgVMDtgmxhM9li2:oui3EtUvJSHOhtrhM9Y2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_9b1a249f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1a249f9a599cea72da14f6a09aefaf8af3933e5c1a4c2c4a3208cdc951a163"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-11-06 06:26:32"
  condition:
    hash.sha256(0, filesize) == "9b1a249f9a599cea72da14f6a09aefaf8af3933e5c1a4c2c4a3208cdc951a163"
}
```

### Sample 12: `f13f0f9de4730711`

| Field | Value |
|---|---|
| SHA-256 | `f13f0f9de473071134fee348f915d0fcbb730c940474b2fbbf1d615eb713fc4c` |
| Family label | `DDoSAgent` |
| File name | `e_amd64` |
| File type | `elf` |
| First seen | `2026-11-06 06:24:51` |
| Reporter | `adliwahid` |
| Tags | `DDoSAgent` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e29520e665e40c253d99a27df3022b50` |
| SHA-1 | `1105188da7822f7786c51a1123f851d571ad301a` |
| SHA-256 | `f13f0f9de473071134fee348f915d0fcbb730c940474b2fbbf1d615eb713fc4c` |
| SHA3-384 | `40e1731eb9fd3728da3cf00d1611a9c2eb61f995790f3ec4d3f3636c6a914fe05970df688d44469f80af2fc76d0e891e` |
| TLSH | `T161A53917BCA049A9C4AE9231896692A6BB31BC490F3127D73F50B37C2F72FD09979744` |
| TELFHASH | `t1b14239754abc35b4b6a6d910b362b474a677297526f834f01023ed84ffc1e806da2c7b` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `24576:D0a8MCA8TQgARBewf30zxldP6XJ8wj87tq0WkcNzQhgtodXL8oUkSEyeUK/x/0tp:D0a8Q8TL+oi3QFPqG2YSEg0AKWwO` |

#### Technical Assessment

- The sample is tracked as `DDoSAgent` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DDoSAgent_012_f13f0f9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f13f0f9de473071134fee348f915d0fcbb730c940474b2fbbf1d615eb713fc4c"
    family = "DDoSAgent"
    file_name = "e_amd64"
    file_type = "elf"
    first_seen = "2026-11-06 06:24:51"
  condition:
    hash.sha256(0, filesize) == "f13f0f9de473071134fee348f915d0fcbb730c940474b2fbbf1d615eb713fc4c"
}
```

### Sample 13: `f1cd80c989a6c9fc`

| Field | Value |
|---|---|
| SHA-256 | `f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a` |
| Family label | `Mirai` |
| File name | `superior.arm7` |
| File type | `elf` |
| First seen | `2026-11-06 06:24:09` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `197b9f5d336d3c2b866456b55036db96` |
| SHA-1 | `6e9dbdb17d90645555e2821bed6a8378377d5a7e` |
| SHA-256 | `f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a` |
| SHA3-384 | `6a031fa401e39d5a88d398464308d40c62c94b4d11830804044750f7efbac9bbadefc68bcd8fb2d656dbd5dd362a1cf5` |
| TLSH | `T184D41A65FC40EA61C5C4257ABA5D82A833331FB4C5EA7102ED14BF2C3BFB45A473A685` |
| SSDEEP | `12288:120b385DxSfoNfOxyW91Xy7CcVchjaNwGtt6nbW0ajRXDg80Ny2:dOVp81iTinbW0ajpg80Ny2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_f1cd80c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a"
    family = "Mirai"
    file_name = "superior.arm7"
    file_type = "elf"
    first_seen = "2026-11-06 06:24:09"
  condition:
    hash.sha256(0, filesize) == "f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a"
}
```

### Sample 14: `e82b0fb2fd0e2101`

| Field | Value |
|---|---|
| SHA-256 | `e82b0fb2fd0e21013c2bb6cfd027eb8ced4a7259eb640f688f893c1358efbba9` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-06 05:59:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24558581cb6fe41881ae8596ac38c934` |
| SHA-1 | `702d309f6fe9ac28370fcb57c8c3c3ededccbc33` |
| SHA-256 | `e82b0fb2fd0e21013c2bb6cfd027eb8ced4a7259eb640f688f893c1358efbba9` |
| SHA3-384 | `2ff2bac1a6bd3b4c3b15d5846586d9786260b00a5950d56a1cba7319637cef36fe05bb18527763e1d36169ad32d34e82` |
| TLSH | `T12F556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP4+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_e82b0fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e82b0fb2fd0e21013c2bb6cfd027eb8ced4a7259eb640f688f893c1358efbba9"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-06 05:59:05"
  condition:
    hash.sha256(0, filesize) == "e82b0fb2fd0e21013c2bb6cfd027eb8ced4a7259eb640f688f893c1358efbba9"
}
```

### Sample 15: `f2c56b981ecc9c98`

| Field | Value |
|---|---|
| SHA-256 | `f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2` |
| Family label | `QuasarRAT` |
| File name | `f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2.bin` |
| File type | `js` |
| First seen | `2026-11-06 05:31:54` |
| Reporter | `Tuxxin` |
| Tags | `js, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40d0ea2400a77b175dcbd2544d407ce4` |
| SHA-1 | `6d104d6860f8e7eb97ca002924ea7c17e67ffdd7` |
| SHA-256 | `f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2` |
| SHA3-384 | `3597d9cd9b20203190ec7bbbb753a4f4cbb30a25688f97acf8bc3ab71cec20a0dc0504563185f0416695df415459d3af` |
| TLSH | `T141730A4B9B069FDC8B6976A55A434ECCF86F7A0633C68B0456C4BF26B04D88D5C7B834` |
| SSDEEP | `1536:pb5ZFSFSPFdFFPFDPFsPZF0FYjFUb5ZFQFvdFlPZF0FvJFcFFPFxMF+b5ZFwFDMH:3jryoeT8y` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_015_f2c56b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2"
    family = "QuasarRAT"
    file_name = "f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2.bin"
    file_type = "js"
    first_seen = "2026-11-06 05:31:54"
  condition:
    hash.sha256(0, filesize) == "f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2"
}
```

### Sample 16: `0d13e956cd34db34`

| Field | Value |
|---|---|
| SHA-256 | `0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92` |
| Family label | `unknown` |
| File name | `0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92.bin` |
| File type | `ps1` |
| First seen | `2026-11-06 05:31:50` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fd0468643ffd3a1437ed9ad1505fb9b` |
| SHA-1 | `597a74f287348d954daf6d3754bc739c3945b600` |
| SHA-256 | `0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92` |
| SHA3-384 | `e2c86ea5637faf6c2b7b5c3b6df5d049e0ab8e4f3935a8cf45725f3742aa80da3ec6d50fa88302f3ce2e59ec8849a35b` |
| TLSH | `T1AD025DB10745DAFF80E2AC2B4336A48CF335703615988541BAFBDE4492C5E78793CE49` |
| SSDEEP | `192:6KGnvJihfO2rCqAPYiqhravvGNPqoU6xihaI6v3gEwzYKu8XtevHNrle0qo:6KMvJihfO2Liqh+vvGNPbU6FIWgE18dA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_0d13e956
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92"
    family = "unknown"
    file_name = "0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92.bin"
    file_type = "ps1"
    first_seen = "2026-11-06 05:31:50"
  condition:
    hash.sha256(0, filesize) == "0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92"
}
```

### Sample 17: `900f628cdbf9a814`

| Field | Value |
|---|---|
| SHA-256 | `900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b` |
| Family label | `Mirai` |
| File name | `900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:41` |
| Reporter | `tanabotan` |
| Tags | `ddos, elf, mips, Mirai, Torii, udp-flood` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2500658f2e5c8e4b18ad4c4fdc2ed828` |
| SHA-1 | `6e1dd9806e3791cae1bf001a25745e51831d0694` |
| SHA-256 | `900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b` |
| SHA3-384 | `23d232462384d3a1400a4dc50f17b0cc4141b5d08b630b603756e2556dfdc2edb2d76197ebbc9d8d0ff3d7849b9d3b9e` |
| TLSH | `T136E3E80E7E258F7DF3ADC23847F75E21921923C626E1D586D26CE9115F6028E241FFA8` |
| TELFHASH | `t1e1214c5c497413e09b711c995baeff73e5a130cf1b266d3b8f11a9a8baadd825d00c0c` |
| SSDEEP | `3072:FchlL94u/HopRSf+Vmt8YNMfBPT7rs8njb6FXCIL:FcXL94u/HopRSf+VDYef5gKjeFBL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_900f628c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b"
    family = "Mirai"
    file_name = "900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:41"
  condition:
    hash.sha256(0, filesize) == "900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b"
}
```

### Sample 18: `8df2346597e0e753`

| Field | Value |
|---|---|
| SHA-256 | `8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077` |
| Family label | `unknown` |
| File name | `8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:34` |
| Reporter | `tanabotan` |
| Tags | `arm, backdoor, elf, heyiwei, persistence` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b23017a5f4c1b373f5161405d873d44` |
| SHA-1 | `0af89ecfc861cff9845084eaf33073dfe094e268` |
| SHA-256 | `8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077` |
| SHA3-384 | `71fdcb14275de736c05638b3e70747d7b9a61a5c7df88b38b0bb0bea9b4b925aaf9e03747fdefbd26854c67cac6b0f4c` |
| TLSH | `T135B319A8F890DB62C6D1667AFB4E428C33130779D3DA7102DD245B3427EB95B4F3AA05` |
| TELFHASH | `t125e02b1686a52a9872d44bc942d7847f8dea32fe635830789fb46fa60663cca3564433` |
| SSDEEP | `1536:f73BNYpHc2eWTEQHhOKACkWXSH0OChf0RrNy4IBjBS+wW9etS6pxUKvwzDCo/mdD:f7spPkzChU5NilS09Fwx+Ko/m0Ige` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_8df23465
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077"
    family = "unknown"
    file_name = "8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:34"
  condition:
    hash.sha256(0, filesize) == "8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077"
}
```

### Sample 19: `cc1b33edd4b08c51`

| Field | Value |
|---|---|
| SHA-256 | `cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5` |
| Family label | `unknown` |
| File name | `cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:27` |
| Reporter | `tanabotan` |
| Tags | `backdoor, elf, heyiwei, persistence, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f94a09fac1f204c0a089505d5e068d61` |
| SHA-1 | `56206a5c234555039c28697653b52dc0109f394e` |
| SHA-256 | `cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5` |
| SHA3-384 | `966a7f4edb942d3c0713e188c9f48cf2ef1ace403da373e9117657854c0cb36aa98d80a4128044aebc84eb52341e9292` |
| TLSH | `T12EB36C41EA93E0F1E0A39232425AE76B8B34DE394152D91BEB1B3E34EC75B81C54E35D` |
| TELFHASH | `t16f517cf56e3b0ce8b780a802e35e5b62ed0ed767556032e614f2296133ead9143f5c34` |
| SSDEEP | `3072:QUnleekSlduGdtaemIIsVNLqTOvqBTj2icm:nleqjhV/IcsBf2O` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_cc1b33ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5"
    family = "unknown"
    file_name = "cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:27"
  condition:
    hash.sha256(0, filesize) == "cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5"
}
```

### Sample 20: `26a130b4d98c369a`

| Field | Value |
|---|---|
| SHA-256 | `26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7` |
| Family label | `unknown` |
| File name | `26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:20` |
| Reporter | `tanabotan` |
| Tags | `backdoor, elf, heyiwei, persistence, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c4f98691f5c90e712e1eee7311ca970` |
| SHA-1 | `100fde7bd69d412880c4d272669123b77c13aa09` |
| SHA-256 | `26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7` |
| SHA3-384 | `0e56fea32d566638c168dfd6ee856c1c9ae8007b580ee524924464ef9a538c2594ccc3c73a125ff711532877c33e54a2` |
| TLSH | `T12FB35C41EA93D0F1E4A35272425AE76B8734DE394112D94BEB1A3E34FCB2A91C60F35D` |
| TELFHASH | `t141516df56e7b0ce87780a802e34e5ba2ed0ed777582032e614f1696032ead9147f5c39` |
| SSDEEP | `3072:lpaWX/9quWHvO9JS0dUaEoA0v666NTcrqxTb2Pam:NAuWWbPo50i5x/2Z` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_26a130b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
    family = "unknown"
    file_name = "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:20"
  condition:
    hash.sha256(0, filesize) == "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
}
```

### Sample 21: `f47a73d40427b211`

| Field | Value |
|---|---|
| SHA-256 | `f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029` |
| Family label | `Gafgyt` |
| File name | `f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:13` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mirai, Torii, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6073b200c44fb1fbde8e048a7bcd539` |
| SHA-1 | `5e541f09411abad753caa32268e8c3ff5d2f8230` |
| SHA-256 | `f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029` |
| SHA3-384 | `f6c30a7c4825aaca6ae75728af8d67e92568e9191a2323bb23acebe1b061ee82b7b1d63acd78653fe658d357dee882af` |
| TLSH | `T1C704D61676C38CEDC053C7B55A8D946B71B0F12F822E503367B1EAA03F1DEA1A9A7351` |
| TELFHASH | `t12231114279f6492d6bf3682858ac47a11556ba227320afb0bf5ec1508933002b875f8e` |
| SSDEEP | `3072:6N2nBmZu1EJqCKLqoE45zM5NCUXAOBljZIMtyDpqPQmPOLVPU8oJDHX:DnJe45z+jlGM8DpklPOLVPU8oJDHX` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_021_f47a73d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029"
    family = "Gafgyt"
    file_name = "f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:13"
  condition:
    hash.sha256(0, filesize) == "f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029"
}
```

### Sample 22: `f341099df5727f0f`

| Field | Value |
|---|---|
| SHA-256 | `f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4` |
| Family label | `Gafgyt` |
| File name | `f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:06` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, m68k, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5158f730646398419a3077f8b75c5e15` |
| SHA-1 | `a5ff1ced3fdd66796b435b6bcedf3cc9e65a56a9` |
| SHA-256 | `f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4` |
| SHA3-384 | `fad4998d74ac292cf1e0086475ccda5747ba39c08ab8984fe356e04202d065af84c0180b372249ae43e3e64dab47d033` |
| TLSH | `T1F204B847A412DF1BD49F673A16930221F6F9E3DD694202337327B8926F634E159BAEC0` |
| TELFHASH | `t17d31ff5279f6492d6bf3682858ac47611556b9227321afb4bf5e81908933002b871f8e` |
| SSDEEP | `3072:TZXJtLegXLnhZXHQgLBv52P13AywiMVOlV7wUQTmPs0ao8UtKFX:TZXbZXwgLBv5nywtclqUQTmPs0ao8Uta` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_022_f341099d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4"
    family = "Gafgyt"
    file_name = "f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:06"
  condition:
    hash.sha256(0, filesize) == "f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4"
}
```

### Sample 23: `eddced2bd1046768`

| Field | Value |
|---|---|
| SHA-256 | `eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e` |
| Family label | `Gafgyt` |
| File name | `eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e` |
| File type | `elf` |
| First seen | `2026-11-06 04:52:00` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mirai, Torii, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37ddce3b5c87da04e2b4005002f2ad77` |
| SHA-1 | `7896c5d7a79af58169d11dbc6e1ab84cb730d04b` |
| SHA-256 | `eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e` |
| SHA3-384 | `224a5d5e9adc6a9681c49e2e852a8f9d91cc060dc77897b2f6e3c9a46b70a98f6fd41e77850bc945c9a98dd931013aa8` |
| TLSH | `T151E308938B66C636E7035AB9126FEF5143B390FF28C78A90F3489B7445C24DBA190B5D` |
| TELFHASH | `t12231114279f6492d6bf3682858ac47a11556ba227320afb0bf5ec1508933002b875f8e` |
| SSDEEP | `3072:HuJc+Ga9UtxUVVpSE8JqMnOlVGXalhCpRwWriH90PfNatph1:ZcQEx9MOl2e4iH90PfNatph1` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_023_eddced2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e"
    family = "Gafgyt"
    file_name = "eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:00"
  condition:
    hash.sha256(0, filesize) == "eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e"
}
```

### Sample 24: `d59d4d658171b04d`

| Field | Value |
|---|---|
| SHA-256 | `d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04` |
| Family label | `Gafgyt` |
| File name | `d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:52` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mirai, powerpc, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e648f58edebfeb5a9041d6758f2bd44d` |
| SHA-1 | `fc5444d60e4b5cec2504f53719bfa09a264e24a0` |
| SHA-256 | `d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04` |
| SHA3-384 | `c773a8e9308795ff872e26dfe8bd6f5e71f453d0cd3cd0b992b8d9d2557544da290e8bdce1f32eaf23f833da3e8c7a53` |
| TLSH | `T1CF0451EFBF1C43DFD64F02B8292663E00FE89561139051C2F5999E420FB3179A92B6B5` |
| TELFHASH | `t114311f5279f6492d6bf3682858ac47611552ba327320afb0bf5e819089330027871f8e` |
| SSDEEP | `3072:ppq5LY0yXjiLX9K2cwsOqxY2XY29FrGStcOsPHs0aozetKNX:ppq5m69LcwsO01Xb9XpsPHs0aozetKNX` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_024_d59d4d65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04"
    family = "Gafgyt"
    file_name = "d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:52"
  condition:
    hash.sha256(0, filesize) == "d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04"
}
```

### Sample 25: `c0d787c9dccb8a17`

| Field | Value |
|---|---|
| SHA-256 | `c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f` |
| Family label | `Gafgyt` |
| File name | `c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:44` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mirai, sparc, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73c8f661e6bde05c34cb8fc94d1998ed` |
| SHA-1 | `0eb85b3b884c1d11dff7adc40d9432adeb78144b` |
| SHA-256 | `c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f` |
| SHA3-384 | `6f83bb61605bd0c96b1a820de8f8048af207f60bd19a0083684256c8b14a03e191590859c5dcdbaf53c1f3fd3fbea8ba` |
| TLSH | `T1AA24A73725232B52C4D1DFBB42A24338B4BED9AD345A0BD3A98D5DD93D30DE135922E2` |
| TELFHASH | `t112310d4279f6492d6bb3682858bc4ba11556b9227620afb0bf5e81904933002b875f8a` |
| SSDEEP | `3072:HOSqovthNPHwm17BmH1PpX/HEEaq8UtEiX:HOSNvPlJiH1hX/HEEaq8UtEiX` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_025_c0d787c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f"
    family = "Gafgyt"
    file_name = "c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:44"
  condition:
    hash.sha256(0, filesize) == "c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f"
}
```

### Sample 26: `baca232b155cd553`

| Field | Value |
|---|---|
| SHA-256 | `baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e` |
| Family label | `Gafgyt` |
| File name | `baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:37` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mirai, Torii, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cf415f06df29eb4dcf33555d50702ff` |
| SHA-1 | `62ebf4f3e05d1f6fe2066f552467461413982c61` |
| SHA-256 | `baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e` |
| SHA3-384 | `190315beadeb0b5d3e0b5f76ea384b9d2752bd6b0cf2d0945de26bb2fc865307d39fc5fec727bfe30c16d869a0a1e901` |
| TLSH | `T185E3F94FE17AC2F1D2470FB32257BCBB03F16129146B1E49F736ED61C9D3A9062A1298` |
| TELFHASH | `t12231114279f6492d6bf3682858ac47a11556ba227320afb0bf5ec1508933002b875f8e` |
| SSDEEP | `3072:XlEoRSgLyZrVvnNYd+soZS9BFGOlV5BBEfR1c9OXH90PfNatph1:X6oR5+qwS9BFFlhK51ckXH90PfNatph1` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_026_baca232b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e"
    family = "Gafgyt"
    file_name = "baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:37"
  condition:
    hash.sha256(0, filesize) == "baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e"
}
```

### Sample 27: `b40f9e77052ff3f2`

| Field | Value |
|---|---|
| SHA-256 | `b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae` |
| Family label | `Gafgyt` |
| File name | `b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:29` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mirai, superh, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b337d6e277cf8f63ab8488a22a1653d` |
| SHA-1 | `45d3309990d4ca0d3679d5ac2471d65896ed6ddb` |
| SHA-256 | `b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae` |
| SHA3-384 | `a032b20c7f92b83917d1f36f2dd7d4aca58c4cb49faa389a3b9bc71322756ed5ab9492064018f4489731614185482e7f` |
| TLSH | `T1DCF3C9968A31D9B7C053E9323A756158B39CBB6A0B0F09CBBE1D75621E1E0CF641F364` |
| TELFHASH | `t13931ff5279f6492d6bf3682858ac47611556b9227321afb4bf5e81948933002b871f8e` |
| SSDEEP | `3072:Xn4Ngp0e9HGp1Ya9Hn29FrhlLIQG9ZQLUD0afD+tKIj:X4Ngee9H+fH29hLoZQLUD0afD+tKIj` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_027_b40f9e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae"
    family = "Gafgyt"
    file_name = "b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:29"
  condition:
    hash.sha256(0, filesize) == "b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae"
}
```

### Sample 28: `6389eb9e2395facd`

| Field | Value |
|---|---|
| SHA-256 | `6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc` |
| Family label | `Gafgyt` |
| File name | `6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:22` |
| Reporter | `tanabotan` |
| Tags | `arceus, arm, elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b548f5c4867ae5240d46f743cdae83c8` |
| SHA-1 | `1d31b5503e70a66a138bb504dc311c5c80efa6d9` |
| SHA-256 | `6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc` |
| SHA3-384 | `8db286c707f32751cbb98f5e0bd69cb465d2ca8ba247ddf30b17d3ee150527afeed7db4a2644e370b9fdd3d43b5323b7` |
| TLSH | `T12E14C80198B0575FDBE39BFAF755B1CE723657981F83330AD3185AB013C12EA9929287` |
| TELFHASH | `t114311252a9f54a1d6bf368289cbc57b11155ba22b2217eb0bf4dc19449320037875e8b` |
| SSDEEP | `3072:VykagYQ9ACfN+MIbkWX4dT6+IYuyrJWtT9raedxGz9KP9LKO4VmNZKh24FCtZp2u:VykdxKOam/IACle9MNlqZTmyN4942Yk` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_028_6389eb9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc"
    family = "Gafgyt"
    file_name = "6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:22"
  condition:
    hash.sha256(0, filesize) == "6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc"
}
```

### Sample 29: `4e438363aa29ee41`

| Field | Value |
|---|---|
| SHA-256 | `4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f` |
| Family label | `Gafgyt` |
| File name | `4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:15` |
| Reporter | `tanabotan` |
| Tags | `arceus, arm, elf, gafgyt, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51f420db23778f5b9090a3c69255d565` |
| SHA-1 | `5d01405759a163fc403ef8fb2be098fa1ba5e47d` |
| SHA-256 | `4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f` |
| SHA3-384 | `5f3ab040d387868d528debd0f43aabb7a14a9662a53cc8cdf4ee938825830a5c2a20f8196ce6a9fdacc3c76ae88655c4` |
| TLSH | `T18A14CA449C645B2FDBE3ABFBF75471CE727646891F833309D72859B013C12EA9929283` |
| TELFHASH | `t17d31ff5279f6492d6bf3682858ac47611556b9227321afb4bf5e81908933002b871f8e` |
| SSDEEP | `3072:q9Ta40GXq11zXqwL5SpNZf1t3aLUUGPNQibtNf8eNgJs12Vhvc5PsEsEUxxQLeJ9:q9O8L6QIk9r7b1klKWoZCQ9gOS1SeX` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_029_4e438363
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f"
    family = "Gafgyt"
    file_name = "4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:15"
  condition:
    hash.sha256(0, filesize) == "4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f"
}
```

### Sample 30: `1fba0568f18e9043`

| Field | Value |
|---|---|
| SHA-256 | `1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93` |
| Family label | `Gafgyt` |
| File name | `1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93` |
| File type | `elf` |
| First seen | `2026-11-06 04:51:07` |
| Reporter | `tanabotan` |
| Tags | `arceus, elf, gafgyt, mips, mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66b4d307811f995b83e20855aae74d75` |
| SHA-1 | `f02c6013dc46e93a2cbb81b186c437a5c0f4e0fa` |
| SHA-256 | `1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93` |
| SHA3-384 | `12eca3129b2dfc7de0669ca9000e02fc71066e0b52be60684d9a414f03e60a90fd46142f511b64df6b02c177696b0c6f` |
| TLSH | `T12534213E3EB15BADD292C3714BF26EF086A565A62282D321D23DC7541E7438E0D7F660` |
| TELFHASH | `t15631ff5279f6492d6bf3682858fc47611556f9227321afb4bf5e81904933002b875f8e` |
| SSDEEP | `3072:RinafG+iwBxtCeO29Fri1BsKDqR/49qHEkuOSX:AqtVBOeR9sBNqR/49qHEkuOSX` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_030_1fba0568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93"
    family = "Gafgyt"
    file_name = "1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:07"
  condition:
    hash.sha256(0, filesize) == "1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93"
}
```

### Sample 31: `797d210c96fdcfa1`

| Field | Value |
|---|---|
| SHA-256 | `797d210c96fdcfa1d41b77380f44272762ec9c6f7c7a485f09c0d3fc56f836fa` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-06 04:39:04` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd26506ef1f64869cc801dc18caafe4c` |
| SHA-1 | `c378600dc373fb4fed4ffcdc768c473b2a52982b` |
| SHA-256 | `797d210c96fdcfa1d41b77380f44272762ec9c6f7c7a485f09c0d3fc56f836fa` |
| SHA3-384 | `7df66cc1ee6fe747738e80cfcf4ddf432a35543aef2aed474bfabb42385d256e33b460ed84f3ab1a76cf83159f1cf7d7` |
| TLSH | `T125667C45BC2C7462D9CAB5B42F7622967A38BC488F81C7275614FB3CBAF27648F13161` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:RltQDhv/uj2/GnWOEK0tzdfcWOHHjipwtL4uI89O0MR4uj+5El:RltQdv/uHnEtzyLTMpRrUEl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_797d210c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "797d210c96fdcfa1d41b77380f44272762ec9c6f7c7a485f09c0d3fc56f836fa"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-06 04:39:04"
  condition:
    hash.sha256(0, filesize) == "797d210c96fdcfa1d41b77380f44272762ec9c6f7c7a485f09c0d3fc56f836fa"
}
```

### Sample 32: `eb5270896f08c350`

| Field | Value |
|---|---|
| SHA-256 | `eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765` |
| Family label | `unknown` |
| File name | `eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765.exe` |
| File type | `exe` |
| First seen | `2026-11-06 03:54:52` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40a7ef02ed43f9bbb5d3d1ab5894d3d1` |
| SHA-1 | `f95f313511937fa943b94cb78492de3a6c843303` |
| SHA-256 | `eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765` |
| SHA3-384 | `05d3c3ab8e96a6cb9536f19c1f4fe6eb67b94cb026823d49b99ec9ca41e71cf1b49e8d7ffb1e86083b9d7c793bc07d87` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T17E91A5C5F75BE6B2EC1C07F500A37994C8682E1492BC9B564FA16F1C3C111AA3D3DA56` |
| SSDEEP | `48:6I7lwe7IPyU08SwJdSR1Ig9TPe1YpV1ZsSZIXxhxhwcRaK:Pl1Md096q1Ig9T2Enwp` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_eb527089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765"
    family = "unknown"
    file_name = "eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765.exe"
    file_type = "exe"
    first_seen = "2026-11-06 03:54:52"
  condition:
    hash.sha256(0, filesize) == "eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765"
}
```

### Sample 33: `c48071a9e15df2ca`

| Field | Value |
|---|---|
| SHA-256 | `c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740` |
| Family label | `Mirai` |
| File name | `c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740` |
| File type | `apk` |
| First seen | `2026-11-06 03:00:11` |
| Reporter | `EnthecSolutions` |
| Tags | `apk, enthec, Mirai, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c18b8cee71575afb1951c4b493e4372` |
| SHA-1 | `d12d9cfdb69fd4dd516d10057bf22138b1da2a18` |
| SHA-256 | `c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740` |
| SHA3-384 | `7511b592d1c7a82ba4581b63154348ba84147a2befadd61f2acc81290f2496b8422580387844fe1e7790e62de970efd8` |
| TLSH | `T16AC42357BA641B3FCCEF52F9BB274D5116642B00E811A3AD9274F61CA787394CB113D4` |
| SSDEEP | `12288:VfIkfo+x3bkhsXUIQchOjBSv1jFNtUfdwu:qk/bkhIUD98v1jFNW17` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_c48071a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740"
    family = "Mirai"
    file_name = "c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740"
    file_type = "apk"
    first_seen = "2026-11-06 03:00:11"
  condition:
    hash.sha256(0, filesize) == "c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740"
}
```

### Sample 34: `9bd9786c48d27a16`

| Field | Value |
|---|---|
| SHA-256 | `9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32` |
| Family label | `Prometei` |
| File name | `9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32` |
| File type | `elf` |
| First seen | `2026-11-06 02:58:46` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81245fb258d39b7aa623ce94f7ea8b42` |
| SHA-1 | `6df40f03b95c8562e80720d81cbc0fef496d3615` |
| SHA-256 | `9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32` |
| SHA3-384 | `5af6bf13a07c473bd32e6f71eb03a804c353129674ef0091373e2e98c4640374d64b1c9a697b927d3671ac60525d901a` |
| TLSH | `T19F9423FBD6C0430FCF16117C277A6E22D2C6553539AD6AB0C62CF8AE0E792075944EA7` |
| SSDEEP | `12288:4h/taqLkdfH8ytYiflIw0BEmWVeygFurhCB:4YdkVLwKvyaJB` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_034_9bd9786c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32"
    family = "Prometei"
    file_name = "9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32"
    file_type = "elf"
    first_seen = "2026-11-06 02:58:46"
  condition:
    hash.sha256(0, filesize) == "9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32"
}
```

### Sample 35: `63adf9ad9100e192`

| Field | Value |
|---|---|
| SHA-256 | `63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a` |
| Family label | `Prometei` |
| File name | `63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a` |
| File type | `exe` |
| First seen | `2026-11-06 02:58:28` |
| Reporter | `c2hunter` |
| Tags | `exe, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad4bb757b71b948d7a37dbe4ad7f6a01` |
| SHA-1 | `9e0a431b8ef4cad0f3d67fa137743c0b6d0c4549` |
| SHA-256 | `63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a` |
| SHA3-384 | `022e2c256f42f18c0bbb7b296c2163d1f2714007c06f97fc9445a3073bc807c1b636fa0d287fbd70de7f988a14a4bc7d` |
| IMPHASH | `551920a564f0da077e7c568c1940defb` |
| TLSH | `T12874D07775B8F15EC88517328F62C7C293993F908993806F7EB4530F29278A91A35B72` |
| SSDEEP | `6144:8RzeTJQJfChxxTnECpq9XkCnNNCoo/iSq9opz5Pv5Pi12dwyJ:8JZJfChLjE4q9X7HGqZ9opzvi1yJ` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_035_63adf9ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
    family = "Prometei"
    file_name = "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
    file_type = "exe"
    first_seen = "2026-11-06 02:58:28"
  condition:
    hash.sha256(0, filesize) == "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
}
```

### Sample 36: `9d03a606ffb60773`

| Field | Value |
|---|---|
| SHA-256 | `9d03a606ffb60773098b968e48f6e4fe86251969a37f73bb6e57e61422f246ae` |
| Family label | `AveMariaRAT` |
| File name | `9d03a606ffb60773.bin` |
| File type | `exe` |
| First seen | `2026-11-06 02:25:21` |
| Reporter | `Tuxxin` |
| Tags | `AveMariaRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2db2e9a6821b3378e3827012a547ae6` |
| SHA-1 | `0d3d0435e2c15fbfc4a598ae2690d688b73b3d96` |
| SHA-256 | `9d03a606ffb60773098b968e48f6e4fe86251969a37f73bb6e57e61422f246ae` |
| SHA3-384 | `4d2c7e322401231941aefcaba9e9c1c0150122290f9248553334c049ca971e7ad9776dc6b4ac7cfffa4e709c6292c433` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BE648D9C726076EFC857D4729EA81C78FB6064BB871F8213A06755ADEA0D897CF100F2` |
| SSDEEP | `6144:Z8kcwEeWDpDU5NBTdbDv+eniH/w7+aRheQ8KSnEgeReNn7EIryYI:Z8HRF2MeniH/U3SEgeReNn7EIryF` |

#### Technical Assessment

- The sample is tracked as `AveMariaRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AveMariaRAT_036_9d03a606
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d03a606ffb60773098b968e48f6e4fe86251969a37f73bb6e57e61422f246ae"
    family = "AveMariaRAT"
    file_name = "9d03a606ffb60773.bin"
    file_type = "exe"
    first_seen = "2026-11-06 02:25:21"
  condition:
    hash.sha256(0, filesize) == "9d03a606ffb60773098b968e48f6e4fe86251969a37f73bb6e57e61422f246ae"
}
```

### Sample 37: `4cee268790d7ab65`

| Field | Value |
|---|---|
| SHA-256 | `4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341` |
| Family label | `unknown` |
| File name | `4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:50:01` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `df285e6a7e3e14a650aaefee43c7e8dd` |
| SHA-1 | `881ac458680da5dc82d9b6c35a9bf9dc1c0c57bc` |
| SHA-256 | `4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341` |
| SHA3-384 | `7599930cb79e912c1f03f3102b856f0af180e40ac97d3802be30297cacf8b127222ac5d6836360953288463ba0af5c49` |
| IMPHASH | `5647fb939de4e6e2843458a387335597` |
| TLSH | `T1B7D5238AFDF648B1E876C3B75AC3643CB02877494A704E9776CC6B444E13A58AC77278` |
| SSDEEP | `49152:IxT/SE0d/a+Y55KXHkk/+boMEd2Bf+zoqCTfBPK35KZcTag+TyYVRcZrEIZjt:hE0d/a+YDsHkk/VMVd+MqIfte4OagvY6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_4cee2687
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341"
    family = "unknown"
    file_name = "4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:50:01"
  condition:
    hash.sha256(0, filesize) == "4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341"
}
```

### Sample 38: `92a8eb4a5952adc2`

| Field | Value |
|---|---|
| SHA-256 | `92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5` |
| Family label | `unknown` |
| File name | `92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:49:54` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `262a6da898077611e3401324393f2b24` |
| SHA-1 | `1675adfcd2876204806ea09d940f5d2b427190cc` |
| SHA-256 | `92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5` |
| SHA3-384 | `c1b80eb1f0cc248b27b27cf3550937542f7c7f57df51a26ae7e74565531ed77e877c9cf7b23ec3212f613cf02cba2c7f` |
| IMPHASH | `3b33063fa6540cfc510bd20fcc99cc96` |
| TLSH | `T1F5D5228CFCF604B5F877C3778297A0AEB0693B8143209D97BACC6B505E136642D76678` |
| SSDEEP | `49152:pMDUr52+C0DVwEEIg967X93MaLsD0gtwcU49pIBLqyAApCHsuiCiCYl1IKrHjall:p9E+CkmM7lMaLpgqcUxBVpCMui7CkIc0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_92a8eb4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5"
    family = "unknown"
    file_name = "92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:49:54"
  condition:
    hash.sha256(0, filesize) == "92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5"
}
```

### Sample 39: `1dde3ee1a023e921`

| Field | Value |
|---|---|
| SHA-256 | `1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a` |
| Family label | `VShell` |
| File name | `1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:41:11` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3033be8bd179b01a7a89aed36b8e4ce6` |
| SHA-1 | `e09f0fd2f8996b9aca90da082565439c0095d723` |
| SHA-256 | `1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a` |
| SHA3-384 | `2bf303a4fb78f8ef8b4c9c5c0cc084c282da16500b33745326898ef730cda431dfc55275d2fa4581f6b188ed515e7aad` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1AB716394F3136AF1E42C46F840D3A564C0199BBCC150BF4D5F60381D3C220BA269EF97` |
| SSDEEP | `48:6Icwm0Ot2WdJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4jDt/SNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_039_1dde3ee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a"
    family = "VShell"
    file_name = "1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:41:11"
  condition:
    hash.sha256(0, filesize) == "1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a"
}
```

### Sample 40: `2731c2579caa28e7`

| Field | Value |
|---|---|
| SHA-256 | `2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a` |
| Family label | `WARDENStealer` |
| File name | `2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:39:54` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a39ca71b0e8bed59720df54c951ee88e` |
| SHA-1 | `cbd4a1def1d8c8f33ffd5ae596aecfff500c84f6` |
| SHA-256 | `2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a` |
| SHA3-384 | `546162fd04f15b6bcaff99cf84f66bb39a0ae2eb6ea5aa9e8f95486ff7b6b92e322eea2c3cb516c3831ec91dc94f1f01` |
| IMPHASH | `bb23e24834e2b74fbad1066aabb046e3` |
| TLSH | `T1E935F04EF7964EF9F422B53741114636A3117C44C7E48AAB769C932E1E262CB8FF9720` |
| SSDEEP | `24576:onnThb10XnKFKH0g42Z/+1XAi/migHt/Z8zmYIOjH4:ondb10X0a0g4c+N/m5bC5H` |
| ICON-DHASH | `1068b27171b26810` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_040_2731c257
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a"
    family = "WARDENStealer"
    file_name = "2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:39:54"
  condition:
    hash.sha256(0, filesize) == "2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a"
}
```

### Sample 41: `af4b153c27eb9996`

| Field | Value |
|---|---|
| SHA-256 | `af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b` |
| Family label | `unknown` |
| File name | `af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:34:56` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64b5d68b5885395a4682ea6575d58157` |
| SHA-1 | `394f34ed0f0308921ed3c8a23d57745415576521` |
| SHA-256 | `af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b` |
| SHA3-384 | `91e2f7daaf06d6664c89838aea56eb03cddbf171c047943c02b15d71422a6d283e34927340a5d9c618367eae18e8c303` |
| TLSH | `T1AEF25F139B1C0A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRUPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfXlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_af4b153c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b"
    family = "unknown"
    file_name = "af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:34:56"
  condition:
    hash.sha256(0, filesize) == "af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b"
}
```

### Sample 42: `ec3e7cf7e7e4119f`

| Field | Value |
|---|---|
| SHA-256 | `ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e` |
| Family label | `unknown` |
| File name | `ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:34:52` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c51c7ee145c5478b888a76fab8f2dff1` |
| SHA-1 | `677e2a6e183db0388fae3bd669acf2ed7613711d` |
| SHA-256 | `ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e` |
| SHA3-384 | `d75ea9fbb696484dbe74b54e931f416cdaac41f885394612022886ac4552235dfc708fc6da8a8671c6f96fde451812ae` |
| TLSH | `T19AF263239B1C5922C44C623C42BF6742A23AF1A146D577674B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7pH14z1dgngS6BndngN/4B0:RUdp8j3jvpWK7t1MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_ec3e7cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e"
    family = "unknown"
    file_name = "ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:34:52"
  condition:
    hash.sha256(0, filesize) == "ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e"
}
```

### Sample 43: `602a346e45e8cba4`

| Field | Value |
|---|---|
| SHA-256 | `602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63` |
| Family label | `unknown` |
| File name | `602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:31:06` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86db62d4528048eb7f1e4886998f1aad` |
| SHA-1 | `90f17d36ea80aad69ddefbc5cf87fe22afdb6926` |
| SHA-256 | `602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63` |
| SHA3-384 | `9a355344593e16b75359d858e912cfc9c09d9319afb13724d21573cb35647baa1fbb8ee2f3714c24add6e9e41e83e05a` |
| TLSH | `T127F273239B1C5922C44C723C82BF6742A23AF1A145D677774B00872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7lHf4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7hfMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_602a346e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63"
    family = "unknown"
    file_name = "602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:31:06"
  condition:
    hash.sha256(0, filesize) == "602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63"
}
```

### Sample 44: `d69754b6f6ce97e5`

| Field | Value |
|---|---|
| SHA-256 | `d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75` |
| Family label | `unknown` |
| File name | `d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:26:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5baa57f706f2fe172c2630ef8da097de` |
| SHA-1 | `b39e2997990834a5afd37b1d024f3cb70bb1e31e` |
| SHA-256 | `d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75` |
| SHA3-384 | `08af330836560954d65d74c3963f7c569ad0812ca957f214f8c9d1b0d1ba589e99601b294572bd318b294e1d9bb917c2` |
| TLSH | `T187F263239B1C5922C48C663C82BB6742A23AF1E145D677774B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7IHk4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7YkMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_d69754b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75"
    family = "unknown"
    file_name = "d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:26:04"
  condition:
    hash.sha256(0, filesize) == "d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75"
}
```

### Sample 45: `1aa949ac5f5056fd`

| Field | Value |
|---|---|
| SHA-256 | `1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d` |
| Family label | `unknown` |
| File name | `1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:26:00` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de779f2b073a715105296cffe235a268` |
| SHA-1 | `42936c7cfdc7bde98ddd8553ab26d9b755530635` |
| SHA-256 | `1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d` |
| SHA3-384 | `8a66c3473ad915fbc7d45159b89ecc9cc95bd50f2a190bf31defc5ede43e0fb075ab76a50cebba373ab71968fb484815` |
| TLSH | `T160F25F139B1C0A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BEB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRzPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfmlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_1aa949ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d"
    family = "unknown"
    file_name = "1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:26:00"
  condition:
    hash.sha256(0, filesize) == "1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d"
}
```

### Sample 46: `f651f36343155c44`

| Field | Value |
|---|---|
| SHA-256 | `f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2` |
| Family label | `unknown` |
| File name | `f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:24:42` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f63cdcf13fdc197b3e903abdb988c63b` |
| SHA-1 | `3b51748e0e75373f321e52c2ad603650ad851684` |
| SHA-256 | `f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2` |
| SHA3-384 | `75fd11cc4164d667847d7119157c106ce3f24563d62285fd63efa48dfd1ead4259d87426e482fb908339e5e7bff0136b` |
| TLSH | `T1F0F263239B1C9922C48C623C42BB6742A23BF1A145D677774B04872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7OHe4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7SeMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_f651f363
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2"
    family = "unknown"
    file_name = "f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:24:42"
  condition:
    hash.sha256(0, filesize) == "f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2"
}
```

### Sample 47: `393375c12fe8293c`

| Field | Value |
|---|---|
| SHA-256 | `393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177` |
| Family label | `unknown` |
| File name | `393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:21:00` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f8993e255a93552c84a99811309d17a` |
| SHA-1 | `bc316b44922817156cf70ec53ef45d7b54899c6e` |
| SHA-256 | `393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177` |
| SHA3-384 | `072d356d86252ce0af8520c7ea05406b504c206420e582db30fbb2b4fc3817db7a1abbdaa7861384d20737117033e374` |
| TLSH | `T1F8E22D43AB4C8965C26D42301AF71BC6A615F6B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUWVZqDDt0TOTLZ0BbFw2mHKk6XrMclSibFqAMcl:z4ZZXvvLVZMt0TO2bVK/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_393375c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177"
    family = "unknown"
    file_name = "393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:21:00"
  condition:
    hash.sha256(0, filesize) == "393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177"
}
```

### Sample 48: `1adac896cf5634ed`

| Field | Value |
|---|---|
| SHA-256 | `1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d` |
| Family label | `unknown` |
| File name | `1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:17:07` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `074946e00e50ec4482a668b549ce270f` |
| SHA-1 | `59055c7d09757d1513571f776c9fe169c1737034` |
| SHA-256 | `1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d` |
| SHA3-384 | `bd84472712ce26f8e1bd5bbb2ae3295869767b8ed0992fcb760fbb50a2683472bc420043d1ffc3ec00191874a1484f0a` |
| TLSH | `T1C2E23E43AB4C9965C26D42301AF71BC6A615F5B09EE26B875750C7217FE13883C72E8F` |
| SSDEEP | `192:z4ZZXvv8VZMt0TO2bVqa/6bMclRbJMcl:z4P38yhlRb/l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_1adac896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d"
    family = "unknown"
    file_name = "1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:17:07"
  condition:
    hash.sha256(0, filesize) == "1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d"
}
```

### Sample 49: `8f33eef6cd5411bd`

| Field | Value |
|---|---|
| SHA-256 | `8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0` |
| Family label | `unknown` |
| File name | `8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:17:01` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `602e022caca3d25d67ecd07de484e455` |
| SHA-1 | `acd9966b2fef3e67c75ec1c439f6d94f60a8f6c4` |
| SHA-256 | `8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0` |
| SHA3-384 | `10e2a96272410efcce2c160f48917f29a2e1a2b4b0958f0f645d928392f6cc0ec26ae9fb699519a1135a7aefd8974999` |
| TLSH | `T18CF25F139B1C0A61C45C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB9D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRsqPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJft4lilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_8f33eef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0"
    family = "unknown"
    file_name = "8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:17:01"
  condition:
    hash.sha256(0, filesize) == "8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0"
}
```

### Sample 50: `6d95b7b322c16956`

| Field | Value |
|---|---|
| SHA-256 | `6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159` |
| Family label | `unknown` |
| File name | `6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:14:46` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6075353816ea6be47588b6ce0399000b` |
| SHA-1 | `2f74ba1b30a2fa910f68e8689de2e435994de898` |
| SHA-256 | `6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159` |
| SHA3-384 | `bee92c4ca7b6493a253ab201c6a7968cc275ff9a5a783a5591873d2e487a61a0f233780e15f7b0396736245882025fac` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T11591C64270B989E7E85C55BB4C0FB8A0B919B40A41C483A74338A5A93F3967BF47CB0D` |
| SSDEEP | `48:6IIF9BlQaexWfgZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMWiA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_6d95b7b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159"
    family = "unknown"
    file_name = "6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:14:46"
  condition:
    hash.sha256(0, filesize) == "6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159"
}
```

### Sample 51: `e7f1ec95be8d9dca`

| Field | Value |
|---|---|
| SHA-256 | `e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda` |
| Family label | `unknown` |
| File name | `e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:12:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da5d5bfd2e6f0cfce4ea5b4337db8958` |
| SHA-1 | `d88abef5a8966e509e7850c9b8362b2e478d2834` |
| SHA-256 | `e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda` |
| SHA3-384 | `6e1a8996459ebaea383ce1cdbe0c7e67203ac2315fa2f973f1f8c3941ed344140a5c9dd1f83137bbcf806c76656f877d` |
| TLSH | `T149F24F139B1C1A61C15D633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRw8PlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfililltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_e7f1ec95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda"
    family = "unknown"
    file_name = "e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:12:04"
  condition:
    hash.sha256(0, filesize) == "e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda"
}
```

### Sample 52: `51476daf7f8fea1d`

| Field | Value |
|---|---|
| SHA-256 | `51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30` |
| Family label | `unknown` |
| File name | `51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:11:59` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d31d4b6a5e486968badd2179463b4635` |
| SHA-1 | `1f667cbe3ab14ecc565856c0ed447919c1feca2f` |
| SHA-256 | `51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30` |
| SHA3-384 | `db666eb73e9cc0213dfef28b7fab24543ddf5a2a4ba4037b715d71f6107b3e6bb050203bcf222254979031b8b45b4c7f` |
| TLSH | `T195F25E139B1C0A61C15C633C92BB1B026236F5D086C56B674B10C76CAFCA3C5BEB9D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRiPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJf9lilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_51476daf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30"
    family = "unknown"
    file_name = "51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:11:59"
  condition:
    hash.sha256(0, filesize) == "51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30"
}
```

### Sample 53: `38a3228eb79fbce3`

| Field | Value |
|---|---|
| SHA-256 | `38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b` |
| Family label | `unknown` |
| File name | `38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:11:54` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aab2c627d6ee2d227b03e0a07059f0e1` |
| SHA-1 | `59eed15438b47e0e4af56cc56a2292cc41794c56` |
| SHA-256 | `38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b` |
| SHA3-384 | `117fc2c425a2d3a8d799dada698c74c3d97655440fc2e12e1c15665f098b250f998e2203db72532145b4d1acbaa9ad46` |
| TLSH | `T179F263239B1C5922C44C623842BF6742A23AF1A145D577774B04C72DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7NHH4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7pHMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_38a3228e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b"
    family = "unknown"
    file_name = "38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:11:54"
  condition:
    hash.sha256(0, filesize) == "38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b"
}
```

### Sample 54: `2c6cc3ecdfa063fd`

| Field | Value |
|---|---|
| SHA-256 | `2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832` |
| Family label | `unknown` |
| File name | `2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:10:59` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c4abee661aa82dc30bcbe60cac59b45` |
| SHA-1 | `689d5b5f215cf5bd4ed598f3af9d7be3f7f7d2ed` |
| SHA-256 | `2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832` |
| SHA3-384 | `6d893ac70d24019ba4c6e6c8ae7c0c6808c1a5cf5bf2059dda24ae0f0c61199d074a284ba45573c0ae913ec35567ac89` |
| TLSH | `T1DBE24F43675C5929D05D83BE62FB1B576609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEy5DbDP67li97WsCqwYjqclS06W1YbqclSl:GI2y5DbDyMwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_2c6cc3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832"
    family = "unknown"
    file_name = "2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:10:59"
  condition:
    hash.sha256(0, filesize) == "2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832"
}
```

### Sample 55: `2500ec5b30002d4e`

| Field | Value |
|---|---|
| SHA-256 | `2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572` |
| Family label | `unknown` |
| File name | `2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:10:07` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf12a2cedea4e0e324bd574855a463b1` |
| SHA-1 | `2b4511d254ae4f89e59702904934454111338ae7` |
| SHA-256 | `2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572` |
| SHA3-384 | `6a5a16cada9ab4934eaa7f56ce2be92bfe13c4a3267d73c8decf9423df6467bd2ce6a3c109cef9882a0bef79cb0e5c7f` |
| TLSH | `T1B3E25F43675C5929D05D83BA22FB5B976619F8A009E45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCSwYjqclS06W1YbqclSl:GI2n5DbDykwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_2500ec5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572"
    family = "unknown"
    file_name = "2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:10:07"
  condition:
    hash.sha256(0, filesize) == "2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572"
}
```

### Sample 56: `9b62873ec976996f`

| Field | Value |
|---|---|
| SHA-256 | `9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297` |
| Family label | `unknown` |
| File name | `9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:10:01` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21d4dc9c2af05a7a2724531f77489db2` |
| SHA-1 | `21e9fc25f3014e74d75db7ae5a703ddf14e02d58` |
| SHA-256 | `9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297` |
| SHA3-384 | `133531992689bbc8d3bc0c32a65fe8cff0bbd8d0657f5361fc26ca3de9516d3d84ea1fd734ad05159f47bc13781c759b` |
| TLSH | `T13DF263239B1C5922C44C623842BB6742A23AF1A145D677774B00872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK70Hf4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7cfMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_9b62873e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297"
    family = "unknown"
    file_name = "9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:10:01"
  condition:
    hash.sha256(0, filesize) == "9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297"
}
```

### Sample 57: `18c0c5487bd8c298`

| Field | Value |
|---|---|
| SHA-256 | `18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a` |
| Family label | `unknown` |
| File name | `18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:09:53` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `713f7e37c1ff3a60709ff1c6c2d7d799` |
| SHA-1 | `21ed5a2994ccc0aade570ee9c77bfad1460fbb52` |
| SHA-256 | `18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a` |
| SHA3-384 | `fde56d90aa81d695bc77d6779145e38cf36aef04575d203188ad01db29b6bb0c15cae062e0ca41343220bd23cd595358` |
| TLSH | `T157E22D43AF4C8965C26D82301AF71BC6A616F5B09EE16B875750C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2yHKk6XrMclSibFqAMcl:z4ZZXvv4VZMt0TO2bV+/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_18c0c548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a"
    family = "unknown"
    file_name = "18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:09:53"
  condition:
    hash.sha256(0, filesize) == "18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a"
}
```

### Sample 58: `2652f5c9af66c641`

| Field | Value |
|---|---|
| SHA-256 | `2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e` |
| Family label | `unknown` |
| File name | `2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:09:48` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4cbd4684a40af0b4267e275df924d0ca` |
| SHA-1 | `caad0942ce4eb50f42cbd63b0d3738f63c05afe9` |
| SHA-256 | `2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e` |
| SHA3-384 | `fa48389c155340e2d806ad9389f9ea956d91bc55c7bb43a35637841a2c730cf34556018660ff93e13c7381f56aea3d3e` |
| TLSH | `T1E3F24F139B1C1A61C15D633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMR3PlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfGlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_2652f5c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e"
    family = "unknown"
    file_name = "2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:09:48"
  condition:
    hash.sha256(0, filesize) == "2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e"
}
```

### Sample 59: `e2394f37e2217eec`

| Field | Value |
|---|---|
| SHA-256 | `e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2` |
| Family label | `unknown` |
| File name | `e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:07:04` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c19f122c18409eab2be65632b17194b` |
| SHA-1 | `41018de3aff55e1713f965b73268e52f5fb7ce75` |
| SHA-256 | `e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2` |
| SHA3-384 | `3614d9285722577d971ebd95f9d22e12e0a4232ec145a83aff7cf6ea4867fb2651bb4e9abb24d6df1da4f0db470f8d6c` |
| TLSH | `T149E24F43675C5929D05D83BE22FB1B576609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEE5DbDP67li97WsCS9wYjqclS06W1YbqclSl:GI2E5DbDys9wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_e2394f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2"
    family = "unknown"
    file_name = "e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:07:04"
  condition:
    hash.sha256(0, filesize) == "e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2"
}
```

### Sample 60: `08a7e23c2f9bb540`

| Field | Value |
|---|---|
| SHA-256 | `08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188` |
| Family label | `unknown` |
| File name | `08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:06:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2f558c808277ccab664f409c7abd1ff8` |
| SHA-1 | `d9b182c387ce30792012f6c499a19124c65b1148` |
| SHA-256 | `08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188` |
| SHA3-384 | `1df30ae21cd2466592c67535f4761eb956df4164e8f6a3108fc4e1f119c19273dfe391049e771cb90b3e347b5e5f67b7` |
| TLSH | `T108E22D43AB4C8965C26D42301AF71BC6A616F5B09EE16B8B5750C7217EE13883C72E8F` |
| SSDEEP | `192:z4ZZXvvlVZMt0TO2bVjb/6bMclRbJMcl:z4P3ly3lRb/l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_08a7e23c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188"
    family = "unknown"
    file_name = "08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:06:57"
  condition:
    hash.sha256(0, filesize) == "08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188"
}
```

### Sample 61: `88891429bd37a961`

| Field | Value |
|---|---|
| SHA-256 | `88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a` |
| Family label | `unknown` |
| File name | `88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:06:52` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9be210d6af6b92956cc378381b2516d3` |
| SHA-1 | `a5cb038907a9c24f062ac2c8e3aa37ee83c30269` |
| SHA-256 | `88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a` |
| SHA3-384 | `4e7e0e6735eb42ff7f740ca712b497cfb1690f2f3f8c1d7c746751e262d342454c04f8d08310776a9dd01eba7c837c06` |
| TLSH | `T1D3F263239B1C5922C45C623C42BF6742A23AF1A145D577774B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7MHn4z1dgngS6BndngN/4B0:RUdp8j3jvpWK70nMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_88891429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a"
    family = "unknown"
    file_name = "88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:06:52"
  condition:
    hash.sha256(0, filesize) == "88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a"
}
```

### Sample 62: `eb423963cff11fab`

| Field | Value |
|---|---|
| SHA-256 | `eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a` |
| Family label | `unknown` |
| File name | `eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:06:09` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1923a72dfeb879dfb05fa913d9416456` |
| SHA-1 | `a6571314a684ed97e1bcdec1ac0f237436f3a514` |
| SHA-256 | `eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a` |
| SHA3-384 | `6320bea76c2aaa5339a9b9ff08e59f7661b28aebf7a6641f4510d28faea58f5061dc0dae5bef16c56d5ab203ef340413` |
| TLSH | `T108F263239B1C5922C48C623882BF6742A23BF1E145D677774B00872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7n+HT4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7CTMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_eb423963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a"
    family = "unknown"
    file_name = "eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:06:09"
  condition:
    hash.sha256(0, filesize) == "eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a"
}
```

### Sample 63: `bb214b043caff0df`

| Field | Value |
|---|---|
| SHA-256 | `bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a` |
| Family label | `VShell` |
| File name | `bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:06:04` |
| Reporter | `Tuxxin` |
| Tags | `exe, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `52c4d63e55ff107e0b5a8b7ad2b44aa5` |
| SHA-1 | `0309ef4255c1420b28bc52063b16d38343ba2362` |
| SHA-256 | `bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a` |
| SHA3-384 | `d4f1035231bcc36073df594a218ac70e6c31dd1dbec6b2157bbda541df3b12ea48adf1f42b23ef3f6d9bc794802ade64` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T151716188F3136EF1E43C46F801D3A624D119ABB8C250BF4D5E60381D3C210BA255EF97` |
| SSDEEP | `48:6Icwm0at2WSJ8zrD7TLjpSpc1ZsSYr8XxhxhwcRaK:4j3tQSNSYp` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_063_bb214b04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a"
    family = "VShell"
    file_name = "bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:06:04"
  condition:
    hash.sha256(0, filesize) == "bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a"
}
```

### Sample 64: `2cc2364073d38d28`

| Field | Value |
|---|---|
| SHA-256 | `2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476` |
| Family label | `unknown` |
| File name | `2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:05:58` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2afc341828c43ceae255a64adebd9d98` |
| SHA-1 | `b0dd6239ec5cc69bd08ba532b64e0ca181723b41` |
| SHA-256 | `2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476` |
| SHA3-384 | `1dafca389b724707d7716e4283e63aef47308a52cb1464eef85824e35dc0d24fe00706ff13e149b7494c7ec9951c4bb4` |
| TLSH | `T1A8E22E43AF4C8965C26D82301AF71BC6A615F5B09EE16B875750C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2pHKk6XrMclSibFqAMcl:z4ZZXvv4VZMt0TO2bVt/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_2cc23640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476"
    family = "unknown"
    file_name = "2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:05:58"
  condition:
    hash.sha256(0, filesize) == "2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476"
}
```

### Sample 65: `bc4370ae232f27a1`

| Field | Value |
|---|---|
| SHA-256 | `bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0` |
| Family label | `unknown` |
| File name | `bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:05:52` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24e5dc5dbea4af41bf64f23eb8e050e2` |
| SHA-1 | `6c483a23ce63b5c7416d3fc320f92561cc1883a1` |
| SHA-256 | `bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0` |
| SHA3-384 | `af8ec48ef9313f9e123326d8de88951a90c16d82eeea99fbf63cdefb08137442361878f48152f499a0cf022dc4dd3ac4` |
| TLSH | `T176E22D43AB4C8965C26D42301AF71BC6A616F5B09EE16B875750C7217FE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2JHKk6XrMclSibFqAMcl:z4ZZXvv4VZMt0TO2bVN/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_bc4370ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0"
    family = "unknown"
    file_name = "bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:05:52"
  condition:
    hash.sha256(0, filesize) == "bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0"
}
```

### Sample 66: `a03196b8929db6a6`

| Field | Value |
|---|---|
| SHA-256 | `a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14` |
| Family label | `unknown` |
| File name | `a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:05:08` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09bc3669c3319e8c8d1b763c9eff9dd8` |
| SHA-1 | `c9b5a6f77007b23c345d21101a2fc8c0d67d1b0a` |
| SHA-256 | `a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14` |
| SHA3-384 | `669a0a30a2ddbe782d3518b0c7e8d06f379ecdfc7b77e613c2344ad1d1ea2b2992f34e268fdd82ec03f36549705fecde` |
| TLSH | `T111F263239B1C5922C48C623C42BB6742A23AF1A145D677674B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7AHu4z1dgngS6BndngN/4B0:RUdp8j3jvpWK7wuMdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_a03196b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14"
    family = "unknown"
    file_name = "a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:05:08"
  condition:
    hash.sha256(0, filesize) == "a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14"
}
```

### Sample 67: `77f7ecdc3fda61a7`

| Field | Value |
|---|---|
| SHA-256 | `77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68` |
| Family label | `unknown` |
| File name | `77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:04:53` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5614d83006f1e4e17a1d5a9d763c80e` |
| SHA-1 | `352b9fc2d08bb568db2ede101fc62e68e55ae734` |
| SHA-256 | `77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68` |
| SHA3-384 | `46e6cc8bf7da0885ab383c26ae9243a677eba4b1db100c0e8fb508797fd700e9f7c6d41eef79ee70ab1278c58326d6f3` |
| TLSH | `T165E24E43675C5929D55D83BE22FB1B976609F8A00AD45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEha5DbDP67li97WsCOwYjqclS06W1YbqclSl:GI2M5DbDy4wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_067_77f7ecdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68"
    family = "unknown"
    file_name = "77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:04:53"
  condition:
    hash.sha256(0, filesize) == "77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68"
}
```

### Sample 68: `94d7b9615e79407a`

| Field | Value |
|---|---|
| SHA-256 | `94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390` |
| Family label | `unknown` |
| File name | `94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:04:44` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `843bbfc2d4a74d43f05c9306697caf4f` |
| SHA-1 | `4ca3a794f73e312ce75cff86752ccc1bcf4fe4d7` |
| SHA-256 | `94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390` |
| SHA3-384 | `26c4bca40b43ae078ea1fa0a34834d84a42d5d7b47e583eaaf13853bceaf892f8671080b1b179ac7079b32a63e30a60e` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T1BC91C64270B999E7E85C41BB4C0FB8A4B91D740A41C483A70338A5993E3A57BF4BCB0E` |
| SSDEEP | `48:6IIF9BlQaex/gZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMCA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_94d7b961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390"
    family = "unknown"
    file_name = "94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:04:44"
  condition:
    hash.sha256(0, filesize) == "94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390"
}
```

### Sample 69: `9bbf84d04f9b7426`

| Field | Value |
|---|---|
| SHA-256 | `9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f` |
| Family label | `unknown` |
| File name | `9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f.exe` |
| File type | `exe` |
| First seen | `2026-11-06 01:02:05` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `905d65d7dbbc1246a23a5a89373a6687` |
| SHA-1 | `81ae861c2b0ec83e1e8c12af09408d0aad404238` |
| SHA-256 | `9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f` |
| SHA3-384 | `7b1c81c900573265bb08d4d3d601061389bb5ee0bd3341d3a257af462bda1c65fce430c431d4f0339162d72d1b2674fb` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T17264DFA0F580D097E8BFA5FDF9A2C58041372CBA7458F9B53590721E6B763118CB0B6B` |
| SSDEEP | `6144:f6gGFf5pzT4N7jK0woFSoah0k3QwnySYAfOGE9ENC:fYJX4NXf9FdGGGEu8` |
| ICON-DHASH | `ccd4d4d4e8e8f069` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_9bbf84d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f"
    family = "unknown"
    file_name = "9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:02:05"
  condition:
    hash.sha256(0, filesize) == "9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f"
}
```

### Sample 70: `b7a17508c5656ccb`

| Field | Value |
|---|---|
| SHA-256 | `b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90` |
| Family label | `unknown` |
| File name | `b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:01:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d80a920198cfb13d5e3276dcdebcdab0` |
| SHA-1 | `48c2be7ac4862f887a8cb98c148e8a9c7cb0898e` |
| SHA-256 | `b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90` |
| SHA3-384 | `67fa704461a89f7de045eb1b0604c096360b8ec48e6e0dfe963dcda9f0a9ddda038ec95e8a5e5047757652e990910aad` |
| TLSH | `T16EE22D43AF4C8965C26D42301AF71BC6A616F5B09EE16B8B5750C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2AHKk6XrMclSibFqAMcl:z4ZZXvv4VZMt0TO2bVw/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_b7a17508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90"
    family = "unknown"
    file_name = "b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:01:57"
  condition:
    hash.sha256(0, filesize) == "b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90"
}
```

### Sample 71: `a587746cb6d1f18f`

| Field | Value |
|---|---|
| SHA-256 | `a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb` |
| Family label | `unknown` |
| File name | `a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:01:51` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c4b33d8e24d550c60a05afebc81629c1` |
| SHA-1 | `d1729d08fa732a888264f86c45a6591ef692140b` |
| SHA-256 | `a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb` |
| SHA3-384 | `e59b4d9334d2c9c10b3122348f8dc8d6e19b98006dc7d39b8a82ab720dd7efefbfdd6f5a0d849c0fc07b717b6815035e` |
| TLSH | `T17AF24E139B1C1A61C05C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BEB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRxtPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfmlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_a587746c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb"
    family = "unknown"
    file_name = "a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:01:51"
  condition:
    hash.sha256(0, filesize) == "a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb"
}
```

### Sample 72: `801859bdd548e396`

| Field | Value |
|---|---|
| SHA-256 | `801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-06 01:01:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6bc4a3cbf3a34bb61daca2802693a8f` |
| SHA-1 | `3d6d96a7eaf3720d2fc29da5ad8474f39328db7e` |
| SHA-256 | `801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55` |
| SHA3-384 | `7f04c417fc0be9bda70e02eadb6146259970020379782756459b0e8e588d24924a6369c67521f418f1acf22bfd635f2d` |
| TLSH | `T1FC556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSB:SDjxB4m5n8XlaPWi+d+a4TjxQP4H` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_801859bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-06 01:01:04"
  condition:
    hash.sha256(0, filesize) == "801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55"
}
```

### Sample 73: `737a706d206367a7`

| Field | Value |
|---|---|
| SHA-256 | `737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f` |
| Family label | `unknown` |
| File name | `737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:01:02` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f432aaec05de65999bdac4555066287c` |
| SHA-1 | `077434fa1bb83ffdb6f883372d0fe85a536e165f` |
| SHA-256 | `737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f` |
| SHA3-384 | `3d107a1306e62354bc81ffba755f26e3fc9fcd639e709e80a34615dd43b99864ab3bafbbbff7ab4589b6232f69d7a8fd` |
| TLSH | `T179F263239B2C5922C48C663C42BB6742A23BF1E145D577674B00872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7HH14z1dgngS6BndngN/4B0:RUdp8j3jvpWK7n1MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_073_737a706d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f"
    family = "unknown"
    file_name = "737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:01:02"
  condition:
    hash.sha256(0, filesize) == "737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f"
}
```

### Sample 74: `293c56299d33f873`

| Field | Value |
|---|---|
| SHA-256 | `293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12` |
| Family label | `unknown` |
| File name | `293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:00:56` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85af1759b289405fabbaf0a948d25182` |
| SHA-1 | `fab9695f15592f27798cf6e72f5917a65b11732f` |
| SHA-256 | `293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12` |
| SHA3-384 | `4f12baa0ac9f70aa7f43ba8e2e8906ea1609d29f8d5aeefbbb17a32a168bf94eee714d46da98381d72f1f9e63eea12b2` |
| TLSH | `T196E24E43675C5929D15D83BA22FB1B976609F9A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZE55DbDP67li97WsCvwYjqclS06W1YbqclSl:GI255DbDyZwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_293c5629
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12"
    family = "unknown"
    file_name = "293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:00:56"
  condition:
    hash.sha256(0, filesize) == "293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12"
}
```

### Sample 75: `8db08682874ef1a9`

| Field | Value |
|---|---|
| SHA-256 | `8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8` |
| Family label | `unknown` |
| File name | `8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8.bin` |
| File type | `macho` |
| First seen | `2026-11-06 01:00:50` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47023580dea8afef89d7a320bc4900e6` |
| SHA-1 | `cdafec131d587057f0e12e7e881c85a61bb5f1a6` |
| SHA-256 | `8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8` |
| SHA3-384 | `7cf377a35afe12dacfadef0935f5ec815578530d814cb7a8b2397e18f5df1935e72831ebbe121c4cbc6ab2f043acad08` |
| TLSH | `T18DF25F139B1C0A61C05C633C92BB1B026236F5D086C56B674B10C76CAFCA3C5BEB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRyHPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJflvlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_8db08682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8"
    family = "unknown"
    file_name = "8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:00:50"
  condition:
    hash.sha256(0, filesize) == "8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8"
}
```

### Sample 76: `1ae8f5ab0c02e6d6`

| Field | Value |
|---|---|
| SHA-256 | `1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36` |
| Family label | `unknown` |
| File name | `1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:59:50` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c71642ecb792dd78bfe27671e39381d9` |
| SHA-1 | `7477eef48d609a3356509224398ea0fb95943d05` |
| SHA-256 | `1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36` |
| SHA3-384 | `38d9156ddb9d989ecf13b5a13e3758da4a8e0a92601a6090f838d18d00c09554ea66be194ecf7717feaf4362a9540211` |
| TLSH | `T158E25143675C5929D05D83BA62FB17576609F4B009E45B432F50D6282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEa5DbDP67li97WsCNwYjqclS06W1YbqclSl:GI2a5DbDyjwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_1ae8f5ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36"
    family = "unknown"
    file_name = "1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:59:50"
  condition:
    hash.sha256(0, filesize) == "1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36"
}
```

### Sample 77: `a6de24126c0f97c8`

| Field | Value |
|---|---|
| SHA-256 | `a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b` |
| Family label | `unknown` |
| File name | `a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:56:50` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1046fb24d51261a43ef50e975400b91e` |
| SHA-1 | `3c162ebc4da1c885fd535d19bf26bd5efd802b8c` |
| SHA-256 | `a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b` |
| SHA3-384 | `bb492608a2ac4200c79790c24d35a9277d8288633df584d8c122c37407796bc05022e1111aabc87168a2f415758be496` |
| TLSH | `T1F0E24E43675C5929D05D83BA62FB1B976609F8B009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZE95DbDP67li97WsCYwYjqclS06W1YbqclSl:GI295DbDyawYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_a6de2412
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b"
    family = "unknown"
    file_name = "a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:56:50"
  condition:
    hash.sha256(0, filesize) == "a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b"
}
```

### Sample 78: `90013156cf8068b8`

| Field | Value |
|---|---|
| SHA-256 | `90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba` |
| Family label | `unknown` |
| File name | `90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:56:03` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7cebeb454a0ab207e56ded2a4ebe4f14` |
| SHA-1 | `41280e5237564feefe0ed313f2a799869b501ebb` |
| SHA-256 | `90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba` |
| SHA3-384 | `4c2923d534f1506f7bdb6ef6b0cce92d410155b42617e75211b11a2c0bf0e8aa9787590509cb48b22683c720e42f5795` |
| TLSH | `T1AFE22D43AF4C8965C26D42301AF71BC6A616F5B09EE16B8B5750C7217EE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUaVZqDDt0TOTLZ0BbFw2oHKk6XrMclSibFqAMcl:z4ZZXvvfVZMt0TO2bV4/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_90013156
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba"
    family = "unknown"
    file_name = "90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:56:03"
  condition:
    hash.sha256(0, filesize) == "90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba"
}
```

### Sample 79: `4b72111486350491`

| Field | Value |
|---|---|
| SHA-256 | `4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55` |
| Family label | `unknown` |
| File name | `4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:55:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c60fae259fc8371df4009905ba6de6b` |
| SHA-1 | `01c4a689a130d420aa6dcecf05f4c9ce7c712f73` |
| SHA-256 | `4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55` |
| SHA3-384 | `f9e7a2fb5d9bd087c00fdc43a0107a7f531fd11dfd1c083e21fd3196481fa4624231ff4a1a40a3e7891067bd1064ef4c` |
| TLSH | `T156E24E43675C5929D05D83BA22FB5B976609F8A009E45B432F50DA282FE23C47CB0FDB` |
| SSDEEP | `96:xcIZEa5DbDP67li97WsCFwYjqclS06W1YbqclSl:GI2a5DbDyfwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_4b721114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55"
    family = "unknown"
    file_name = "4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:55:57"
  condition:
    hash.sha256(0, filesize) == "4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55"
}
```

### Sample 80: `5bde2bcb559f5bfa`

| Field | Value |
|---|---|
| SHA-256 | `5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0` |
| Family label | `unknown` |
| File name | `5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:55:52` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6340a5dd1ec3066be2c8a1eb4699fa9` |
| SHA-1 | `61f380be7f26e4cb5ddcd941f062b06fb5dba6f1` |
| SHA-256 | `5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0` |
| SHA3-384 | `6c6289e0c18deeaeac2e6baf406148e8fbd5e7d6517ea7f9b715014a18bb6a05e589f979578e1dbe91171c11d8963a39` |
| TLSH | `T183F24E139B1C0A61C55C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRkPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfXlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_5bde2bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0"
    family = "unknown"
    file_name = "5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:55:52"
  condition:
    hash.sha256(0, filesize) == "5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0"
}
```

### Sample 81: `5691e08df9fd650f`

| Field | Value |
|---|---|
| SHA-256 | `5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228` |
| Family label | `unknown` |
| File name | `5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:54:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `258397f58e8468bdabcb8d76fe7e5d49` |
| SHA-1 | `b3de6e50dcd1f49389f768b00a47c1230b2e4b37` |
| SHA-256 | `5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228` |
| SHA3-384 | `2c4c043b2fef3d6e39efcc87286d51944751dbf6d701080c417580c3272a1abb874a59aba999165db0b76098d89cfd8a` |
| TLSH | `T131F273239B1C6922C48C623842BB6742A23BF1E145C677774B04872DAFCA3C5B9E5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7MH44z1dgngS6BndngN/4B0:RUdp8j3jvpWK704MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_5691e08d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228"
    family = "unknown"
    file_name = "5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:54:57"
  condition:
    hash.sha256(0, filesize) == "5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228"
}
```

### Sample 82: `11a54ea07fa357e2`

| Field | Value |
|---|---|
| SHA-256 | `11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e` |
| Family label | `unknown` |
| File name | `11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:54:51` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4338247482e0c501cd1b3d7cd2b28fde` |
| SHA-1 | `0ca625d1939b6e463e237691ce269457e9a30e1e` |
| SHA-256 | `11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e` |
| SHA3-384 | `ac95248d00d25762526f9975ed01e1202f58068c5a5083fdf63eadd5aed61ace9a2f5478431182ca709ca8ffbabdd456` |
| TLSH | `T1A3E22C43AB4C9965C26D42301AF71BC6A615F5B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvURVZqDDt0TOTLZ0BbFw2nHKk6XrMclSibFqAMcl:z4ZZXvvQVZMt0TO2bVH/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_11a54ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e"
    family = "unknown"
    file_name = "11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:54:51"
  condition:
    hash.sha256(0, filesize) == "11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e"
}
```

### Sample 83: `086b9625247a2ef5`

| Field | Value |
|---|---|
| SHA-256 | `086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec` |
| Family label | `Mirai` |
| File name | `086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec` |
| File type | `elf` |
| First seen | `2026-11-06 00:53:53` |
| Reporter | `spydisec` |
| Tags | `cowrie, elf, honeypot, Mirai, Prometei, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c29fa206a4d2aaf0ee86af7d030a28ad` |
| SHA-1 | `0f94dedfff76753d2b6dc615074efc71e7fb97a5` |
| SHA-256 | `086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec` |
| SHA3-384 | `a7cfd028e04a030a608d7502268fd8a7fd86985e7d97c93122c70293229c69a258c0bdaf41e64c76b8ae97d602d83942` |
| TLSH | `T14E556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS8:SDjxB4m5n8XlaPWi+d+a4TjxQP4u` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_086b9625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec"
    family = "Mirai"
    file_name = "086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec"
    file_type = "elf"
    first_seen = "2026-11-06 00:53:53"
  condition:
    hash.sha256(0, filesize) == "086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec"
}
```

### Sample 84: `fe436d8c0a8523df`

| Field | Value |
|---|---|
| SHA-256 | `fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a` |
| Family label | `unknown` |
| File name | `fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:51:56` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a81eb77159d9a96d77a553a08733a245` |
| SHA-1 | `1d8174377125e80ac557029f6fbd0876f1ac83f8` |
| SHA-256 | `fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a` |
| SHA3-384 | `fa648ece027185c2906524c334c91c4e356f6bb03eaa15a067943c4da517ae7949f1ea42b54a31f141c3f2cbd505cac5` |
| TLSH | `T131E24E43675C5929D05D83BA22FB5B976609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCIwYjqclS06W1YbqclSl:GI2n5DbDyKwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_fe436d8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a"
    family = "unknown"
    file_name = "fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:56"
  condition:
    hash.sha256(0, filesize) == "fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a"
}
```

### Sample 85: `fd7c3eb4c96e608c`

| Field | Value |
|---|---|
| SHA-256 | `fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025` |
| Family label | `unknown` |
| File name | `fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:51:50` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60c04eabc4a54ce0353034b079b8d8d8` |
| SHA-1 | `6320422513ae4766427a71f1c004d06be96dcd5f` |
| SHA-256 | `fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025` |
| SHA3-384 | `7213db4271528a86412571a8d03b0dbf66ea0c79c821a9350f0947ebbc5183bf306eb855f0507b0c205445c2ed5dfe28` |
| TLSH | `T14FF25F139B1C0A61C15C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMR3PlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfGlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_fd7c3eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025"
    family = "unknown"
    file_name = "fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:50"
  condition:
    hash.sha256(0, filesize) == "fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025"
}
```

### Sample 86: `21d2fa4b6cdd15da`

| Field | Value |
|---|---|
| SHA-256 | `21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce` |
| Family label | `unknown` |
| File name | `images.7fec4c32.js` |
| File type | `js` |
| First seen | `2026-11-06 00:51:31` |
| Reporter | `MotherSphere` |
| Tags | `javascript, js, k2f, loader, NIKKE, supply-chain` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `481e9b5ab8fb93406bf31980b53e0578` |
| SHA-1 | `50dbc570f3d38264d786c9a68e798f94cd50f1ea` |
| SHA-256 | `21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce` |
| SHA3-384 | `011a3a73e459a279089dec8b330df899d68e53c5cf60a5b11ab05bf72cbfc28971615f55e2b09e772a1f52d57c711284` |
| TLSH | `T1A191A7A9BB64A07181159DFA013F4905B13E33117C12D0D4F82DECD67B78A986637EBC` |
| SSDEEP | `96:Njhx31LmaILZ7AuXW9MmeDZ/w/QTSTSu2AnC4qeoijLApaeX5Fko1Tjf:N331Lmhl7AyvmYZ/w/cSTSu2Anvqz2LO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_21d2fa4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce"
    family = "unknown"
    file_name = "images.7fec4c32.js"
    file_type = "js"
    first_seen = "2026-11-06 00:51:31"
  condition:
    hash.sha256(0, filesize) == "21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce"
}
```

### Sample 87: `04471ccf9f6ebac4`

| Field | Value |
|---|---|
| SHA-256 | `04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d` |
| Family label | `unknown` |
| File name | `aegis-fix.min.js` |
| File type | `js` |
| First seen | `2026-11-06 00:51:22` |
| Reporter | `MotherSphere` |
| Tags | `javascript, js, k2f, loader, NIKKE, supply-chain` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50d1861152ea7f6875ffceb7d08445b5` |
| SHA-1 | `a35847718e890f9dd846c5b192b871ce0f7f68f2` |
| SHA-256 | `04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d` |
| SHA3-384 | `ad85c15dd4738554fc28826435efb13a56d657fb613dcd9c51bf56e3a18a786ca89335443eb4c27c4af825c1c53e186e` |
| TLSH | `T1EA630A8EB68570720BA76570803F210BB33B7BA954088464F619DEF56CB8A4F5227F3D` |
| SSDEEP | `768:PH2q4D5xJTQQMiLKHdEeW0W68sHIiMnasWVByzZ0lsrzrXcQg:uTH1KmeIi5/dea` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_04471ccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d"
    family = "unknown"
    file_name = "aegis-fix.min.js"
    file_type = "js"
    first_seen = "2026-11-06 00:51:22"
  condition:
    hash.sha256(0, filesize) == "04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d"
}
```

### Sample 88: `152d1485f109f015`

| Field | Value |
|---|---|
| SHA-256 | `152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846` |
| Family label | `unknown` |
| File name | `152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:51:09` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65b96f35ff8d6e75636d6c4ae6277beb` |
| SHA-1 | `a45fc072b28f1b29c863fa2f6d822bb6a6166748` |
| SHA-256 | `152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846` |
| SHA3-384 | `360458b4b8706b2bc9fb646eb463b010a6d449f0a2e6b44678f584e1abcce89ab863999f338e913b9f98164015d6aafa` |
| TLSH | `T103F24E139B1C0A61C15D633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRHPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfylilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_152d1485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846"
    family = "unknown"
    file_name = "152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:09"
  condition:
    hash.sha256(0, filesize) == "152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846"
}
```

### Sample 89: `bfc08bb7ea589fcd`

| Field | Value |
|---|---|
| SHA-256 | `bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4` |
| Family label | `unknown` |
| File name | `bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:51:03` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `09e87a4b69237eb4fa19dffc44a2362b` |
| SHA-1 | `5d368b3fa93ddcd12196439272012f8c1ba7a986` |
| SHA-256 | `bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4` |
| SHA3-384 | `b4c1050edc04f8e0d3eff0141f5dbc840e971aff399f4608e7b7888b2988da68f7c61e1084c9b9fac851dd99c2dc2881` |
| TLSH | `T18BF25F139B1C0A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMR5PlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfwlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_bfc08bb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4"
    family = "unknown"
    file_name = "bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:03"
  condition:
    hash.sha256(0, filesize) == "bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4"
}
```

### Sample 90: `f9cc2ee7b979473c`

| Field | Value |
|---|---|
| SHA-256 | `f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c` |
| Family label | `unknown` |
| File name | `f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:50:56` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b14e262d78e01586dcd5077f19ce8914` |
| SHA-1 | `3e193c0f2f5ab8b94f5659f50d430fb1651d8510` |
| SHA-256 | `f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c` |
| SHA3-384 | `49f0db0bd79860b2cdcf06274b01e68d8bea91507f5c8648fdca493b7326133ff6904593a303cd2d947498fc7fb0247f` |
| TLSH | `T1E7E24E43675C5929D05D83BA22FB1B976619F8A009D45B432F90DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZE95DbDP67li97WsCYwYjqclS06W1YbqclSl:GI295DbDyuwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_f9cc2ee7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c"
    family = "unknown"
    file_name = "f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:50:56"
  condition:
    hash.sha256(0, filesize) == "f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c"
}
```

### Sample 91: `db6c7c1d1d690f3e`

| Field | Value |
|---|---|
| SHA-256 | `db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb` |
| Family label | `unknown` |
| File name | `db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb.exe` |
| File type | `exe` |
| First seen | `2026-11-06 00:50:50` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb6ad5cf65846f6a634b7322c3e2751e` |
| SHA-1 | `47a3662930503e3e0f4e8e5d35419e33e3ad692d` |
| SHA-256 | `db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb` |
| SHA3-384 | `91836fa2f68a62a8d7abf3b079eea22331fcd3a57d79ad3be8740b696d4afd3717e42aa5d4029ee035392a941fc53aa1` |
| IMPHASH | `e82dd51b077167be63c004bed23d0c1e` |
| TLSH | `T10291C64270B989E7E85C51BF4C0FB8A0B919740A41C483A74338A5953E3A57BF57CB0D` |
| SSDEEP | `48:6IIF9BlQaexjxgZD7An0cF5uduvxRxUjbON9XM/ge93ahr0/:y9BOaMjUA0cF50uDxUOvXeg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_091_db6c7c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb"
    family = "unknown"
    file_name = "db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb.exe"
    file_type = "exe"
    first_seen = "2026-11-06 00:50:50"
  condition:
    hash.sha256(0, filesize) == "db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb"
}
```

### Sample 92: `2a15faa0419d715a`

| Field | Value |
|---|---|
| SHA-256 | `2a15faa0419d715a493468839ac908451ed33a00335446d19e3a468608726f4e` |
| Family label | `unknown` |
| File name | `macho_2a15faa0419d.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:50:03` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5092c84334550fbc9e5b883dd9eebe5` |
| SHA-1 | `27df88ff6cb8ff70ffbec6c30d4bb97be3fb3cd3` |
| SHA-256 | `2a15faa0419d715a493468839ac908451ed33a00335446d19e3a468608726f4e` |
| SHA3-384 | `d90f4bad0708c4476ea68946f01a83af08d0333e932f30944085115321434578e87d3c628f75ad41b540c7a92521a606` |
| TLSH | `T1AB361220472BA89EC05510331C964F5905702EB1DE0EFDE71B52E2ABDE3B2C3B6655BB` |
| SSDEEP | `49152:TfnXPDH2z53JIX7AO3Rc1r53m3Meluu3jRAXBCQLNNpKOu2nr35kTtE+bNcvLj3j:Tfn7UYOT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_2a15faa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a15faa0419d715a493468839ac908451ed33a00335446d19e3a468608726f4e"
    family = "unknown"
    file_name = "macho_2a15faa0419d.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:50:03"
  condition:
    hash.sha256(0, filesize) == "2a15faa0419d715a493468839ac908451ed33a00335446d19e3a468608726f4e"
}
```

### Sample 93: `9c825f1fd9a21713`

| Field | Value |
|---|---|
| SHA-256 | `9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72` |
| Family label | `unknown` |
| File name | `9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:46:58` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc05d379da5a580544351b5628f3c8a8` |
| SHA-1 | `e3812a5dd0b8a5ad0df00abbb2ce74924f19bfd5` |
| SHA-256 | `9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72` |
| SHA3-384 | `092c9e8375772fb5230e1ecbdda8e7b0bf280f1e6b929f8c79f22cdb9fef6a9ed0d8c8f70085c497f99dd6ea8e4a52b9` |
| TLSH | `T1D0E22D43AB4C8965C26D42301AF71BC6A616F5B09EE16B875750C7217FE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUTVZqDDt0TOTLZ0BbFw2zHKk6XrMclSibFqAMcl:z4ZZXvvKVZMt0TO2bV7/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_9c825f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72"
    family = "unknown"
    file_name = "9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:46:58"
  condition:
    hash.sha256(0, filesize) == "9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72"
}
```

### Sample 94: `152570c743eba81a`

| Field | Value |
|---|---|
| SHA-256 | `152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6` |
| Family label | `unknown` |
| File name | `152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:46:51` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `670fe59ad6f7d803f8f84174c25334f8` |
| SHA-1 | `381c8c17b0556603565036a4b696e12cc34b8786` |
| SHA-256 | `152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6` |
| SHA3-384 | `74dc0beb3e97340c98e29fc3b1bdb23146a51a9049e2fcadab2124a8c468f4e5d39e2bda768f08918bc953cbf5a620bc` |
| TLSH | `T1CEE22C43AB4C8965C26D42301AF71BC6A615F5B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUNVZqDDt0TOTLZ0BbFw2MHKk6XrMclSibFqAMcl:z4ZZXvvkVZMt0TO2bV0/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_152570c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6"
    family = "unknown"
    file_name = "152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:46:51"
  condition:
    hash.sha256(0, filesize) == "152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6"
}
```

### Sample 95: `32d0929d2dc0d0e5`

| Field | Value |
|---|---|
| SHA-256 | `32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20` |
| Family label | `unknown` |
| File name | `32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:45:59` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `271b4a87389419aa0454e6e9c7518925` |
| SHA-1 | `9c59ff2364bb21e3e0571dca5b149899a3f74a2c` |
| SHA-256 | `32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20` |
| SHA3-384 | `316dbf37d80a2ba5f5e2f72160201351c1b08358e3b28148ff1ea43344f0c5ae47b7fcdfcbc79ae5e3f2b4c1f9e43a54` |
| TLSH | `T1EAF23E139B1C1A61C15D633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRDPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfelilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_32d0929d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20"
    family = "unknown"
    file_name = "32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:45:59"
  condition:
    hash.sha256(0, filesize) == "32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20"
}
```

### Sample 96: `aeadf162491994c9`

| Field | Value |
|---|---|
| SHA-256 | `aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750` |
| Family label | `unknown` |
| File name | `aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:45:51` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `57e21b5a3f5e256286803c839da91971` |
| SHA-1 | `4a1808cec47ae369c88e3f1e61d7485c5405434f` |
| SHA-256 | `aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750` |
| SHA3-384 | `dad88804609c0f9e1d9915ad1b34578ea8b991ac7a64954f1c23a76947d4b1127cf922c6d2e03ba808b25a15e1d2e158` |
| TLSH | `T1A8F25F139B1C1A61C15C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRQPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfHlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_aeadf162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750"
    family = "unknown"
    file_name = "aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:45:51"
  condition:
    hash.sha256(0, filesize) == "aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750"
}
```

### Sample 97: `5e331ae6cd7264ca`

| Field | Value |
|---|---|
| SHA-256 | `5e331ae6cd7264ca0d975fc519f56c4797ad1bea63b05539259b57ba522e771f` |
| Family label | `unknown` |
| File name | `macho_5e331ae6cd72.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:45:21` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ffae2350133d22a7efadd21c18a0e440` |
| SHA-1 | `e252d2e000110c298c13f1dc6ce6c1ed1c3abeba` |
| SHA-256 | `5e331ae6cd7264ca0d975fc519f56c4797ad1bea63b05539259b57ba522e771f` |
| SHA3-384 | `4c18419abfad19a374521bdcbf3ff2b695183e3a23813c54f20de5aa32d0f984587f26d794dccd45177a48eb7a617848` |
| TLSH | `T1DD5612408F1A51A7DA5841376C9F4F1185B03181C9CCDEEA9741B6CADE7A7C3B22B4BB` |
| SSDEEP | `49152:qhOUyDkrLRLhTpRCSZ/LB6W+uZw1514on6y6DgNEWzDN4VwhF74aFea5otLx7hbj:dzma74p` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_5e331ae6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e331ae6cd7264ca0d975fc519f56c4797ad1bea63b05539259b57ba522e771f"
    family = "unknown"
    file_name = "macho_5e331ae6cd72.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:45:21"
  condition:
    hash.sha256(0, filesize) == "5e331ae6cd7264ca0d975fc519f56c4797ad1bea63b05539259b57ba522e771f"
}
```

### Sample 98: `7f9cfd0d37cad548`

| Field | Value |
|---|---|
| SHA-256 | `7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed` |
| Family label | `unknown` |
| File name | `7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:44:54` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37d90808cd28f4eee6ad0e1e94d7922b` |
| SHA-1 | `0a13611bdc3bbd2f1d81036dc86b3267addbe5c6` |
| SHA-256 | `7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed` |
| SHA3-384 | `4bdc3a8c79d8a28cd59617f3ee8da5ab4c98318a9a4db5dc3b01ad7f934897f8ece9cb8d92e325686b0ebf74835d1fb5` |
| TLSH | `T1F0F24E139B1C0A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRIPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJf3lilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_7f9cfd0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed"
    family = "unknown"
    file_name = "7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:44:54"
  condition:
    hash.sha256(0, filesize) == "7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed"
}
```

### Sample 99: `4476a579c8684e92`

| Field | Value |
|---|---|
| SHA-256 | `4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c` |
| Family label | `unknown` |
| File name | `4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:44:47` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53a56728de88765229efe52ed5fca907` |
| SHA-1 | `2e7cf7926572e1eddd5001f7bfde0311ccfb5ee5` |
| SHA-256 | `4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c` |
| SHA3-384 | `a1ac79cbb252782383e52ed80f527aa18a346d48c244ffadc6fd3d821d2b4b60ea7bd47d0df63424c1ac43bc70e51825` |
| TLSH | `T1E1E23E43AB4C8965C26D82301AF71BC6A615F5B09EE16B875750C7217FE17883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUWVZqDDt0TOTLZ0BbFw2HHKk6XrMclSibFqAMcl:z4ZZXvvHVZMt0TO2bVn/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_4476a579
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c"
    family = "unknown"
    file_name = "4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:44:47"
  condition:
    hash.sha256(0, filesize) == "4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c"
}
```

### Sample 100: `91d927e18cbfd210`

| Field | Value |
|---|---|
| SHA-256 | `91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89` |
| Family label | `unknown` |
| File name | `91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89.bin` |
| File type | `macho` |
| First seen | `2026-11-06 00:44:42` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `992b4964dc94afacd8d5d212364e4bc3` |
| SHA-1 | `1bfc7bcb8d99141ea2e96500f2f042469e21e97a` |
| SHA-256 | `91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89` |
| SHA3-384 | `18d6557af0282269675362db9d013b89aae813536968982394c40f8e50063e9418efb2092e7b9351743fb5a22924cc3a` |
| TLSH | `T130F24E139B1C1A61C05D633C92BB1B026236F5D086C66B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRTBiEPlxkllLRgowjWaXLRgoz0Mq:MGL7IKo4Gxcf/mJfPmlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_91d927e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89"
    family = "unknown"
    file_name = "91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:44:42"
  condition:
    hash.sha256(0, filesize) == "91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89"
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
 * Generated: 2026-11-06T06:58:26.459519+00:00
 */

rule MalwareBazaar_DarkCoreRAT_001_32fa7a24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32fa7a24cd9b8691c1965aa788d1c93e3b923404c4d33b73e8474b7e8bbfa939"
    family = "DarkCoreRAT"
    file_name = "042538776d6c16f7f63e679b1b9dc0b3.exe"
    file_type = "exe"
    first_seen = "2026-11-06 06:56:04"
  condition:
    hash.sha256(0, filesize) == "32fa7a24cd9b8691c1965aa788d1c93e3b923404c4d33b73e8474b7e8bbfa939"
}

rule MalwareBazaar_DarkCoreRAT_002_d51e0e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d51e0e128839839b7caf0d96cd6b082e2dd23f32a52da5fd1d9fadefca5f9e87"
    family = "DarkCoreRAT"
    file_name = "3e26f226cc8699617fc8a7e24f100edf.exe"
    file_type = "exe"
    first_seen = "2026-11-06 06:54:54"
  condition:
    hash.sha256(0, filesize) == "d51e0e128839839b7caf0d96cd6b082e2dd23f32a52da5fd1d9fadefca5f9e87"
}

rule MalwareBazaar_WARDENStealer_003_3f6e9fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f6e9fd9ad8b6d6561407e284ee202b96f850a46d037572c8f4425bb8706f5d8"
    family = "WARDENStealer"
    file_name = "1.exe"
    file_type = "exe"
    first_seen = "2026-11-06 06:51:36"
  condition:
    hash.sha256(0, filesize) == "3f6e9fd9ad8b6d6561407e284ee202b96f850a46d037572c8f4425bb8706f5d8"
}

rule MalwareBazaar_unknown_004_bde4d2d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bde4d2d549d4fd5550e22f0b820246556f51b413420420697700a1f5f0982d53"
    family = "unknown"
    file_name = "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
    file_type = "elf"
    first_seen = "2026-11-06 06:49:34"
  condition:
    hash.sha256(0, filesize) == "bde4d2d549d4fd5550e22f0b820246556f51b413420420697700a1f5f0982d53"
}

rule MalwareBazaar_unknown_005_8d23f427
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d23f427a29a0d2010097c8066901e026e81c41163672cbb5e522942786d1091"
    family = "unknown"
    file_name = "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
    file_type = "elf"
    first_seen = "2026-11-06 06:49:21"
  condition:
    hash.sha256(0, filesize) == "8d23f427a29a0d2010097c8066901e026e81c41163672cbb5e522942786d1091"
}

rule MalwareBazaar_unknown_006_b5105b0b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5"
    family = "unknown"
    file_name = "b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5"
    file_type = "pl"
    first_seen = "2026-11-06 06:43:21"
  condition:
    hash.sha256(0, filesize) == "b5105b0b23e2723260317d0ab187f7e28df68872fb8c18af1c50bce9a50ee9c5"
}

rule MalwareBazaar_unknown_007_0d44deb0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
    family = "unknown"
    file_name = "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
    file_type = "elf"
    first_seen = "2026-11-06 06:43:17"
  condition:
    hash.sha256(0, filesize) == "0d44deb0f7a325ee32fdf99da61ea281d2df0f43fb3090b92d20d94ba6a4e806"
}

rule MalwareBazaar_Mirai_008_6e11016d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264"
    family = "Mirai"
    file_name = "6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264"
    file_type = "elf"
    first_seen = "2026-11-06 06:43:05"
  condition:
    hash.sha256(0, filesize) == "6e11016d0f4e3e0b4481f9cb2ec2a451c74c1c5ab6cceb3bbe7b025b2b7dd264"
}

rule MalwareBazaar_unknown_009_40d3cd16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3"
    family = "unknown"
    file_name = "40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3"
    file_type = "elf"
    first_seen = "2026-11-06 06:43:01"
  condition:
    hash.sha256(0, filesize) == "40d3cd162165639c99cf47e946ad41d161f8e9699afa3f43c59d5a529b57b5b3"
}

rule MalwareBazaar_unknown_010_022b8f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
    family = "unknown"
    file_name = "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
    file_type = "elf"
    first_seen = "2026-11-06 06:42:54"
  condition:
    hash.sha256(0, filesize) == "022b8f9010612de609d12fece571670d696c79297b129709842f021d73cecd42"
}

rule MalwareBazaar_unknown_011_9b1a249f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b1a249f9a599cea72da14f6a09aefaf8af3933e5c1a4c2c4a3208cdc951a163"
    family = "unknown"
    file_name = "install.sh"
    file_type = "sh"
    first_seen = "2026-11-06 06:26:32"
  condition:
    hash.sha256(0, filesize) == "9b1a249f9a599cea72da14f6a09aefaf8af3933e5c1a4c2c4a3208cdc951a163"
}

rule MalwareBazaar_DDoSAgent_012_f13f0f9d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f13f0f9de473071134fee348f915d0fcbb730c940474b2fbbf1d615eb713fc4c"
    family = "DDoSAgent"
    file_name = "e_amd64"
    file_type = "elf"
    first_seen = "2026-11-06 06:24:51"
  condition:
    hash.sha256(0, filesize) == "f13f0f9de473071134fee348f915d0fcbb730c940474b2fbbf1d615eb713fc4c"
}

rule MalwareBazaar_Mirai_013_f1cd80c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a"
    family = "Mirai"
    file_name = "superior.arm7"
    file_type = "elf"
    first_seen = "2026-11-06 06:24:09"
  condition:
    hash.sha256(0, filesize) == "f1cd80c989a6c9fc872978c8f2ecf6ed42788a6144e4936f2e2088e3bd77c03a"
}

rule MalwareBazaar_Mirai_014_e82b0fb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e82b0fb2fd0e21013c2bb6cfd027eb8ced4a7259eb640f688f893c1358efbba9"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-06 05:59:05"
  condition:
    hash.sha256(0, filesize) == "e82b0fb2fd0e21013c2bb6cfd027eb8ced4a7259eb640f688f893c1358efbba9"
}

rule MalwareBazaar_QuasarRAT_015_f2c56b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2"
    family = "QuasarRAT"
    file_name = "f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2.bin"
    file_type = "js"
    first_seen = "2026-11-06 05:31:54"
  condition:
    hash.sha256(0, filesize) == "f2c56b981ecc9c9881e23f27dc2ec746d925ca658dd854044b996ae20c8989a2"
}

rule MalwareBazaar_unknown_016_0d13e956
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92"
    family = "unknown"
    file_name = "0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92.bin"
    file_type = "ps1"
    first_seen = "2026-11-06 05:31:50"
  condition:
    hash.sha256(0, filesize) == "0d13e956cd34db3481e7998ae91efffb75be7c7288061532358c977599ec1c92"
}

rule MalwareBazaar_Mirai_017_900f628c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b"
    family = "Mirai"
    file_name = "900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:41"
  condition:
    hash.sha256(0, filesize) == "900f628cdbf9a814a8cdfb059b788b03952f3de51ed79eec0faada6ff991901b"
}

rule MalwareBazaar_unknown_018_8df23465
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077"
    family = "unknown"
    file_name = "8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:34"
  condition:
    hash.sha256(0, filesize) == "8df2346597e0e753d3256cdf100f846664706ce81942531aab44e39a80dd2077"
}

rule MalwareBazaar_unknown_019_cc1b33ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5"
    family = "unknown"
    file_name = "cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:27"
  condition:
    hash.sha256(0, filesize) == "cc1b33edd4b08c51884b3e8da0d1536fa531a7119e6ab08e5d3a29b0c91188e5"
}

rule MalwareBazaar_unknown_020_26a130b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
    family = "unknown"
    file_name = "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:20"
  condition:
    hash.sha256(0, filesize) == "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
}

rule MalwareBazaar_Gafgyt_021_f47a73d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029"
    family = "Gafgyt"
    file_name = "f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:13"
  condition:
    hash.sha256(0, filesize) == "f47a73d40427b2118ee44133d455836f64497da47a263e269c58ea80f6ca7029"
}

rule MalwareBazaar_Gafgyt_022_f341099d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4"
    family = "Gafgyt"
    file_name = "f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:06"
  condition:
    hash.sha256(0, filesize) == "f341099df5727f0f408085034b8b698ffabb0da293e4d4177af0ca307fdb1ed4"
}

rule MalwareBazaar_Gafgyt_023_eddced2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e"
    family = "Gafgyt"
    file_name = "eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e"
    file_type = "elf"
    first_seen = "2026-11-06 04:52:00"
  condition:
    hash.sha256(0, filesize) == "eddced2bd1046768c1b1874c028b1ead49131585c422a469fbe827a18b3d245e"
}

rule MalwareBazaar_Gafgyt_024_d59d4d65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04"
    family = "Gafgyt"
    file_name = "d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:52"
  condition:
    hash.sha256(0, filesize) == "d59d4d658171b04d9400bcf36e3ab27bfb9e6691b6d7e54ab3fc3e1b6e6ebc04"
}

rule MalwareBazaar_Gafgyt_025_c0d787c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f"
    family = "Gafgyt"
    file_name = "c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:44"
  condition:
    hash.sha256(0, filesize) == "c0d787c9dccb8a17af19754f37dc2c331af2f8ba935eb7c7df449440ee86a56f"
}

rule MalwareBazaar_Gafgyt_026_baca232b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e"
    family = "Gafgyt"
    file_name = "baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:37"
  condition:
    hash.sha256(0, filesize) == "baca232b155cd553fe1973a3d689ce7dd8236ea55e573ec8460eae6c4a5d885e"
}

rule MalwareBazaar_Gafgyt_027_b40f9e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae"
    family = "Gafgyt"
    file_name = "b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:29"
  condition:
    hash.sha256(0, filesize) == "b40f9e77052ff3f253ebc48d20014052c8e5abad53cf04c0e4c0a9a0263f3eae"
}

rule MalwareBazaar_Gafgyt_028_6389eb9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc"
    family = "Gafgyt"
    file_name = "6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:22"
  condition:
    hash.sha256(0, filesize) == "6389eb9e2395facd4be79354a9989b7cb73d66464b8f7759479ee3c915439dcc"
}

rule MalwareBazaar_Gafgyt_029_4e438363
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f"
    family = "Gafgyt"
    file_name = "4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:15"
  condition:
    hash.sha256(0, filesize) == "4e438363aa29ee41de02f71acb62a41bb93e5c66cd6362626c140b0b9b58ac3f"
}

rule MalwareBazaar_Gafgyt_030_1fba0568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93"
    family = "Gafgyt"
    file_name = "1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93"
    file_type = "elf"
    first_seen = "2026-11-06 04:51:07"
  condition:
    hash.sha256(0, filesize) == "1fba0568f18e904312ec583912d4d754bc8939fa6551db22b074c69e4328ca93"
}

rule MalwareBazaar_unknown_031_797d210c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "797d210c96fdcfa1d41b77380f44272762ec9c6f7c7a485f09c0d3fc56f836fa"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-06 04:39:04"
  condition:
    hash.sha256(0, filesize) == "797d210c96fdcfa1d41b77380f44272762ec9c6f7c7a485f09c0d3fc56f836fa"
}

rule MalwareBazaar_unknown_032_eb527089
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765"
    family = "unknown"
    file_name = "eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765.exe"
    file_type = "exe"
    first_seen = "2026-11-06 03:54:52"
  condition:
    hash.sha256(0, filesize) == "eb5270896f08c3509ad3e1fce2adb31a4cc6692c63b36e4b8aa89ed1d0bcc765"
}

rule MalwareBazaar_Mirai_033_c48071a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740"
    family = "Mirai"
    file_name = "c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740"
    file_type = "apk"
    first_seen = "2026-11-06 03:00:11"
  condition:
    hash.sha256(0, filesize) == "c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740"
}

rule MalwareBazaar_Prometei_034_9bd9786c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32"
    family = "Prometei"
    file_name = "9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32"
    file_type = "elf"
    first_seen = "2026-11-06 02:58:46"
  condition:
    hash.sha256(0, filesize) == "9bd9786c48d27a1681750894b4673ac9402c1615248f5e18e7ae5d59e07dfe32"
}

rule MalwareBazaar_Prometei_035_63adf9ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
    family = "Prometei"
    file_name = "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
    file_type = "exe"
    first_seen = "2026-11-06 02:58:28"
  condition:
    hash.sha256(0, filesize) == "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
}

rule MalwareBazaar_AveMariaRAT_036_9d03a606
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d03a606ffb60773098b968e48f6e4fe86251969a37f73bb6e57e61422f246ae"
    family = "AveMariaRAT"
    file_name = "9d03a606ffb60773.bin"
    file_type = "exe"
    first_seen = "2026-11-06 02:25:21"
  condition:
    hash.sha256(0, filesize) == "9d03a606ffb60773098b968e48f6e4fe86251969a37f73bb6e57e61422f246ae"
}

rule MalwareBazaar_unknown_037_4cee2687
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341"
    family = "unknown"
    file_name = "4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:50:01"
  condition:
    hash.sha256(0, filesize) == "4cee268790d7ab65de093f799e4b210f49619e1469a70e400bbebef6fd102341"
}

rule MalwareBazaar_unknown_038_92a8eb4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5"
    family = "unknown"
    file_name = "92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:49:54"
  condition:
    hash.sha256(0, filesize) == "92a8eb4a5952adc2d8b19a17a614fecca8d3ea24ce84aac2405f4376fc0e79d5"
}

rule MalwareBazaar_VShell_039_1dde3ee1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a"
    family = "VShell"
    file_name = "1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:41:11"
  condition:
    hash.sha256(0, filesize) == "1dde3ee1a023e9210564bc443ec852491ead0e333b5973e20513386c4d91e71a"
}

rule MalwareBazaar_WARDENStealer_040_2731c257
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a"
    family = "WARDENStealer"
    file_name = "2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:39:54"
  condition:
    hash.sha256(0, filesize) == "2731c2579caa28e7b3e5f3ba913b31d1036f23596d2d9c942be03a2df0e2bd2a"
}

rule MalwareBazaar_unknown_041_af4b153c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b"
    family = "unknown"
    file_name = "af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:34:56"
  condition:
    hash.sha256(0, filesize) == "af4b153c27eb99967a5a58b8dc51eeb848e1f99b22c126e0ad2e6316f988ec8b"
}

rule MalwareBazaar_unknown_042_ec3e7cf7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e"
    family = "unknown"
    file_name = "ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:34:52"
  condition:
    hash.sha256(0, filesize) == "ec3e7cf7e7e4119f3c076a505d647e7907eb5c024ec349dc904971e5329d3a9e"
}

rule MalwareBazaar_unknown_043_602a346e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63"
    family = "unknown"
    file_name = "602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:31:06"
  condition:
    hash.sha256(0, filesize) == "602a346e45e8cba4c17e1f2caf7f6508f108469153cea0db0cbf67fdff505a63"
}

rule MalwareBazaar_unknown_044_d69754b6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75"
    family = "unknown"
    file_name = "d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:26:04"
  condition:
    hash.sha256(0, filesize) == "d69754b6f6ce97e5962c22d3e8dfd1421a5068841876af28a3698d00c0f30e75"
}

rule MalwareBazaar_unknown_045_1aa949ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d"
    family = "unknown"
    file_name = "1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:26:00"
  condition:
    hash.sha256(0, filesize) == "1aa949ac5f5056fda038823eed18f348effd7b43210aa1c8e8e667abe296e60d"
}

rule MalwareBazaar_unknown_046_f651f363
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2"
    family = "unknown"
    file_name = "f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:24:42"
  condition:
    hash.sha256(0, filesize) == "f651f36343155c44f03a0b697406ed80bb93ddb2b5444b2d1567ab93e5b6a8b2"
}

rule MalwareBazaar_unknown_047_393375c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177"
    family = "unknown"
    file_name = "393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:21:00"
  condition:
    hash.sha256(0, filesize) == "393375c12fe8293c7e3ad32dfa59e157712151748ea4b4390056579247ce8177"
}

rule MalwareBazaar_unknown_048_1adac896
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d"
    family = "unknown"
    file_name = "1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:17:07"
  condition:
    hash.sha256(0, filesize) == "1adac896cf5634edf9a29fe440a0f3775c0c6684c12d71735de269f070e8557d"
}

rule MalwareBazaar_unknown_049_8f33eef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0"
    family = "unknown"
    file_name = "8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:17:01"
  condition:
    hash.sha256(0, filesize) == "8f33eef6cd5411bd5bba7acf26a72c7241e0fdc805291c6be13d7aabc3d822d0"
}

rule MalwareBazaar_unknown_050_6d95b7b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159"
    family = "unknown"
    file_name = "6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:14:46"
  condition:
    hash.sha256(0, filesize) == "6d95b7b322c16956411910106e8a225749e552c6e778d614aa94189a51f23159"
}

rule MalwareBazaar_unknown_051_e7f1ec95
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda"
    family = "unknown"
    file_name = "e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:12:04"
  condition:
    hash.sha256(0, filesize) == "e7f1ec95be8d9dca9ed5dd8130eab61b5c8194ba103ed25e8da30b7958bd1dda"
}

rule MalwareBazaar_unknown_052_51476daf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30"
    family = "unknown"
    file_name = "51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:11:59"
  condition:
    hash.sha256(0, filesize) == "51476daf7f8fea1d79142dca3f888dfcb944d37a62428a4770342a67b4cd6e30"
}

rule MalwareBazaar_unknown_053_38a3228e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b"
    family = "unknown"
    file_name = "38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:11:54"
  condition:
    hash.sha256(0, filesize) == "38a3228eb79fbce3708d654fb35beeae058bed706cecf0268a7bc2440133450b"
}

rule MalwareBazaar_unknown_054_2c6cc3ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832"
    family = "unknown"
    file_name = "2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:10:59"
  condition:
    hash.sha256(0, filesize) == "2c6cc3ecdfa063fdc18a75a4ac6f508d6e2a962f5aeda252a2c71ba25bdc0832"
}

rule MalwareBazaar_unknown_055_2500ec5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572"
    family = "unknown"
    file_name = "2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:10:07"
  condition:
    hash.sha256(0, filesize) == "2500ec5b30002d4e6eab75b78c1178bc249c8ef3e6528c01911f17487cf60572"
}

rule MalwareBazaar_unknown_056_9b62873e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297"
    family = "unknown"
    file_name = "9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:10:01"
  condition:
    hash.sha256(0, filesize) == "9b62873ec976996f43534dc372bf96ff9163801d70ca5919892414ba94442297"
}

rule MalwareBazaar_unknown_057_18c0c548
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a"
    family = "unknown"
    file_name = "18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:09:53"
  condition:
    hash.sha256(0, filesize) == "18c0c5487bd8c298962ec458d4bc5cc8f780e50346a954f392450d6314cc000a"
}

rule MalwareBazaar_unknown_058_2652f5c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e"
    family = "unknown"
    file_name = "2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:09:48"
  condition:
    hash.sha256(0, filesize) == "2652f5c9af66c6414066c9151cf63604c0273417a4605ac19fdefed4b190b78e"
}

rule MalwareBazaar_unknown_059_e2394f37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2"
    family = "unknown"
    file_name = "e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:07:04"
  condition:
    hash.sha256(0, filesize) == "e2394f37e2217eece4c8ba21f6948d993f12c1499237c0a4a3e362bdf51514a2"
}

rule MalwareBazaar_unknown_060_08a7e23c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188"
    family = "unknown"
    file_name = "08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:06:57"
  condition:
    hash.sha256(0, filesize) == "08a7e23c2f9bb5400b69190f1863d6a9279977032edeb9c1d57737301a1a2188"
}

rule MalwareBazaar_unknown_061_88891429
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a"
    family = "unknown"
    file_name = "88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:06:52"
  condition:
    hash.sha256(0, filesize) == "88891429bd37a961776fb17a2bf30416dfac8a8622c18272a4a6fdcc8c87295a"
}

rule MalwareBazaar_unknown_062_eb423963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a"
    family = "unknown"
    file_name = "eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:06:09"
  condition:
    hash.sha256(0, filesize) == "eb423963cff11fab2f3ff7bc7f338325fe514b6dae8150fbcaf23a033218cd3a"
}

rule MalwareBazaar_VShell_063_bb214b04
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a"
    family = "VShell"
    file_name = "bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:06:04"
  condition:
    hash.sha256(0, filesize) == "bb214b043caff0dfa492954c8b8d1aea48f3a7adf5da1f76f02af30ecda3116a"
}

rule MalwareBazaar_unknown_064_2cc23640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476"
    family = "unknown"
    file_name = "2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:05:58"
  condition:
    hash.sha256(0, filesize) == "2cc2364073d38d280ab584c34f485b2d30e509ef00cda415038321150f164476"
}

rule MalwareBazaar_unknown_065_bc4370ae
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0"
    family = "unknown"
    file_name = "bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:05:52"
  condition:
    hash.sha256(0, filesize) == "bc4370ae232f27a17e4a0ccaa0c3ca7cd814b74cba7aef935a669adece6c20e0"
}

rule MalwareBazaar_unknown_066_a03196b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14"
    family = "unknown"
    file_name = "a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:05:08"
  condition:
    hash.sha256(0, filesize) == "a03196b8929db6a6d5fb6a98e114dad05e5cbc7512029c16004d45d8e5a38f14"
}

rule MalwareBazaar_unknown_067_77f7ecdc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68"
    family = "unknown"
    file_name = "77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:04:53"
  condition:
    hash.sha256(0, filesize) == "77f7ecdc3fda61a7713e556cfdc46fb45c5f40526f02f231f93e5cbd919fbd68"
}

rule MalwareBazaar_unknown_068_94d7b961
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390"
    family = "unknown"
    file_name = "94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:04:44"
  condition:
    hash.sha256(0, filesize) == "94d7b9615e79407a2917d5d29f5e973ae87741a76ece5150359ddf1b04249390"
}

rule MalwareBazaar_unknown_069_9bbf84d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f"
    family = "unknown"
    file_name = "9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f.exe"
    file_type = "exe"
    first_seen = "2026-11-06 01:02:05"
  condition:
    hash.sha256(0, filesize) == "9bbf84d04f9b7426c339c6c6729e7dbb1ccdcf58f3dbc5d4861c772508c2098f"
}

rule MalwareBazaar_unknown_070_b7a17508
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90"
    family = "unknown"
    file_name = "b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:01:57"
  condition:
    hash.sha256(0, filesize) == "b7a17508c5656ccb5fb5eb620025b8e0ed51e266f1050e6156c0b4509c714a90"
}

rule MalwareBazaar_unknown_071_a587746c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb"
    family = "unknown"
    file_name = "a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:01:51"
  condition:
    hash.sha256(0, filesize) == "a587746cb6d1f18f834da23e407d3aede7cef26190e5879285db4520a12778fb"
}

rule MalwareBazaar_Mirai_072_801859bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-06 01:01:04"
  condition:
    hash.sha256(0, filesize) == "801859bdd548e3965de19e14b373fbad39b9f67850b72b388e527e18efa13c55"
}

rule MalwareBazaar_unknown_073_737a706d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f"
    family = "unknown"
    file_name = "737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:01:02"
  condition:
    hash.sha256(0, filesize) == "737a706d206367a7197d9eee2d9a99f885e934537e0143e077e928b3f76d546f"
}

rule MalwareBazaar_unknown_074_293c5629
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12"
    family = "unknown"
    file_name = "293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:00:56"
  condition:
    hash.sha256(0, filesize) == "293c56299d33f8731ed4114c3d53caaead7d175564071892f61302d2d3be3d12"
}

rule MalwareBazaar_unknown_075_8db08682
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8"
    family = "unknown"
    file_name = "8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8.bin"
    file_type = "macho"
    first_seen = "2026-11-06 01:00:50"
  condition:
    hash.sha256(0, filesize) == "8db08682874ef1a9771fb421274c8173821398b7ddd663d4dacf44be3348d5b8"
}

rule MalwareBazaar_unknown_076_1ae8f5ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36"
    family = "unknown"
    file_name = "1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:59:50"
  condition:
    hash.sha256(0, filesize) == "1ae8f5ab0c02e6d6fb29d50a97a877f10ce02c50d91d379799ca64908d2fdd36"
}

rule MalwareBazaar_unknown_077_a6de2412
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b"
    family = "unknown"
    file_name = "a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:56:50"
  condition:
    hash.sha256(0, filesize) == "a6de24126c0f97c8b78706e511ad9a33be1fb5fc210f9c8db387228963a8377b"
}

rule MalwareBazaar_unknown_078_90013156
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba"
    family = "unknown"
    file_name = "90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:56:03"
  condition:
    hash.sha256(0, filesize) == "90013156cf8068b87624a4e3f82272e8da0d2e2079251bddbf9e5fecded04fba"
}

rule MalwareBazaar_unknown_079_4b721114
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55"
    family = "unknown"
    file_name = "4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:55:57"
  condition:
    hash.sha256(0, filesize) == "4b721114863504919008e3e8820b7a009c2828a9507dd65a6d6275089c1c3e55"
}

rule MalwareBazaar_unknown_080_5bde2bcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0"
    family = "unknown"
    file_name = "5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:55:52"
  condition:
    hash.sha256(0, filesize) == "5bde2bcb559f5bfaa0898d7b3bcb7a8bec4c5145633b404f4641144afc6f78a0"
}

rule MalwareBazaar_unknown_081_5691e08d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228"
    family = "unknown"
    file_name = "5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:54:57"
  condition:
    hash.sha256(0, filesize) == "5691e08df9fd650fcb148a40c84c7a044a9926c74b4fb58411ba0516d4a14228"
}

rule MalwareBazaar_unknown_082_11a54ea0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e"
    family = "unknown"
    file_name = "11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:54:51"
  condition:
    hash.sha256(0, filesize) == "11a54ea07fa357e2f8b9629c73ffae11a0adaf0e98253479658efdcaad9ed71e"
}

rule MalwareBazaar_Mirai_083_086b9625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec"
    family = "Mirai"
    file_name = "086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec"
    file_type = "elf"
    first_seen = "2026-11-06 00:53:53"
  condition:
    hash.sha256(0, filesize) == "086b9625247a2ef58a4ee4fdd2d377c6c6a23e9cd167c9bd529c1140fd5335ec"
}

rule MalwareBazaar_unknown_084_fe436d8c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a"
    family = "unknown"
    file_name = "fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:56"
  condition:
    hash.sha256(0, filesize) == "fe436d8c0a8523dfeed6485c8c78d5b91e9a77734df86db5987b2eda8c78732a"
}

rule MalwareBazaar_unknown_085_fd7c3eb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025"
    family = "unknown"
    file_name = "fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:50"
  condition:
    hash.sha256(0, filesize) == "fd7c3eb4c96e608cb49ba513e12077376fe26b558b68823bb09e38475b551025"
}

rule MalwareBazaar_unknown_086_21d2fa4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce"
    family = "unknown"
    file_name = "images.7fec4c32.js"
    file_type = "js"
    first_seen = "2026-11-06 00:51:31"
  condition:
    hash.sha256(0, filesize) == "21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce"
}

rule MalwareBazaar_unknown_087_04471ccf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d"
    family = "unknown"
    file_name = "aegis-fix.min.js"
    file_type = "js"
    first_seen = "2026-11-06 00:51:22"
  condition:
    hash.sha256(0, filesize) == "04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d"
}

rule MalwareBazaar_unknown_088_152d1485
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846"
    family = "unknown"
    file_name = "152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:09"
  condition:
    hash.sha256(0, filesize) == "152d1485f109f015690d48bfd12ecb9a7f7735eb473fbaceb8c83ab019715846"
}

rule MalwareBazaar_unknown_089_bfc08bb7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4"
    family = "unknown"
    file_name = "bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:51:03"
  condition:
    hash.sha256(0, filesize) == "bfc08bb7ea589fcda91e6353f1fc7e562134b818c2a220acdb89fe88c1f524b4"
}

rule MalwareBazaar_unknown_090_f9cc2ee7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c"
    family = "unknown"
    file_name = "f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:50:56"
  condition:
    hash.sha256(0, filesize) == "f9cc2ee7b979473c61465fd6c6dfc25a6bfcbdb9248e029c6ca1603eaa67a78c"
}

rule MalwareBazaar_unknown_091_db6c7c1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb"
    family = "unknown"
    file_name = "db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb.exe"
    file_type = "exe"
    first_seen = "2026-11-06 00:50:50"
  condition:
    hash.sha256(0, filesize) == "db6c7c1d1d690f3e91d3b0c2f102e6d64e1abb157a08d536df62568e25d9f4bb"
}

rule MalwareBazaar_unknown_092_2a15faa0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a15faa0419d715a493468839ac908451ed33a00335446d19e3a468608726f4e"
    family = "unknown"
    file_name = "macho_2a15faa0419d.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:50:03"
  condition:
    hash.sha256(0, filesize) == "2a15faa0419d715a493468839ac908451ed33a00335446d19e3a468608726f4e"
}

rule MalwareBazaar_unknown_093_9c825f1f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72"
    family = "unknown"
    file_name = "9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:46:58"
  condition:
    hash.sha256(0, filesize) == "9c825f1fd9a21713b6f179ad455ded64811fff34140daad44954c6f4b5586f72"
}

rule MalwareBazaar_unknown_094_152570c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6"
    family = "unknown"
    file_name = "152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:46:51"
  condition:
    hash.sha256(0, filesize) == "152570c743eba81a4fdcdde1cce97f4b624e89fb77f18be8d309c6c29a642bb6"
}

rule MalwareBazaar_unknown_095_32d0929d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20"
    family = "unknown"
    file_name = "32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:45:59"
  condition:
    hash.sha256(0, filesize) == "32d0929d2dc0d0e55e35960b35de335c0600a52ccc6d6cd249fbfb03a0c1ea20"
}

rule MalwareBazaar_unknown_096_aeadf162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750"
    family = "unknown"
    file_name = "aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:45:51"
  condition:
    hash.sha256(0, filesize) == "aeadf162491994c9299d8d6264e5c1fba45090a2be63c5b59a41c1af8bfc2750"
}

rule MalwareBazaar_unknown_097_5e331ae6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e331ae6cd7264ca0d975fc519f56c4797ad1bea63b05539259b57ba522e771f"
    family = "unknown"
    file_name = "macho_5e331ae6cd72.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:45:21"
  condition:
    hash.sha256(0, filesize) == "5e331ae6cd7264ca0d975fc519f56c4797ad1bea63b05539259b57ba522e771f"
}

rule MalwareBazaar_unknown_098_7f9cfd0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed"
    family = "unknown"
    file_name = "7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:44:54"
  condition:
    hash.sha256(0, filesize) == "7f9cfd0d37cad548e13e70668fb1b2e2b5ce07f9373d7b0c64197b53f98e01ed"
}

rule MalwareBazaar_unknown_099_4476a579
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c"
    family = "unknown"
    file_name = "4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:44:47"
  condition:
    hash.sha256(0, filesize) == "4476a579c8684e9297b69123bde982560413c4643b411a4da2c6929fc7785e4c"
}

rule MalwareBazaar_unknown_100_91d927e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89"
    family = "unknown"
    file_name = "91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89.bin"
    file_type = "macho"
    first_seen = "2026-11-06 00:44:42"
  condition:
    hash.sha256(0, filesize) == "91d927e18cbfd210cd2b0c04d77ea239436c4c1c63b7add4a5182c053fe2ec89"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

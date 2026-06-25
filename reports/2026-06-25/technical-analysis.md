# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-06-25

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 659 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 659 |
| Unique family labels | 8 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 51 |
| unknown | 30 |
| BtmobRAT | 14 |
| RemoteManipulator | 1 |
| RustyStealer | 1 |
| Formbook | 1 |
| Stealc | 1 |
| IRATA | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 55 |
| apk | 18 |
| exe | 12 |
| sh | 9 |
| dll | 3 |
| jar | 1 |
| vbs | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `f1a895267514b8b6`

| Field | Value |
|---|---|
| SHA-256 | `f1a895267514b8b63673820a534724b1b9ad41b314be2aa1c458512f0d75a8d3` |
| Family label | `unknown` |
| File name | `menu.exe` |
| File type | `exe` |
| First seen | `2026-06-25 04:33:06` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealc, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33f940fc07c36a2309cc994192f706a2` |
| SHA-1 | `488337c138f299e899a72237558b935abb9bc26c` |
| SHA-256 | `f1a895267514b8b63673820a534724b1b9ad41b314be2aa1c458512f0d75a8d3` |
| SHA3-384 | `1cff4467974ba520a6dc28212f37876c4cc91159326786a7aefd85e2ab5d813b0ba742b6ab8a531f7d31f8a3256a9ec6` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E7D58D0BACD009FAD49AE732497A11927B75BD991B31A3C71ED0B2382EB73D08D36745` |
| SSDEEP | `49152:ySU0to2U/Rw/Eqw8PUDwyADBD1qVK4hoIcY4pA:yS0xvefyAlMVK4OIcYIA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_f1a89526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1a895267514b8b63673820a534724b1b9ad41b314be2aa1c458512f0d75a8d3"
    family = "unknown"
    file_name = "menu.exe"
    file_type = "exe"
    first_seen = "2026-06-25 04:33:06"
  condition:
    hash.sha256(0, filesize) == "f1a895267514b8b63673820a534724b1b9ad41b314be2aa1c458512f0d75a8d3"
}
```

### Sample 2: `7f01a05055ec07b2`

| Field | Value |
|---|---|
| SHA-256 | `7f01a05055ec07b287de38a6e92f2a04dc512fe1b6972c16e2412ff27c53ce6a` |
| Family label | `RemoteManipulator` |
| File name | `744c291f1af31190766580c630d0c032.exe` |
| File type | `exe` |
| First seen | `2026-06-25 04:25:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, RemoteManipulator` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `744c291f1af31190766580c630d0c032` |
| SHA-1 | `23f1bb7c643902b3b00b41d43a04ed3fe3b84cf5` |
| SHA-256 | `7f01a05055ec07b287de38a6e92f2a04dc512fe1b6972c16e2412ff27c53ce6a` |
| SHA3-384 | `36b83e49a3367428bf3225776075751e7b418628c4197ffbe7327fd0edd969c9758c48c0939412cde9354d91bc4116b0` |
| IMPHASH | `6ce4d8f9b917fabee4acaf8bf0692ddf` |
| TLSH | `T1E3171227B384693DC4AF1B37497787145A3FBEA169038F4F53F5680C8E396812E3A646` |
| SSDEEP | `393216:2SFCrFhSz35h3tDYUswv53Z8WJ09AEjgKV+ACUub1GRygHT:b7zf3V7v5J8wE/+/UuZ3K` |
| ICON-DHASH | `c4dacabacac0c244` |

#### Technical Assessment

- The sample is tracked as `RemoteManipulator` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemoteManipulator_002_7f01a050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f01a05055ec07b287de38a6e92f2a04dc512fe1b6972c16e2412ff27c53ce6a"
    family = "RemoteManipulator"
    file_name = "744c291f1af31190766580c630d0c032.exe"
    file_type = "exe"
    first_seen = "2026-06-25 04:25:06"
  condition:
    hash.sha256(0, filesize) == "7f01a05055ec07b287de38a6e92f2a04dc512fe1b6972c16e2412ff27c53ce6a"
}
```

### Sample 3: `f8f951f3a2fa091e`

| Field | Value |
|---|---|
| SHA-256 | `f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443` |
| Family label | `unknown` |
| File name | `f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443.dll` |
| File type | `dll` |
| First seen | `2026-06-25 04:13:41` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0cf51f129a326966775ecf5d2ac11fdd` |
| SHA-1 | `926260a6d371ed2afde82ea9ff01ad36515aab45` |
| SHA-256 | `f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443` |
| SHA3-384 | `c6c41b1247b02a4c6c7609d9272ecf962823de3573686a1bad727b8516486e4c09e20961c81dd22351683e9e522ebeec` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1CA3682E73544CC68FCF8C938DA5D06D8BD71AA09E1D6412B0660851D2D2F1F7AAFEB21` |
| SSDEEP | `6144:yE9l9yNqIYVTH5DgSg8ajldktM0XXrs2QhE:ywbLgPluxQhE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_f8f951f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443"
    family = "unknown"
    file_name = "f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443.dll"
    file_type = "dll"
    first_seen = "2026-06-25 04:13:41"
  condition:
    hash.sha256(0, filesize) == "f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443"
}
```

### Sample 4: `0b2d6d916b7c65a1`

| Field | Value |
|---|---|
| SHA-256 | `0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11` |
| Family label | `unknown` |
| File name | `0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11.dll` |
| File type | `dll` |
| First seen | `2026-06-25 04:07:02` |
| Reporter | `Kejult` |
| Tags | `dll, wannacry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d40f14f19c72f1d54250c94bed057906` |
| SHA-1 | `e824f2c27a3be826f723b98f60161c753456d7db` |
| SHA-256 | `0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11` |
| SHA3-384 | `483d1a80a3e70865bc4effdf4a7f88f70f410fe2de7c693ba8c034fb7f5640a4799ab3a1ab0836a937cbcec5d3127546` |
| IMPHASH | `2e5708ae5fed0403e8117c645fb23e5b` |
| TLSH | `T1DE36E115A1E86B64E7F36EB2217B871007797E45889B925E1760A04F0C33F5CDEE2F29` |
| SSDEEP | `49152:RnaQqMSPbcBVQej/1INRx+TSqTdv1HkQo6SAA:1lqPoBhz1aRxcSUbk36SA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_0b2d6d91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11"
    family = "unknown"
    file_name = "0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11.dll"
    file_type = "dll"
    first_seen = "2026-06-25 04:07:02"
  condition:
    hash.sha256(0, filesize) == "0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11"
}
```

### Sample 5: `43172e45afb4cef9`

| Field | Value |
|---|---|
| SHA-256 | `43172e45afb4cef97225b8ed783bd66bd7b06839c6fa95c957d248d67ca1725d` |
| Family label | `unknown` |
| File name | `deploy_softwaretech.sh` |
| File type | `sh` |
| First seen | `2026-06-25 03:55:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3969cc1ce4476e0e6595101866079277` |
| SHA-1 | `854aca99f735289be8c349b266f88ba819a3b74f` |
| SHA-256 | `43172e45afb4cef97225b8ed783bd66bd7b06839c6fa95c957d248d67ca1725d` |
| SHA3-384 | `d7c863bb8c749d8674497cb126eef4b3e0a1f7f1babed9d81dc3c33423983f0949ad7c035d8a98e3c0872a957c51cef9` |
| TLSH | `T12A529672BA65D57638ACC22C998E9110392B3AEB36183458B4ED76043FFC31D51F277A` |
| SSDEEP | `192:2875rR274COKyAVF1mBt6e4egQq1GZ0HRit4Nmn5PH03/BNGBggGQd:T5zT4LyMiXn5PUQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_43172e45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43172e45afb4cef97225b8ed783bd66bd7b06839c6fa95c957d248d67ca1725d"
    family = "unknown"
    file_name = "deploy_softwaretech.sh"
    file_type = "sh"
    first_seen = "2026-06-25 03:55:14"
  condition:
    hash.sha256(0, filesize) == "43172e45afb4cef97225b8ed783bd66bd7b06839c6fa95c957d248d67ca1725d"
}
```

### Sample 6: `34b1ab13d92e0551`

| Field | Value |
|---|---|
| SHA-256 | `34b1ab13d92e0551fb4bd85319cdec417ef110628d6af437b734c81358257254` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-25 03:38:28` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72304734486b1010ccdd69dd0369daf1` |
| SHA-1 | `2eac89a4cade7be7e088425410351949fcc1f9bd` |
| SHA-256 | `34b1ab13d92e0551fb4bd85319cdec417ef110628d6af437b734c81358257254` |
| SHA3-384 | `2c89ef7ece879486c56897c58005f3499f333de6fa860222576c15e6e66348a663385c0dfc37fabc233af3fd536acfd7` |
| TLSH | `T1BA136D6526953C25AE99883B5C7E2F0CBDA983E1304491DDBFCA3CF18C15A9CE319B19` |
| SSDEEP | `768:Hr9NyXsZztCL9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:LHusZFco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_34b1ab13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34b1ab13d92e0551fb4bd85319cdec417ef110628d6af437b734c81358257254"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-25 03:38:28"
  condition:
    hash.sha256(0, filesize) == "34b1ab13d92e0551fb4bd85319cdec417ef110628d6af437b734c81358257254"
}
```

### Sample 7: `a8484c9b65270cb4`

| Field | Value |
|---|---|
| SHA-256 | `a8484c9b65270cb49da643faf17994959a035be72203eb9b4f9e90feb37f75e7` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-25 03:00:16` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `353d831ea59f2a9a29fc339bbd432e72` |
| SHA-1 | `04c8fa06daa7279db6f09f7a17123c83540ade3e` |
| SHA-256 | `a8484c9b65270cb49da643faf17994959a035be72203eb9b4f9e90feb37f75e7` |
| SHA3-384 | `d5b4793e70c82334efbe20cf81ec46a9fcafc8beca68f5ba2e3c1ee2ef2795cdac5d67b339816a648fe50ac3a5dddd68` |
| TLSH | `T14C137D6566913C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C19A9CD21871D` |
| SSDEEP | `768:4XRWNGxV89GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:slxbco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_a8484c9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8484c9b65270cb49da643faf17994959a035be72203eb9b4f9e90feb37f75e7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-25 03:00:16"
  condition:
    hash.sha256(0, filesize) == "a8484c9b65270cb49da643faf17994959a035be72203eb9b4f9e90feb37f75e7"
}
```

### Sample 8: `1bee14b1afc29e40`

| Field | Value |
|---|---|
| SHA-256 | `1bee14b1afc29e401d0f8f6e559cab82d2b40c6fde24e38bcaf70631795fac21` |
| Family label | `unknown` |
| File name | `文档.exe` |
| File type | `exe` |
| First seen | `2026-06-25 02:21:57` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bg[qtsc], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2894a452a69cd574591dd927e38f105` |
| SHA-1 | `ea19b2afb22abede82c1e2fb8c00eee4a2230c06` |
| SHA-256 | `1bee14b1afc29e401d0f8f6e559cab82d2b40c6fde24e38bcaf70631795fac21` |
| SHA3-384 | `3902e5beafeae6b97fa22e8dfd9daebefcdf2740b66b5e710d294e8eab23ea1e644d4804161dff4e6f102a45061d7777` |
| IMPHASH | `5bf3e23a459983ccf98096c50cb7d303` |
| TLSH | `T175E52C2ED6A9C2F8C7BAC0348A1F4133F5B1781A971897C75028C6726EFB6C56E39714` |
| SSDEEP | `98304:3f5wcbhKfSxJvZb+Gey3FaeW0Z24tRuY4cLDw:3f5wcbhKfSxJvZb+GJ3FaeW0Z24tRuYU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_1bee14b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bee14b1afc29e401d0f8f6e559cab82d2b40c6fde24e38bcaf70631795fac21"
    family = "unknown"
    file_name = "文档.exe"
    file_type = "exe"
    first_seen = "2026-06-25 02:21:57"
  condition:
    hash.sha256(0, filesize) == "1bee14b1afc29e401d0f8f6e559cab82d2b40c6fde24e38bcaf70631795fac21"
}
```

### Sample 9: `396c4ffc3d7428e5`

| Field | Value |
|---|---|
| SHA-256 | `396c4ffc3d7428e57ecf71eb3dca8a7f07deee530ed28aad065d9dc83b130662` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-25 01:59:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0f3aa80f9a768400028faa9d1c54e9f` |
| SHA-1 | `8aa8341d1d8bb62f03b081941b27042fcb3de9ed` |
| SHA-256 | `396c4ffc3d7428e57ecf71eb3dca8a7f07deee530ed28aad065d9dc83b130662` |
| SHA3-384 | `62a841a3ab1f8b06f2eb6fb24ec3ae9d58221bee5e2867ddfa1e1235ffd2a0d8911917f723e6fad51ce4be91dcb8df1c` |
| TLSH | `T165A3C64E2E628F6EF76D82354BB35F35C654339B2AD0C641D1BCE9055E2020EA85FB78` |
| TELFHASH | `t11f119e18853813f4d7891ced6bedff76d0a140df0a219e33ce40fab69a60a429e00c2c` |
| SSDEEP | `1536:ZQcccZPj95viyJq/6sEUPr6hQTgEeNlszkdDusEZMw3xs759EtECbbkV5/:ZQvcZviyJVnfceksEZMw3xs7YyC3Kl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_396c4ffc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "396c4ffc3d7428e57ecf71eb3dca8a7f07deee530ed28aad065d9dc83b130662"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-25 01:59:36"
  condition:
    hash.sha256(0, filesize) == "396c4ffc3d7428e57ecf71eb3dca8a7f07deee530ed28aad065d9dc83b130662"
}
```

### Sample 10: `6c876f85aac3f9ba`

| Field | Value |
|---|---|
| SHA-256 | `6c876f85aac3f9ba5ea1d6533ab19b366e6a7be2cab00e8b3abd607c9b8b09a5` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-25 01:56:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11f4c81f4778a9bb98b0bd29568f3442` |
| SHA-1 | `7802c8433b869cc2cb02d8168b8987f808cbd1c5` |
| SHA-256 | `6c876f85aac3f9ba5ea1d6533ab19b366e6a7be2cab00e8b3abd607c9b8b09a5` |
| SHA3-384 | `266cd70ac633b7f916cd57e8aa8b01888ba7e922fbdbf1714dd3d0f50f2e8ec7a9a77960fe02c8e4a9bc9ebeb0cb4228` |
| TLSH | `T1A9E34C47FA418A13C4D22779BAEF9245332397A5D3D733068918AFF83F8369A0E66505` |
| TELFHASH | `t1132112f6e934d52eadb20824dd5d4af15110e317632d0d31af38c5dc1e3a092a56ad7f` |
| SSDEEP | `3072:rkXhwtLYo4x8UhPrz696g66G07rd97Xy4FHMXDM/9EO5IbL:IXhwtLYo4xBhPrzq6B6G07rn7FHMTM/o` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_6c876f85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c876f85aac3f9ba5ea1d6533ab19b366e6a7be2cab00e8b3abd607c9b8b09a5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-25 01:56:20"
  condition:
    hash.sha256(0, filesize) == "6c876f85aac3f9ba5ea1d6533ab19b366e6a7be2cab00e8b3abd607c9b8b09a5"
}
```

### Sample 11: `7e65fbe7ff6d5f92`

| Field | Value |
|---|---|
| SHA-256 | `7e65fbe7ff6d5f92090ea2df29477865a234018ec043920471e371fc70fe3ee7` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-25 01:47:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b0c0e3f09a3907b57db92631ec13d2e0` |
| SHA-1 | `6bb386d2e6bfdc02cdff81ab9df678619a8cd058` |
| SHA-256 | `7e65fbe7ff6d5f92090ea2df29477865a234018ec043920471e371fc70fe3ee7` |
| SHA3-384 | `8d6cf2bcc64f41796ccb376271ac0c98ebdd3658eff23a59388dd80f485f0fc8245e1fe075b86bf6d996059c782d1441` |
| TLSH | `T19A73F750F94784F5D84368B098E7F33FA630D9585231E65FEF9A9B36DA33B0A521224C` |
| TELFHASH | `t19921d8ba1f3a19e4b7d08845d21d9b116fbaa77b142032e711735d2125dedc250bbc39` |
| SSDEEP | `1536:LDQTDHEbkwPyDWQ35/qZyEp8HhTVhXhA4hO9X1b7VTLRMx1Sq5Mr:LetB6yEp8xiF1b7BLY1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_7e65fbe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e65fbe7ff6d5f92090ea2df29477865a234018ec043920471e371fc70fe3ee7"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-25 01:47:13"
  condition:
    hash.sha256(0, filesize) == "7e65fbe7ff6d5f92090ea2df29477865a234018ec043920471e371fc70fe3ee7"
}
```

### Sample 12: `ac4de25e87b96bd8`

| Field | Value |
|---|---|
| SHA-256 | `ac4de25e87b96bd85e9b50e1688cbb6ccef9de8beaac552180fe0547586dc968` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-06-25 01:47:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb8c275a6914d61313f9091df86e01bf` |
| SHA-1 | `c50c99fc179517cdb605d8af09f283e5b4662e48` |
| SHA-256 | `ac4de25e87b96bd85e9b50e1688cbb6ccef9de8beaac552180fe0547586dc968` |
| SHA3-384 | `060e9e18d4d2527bfc9e4f3c8c971a6feb031dfe851af7b8e419695b4317b2d466dcae59e386eedc2480cea193029bed` |
| TLSH | `T116734A876411DEADFC0FB67A89174E05F539E7808F520E33A3B2BC678C560958E6BE11` |
| SSDEEP | `1536:MT+yqzisf5dVYFKsBcIqmgMsKcwUwBcAnA9Dg4fS+bEVdMh8XmzqK9k3Lr9v6s/g:MCyqzisf5deEsBcIqmgMsKcwUwBcAnAP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_ac4de25e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4de25e87b96bd85e9b50e1688cbb6ccef9de8beaac552180fe0547586dc968"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-25 01:47:12"
  condition:
    hash.sha256(0, filesize) == "ac4de25e87b96bd85e9b50e1688cbb6ccef9de8beaac552180fe0547586dc968"
}
```

### Sample 13: `7db97598eb3c11ab`

| Field | Value |
|---|---|
| SHA-256 | `7db97598eb3c11ab87d56215afc4f053d0db5064d97376cc6278d6af739a2e27` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-06-25 01:28:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `968d03ed4ea22f0010826c271cfa34f0` |
| SHA-1 | `265bd397ecc7a763d2168a2f9286ad80cd54698d` |
| SHA-256 | `7db97598eb3c11ab87d56215afc4f053d0db5064d97376cc6278d6af739a2e27` |
| SHA3-384 | `68622053dcbb33978fe26fcc365c80fefffa3b7ae321930e2b85ab3a09d6522f43f6b1c791b030c95f60cb24454c638c` |
| TLSH | `T1A4432A05FB47D9F1D89359B0516BFA3A9A35BC715120D92BE7D0FFA3B9312C2A005329` |
| TELFHASH | `t1cf2190fa3eed18e8b6e58c0c825a1e260775d13b189135b543b0e41523e7e429177c38` |
| SSDEEP | `768:EZZ3t41yZHn2cPGRNNmrds9zddHZxo827KnkXP94plmrq:cZ94clRPGZMW/5R27Ki+m+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_7db97598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7db97598eb3c11ab87d56215afc4f053d0db5064d97376cc6278d6af739a2e27"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-06-25 01:28:19"
  condition:
    hash.sha256(0, filesize) == "7db97598eb3c11ab87d56215afc4f053d0db5064d97376cc6278d6af739a2e27"
}
```

### Sample 14: `18372ae33ff340d0`

| Field | Value |
|---|---|
| SHA-256 | `18372ae33ff340d0c683a4b40f85ce0573bdfb448a8ede0ca1ce031d53a4df87` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-25 01:27:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6e46a32b8bab6d2d4565876f963f007` |
| SHA-1 | `cf56c26ced7e6114489cf5e614e3c2776877e640` |
| SHA-256 | `18372ae33ff340d0c683a4b40f85ce0573bdfb448a8ede0ca1ce031d53a4df87` |
| SHA3-384 | `63752b6ea5fbeaa34d09772b5926ff595a72d1813cbdfa0edb7b1899c9ecffd2c6212b0ad602f08d6dd0cb4b28e36732` |
| TLSH | `T191734A06B8E2CA56D6D5727ABA1E818C331213F4C2DF3207CD05AF797BC695A0E7B584` |
| TELFHASH | `t17441c1eb9f740fec17d2a14481cea13e17fd309b5e512443820dab0fc417693f059826` |
| SSDEEP | `1536:MKipeAE86kDOihhb1I9UokbGyxVVdOH0AutplLNiR/ts+FEsR:MKipeAE8nbbRIrkCcdOULplLco+N` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_18372ae3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18372ae33ff340d0c683a4b40f85ce0573bdfb448a8ede0ca1ce031d53a4df87"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-25 01:27:15"
  condition:
    hash.sha256(0, filesize) == "18372ae33ff340d0c683a4b40f85ce0573bdfb448a8ede0ca1ce031d53a4df87"
}
```

### Sample 15: `4ba0eea142e43246`

| Field | Value |
|---|---|
| SHA-256 | `4ba0eea142e43246981a2d7b7f06479affeec4ccf57aaa64b452e77075606a17` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-25 01:23:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2341810d35b3d618caf5bc85d79e8b29` |
| SHA-1 | `e3996aedd3209d18b9bae698250890e0bf226cf0` |
| SHA-256 | `4ba0eea142e43246981a2d7b7f06479affeec4ccf57aaa64b452e77075606a17` |
| SHA3-384 | `210aeb023333e036e6b14fe592e865d206e6a10c72670dc2f3d247fae1fb455781b042488c02eb7167c577210fa8ecd0` |
| TLSH | `T1E6735A03758080BCC08AC1384A7FB636E562B57E23356E5977D8FF667F87A202A6D714` |
| TELFHASH | `t11f2157703c871da061e3b739e301d1e42c342a6116f536e48a76dcf2cf6b7844d91427` |
| SSDEEP | `768:JuJKrd2SrAG7M2WR2tiOtTdusSRDsQQU0EedtqlEYDUyjOGLcSW5jePpl0uj0YuM:xp2SBM2WOvdolQzvdq4yCGhzr0b8qAX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_4ba0eea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ba0eea142e43246981a2d7b7f06479affeec4ccf57aaa64b452e77075606a17"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-25 01:23:17"
  condition:
    hash.sha256(0, filesize) == "4ba0eea142e43246981a2d7b7f06479affeec4ccf57aaa64b452e77075606a17"
}
```

### Sample 16: `5a8795076e41edd2`

| Field | Value |
|---|---|
| SHA-256 | `5a8795076e41edd2aa2850f7945b06dfe27059a08eed47450e9fc83c108995f5` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-06-25 01:21:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e407ccd4d3f0d17745d03342f9a88c3` |
| SHA-1 | `39b509caf7c134bec85a705c9968a0a7647f80e1` |
| SHA-256 | `5a8795076e41edd2aa2850f7945b06dfe27059a08eed47450e9fc83c108995f5` |
| SHA3-384 | `a9509b68f66a880e6fc5ee49ad60b2547a7ee3b4af7e0dd843ca21681305524ed196a9fa7a32f5c8282dbc008139fccf` |
| TLSH | `T13C835C3379B85D17C8C4A67A22E74334F5F7474525F8CA2E7C224EADBB00660226777A` |
| SSDEEP | `1536:j+W/kOzr3E5Tn/J60cDLwznea7s0Yuo+Ry:j5/kOzrUB0R/6nF7sFuo3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_5a879507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a8795076e41edd2aa2850f7945b06dfe27059a08eed47450e9fc83c108995f5"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-06-25 01:21:34"
  condition:
    hash.sha256(0, filesize) == "5a8795076e41edd2aa2850f7945b06dfe27059a08eed47450e9fc83c108995f5"
}
```

### Sample 17: `c686e9d277411bee`

| Field | Value |
|---|---|
| SHA-256 | `c686e9d277411bee3f43666fe898cddb7cdf55971b576eb1c30b45f820cd67f3` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-06-25 01:08:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97a8fcbbb01601ad7b6d754f6fb1c077` |
| SHA-1 | `84f90e6253db3897101d0902b35569b6796f9326` |
| SHA-256 | `c686e9d277411bee3f43666fe898cddb7cdf55971b576eb1c30b45f820cd67f3` |
| SHA3-384 | `d8bc85a228ef83307102287740999c1443cba5292440007951506fb6074f8093240f6013d39762d29d280e16ab58955c` |
| TLSH | `T19B633B85EA83E4F0EC0515B029B3F7372A32E4650124B94BE779E77BAC12772E54678C` |
| TELFHASH | `t18421e5f52d7e1cd9b7d15c00c25e1fa57a2ab63b356036e108b3697436eba005075c76` |
| SSDEEP | `1536:8XXdyuq2jmilBnk7tYnqPIUlK2he6hvhljhPFpgqMeqIn8N:aNyuRm2VDvwjlFpbMRk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_c686e9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c686e9d277411bee3f43666fe898cddb7cdf55971b576eb1c30b45f820cd67f3"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-06-25 01:08:32"
  condition:
    hash.sha256(0, filesize) == "c686e9d277411bee3f43666fe898cddb7cdf55971b576eb1c30b45f820cd67f3"
}
```

### Sample 18: `4df5911bd816cd34`

| Field | Value |
|---|---|
| SHA-256 | `4df5911bd816cd345e4f2f96e55c7026b6f305e40de436a5b928b05f145146c2` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-06-25 00:49:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `45a2fc3fc8067fd290a8bd86a1d7d0eb` |
| SHA-1 | `55d87d06b3c1c14a1bf4336d1d2f2a24f34e7b33` |
| SHA-256 | `4df5911bd816cd345e4f2f96e55c7026b6f305e40de436a5b928b05f145146c2` |
| SHA3-384 | `69287baf67d1d1cd977d5d1dbf3082f98b46f80b717a9130df0957ddf8b950893899c1663bb1120d0c5bb0572e99f24e` |
| TLSH | `T16FB32B03BD52CA53D5D217B97AAF91583322A7B5C39B3302C914AFF42F836DA0E7A511` |
| TELFHASH | `t1d42120f6e934d52eadb20820dc5d4ab14110e327632d0d31af38c1dc1e3a082a52ad6f` |
| SSDEEP | `3072:a/jKcGbiouZM7ufcprqISTLwDiQcoH+puio:a/jKcGbiNM7ufUDSTMijOio` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_4df5911b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4df5911bd816cd345e4f2f96e55c7026b6f305e40de436a5b928b05f145146c2"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-25 00:49:19"
  condition:
    hash.sha256(0, filesize) == "4df5911bd816cd345e4f2f96e55c7026b6f305e40de436a5b928b05f145146c2"
}
```

### Sample 19: `1e31599608087395`

| Field | Value |
|---|---|
| SHA-256 | `1e31599608087395f5f717647667581f5d90107bab7517fc4e4d26ecde9e2534` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-25 00:39:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29589f29ef42e4da59ffa12511596ae0` |
| SHA-1 | `b0653399cc458f4a1cf4c60b2a99427ac07db662` |
| SHA-256 | `1e31599608087395f5f717647667581f5d90107bab7517fc4e4d26ecde9e2534` |
| SHA3-384 | `6403393adc51bc3b15f3ba95118c4e7e821fd1b03a934e535d8e813f13c05cca9c52595ff9766d81d00fdcb52786e0e1` |
| TLSH | `T129A3B4097F710EF7D8ABCD3355B84702219C9B0622A97BB67C74D518FB4A54F0AE3828` |
| SSDEEP | `1536:nRqZbd/i9o9d5ryvXs2ui8q8n7LqnhQIalbpmFJpPzgnwNUdZQGogBQDv:n47iitcs2obpmawCd0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_1e315996
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e31599608087395f5f717647667581f5d90107bab7517fc4e4d26ecde9e2534"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-25 00:39:05"
  condition:
    hash.sha256(0, filesize) == "1e31599608087395f5f717647667581f5d90107bab7517fc4e4d26ecde9e2534"
}
```

### Sample 20: `2e8441299af33b3a`

| Field | Value |
|---|---|
| SHA-256 | `2e8441299af33b3ad8701c04b159d8a0ff5bfca6d6f1d8bc0f0bfa0c50130b15` |
| Family label | `Mirai` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-06-25 00:35:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `473b9e0bd4590ba3b3ffe67a28c2e594` |
| SHA-1 | `f75eace52beb7a481ccde715e3bd8a410d39f4d8` |
| SHA-256 | `2e8441299af33b3ad8701c04b159d8a0ff5bfca6d6f1d8bc0f0bfa0c50130b15` |
| SHA3-384 | `cbb47ad2c9a21b430f80f181f4e6f883672320a6cf36d52be7e3272adf2a47751b1043ed252881215ee79f1b852b4a30` |
| TLSH | `T12E933C4AE393D4F0ED4255B006EBF7BB6A3099266150FA2FE74CF9B77932603211661C` |
| TELFHASH | `t14231f67a0fb10ce8b7d04802d20ba731de7d676b1924369342f21925739aa41417be39` |
| SSDEEP | `1536:U7ATdAqhd1xOOtUsod5bFVhNh6hthYhfhEZ9U9yvXo9MtUn31kkeQ5PJr:Hxxesod5U9UEgpao` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_2e844129
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e8441299af33b3ad8701c04b159d8a0ff5bfca6d6f1d8bc0f0bfa0c50130b15"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-06-25 00:35:23"
  condition:
    hash.sha256(0, filesize) == "2e8441299af33b3ad8701c04b159d8a0ff5bfca6d6f1d8bc0f0bfa0c50130b15"
}
```

### Sample 21: `aa14067a93d55af1`

| Field | Value |
|---|---|
| SHA-256 | `aa14067a93d55af1624194f22ea30de722bbc81e133c5919be4129b4deca91d6` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-06-25 00:33:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7b613a6234566db92597eade91a135c` |
| SHA-1 | `be2627c6270a4065cdcb476439c328a8bafdc1f7` |
| SHA-256 | `aa14067a93d55af1624194f22ea30de722bbc81e133c5919be4129b4deca91d6` |
| SHA3-384 | `ed51a10041a60b365996e5fa64674985dea5a6f25bef3e8b54802105958dc03cbcd56a1f70ab8c61ac2041bea3557f8e` |
| TLSH | `T10163AE97C43B2E40D586A6B1A0F5CE79C743D50193430EB72A9AD67A9487CCD724F3B8` |
| SSDEEP | `768:LNYF5wDho80IcIzeBiCrWf9BNDJs3EWvgoyTGGRHno79oiAX9ICiCWdu:t7zeiMW3T+EWv9yTfm7yiYICiz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_aa14067a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa14067a93d55af1624194f22ea30de722bbc81e133c5919be4129b4deca91d6"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-25 00:33:12"
  condition:
    hash.sha256(0, filesize) == "aa14067a93d55af1624194f22ea30de722bbc81e133c5919be4129b4deca91d6"
}
```

### Sample 22: `a852f8958a507f78`

| Field | Value |
|---|---|
| SHA-256 | `a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344` |
| Family label | `unknown` |
| File name | `a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344` |
| File type | `elf` |
| First seen | `2026-06-25 00:31:11` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ae8ab8570544b8d7724d2207c85a77b` |
| SHA-1 | `5a6688c9ae2e0afd3f545616b4c43742ada9940b` |
| SHA-256 | `a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344` |
| SHA3-384 | `8fbe40d61751875eddcfb1004ca709065de5b40b64c9051ea821538791edb84c0452c0d731bd858b9b0225c838ae18ea` |
| TLSH | `T10695F757F49590E4C0EEE174C726A213BEA13499473837E36FA186F11B26FE4A6BC314` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzBt:cqYUQuVDtt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_a852f895
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344"
    family = "unknown"
    file_name = "a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344"
    file_type = "elf"
    first_seen = "2026-06-25 00:31:11"
  condition:
    hash.sha256(0, filesize) == "a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344"
}
```

### Sample 23: `5ebed0bd0c875ada`

| Field | Value |
|---|---|
| SHA-256 | `5ebed0bd0c875ada468c98854eb88f6244461eea138933380e696f27c67a91be` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-25 00:18:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dec96b623802a6f709b51557050e067` |
| SHA-1 | `db5c1260f708a2a85c3151f97acbce77a50a0eaf` |
| SHA-256 | `5ebed0bd0c875ada468c98854eb88f6244461eea138933380e696f27c67a91be` |
| SHA3-384 | `a2d925ccd77b8f199b4553c8a12f9d15ceeeed79fd2ad53505f6134e2c70433586bb2798192f0eb95fbf10f5fb7cc788` |
| TLSH | `T1D8137D6566953C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C19A9CD21871D` |
| SSDEEP | `768:y4XRWNGxVJb9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:nlxwco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_5ebed0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ebed0bd0c875ada468c98854eb88f6244461eea138933380e696f27c67a91be"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-25 00:18:13"
  condition:
    hash.sha256(0, filesize) == "5ebed0bd0c875ada468c98854eb88f6244461eea138933380e696f27c67a91be"
}
```

### Sample 24: `fe08f7fddb6b9bf9`

| Field | Value |
|---|---|
| SHA-256 | `fe08f7fddb6b9bf9757d47f6fb1f1b82a54490e10db140b7d8fbb11b3baaa6a4` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-06-25 00:09:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f55551b1f467d4304f30e4dbe051166` |
| SHA-1 | `e78651daaeccee639cae89032288d37adf4d1e74` |
| SHA-256 | `fe08f7fddb6b9bf9757d47f6fb1f1b82a54490e10db140b7d8fbb11b3baaa6a4` |
| SHA3-384 | `0251c4f6a7b2a86677e9f255909af5d32a6a3f52ecfdadd15af7965cb4307216afde88a0be7d074b0d156ee70f0c2264` |
| TLSH | `T19CF38C87B3265C97CC910AFA4BD75B8C5BB351418F6BC7D63D0C66380E6AACD9D0A381` |
| TELFHASH | `t1433111a6e935c52d7ea21824ec5d4fb18111d72763291e31af3cc1dc5e3f082a469d6f` |
| SSDEEP | `3072:CeG6FQAwvRNjiBsUpoegiLqFrvhkyFm2cK:RG6aRpia0bqMyFm2cK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_fe08f7fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe08f7fddb6b9bf9757d47f6fb1f1b82a54490e10db140b7d8fbb11b3baaa6a4"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-06-25 00:09:21"
  condition:
    hash.sha256(0, filesize) == "fe08f7fddb6b9bf9757d47f6fb1f1b82a54490e10db140b7d8fbb11b3baaa6a4"
}
```

### Sample 25: `a880b428d160b7e3`

| Field | Value |
|---|---|
| SHA-256 | `a880b428d160b7e38557c282c58387db908c982d905259a17d12c29bc2cae1a3` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-25 00:05:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6127527a67b5a43b28172321e7b33f2e` |
| SHA-1 | `66ff02cda753d804f46c860e7ec0d029f466543c` |
| SHA-256 | `a880b428d160b7e38557c282c58387db908c982d905259a17d12c29bc2cae1a3` |
| SHA3-384 | `d7cc03bca238b057c9d5aa082e76795c5e45aa4448538536dd57ba1bbb1a89196347efef43fa1b48f68d245e1e7d017f` |
| TLSH | `T1BD733A4678E2CA56CAC5727ABA1E918C331113F8C2DB3303CD15AF797BC695A0E7B584` |
| SSDEEP | `1536:wtQpCAlZaBRj4jLe2AzHvi9RgVG3W4cFxutfKpgORORs7FFWw:wtQpCAlZi54BArKkGG4q4fKpPd7q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_a880b428
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a880b428d160b7e38557c282c58387db908c982d905259a17d12c29bc2cae1a3"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-25 00:05:17"
  condition:
    hash.sha256(0, filesize) == "a880b428d160b7e38557c282c58387db908c982d905259a17d12c29bc2cae1a3"
}
```

### Sample 26: `063e70ebc453de41`

| Field | Value |
|---|---|
| SHA-256 | `063e70ebc453de4191e8b37a8508763cccd328fb44c9309ed44c4c13b729f4a2` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-25 00:03:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `629ef7a4470c14ee2f3e3fd0210d16d8` |
| SHA-1 | `2b89b384c58d58096c80ece4dd5d1dab50695a15` |
| SHA-256 | `063e70ebc453de4191e8b37a8508763cccd328fb44c9309ed44c4c13b729f4a2` |
| SHA3-384 | `e9f346a0b72704901f94e6cdce469f4ace36e3e0c3dcc6f14ae136ab3ae57d1df7eaf7a302d00b6ff250a4e205f9e841` |
| TLSH | `T129B34B5BAA9D3EDBD2C2473D8A82AA701117F47ECF0383721F11528DAE9EA8DDD94444` |
| TELFHASH | `t1142112f5ed75d12dae920970dc5d49b09110e317632e0e31ef38c1dc5e3a091a11adaf` |
| SSDEEP | `1536:EP0lWTj70B+yncrd3c84PVcehLDzaLmgvBbswvgpsYpDAQ:WawP4tcwqLmmNhd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_063e70eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "063e70ebc453de4191e8b37a8508763cccd328fb44c9309ed44c4c13b729f4a2"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-25 00:03:13"
  condition:
    hash.sha256(0, filesize) == "063e70ebc453de4191e8b37a8508763cccd328fb44c9309ed44c4c13b729f4a2"
}
```

### Sample 27: `faecc582b335ed2b`

| Field | Value |
|---|---|
| SHA-256 | `faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-24 23:47:57` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX7.file, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27988a7e5afee247366e8f560bd37e14` |
| SHA-1 | `d8bf3a711962b0f52ca26fe424d48678ae07a245` |
| SHA-256 | `faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe` |
| SHA3-384 | `c758f8d43d87223ff576dbc6d89e93cfc61ccb9774ffecb4b50b6ea5af8246725d5cf38052fbe24e537504d7df481518` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C0D59D077CE188E9C4AAA33288B762957B74FC054F3227C72E50B6782F76AD05E76744` |
| SSDEEP | `49152:EW/tR0aedpqaP/BuPhfobLQAeB02wx4Q+H6i+plxR1uV+:EWlmZM02TQHbxmw` |
| ICON-DHASH | `70f89cf8f8f2f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_faecc582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 23:47:57"
  condition:
    hash.sha256(0, filesize) == "faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe"
}
```

### Sample 28: `7fb004cc7b621d44`

| Field | Value |
|---|---|
| SHA-256 | `7fb004cc7b621d44c3524a65439f97cc8bf856359100f439f5ce8cfb6caf774a` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-24 23:25:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c60b4a44d173787c6f1a34083eb9b2f7` |
| SHA-1 | `c6d8497f0caf059bef1f4a2393b7e6c9a908c390` |
| SHA-256 | `7fb004cc7b621d44c3524a65439f97cc8bf856359100f439f5ce8cfb6caf774a` |
| SHA3-384 | `d134fb01900f97b4b7519d5550a0f88d6e5aa5deb247acda9e030190e4e83f860e839b417eb8d600f5b24e89eff61571` |
| TLSH | `T137738E4173090F53C5676A30583F2BD28399DAA522B9D7452A1F6B0FC1B2E71868EEDC` |
| SSDEEP | `1536:x2lqeqMW48fRwV/Kry7C+W4bPor7M4zern5N/2MNv1Hz3q8lk3XhIhO2o:iCGN1vFLlIXhI4l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_7fb004cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fb004cc7b621d44c3524a65439f97cc8bf856359100f439f5ce8cfb6caf774a"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-24 23:25:13"
  condition:
    hash.sha256(0, filesize) == "7fb004cc7b621d44c3524a65439f97cc8bf856359100f439f5ce8cfb6caf774a"
}
```

### Sample 29: `c762e76a87832917`

| Field | Value |
|---|---|
| SHA-256 | `c762e76a878329177113d991e1d1bceca046cc101f5f7429fc098f8009828b12` |
| Family label | `unknown` |
| File name | `tbk` |
| File type | `sh` |
| First seen | `2026-06-24 22:09:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9158a62d6c28e88c011519bffc1dac27` |
| SHA-1 | `a05d22b2d19dad87682192cc1e78481108a30fd5` |
| SHA-256 | `c762e76a878329177113d991e1d1bceca046cc101f5f7429fc098f8009828b12` |
| SHA3-384 | `0907661f95513633a906e13f494a424f9bc31a0dc04cf2689b959d7e563995197d9113bd2b8f0af105494ff725114664` |
| TLSH | `T16DF031DA132729B6F910EE2570B1548A53DFAFD625D823ACF8684DB3404AC70B806F99` |
| SSDEEP | `12:BtjBnFjFF+jlewzjlOWNn+0HjBnviQjYjlewtnjlZt+JGy:rX/ulBXHJglBxs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_c762e76a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c762e76a878329177113d991e1d1bceca046cc101f5f7429fc098f8009828b12"
    family = "unknown"
    file_name = "tbk"
    file_type = "sh"
    first_seen = "2026-06-24 22:09:22"
  condition:
    hash.sha256(0, filesize) == "c762e76a878329177113d991e1d1bceca046cc101f5f7429fc098f8009828b12"
}
```

### Sample 30: `f4d3a9898f156bd4`

| Field | Value |
|---|---|
| SHA-256 | `f4d3a9898f156bd443ba241ab0a9e2c22ace7439cbe2e5086695d4e3a01a98fd` |
| Family label | `unknown` |
| File name | `lterouter` |
| File type | `sh` |
| First seen | `2026-06-24 21:56:57` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cdee66f35e00d9a657f6f75d005e0df` |
| SHA-1 | `00fc65303b5ac5dc12e02b96924eace7303e47a7` |
| SHA-256 | `f4d3a9898f156bd443ba241ab0a9e2c22ace7439cbe2e5086695d4e3a01a98fd` |
| SHA3-384 | `8b8184285093f705e285791349123e842db4320a267a252b56f701f4a21ca6ff192ae44f9cd48ac2df31bbf74ba1ed0b` |
| TLSH | `T169C08CCB06163830C081EC287266009E439F878238E00F0CF8980AA3868A940F811F81` |
| SSDEEP | `3:O22exART6ZLXm3FOdJ2GL9rSL6ZLXnBFS/TWUKT6VVI9LJdvvvF:O2546ZjB2GLNSL6ZjFTT6IZJn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_f4d3a989
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d3a9898f156bd443ba241ab0a9e2c22ace7439cbe2e5086695d4e3a01a98fd"
    family = "unknown"
    file_name = "lterouter"
    file_type = "sh"
    first_seen = "2026-06-24 21:56:57"
  condition:
    hash.sha256(0, filesize) == "f4d3a9898f156bd443ba241ab0a9e2c22ace7439cbe2e5086695d4e3a01a98fd"
}
```

### Sample 31: `eb1fa0496503a61c`

| Field | Value |
|---|---|
| SHA-256 | `eb1fa0496503a61c43d02e4378556049b0301941ed48eac154b55aa2f8434b28` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-24 21:48:55` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0821fdd5f3767799074af664853da76` |
| SHA-1 | `e0d3f71447fb38bc7a2cf85d25ab28c3ff47f8c0` |
| SHA-256 | `eb1fa0496503a61c43d02e4378556049b0301941ed48eac154b55aa2f8434b28` |
| SHA3-384 | `66c829cba4383478d9c377b0d70fa124a7d8c0472ec3c23f571f3f83af504c7e4edea60aaed64045c7fe2e1a5d92d33c` |
| TLSH | `T13B332903F943DAFEC55AC2B003EBB539A976783E013971A97BE0FE925694DD01E2D600` |
| TELFHASH | `t19601f5b2766534f0e1fbe8627319e528a53819a101d037f2e5b2adfabb413401975c1a` |
| SSDEEP | `1536:IF41+mQu5fTAp8jDRgYBcGt46k9cstK+i:IF4sm3f8CRggcPh9cYNi` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_eb1fa049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb1fa0496503a61c43d02e4378556049b0301941ed48eac154b55aa2f8434b28"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-24 21:48:55"
  condition:
    hash.sha256(0, filesize) == "eb1fa0496503a61c43d02e4378556049b0301941ed48eac154b55aa2f8434b28"
}
```

### Sample 32: `a64eee9ab72607f0`

| Field | Value |
|---|---|
| SHA-256 | `a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-24 21:27:22` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `215d24f82100037b3b0212c7a53166e6` |
| SHA-1 | `a6d21904e1661fd2f368afa633088aeffcb21ba3` |
| SHA-256 | `a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5` |
| SHA3-384 | `8d2584b34f5aadaf883794abf8ac34393eb61f521ddd9ca4acdbfe04013443ce7debdd42534032002ac96c89fa069ef1` |
| IMPHASH | `0bc1b1e557f4a4387777840b7c7925ef` |
| TLSH | `T1D477F158020CE388785F4636F3E4F83FE3DC25993776E8A9BC39D1DAA412295C279587` |
| SSDEEP | `786432:GgTFxe3rJH0VCahDLBtVbD1DT9SfhMhz:GgTFxe3razhDLBTmMhz` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_032_a64eee9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 21:27:22"
  condition:
    hash.sha256(0, filesize) == "a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5"
}
```

### Sample 33: `72d80252032723c3`

| Field | Value |
|---|---|
| SHA-256 | `72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316` |
| Family label | `unknown` |
| File name | `PrestigeClient.jar` |
| File type | `jar` |
| First seen | `2026-06-24 21:04:36` |
| Reporter | `anonymous` |
| Tags | `dropper, jar, minecraft, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `90eac76c66312a53a00774a796c3038b` |
| SHA-1 | `18d2aec50aace75a08802583b9811f3e5320727a` |
| SHA-256 | `72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316` |
| SHA3-384 | `a5a4db1042ad8065141c27dc63e60e180da4a53444759879bafbb88dfffa7d838cc20317f7028e6fb52550ae3b11199d` |
| TLSH | `T15F8302379C4FCE1EE8174E79671864F7BB7F2893148A10767F939D4EC6325A02606136` |
| SSDEEP | `1536:wc7ZhnrtTSqboNZwofgy0vnE2zCnV+5GwWLshE/ndeQ0mwui1J:wOVtTnMzwofgyunfz8VSjAshEVeQ4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `jar`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_72d80252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316"
    family = "unknown"
    file_name = "PrestigeClient.jar"
    file_type = "jar"
    first_seen = "2026-06-24 21:04:36"
  condition:
    hash.sha256(0, filesize) == "72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316"
}
```

### Sample 34: `f5952b1650e8d5e9`

| Field | Value |
|---|---|
| SHA-256 | `f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92` |
| Family label | `unknown` |
| File name | `gRvidixkmlMIeXBedzwX.vbs` |
| File type | `vbs` |
| First seen | `2026-06-24 21:03:41` |
| Reporter | `BastianHein_` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a9a6d7d9f54d4fccc65d116d64480e1` |
| SHA-1 | `5a543acca58e1bc860f36aac7c83acbd97ffc711` |
| SHA-256 | `f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92` |
| SHA3-384 | `61dc946e197d661bdd19e45846594717299ce02f91544ec97d1d1250c9cb05d395662bfea4873c503ade8ef09e954ce9` |
| TLSH | `T110E0260999BDD8F0628AE11013D9DCCCA751AADFE13CF88D5A10CA840A299F847356CB` |
| SSDEEP | `6:ZXv3oNiPL+7yS2wOARk2keOoVeda6UqKogA0Ezq8NUqKoaXvU8ARATqtF:acPaxHOARknAqMH93wZmHHXs80ATuF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_f5952b16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92"
    family = "unknown"
    file_name = "gRvidixkmlMIeXBedzwX.vbs"
    file_type = "vbs"
    first_seen = "2026-06-24 21:03:41"
  condition:
    hash.sha256(0, filesize) == "f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92"
}
```

### Sample 35: `7c8ddbd9294e581b`

| Field | Value |
|---|---|
| SHA-256 | `7c8ddbd9294e581b2266ab50e6075e40ad2bd39f61d44fca52910e9b9634a46e` |
| Family label | `unknown` |
| File name | `ijevhpezl1vxjabh.dll` |
| File type | `exe` |
| First seen | `2026-06-24 21:03:35` |
| Reporter | `BastianHein_` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ffd22bda1d0f1e6d7a820967127237d` |
| SHA-1 | `7241584f44538bfdcaa3578adccb6da1ed72e75b` |
| SHA-256 | `7c8ddbd9294e581b2266ab50e6075e40ad2bd39f61d44fca52910e9b9634a46e` |
| SHA3-384 | `8aaafd3b75ffade0977d950d6dc9c2a41bad7bfae21db0bfd345db168d91a9c286a3ce097e04731c7b015e9e050cfc02` |
| IMPHASH | `6ce33c0cf2229cc5a025f5c023abbf7f` |
| TLSH | `T1E5D4D4067F549462D1665D38C9B6C7B8E3B1FC094751939B32E26E2BBEDB3C21D262C0` |
| SSDEEP | `6144:I++J8H7jQ9mKA/74bR7qdjQrd5KDX+ZS7ohQzItJMY4Lmo8uhL7LjICBE:I+C8H7qmf7C8djQrdmE8oizF7hLjFy` |
| ICON-DHASH | `9271e8d0f0c0c0c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_7c8ddbd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8ddbd9294e581b2266ab50e6075e40ad2bd39f61d44fca52910e9b9634a46e"
    family = "unknown"
    file_name = "ijevhpezl1vxjabh.dll"
    file_type = "exe"
    first_seen = "2026-06-24 21:03:35"
  condition:
    hash.sha256(0, filesize) == "7c8ddbd9294e581b2266ab50e6075e40ad2bd39f61d44fca52910e9b9634a46e"
}
```

### Sample 36: `b710e94d81dab660`

| Field | Value |
|---|---|
| SHA-256 | `b710e94d81dab6603ad14a45ee82926305bfb35f848d9108d4fc31eaf5161707` |
| Family label | `Formbook` |
| File name | `09786y7662026-DMS108997.bat` |
| File type | `exe` |
| First seen | `2026-06-24 20:57:30` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `280a26accb8a0b6ea46506785fe22391` |
| SHA-1 | `e8faecc955939d21d2ada0465bd42c8bb6df7946` |
| SHA-256 | `b710e94d81dab6603ad14a45ee82926305bfb35f848d9108d4fc31eaf5161707` |
| SHA3-384 | `6ff1d91439994c16528a028ecc872953b2e2559cc13860c2022285f338fb8cd6b9510e6feef6b466554126db9c21844a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T110350244339DEA01D5A84BB14871F3B813703EA9A921D3079EE9ADFFB572B056D58383` |
| SSDEEP | `24576:tP3hytuUb/lvVSt9ogoVLSe9VT5Nd8ml3YIRFg1uqtsMmKA+T+:muIleogOXT5f8ml3YIRW3tp5A` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_036_b710e94d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b710e94d81dab6603ad14a45ee82926305bfb35f848d9108d4fc31eaf5161707"
    family = "Formbook"
    file_name = "09786y7662026-DMS108997.bat"
    file_type = "exe"
    first_seen = "2026-06-24 20:57:30"
  condition:
    hash.sha256(0, filesize) == "b710e94d81dab6603ad14a45ee82926305bfb35f848d9108d4fc31eaf5161707"
}
```

### Sample 37: `07f1818fddf2e3fc`

| Field | Value |
|---|---|
| SHA-256 | `07f1818fddf2e3fcde507aab8cded1356890eeabe10ea4b2941cc10df7e6e626` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-24 20:51:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ceea35adfe67b4361eaba0cd2b9a1246` |
| SHA-1 | `09fe85f8a9daaf5ff97deb2965e9cf7a34662c14` |
| SHA-256 | `07f1818fddf2e3fcde507aab8cded1356890eeabe10ea4b2941cc10df7e6e626` |
| SHA3-384 | `7676f41645249a6573d17eeea9016518747d68bb7e3907e0edb379bd932bff57250ee0b544e4f495655b1d61edb2969e` |
| TLSH | `T174E34B07FB418A53C4D22779BAEF9249332397A5D3D7330689189FF83F8369A0E66505` |
| TELFHASH | `t1132112f6e934d52eadb20824dd5d4af15110e317632d0d31af38c5dc1e3a092a56ad7f` |
| SSDEEP | `3072:rEJBrYirGaXhW/5bn5SD/sa/ZYPBH37/bM/9D66nPQL:YJBrYEGaXE/dn5SD/z/cBH3rbM/9DNYL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_07f1818f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f1818fddf2e3fcde507aab8cded1356890eeabe10ea4b2941cc10df7e6e626"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-24 20:51:21"
  condition:
    hash.sha256(0, filesize) == "07f1818fddf2e3fcde507aab8cded1356890eeabe10ea4b2941cc10df7e6e626"
}
```

### Sample 38: `0e838c6a588d00c0`

| Field | Value |
|---|---|
| SHA-256 | `0e838c6a588d00c029ea5e469e55e121688df7a6e8af7b75e53504dc81631cb5` |
| Family label | `Mirai` |
| File name | `ml` |
| File type | `elf` |
| First seen | `2026-06-24 20:51:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db9af0b0980155373edbdc1e7d2af87e` |
| SHA-1 | `f2ae2427e5b20d785a96f50bfe7f8a313a5b3bb3` |
| SHA-256 | `0e838c6a588d00c029ea5e469e55e121688df7a6e8af7b75e53504dc81631cb5` |
| SHA3-384 | `ec1530d41e6974635026afdbefee2b4d833900ea4f5a4836e3f93f9d12ad35caf6291f9575442d6eb49ff9a3d5507380` |
| TLSH | `T18CB3E81ABF610EF7D86BCD3702A91B0534CC554B22A97B35B630C92CF54A24B59E3DB8` |
| SSDEEP | `1536:t4zLwBdoO+LueQe4uyrdZEOegOG+l2A97vj9m0BCImg:qzLwBGOl5d0MA9779my` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_0e838c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e838c6a588d00c029ea5e469e55e121688df7a6e8af7b75e53504dc81631cb5"
    family = "Mirai"
    file_name = "ml"
    file_type = "elf"
    first_seen = "2026-06-24 20:51:20"
  condition:
    hash.sha256(0, filesize) == "0e838c6a588d00c029ea5e469e55e121688df7a6e8af7b75e53504dc81631cb5"
}
```

### Sample 39: `2122acaa42afef0b`

| Field | Value |
|---|---|
| SHA-256 | `2122acaa42afef0b94d57ae665aad3e63bab5a28c07d03378feab8a4001312f4` |
| Family label | `Mirai` |
| File name | `data_arm4` |
| File type | `elf` |
| First seen | `2026-06-24 20:46:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8bae7f28442ff5af0fc1e06e1fe70d53` |
| SHA-1 | `922e0caed7c90afc75e2b409906c773bc9255203` |
| SHA-256 | `2122acaa42afef0b94d57ae665aad3e63bab5a28c07d03378feab8a4001312f4` |
| SHA3-384 | `323ded8ca77adcc04e7b2ca787eee5035e4cc4c0042bd16d414899e71ce0210092da7e5bd5334afe73d829f92d44d471` |
| TLSH | `T12DC30B52BD429F13C6C321F6FBAE42993B136778D7EA3102AD247F5127878DA0E36511` |
| TELFHASH | `t14f211214efd81b8d5fe4861482d9f02499ec319d2b65381a8b2f2b0b85962c5700ec1a` |
| SSDEEP | `1536:esUdW9C6Oh8ODJu6WvewdQbLPp5AuBfRY//OuwvmdZmuNvd3VyAPrFG8OYc9WarZ:IdKNS/uXKS/O7mTDxd3gWKNTxfI9Ik6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_2122acaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2122acaa42afef0b94d57ae665aad3e63bab5a28c07d03378feab8a4001312f4"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-06-24 20:46:33"
  condition:
    hash.sha256(0, filesize) == "2122acaa42afef0b94d57ae665aad3e63bab5a28c07d03378feab8a4001312f4"
}
```

### Sample 40: `38653b45cc1ad44b`

| Field | Value |
|---|---|
| SHA-256 | `38653b45cc1ad44b143751d4cf64d1924b4b22bef833b8c8e341b2ba4b5e1470` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-24 20:39:40` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6d2d0c5fee3c41f30b51b8331fe2b49` |
| SHA-1 | `57bf46e51aab794c56990db32ef3748c2effd507` |
| SHA-256 | `38653b45cc1ad44b143751d4cf64d1924b4b22bef833b8c8e341b2ba4b5e1470` |
| SHA3-384 | `af0b68bcc930f8375320d4dfe42047d02997f116866c9c32d1b7d160adc3d76df7038dc3171705ff502ccc0fbcfa47a6` |
| IMPHASH | `fb40ad72cb65f1767a2e06fa73fcbc83` |
| TLSH | `T1EDA62312B7C3D176DFA219F3D5BAAA36193DBC380B2888CBA380742DD5715C16B36716` |
| SSDEEP | `196608:p4EdgaXCU8UNWIR/l7BqK8I7V37tnTyMXpau9gxGtbzCSGoYTFK9AlGiJxVqfX95:p4EgantWIRtEK8IpLx+MRtbBNYTFuMGb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_38653b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38653b45cc1ad44b143751d4cf64d1924b4b22bef833b8c8e341b2ba4b5e1470"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 20:39:40"
  condition:
    hash.sha256(0, filesize) == "38653b45cc1ad44b143751d4cf64d1924b4b22bef833b8c8e341b2ba4b5e1470"
}
```

### Sample 41: `2ec5ae79d9e5f7a8`

| Field | Value |
|---|---|
| SHA-256 | `2ec5ae79d9e5f7a8a0026fb8f4e6a4fa059991884bbae53c91e5753ee139ac4a` |
| Family label | `unknown` |
| File name | `Canon.dll` |
| File type | `dll` |
| First seen | `2026-06-24 20:32:25` |
| Reporter | `smica83` |
| Tags | `dll, MustangPanda, PlugX` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41f9450bba235c37d40cd0315c1013cf` |
| SHA-1 | `9a1436ca008d59c518ea83aec40d9b655a840c81` |
| SHA-256 | `2ec5ae79d9e5f7a8a0026fb8f4e6a4fa059991884bbae53c91e5753ee139ac4a` |
| SHA3-384 | `612888535271b7efc52a797da62214029ca2dade97f8c61c8a47b74eead2ac717e36c954d84f6a21077697e2788d93f9` |
| IMPHASH | `85e7a31dd6c0ac31fb68b80e0eef7ea7` |
| TLSH | `T1BE44AFC1A592D4B7EAFE1474905CC53DC77D2E00ABB0CE7B2789DDA91923B11C26933A` |
| SSDEEP | `6144:E/S+yzOfgo/7YLkMYQwk5lIwJ5qPInKlp/1/2qinkJVJZHW:Ea+yzb5LkMKk5lVJg5R1s2lW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_2ec5ae79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec5ae79d9e5f7a8a0026fb8f4e6a4fa059991884bbae53c91e5753ee139ac4a"
    family = "unknown"
    file_name = "Canon.dll"
    file_type = "dll"
    first_seen = "2026-06-24 20:32:25"
  condition:
    hash.sha256(0, filesize) == "2ec5ae79d9e5f7a8a0026fb8f4e6a4fa059991884bbae53c91e5753ee139ac4a"
}
```

### Sample 42: `34feec85340a0252`

| Field | Value |
|---|---|
| SHA-256 | `34feec85340a025234d379a0095489f526181765b6bee67cbb4d3e07000f7086` |
| Family label | `Mirai` |
| File name | `data_aarch64` |
| File type | `elf` |
| First seen | `2026-06-24 20:29:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0363b7a63bae9c7f49fe8b741a12eff` |
| SHA-1 | `129bbbf4536e3d9d8e4c3b9a9fe2fbf146ab4efd` |
| SHA-256 | `34feec85340a025234d379a0095489f526181765b6bee67cbb4d3e07000f7086` |
| SHA3-384 | `36a5f220fc5b24d800e59c480eaf132f33883a28762ae6949a1343d9525c4df15da609603ee4b7ac307c523866d5744a` |
| TLSH | `T135E47E9DFE4E3C42E3C7E2789A4D87E1722B71E0D32391637982034CD5D69D98BB1A25` |
| SSDEEP | `12288:9/Nemn4Bm5I//nJMYmT+vyFHLj7FyxWpNsStrBms5d+E2gww5X4t7q:9Vem+3//nXWHLj7FyeZFcvH5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_34feec85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34feec85340a025234d379a0095489f526181765b6bee67cbb4d3e07000f7086"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-06-24 20:29:54"
  condition:
    hash.sha256(0, filesize) == "34feec85340a025234d379a0095489f526181765b6bee67cbb4d3e07000f7086"
}
```

### Sample 43: `d0310e982b671884`

| Field | Value |
|---|---|
| SHA-256 | `d0310e982b671884e67580d627b1ad9dbaeaf2f68fef0611526615604ed93449` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-06-24 20:26:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b17532532560628d67674ca968c38b47` |
| SHA-1 | `b0782a9d6eef2ce02f734a6e5e1d8e0f9a2b65be` |
| SHA-256 | `d0310e982b671884e67580d627b1ad9dbaeaf2f68fef0611526615604ed93449` |
| SHA3-384 | `30cd8e36a8a4528f31569b699d3eb7a1181b6496bdb001767a3093648d8bd111f0050f6daa47051f6a25b98fb1b2d82e` |
| TLSH | `T13063E75AF9819F02D4D620BAFF9F414933536FA8E3F97201D920AF6063869DB0F76512` |
| TELFHASH | `t162e0ab200904697ca7f2504970bcf600be15b0f538123497e7eb9d8883638e21022f3e` |
| SSDEEP | `1536:19nLXBSGc3K5I8naya/9rJfV+LiEOfhOLYUc+/:bXQGN5I8naya/9ryJOfhOLm+/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_d0310e98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0310e982b671884e67580d627b1ad9dbaeaf2f68fef0611526615604ed93449"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-24 20:26:01"
  condition:
    hash.sha256(0, filesize) == "d0310e982b671884e67580d627b1ad9dbaeaf2f68fef0611526615604ed93449"
}
```

### Sample 44: `4d970ab889778706`

| Field | Value |
|---|---|
| SHA-256 | `4d970ab8897787064a00c021896b429d2ee7d60cc1c3e3af34448c3692abb342` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-24 20:25:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `022ae64057a8d6817c056537a33eb90a` |
| SHA-1 | `76909747fdd79f8592e1a2d0b2db545937ba8d75` |
| SHA-256 | `4d970ab8897787064a00c021896b429d2ee7d60cc1c3e3af34448c3692abb342` |
| SHA3-384 | `f55065e15367235ad738f8234aa22e6015fb39650ed97414c625e2a4d9f3824ac844fdb951f8208f14817c3821296307` |
| TLSH | `T1D6735A0678E2CA56C6D673BABA1E818C331113F4C2DB3603CD15AF797BC695A0E7B584` |
| TELFHASH | `t1a641bdeacb790bec53e5954481cda43e5bedb05b1f151483960c6b1fc24a697f04d436` |
| SSDEEP | `1536:5eypyAPWGDtvUQ3sjJg+SbGyGVVouH0Mutple/iRetsIF/atJbI7:5eypyAPWIj3+g+SChouUHple6ZIY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_4d970ab8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d970ab8897787064a00c021896b429d2ee7d60cc1c3e3af34448c3692abb342"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-24 20:25:00"
  condition:
    hash.sha256(0, filesize) == "4d970ab8897787064a00c021896b429d2ee7d60cc1c3e3af34448c3692abb342"
}
```

### Sample 45: `d3f573839eb3a0ca`

| Field | Value |
|---|---|
| SHA-256 | `d3f573839eb3a0ca6c7f6a53085d1eb9b8cc258f63aa404946b4cf1c4e8db7cd` |
| Family label | `Mirai` |
| File name | `data_arm6` |
| File type | `elf` |
| First seen | `2026-06-24 20:22:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7a3f465f14e50d15e50b04dd16cb8f4` |
| SHA-1 | `6f689a1b1b9950a61a3d11a3993d2d0f213e5d05` |
| SHA-256 | `d3f573839eb3a0ca6c7f6a53085d1eb9b8cc258f63aa404946b4cf1c4e8db7cd` |
| SHA3-384 | `715a0a2661de47907dc08197c6cc42a40353b6018371f8b058844347a803409ec05c36b90e059918df5ab0227fa9e184` |
| TLSH | `T102C31A56B952DB12C1C321BAFB5E514D37136FB8E3ED32129D10AF60278B8DB0E7A512` |
| TELFHASH | `t1ee21fea9dba406ec6bea53dc8189b9280fe5709d370139576a6c736f44c2dd1303d813` |
| SSDEEP | `3072:OhRUd97soHwQdD6sYU7mKn+vlRaVDFYHZDZBEUYdwE6:Ow/7tHwQA1K+v3a92ZDZYdwE6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_d3f57383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f573839eb3a0ca6c7f6a53085d1eb9b8cc258f63aa404946b4cf1c4e8db7cd"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-06-24 20:22:55"
  condition:
    hash.sha256(0, filesize) == "d3f573839eb3a0ca6c7f6a53085d1eb9b8cc258f63aa404946b4cf1c4e8db7cd"
}
```

### Sample 46: `73c99c65a819726b`

| Field | Value |
|---|---|
| SHA-256 | `73c99c65a819726ba3e1d68ed2ec58b941a705c393c05934ff351575bbf74940` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-24 20:17:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a52c5bf8708c587b15ea35218e5c6bb` |
| SHA-1 | `d796fd38c246bb50812952d05d68cb60acfb2b8b` |
| SHA-256 | `73c99c65a819726ba3e1d68ed2ec58b941a705c393c05934ff351575bbf74940` |
| SHA3-384 | `41580f58fae4092d9bd3dfcbf0136cfc92e0df239c830d75a693a25ef91506ed36a89dca9ed71d4830e2ab061744a057` |
| TLSH | `T10C734A4678E2CA56C6D573BABA1E818C331213F4D2DB3603CD05AF797BC695A0E7B484` |
| SSDEEP | `1536:F94GpCAZX+Fg/H1VE6YcMM3H5JVAIVb3XhCPutZj5H+Ka+RdtsWFNd4D:X4GpCAZXrd66tMQZzlb3XkCZj5HJ6W94` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_73c99c65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73c99c65a819726ba3e1d68ed2ec58b941a705c393c05934ff351575bbf74940"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-24 20:17:53"
  condition:
    hash.sha256(0, filesize) == "73c99c65a819726ba3e1d68ed2ec58b941a705c393c05934ff351575bbf74940"
}
```

### Sample 47: `c8e59f57038524cd`

| Field | Value |
|---|---|
| SHA-256 | `c8e59f57038524cdd3f42fd80d4c721d0d2356e4f616079cd78ed90bb24edaa2` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-24 20:08:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b118526e29c49ad3c6de1502c045576` |
| SHA-1 | `cbc31e1c6d3f8c474e6eafbb0a0dca1e3fd29835` |
| SHA-256 | `c8e59f57038524cdd3f42fd80d4c721d0d2356e4f616079cd78ed90bb24edaa2` |
| SHA3-384 | `a9202c840d22e46c3d5b928e453c5e1b6b03d912c45e13b2ea6bcac29a5d153a21170a52f703acaf462c03a60b59dbe4` |
| TLSH | `T1D7A3D54E2E628F6EF76D82351BB35F35C654339B2ED4C641D17CE9056E2020EA81FB68` |
| TELFHASH | `t1e5118c18853813f4d7891ced6bedff76d0a140db4a259e338e40faa69a60a429e00c2c` |
| SSDEEP | `1536:7WIQIYviFU6gaVbUmaZkFE8gEKxIhb5mlznMxE7xsB8K3ZsEvEI4Yka98tdSEbTc:7WfBvii6tvhQsBdvEI4Yk5TSOgn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_c8e59f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8e59f57038524cdd3f42fd80d4c721d0d2356e4f616079cd78ed90bb24edaa2"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-24 20:08:54"
  condition:
    hash.sha256(0, filesize) == "c8e59f57038524cdd3f42fd80d4c721d0d2356e4f616079cd78ed90bb24edaa2"
}
```

### Sample 48: `042fe062e97f7a32`

| Field | Value |
|---|---|
| SHA-256 | `042fe062e97f7a321a0e88046dd1ada8a7cb41b449e2cad27db8ad8be50ce9f4` |
| Family label | `Mirai` |
| File name | `data_arm7` |
| File type | `elf` |
| First seen | `2026-06-24 19:59:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c72135657e0355918cc2d3144204c0ce` |
| SHA-1 | `73dadd2bf06ed596bee8696926399c0712067949` |
| SHA-256 | `042fe062e97f7a321a0e88046dd1ada8a7cb41b449e2cad27db8ad8be50ce9f4` |
| SHA3-384 | `35b867bc9739bc64a3d84f9daceff0b3f67f0b3b22af4bef5e2664aec2c7d8db8d7bb3ba07a90129f2b91c89cfdc90d9` |
| TLSH | `T1D4E3185AB9519F12D5C321FAFB9F814933136FB8E3F93102DD206F60278A99B0E76512` |
| TELFHASH | `t1e921c125dbad1a6c7bd48345425a4226a6b830fc2f0001f69e6c8f5e4b125c3b42b926` |
| SSDEEP | `3072:KdqfO+OGhF+094Vnrykp7IPzauLhZ6tQC+KCUlEWU+oxFoAC2:KmjthF+0MOkKPzauLhZ6tQ1KCDW1+oAh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_042fe062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "042fe062e97f7a321a0e88046dd1ada8a7cb41b449e2cad27db8ad8be50ce9f4"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-06-24 19:59:52"
  condition:
    hash.sha256(0, filesize) == "042fe062e97f7a321a0e88046dd1ada8a7cb41b449e2cad27db8ad8be50ce9f4"
}
```

### Sample 49: `b66cde24a585798b`

| Field | Value |
|---|---|
| SHA-256 | `b66cde24a585798b61132a8fce61bbd704169264b9bf497cacd5ed4f0804453d` |
| Family label | `Mirai` |
| File name | `data_x86_64` |
| File type | `elf` |
| First seen | `2026-06-24 19:58:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40e5e5e048690ec87d6e4ea408ee863b` |
| SHA-1 | `423d4960092711ee3bd76147cbdf0ac633181773` |
| SHA-256 | `b66cde24a585798b61132a8fce61bbd704169264b9bf497cacd5ed4f0804453d` |
| SHA3-384 | `0da591654972c25638a647c3d86f33ff6809c8e6f66189546105b94c6bff4010e7db0cfbc72b1cee66afb0947e2311ea` |
| TLSH | `T11F844A52F2A228FDD952C930825D6123E638744943129EFB27C8EB753A16ED06F3EB51` |
| TELFHASH | `t1b6a136b1418a64f9d162e9a58fb2b73696f207e593546931823dfd70ec43fe86e21c03` |
| SSDEEP | `6144:KiVEL9iGruSOwl60jkALIsYTFyJ10hspXuzKONq8LOUiqzO4JWktw5Q:KInG2v9AksC8JCYurBLOUNK4e5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_b66cde24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66cde24a585798b61132a8fce61bbd704169264b9bf497cacd5ed4f0804453d"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-06-24 19:58:54"
  condition:
    hash.sha256(0, filesize) == "b66cde24a585798b61132a8fce61bbd704169264b9bf497cacd5ed4f0804453d"
}
```

### Sample 50: `04614935b46d278a`

| Field | Value |
|---|---|
| SHA-256 | `04614935b46d278acf30fbd275dfa2b55e19a1a96ece17be852325305469343e` |
| Family label | `unknown` |
| File name | `bbc` |
| File type | `sh` |
| First seen | `2026-06-24 19:51:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `133a5a93b5a00a4add88fd344ec023d4` |
| SHA-1 | `056231d3a34b95d81fdf45953bed23dfa2455344` |
| SHA-256 | `04614935b46d278acf30fbd275dfa2b55e19a1a96ece17be852325305469343e` |
| SHA3-384 | `d766818f323bd41a4198057c736d1446a2632ec09ab32422ba7b794f39115cc37a8d8e974c9fc2ae5d7b78d3d47f90e4` |
| TLSH | `T14EF0C247A497F036808038E4E76AF659FC21B8876262DE4CB940BF55DEE65347421184` |
| SSDEEP | `12:Sy41c0PZ9tSjhh1OL9ephRjk4Y4bou7Co1VOq2xddNizdI/HXHQ:SyqPHtk1gYpTr8i3fOq2bf8IfQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_04614935
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04614935b46d278acf30fbd275dfa2b55e19a1a96ece17be852325305469343e"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-06-24 19:51:52"
  condition:
    hash.sha256(0, filesize) == "04614935b46d278acf30fbd275dfa2b55e19a1a96ece17be852325305469343e"
}
```

### Sample 51: `1737369bee038e31`

| Field | Value |
|---|---|
| SHA-256 | `1737369bee038e31b39e2cb66b9dd18ecbec92a7be1324adc16060682141f2fd` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-24 19:51:20` |
| Reporter | `Bitsight` |
| Tags | `D, dropped-by-GCleaner, EU0.file, exe, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00b984f712d36a8761adeb4ac5cc7d48` |
| SHA-1 | `09d2c4bd431a4e5c9087b1926123b9ad03911d73` |
| SHA-256 | `1737369bee038e31b39e2cb66b9dd18ecbec92a7be1324adc16060682141f2fd` |
| SHA3-384 | `4f8e2770f2a0ef22efafe7614f60c0ee4680b0b0911f3eb3e79e0d68e95d7dfe727cd8d58894db893b7aeeb8921cf5b2` |
| IMPHASH | `4cea7ae85c87ddc7295d39ff9cda31d1` |
| TLSH | `T1D885231033FA90A0F0B54B799CF3415B2A717EA31A35A1DF239866AE1F335C1E936761` |
| SSDEEP | `49152:lHtF7b5usfJVCCEmPoYCa5rlRaj6q40I07E3tt+TeJH:179uCVfEKp/ajp7ittr` |
| ICON-DHASH | `2216b1896c25ac44` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_051_1737369b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1737369bee038e31b39e2cb66b9dd18ecbec92a7be1324adc16060682141f2fd"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 19:51:20"
  condition:
    hash.sha256(0, filesize) == "1737369bee038e31b39e2cb66b9dd18ecbec92a7be1324adc16060682141f2fd"
}
```

### Sample 52: `c5dc6d8f325c125f`

| Field | Value |
|---|---|
| SHA-256 | `c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45` |
| Family label | `unknown` |
| File name | `???_??????+.apk` |
| File type | `apk` |
| First seen | `2026-06-24 19:50:46` |
| Reporter | `jitesh` |
| Tags | `Android, apk, Dropper, Malware, Riskware, signed, TikTok, Trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84184f95b7743e1c9c534587e7fde316` |
| SHA-1 | `c805757eb686b7755a839715d413a55827881fb1` |
| SHA-256 | `c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45` |
| SHA3-384 | `c3b9315cafbc49524b4f0873df72de225439b3d4b819abdf709460369cf67be508d1de5e50d88d774d389e388f267b38` |
| TLSH | `T1A7562380FF46D92FC47B44370E524731229AEE2E8696A34384EC3A1D6C776E44ED9ED4` |
| SSDEEP | `98304:f/LDuZ6OAyu8AMJm5eDxgZz7ITd61FT2cLW9Iby+4Sb8igkM0cmOF2:3LDuZ3AyuLuRgZzETd61FTDoI++4SbgK` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_c5dc6d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
    family = "unknown"
    file_name = "???_??????+.apk"
    file_type = "apk"
    first_seen = "2026-06-24 19:50:46"
  condition:
    hash.sha256(0, filesize) == "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
}
```

### Sample 53: `68bd19635359188e`

| Field | Value |
|---|---|
| SHA-256 | `68bd19635359188ea8ab42541ba0e573b34a1819fde6115e8dced39c4ebd97b9` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-06-24 19:49:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `913a3fabec8a0fc69cb9d705d0d4f521` |
| SHA-1 | `5bcc7b477409a390125791ac9fffe9a71c4c0422` |
| SHA-256 | `68bd19635359188ea8ab42541ba0e573b34a1819fde6115e8dced39c4ebd97b9` |
| SHA3-384 | `bd2467f83393d0a57bf8bf8dda8d38764618db689e5ef35e3713cd40d889df08ef4f337b4dbea87c1bd9f46eb178d50f` |
| TLSH | `T18DB34A5BAA9D3EDBC2C2873E9E966A701117F47D8F0383721F11528DAE9FA8DDD90044` |
| TELFHASH | `t1142112f5ed75d12dae920970dc5d49b09110e317632e0e31ef38c1dc5e3a091a11adaf` |
| SSDEEP | `1536:SCB06qowuZnUAl3yQxQPFNSNSCJyEQ/o/r5w82jtbmpDWWO07KSw9VF2uL:hm6qh9Ny8YT5mj5zFj9VFh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_68bd1963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68bd19635359188ea8ab42541ba0e573b34a1819fde6115e8dced39c4ebd97b9"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-24 19:49:52"
  condition:
    hash.sha256(0, filesize) == "68bd19635359188ea8ab42541ba0e573b34a1819fde6115e8dced39c4ebd97b9"
}
```

### Sample 54: `ef5d4d0fbfd73d3e`

| Field | Value |
|---|---|
| SHA-256 | `ef5d4d0fbfd73d3e50607ac5f62287ec6f9045ce6fb5940afeab6bb2601b0cb6` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-06-24 19:49:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fdc9d4bfd26b38399d5f96867ec96ef` |
| SHA-1 | `b6aa8c03a62288c1f80a992f5b5eb06297a299ff` |
| SHA-256 | `ef5d4d0fbfd73d3e50607ac5f62287ec6f9045ce6fb5940afeab6bb2601b0cb6` |
| SHA3-384 | `b6a41335f170fe646e180904f42667e83af97934c4babe4ccd5b04304457a274ba3ac24e614028b3cd0979404a7b69f0` |
| TLSH | `T1AE43E880F98BCBF1E41B09B081AAB23EDA30E92D0865C5BEDFA5FFE5D9635C56111305` |
| TELFHASH | `t1db11e7fa3dbe19f8b3d49d4c820e6e022b39e17b256433a446f2e05231e3e625175c79` |
| SSDEEP | `1536:qdlVBi9XF0+oTYuvObBVlvm2QRk3N0S8UtKomN8m:qm91Jo8uv25lQG3N0rUtKome` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_ef5d4d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef5d4d0fbfd73d3e50607ac5f62287ec6f9045ce6fb5940afeab6bb2601b0cb6"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-06-24 19:49:50"
  condition:
    hash.sha256(0, filesize) == "ef5d4d0fbfd73d3e50607ac5f62287ec6f9045ce6fb5940afeab6bb2601b0cb6"
}
```

### Sample 55: `94fdbdfea6c70f8d`

| Field | Value |
|---|---|
| SHA-256 | `94fdbdfea6c70f8d83acf32f495584ff7a25c9270bfb36fe045eb43efb7ac04d` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-06-24 19:48:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15039b463cc4e696fbc73824cc538313` |
| SHA-1 | `3a6f7badd9e344e0070987a5316849abe1b2d0a2` |
| SHA-256 | `94fdbdfea6c70f8d83acf32f495584ff7a25c9270bfb36fe045eb43efb7ac04d` |
| SHA3-384 | `7c3ac44d1b49457813993e0a94f94cdc229b1859a4987129dc8a7802f9581477bbfdd621924ecba052e77c27a387bebe` |
| TLSH | `T1A9735C8761119DADFC0FB5768A174A01F539E7508F630F3393A2FC6398520E65A7BE41` |
| SSDEEP | `1536:9Uw+yqzisONOWB448GWcaTdPvC3JztwU0GYS8OUJc+bE6sMr8umXCeKBFLGuvp9O:9UFyqzisOwWB44LWcaTdPvC3JztwU0GR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_94fdbdfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94fdbdfea6c70f8d83acf32f495584ff7a25c9270bfb36fe045eb43efb7ac04d"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-24 19:48:52"
  condition:
    hash.sha256(0, filesize) == "94fdbdfea6c70f8d83acf32f495584ff7a25c9270bfb36fe045eb43efb7ac04d"
}
```

### Sample 56: `4778d350b0175cac`

| Field | Value |
|---|---|
| SHA-256 | `4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8` |
| Family label | `unknown` |
| File name | `4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8` |
| File type | `exe` |
| First seen | `2026-06-24 19:43:55` |
| Reporter | `johnk3r` |
| Tags | `banker, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbf0f03147fd6077aeb202b68a5dc948` |
| SHA-1 | `9b9bf391a24eee06b2268cc626ea0a71f0e39c02` |
| SHA-256 | `4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8` |
| SHA3-384 | `b630f53c5be26778f631fc43f861e5b6d21ccccf3f0ec6676d772223793b492555da575e6c7153921c083deb1e5d51e8` |
| IMPHASH | `278c5b3315d1bc544295d3240b704222` |
| TLSH | `T1C1266C137348A03FE06B1A3A5C77D710593FB66029138E5FA7F48A5C8E763806E2E657` |
| SSDEEP | `49152:HqJ8E8oLLASg5WbvKqegAitdBwQ+RyE/H5mKMQUzuoDFB:Hq63CSgAitdBwQ+RyhKMQSB` |
| ICON-DHASH | `f0f4a20d8e9eb6f8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_4778d350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8"
    family = "unknown"
    file_name = "4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8"
    file_type = "exe"
    first_seen = "2026-06-24 19:43:55"
  condition:
    hash.sha256(0, filesize) == "4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8"
}
```

### Sample 57: `1ca3b901935fead6`

| Field | Value |
|---|---|
| SHA-256 | `1ca3b901935fead67478eae99eaf7061c871fc0fcea3403086a0c5cc154c1f3f` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-06-24 19:43:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2896e7e266794b33d83c1ca454bedd83` |
| SHA-1 | `c4af1b575649dd4c20b17d406a3f05d1114817f0` |
| SHA-256 | `1ca3b901935fead67478eae99eaf7061c871fc0fcea3403086a0c5cc154c1f3f` |
| SHA3-384 | `1acb630ad3ce29ec3e117ba941603908dd05ca9c36571baa679d5a00465b96ec8c61725414651ea6fef129de853b4cf8` |
| TLSH | `T1B1A3C4097F710EF7D8ABCD3755F84702219C9A0622A97BB67C74D518FB4B54B0AE3828` |
| SSDEEP | `1536:XEM/I9v9OFg5DSQpd02/6J5I6lbpmFoH+pzxog64NnZAF5x1d:XxItUqWQT02YbpmOfgRn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_1ca3b901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ca3b901935fead67478eae99eaf7061c871fc0fcea3403086a0c5cc154c1f3f"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-24 19:43:54"
  condition:
    hash.sha256(0, filesize) == "1ca3b901935fead67478eae99eaf7061c871fc0fcea3403086a0c5cc154c1f3f"
}
```

### Sample 58: `34d2e47fa8f6b64e`

| Field | Value |
|---|---|
| SHA-256 | `34d2e47fa8f6b64e346623b4ed66898b86d53891900b953e69f02e2b3ffb2cc9` |
| Family label | `unknown` |
| File name | `dropper_34d2e47f.sh` |
| File type | `sh` |
| First seen | `2026-06-24 19:34:03` |
| Reporter | `nullblue67` |
| Tags | `bash, botnet, ddos, dropper, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `122b1825c4c0ceb3537a0986300c1019` |
| SHA-1 | `62787eb954262bd7cd8ae01df8c95de54eb51671` |
| SHA-256 | `34d2e47fa8f6b64e346623b4ed66898b86d53891900b953e69f02e2b3ffb2cc9` |
| SHA3-384 | `5a0eec3b7b98f3ae827212b8a43d12dd1d66358dd2b88afa2cd60e805c69f3b22211ad8582ba15526cdeeb856899a353` |
| TLSH | `T17B415EF1E8B49833B86FCA18F11CD0A45EF76E3F156B3588B472996D6D1E408271D722` |
| SSDEEP | `24:jx/1aMvM5MCYhuIhLxMlvheNbt0f/NQ6SCLIeB:jx/1aMvM5MCKuIhLxMl5Obt0f/NQ6lk+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_34d2e47f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d2e47fa8f6b64e346623b4ed66898b86d53891900b953e69f02e2b3ffb2cc9"
    family = "unknown"
    file_name = "dropper_34d2e47f.sh"
    file_type = "sh"
    first_seen = "2026-06-24 19:34:03"
  condition:
    hash.sha256(0, filesize) == "34d2e47fa8f6b64e346623b4ed66898b86d53891900b953e69f02e2b3ffb2cc9"
}
```

### Sample 59: `404df61aa1d3bfcf`

| Field | Value |
|---|---|
| SHA-256 | `404df61aa1d3bfcfc14288b9cc0131642cbafb31256f28c5fd7e5ef51bbe2d69` |
| Family label | `Mirai` |
| File name | `bot_404df61a.elf` |
| File type | `elf` |
| First seen | `2026-06-24 19:34:00` |
| Reporter | `nullblue67` |
| Tags | `DDoSAgent, elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2314aeaed29c72a1fed332f0099987dc` |
| SHA-1 | `1f1e0bc92fb6569dafd1507d5123e0332632beeb` |
| SHA-256 | `404df61aa1d3bfcfc14288b9cc0131642cbafb31256f28c5fd7e5ef51bbe2d69` |
| SHA3-384 | `cd54eb42d36f54e147e1d313dec0d634712e4d1da82f8a6fda0f0c63c8ac24b442bb7c98105150a4dce63c901c74efae` |
| TLSH | `T1EC762852F98B08F6E9031D3215BFA26F27311D064B24DBC7EA407F2AF97B5D52936209` |
| TELFHASH | `t1afe2cfb3059ca4fc67e04507966f7520dfe6e0a726d038f119f3b8c19a72d93a726878` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:TqzbMh9JqocHABOCLzUc7P2thQYVSnt7E1IDNp2XeyTjKPZO4YA+9d2o5tWBptqw:TIMzjeo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_404df61a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404df61aa1d3bfcfc14288b9cc0131642cbafb31256f28c5fd7e5ef51bbe2d69"
    family = "Mirai"
    file_name = "bot_404df61a.elf"
    file_type = "elf"
    first_seen = "2026-06-24 19:34:00"
  condition:
    hash.sha256(0, filesize) == "404df61aa1d3bfcfc14288b9cc0131642cbafb31256f28c5fd7e5ef51bbe2d69"
}
```

### Sample 60: `533ab567dfbbdae5`

| Field | Value |
|---|---|
| SHA-256 | `533ab567dfbbdae5fde5bf1443f2291a169da6de448d08bbf950ead27ccf0582` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-06-24 19:33:52` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b58e52acef8ca9cbf30e997b9449b5cd` |
| SHA-1 | `fdd819056ccac60bd44d8e084acdd4883a9a964f` |
| SHA-256 | `533ab567dfbbdae5fde5bf1443f2291a169da6de448d08bbf950ead27ccf0582` |
| SHA3-384 | `e5d1505c1cd4149ddf72531dbdb5e52adf538d680550e4373b7396756d81e1f46aca569c1cad7aabc31a1af757948fc8` |
| TLSH | `T146137D6966857C24AE99883B1C7E2F0CB9A983E1310451EDBFCB3CF58C49B9CD21971D` |
| SSDEEP | `768:z+A9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:z+9co` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_533ab567
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "533ab567dfbbdae5fde5bf1443f2291a169da6de448d08bbf950ead27ccf0582"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-24 19:33:52"
  condition:
    hash.sha256(0, filesize) == "533ab567dfbbdae5fde5bf1443f2291a169da6de448d08bbf950ead27ccf0582"
}
```

### Sample 61: `ffb744e91515a6bd`

| Field | Value |
|---|---|
| SHA-256 | `ffb744e91515a6bdb0bf0588065455efd591250c882026b6c16f6afca11ca98f` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-06-24 19:28:53` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `beeeafede3af16339a59ac5b062ce9e7` |
| SHA-1 | `32d96d18640d935edf82df346f871c1beaea2e99` |
| SHA-256 | `ffb744e91515a6bdb0bf0588065455efd591250c882026b6c16f6afca11ca98f` |
| SHA3-384 | `02b1335f7b4f365ea8bd397d47ac855225d17cd940b7eb68fc9f73b6b426af6e921ade818f3caced848b23f13986d047` |
| TLSH | `T1B373F854F94784F9D80359B098A7F33FA770D9485235A61FEF89AF29DA33B06521238C` |
| TELFHASH | `t1482103f50f3a48a8b7c08844920d46225f7e63732d5436a309b3592076ddd8350bbc3d` |
| SSDEEP | `1536:SBRyLmS6qPcISxxE3U/qZPNXwS7hXdh0hn4htpXb9VjZFMx1Sz:Sjvq6xxglXwS5Ocb9RZ81` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_ffb744e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb744e91515a6bdb0bf0588065455efd591250c882026b6c16f6afca11ca98f"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-06-24 19:28:53"
  condition:
    hash.sha256(0, filesize) == "ffb744e91515a6bdb0bf0588065455efd591250c882026b6c16f6afca11ca98f"
}
```

### Sample 62: `e4697c702263e186`

| Field | Value |
|---|---|
| SHA-256 | `e4697c702263e186097be61c198ffc5a148631b1d3db08f2b515c1b742f8e919` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-06-24 19:20:59` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `242773a1c75fa4419f84994f4098579c` |
| SHA-1 | `f17f10b4c801a43a2258b53f96128291bb262431` |
| SHA-256 | `e4697c702263e186097be61c198ffc5a148631b1d3db08f2b515c1b742f8e919` |
| SHA3-384 | `7292fc25bb372f3a3e1e1709a3cc49aa434a17201f96a851c010150be4b956f201030c95f0bdd1d4ee28bd80a7f0cb13` |
| TLSH | `T19EB31A037D52CA53D1D227B97AAF95583322A7B4C3DB33029914AFF42F836DA0E7A511` |
| TELFHASH | `t1d42120f6e934d52eadb20820dc5d4ab14110e327632d0d31af38c1dc1e3a082a52ad6f` |
| SSDEEP | `1536:wsnJCdt1kOUl+h+7Mfz9culm+kQwMGiuLBFLbugiqw/K/X64zbJfNQsp:ZCdt1Bh3fz2ZLLBFLbpiqw/8lio` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_e4697c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4697c702263e186097be61c198ffc5a148631b1d3db08f2b515c1b742f8e919"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-24 19:20:59"
  condition:
    hash.sha256(0, filesize) == "e4697c702263e186097be61c198ffc5a148631b1d3db08f2b515c1b742f8e919"
}
```

### Sample 63: `5913021291f2e439`

| Field | Value |
|---|---|
| SHA-256 | `5913021291f2e43955ccf5a4dd9b0daf462fc378b60dbc02b26271bf700939a8` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-06-24 18:49:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1b40bdc199977d96c9cc0013a32e53c` |
| SHA-1 | `508b8e22ac56f9135d66db4fbb09d7c9b3e245ad` |
| SHA-256 | `5913021291f2e43955ccf5a4dd9b0daf462fc378b60dbc02b26271bf700939a8` |
| SHA3-384 | `0fdf80c191f414ead34790e080bd154580ecda30a00086f991c89bbd1adf5ef9025df8e364a7f9e3623258bf437ebeb5` |
| TLSH | `T12F733903758180FCD488C1740A3FA536E5A2B57E23356E5937E8FF267B4BA242E2D664` |
| TELFHASH | `t18f21d6743c9618e065dbbb71f342d1f158321e2611f131e2ca3b99f2de66bc50da4427` |
| SSDEEP | `1536:iyp2vv2HD9eunps9Uvv6PSPb6ad0GkIbHJ:iAheKXvOSmaiIbH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_59130212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5913021291f2e43955ccf5a4dd9b0daf462fc378b60dbc02b26271bf700939a8"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-24 18:49:56"
  condition:
    hash.sha256(0, filesize) == "5913021291f2e43955ccf5a4dd9b0daf462fc378b60dbc02b26271bf700939a8"
}
```

### Sample 64: `a485a98f07b6c335`

| Field | Value |
|---|---|
| SHA-256 | `a485a98f07b6c3357436071164908a99f6a2e13d86d39e53ae9897e7e21ecf4f` |
| Family label | `unknown` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-06-24 18:47:03` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b216cde3baafff1c591ac4366e58eaa0` |
| SHA-1 | `842e926773a607ee7de28313833fe4d98290cf4c` |
| SHA-256 | `a485a98f07b6c3357436071164908a99f6a2e13d86d39e53ae9897e7e21ecf4f` |
| SHA3-384 | `c1ba52f9432341667e128bc5c1bbc514b4f735b60753685d85398b743d866586db244e288b592ae5f7e7ca9323b6603e` |
| TLSH | `T1C1D38A5E6E328FAEF66CC73447B74A21975823D526E0D684E2ACC1141F2039E545FBF8` |
| TELFHASH | `t1ea31761c0a7823f467355c8d15adff7792b731db6a121d378e01a85aa76d8c25e10c1c` |
| SSDEEP | `1536:yFHNkl+qoOloOEtOZ4SSX2/otFsrhyWIOrveJoVS+OIzqjTQylef8RVqP5Nj:yFHNSFUFEhyWIOrO6SlhUf8CNj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_a485a98f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a485a98f07b6c3357436071164908a99f6a2e13d86d39e53ae9897e7e21ecf4f"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-24 18:47:03"
  condition:
    hash.sha256(0, filesize) == "a485a98f07b6c3357436071164908a99f6a2e13d86d39e53ae9897e7e21ecf4f"
}
```

### Sample 65: `d6189cdbc46765f1`

| Field | Value |
|---|---|
| SHA-256 | `d6189cdbc46765f124c982b97f99f7251afd1ed03d67829a76b003f31b2a88a0` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-06-24 18:45:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a8efe3e957ec7a5503a4c1527e2a16c0` |
| SHA-1 | `064464b4a5fffe73939d093c405e05e4bcba8043` |
| SHA-256 | `d6189cdbc46765f124c982b97f99f7251afd1ed03d67829a76b003f31b2a88a0` |
| SHA3-384 | `bdac6b83937c5c4dcf67e0d07274ab7ec50ac469b3781c4ffc310a44c27a0f84d87377497e731dfbf33e64983a4f2139` |
| TLSH | `T183F37C87B7165CA3CC510BF94B875B8C6BA351418F6BC7D73D0DA6380E6A9CE9D0A381` |
| TELFHASH | `t1433111a6e935c52d7ea21824ec5d4fb18111d72763291e31af3cc1dc5e3f082a469d6f` |
| SSDEEP | `3072:dZE96WmJQawxvikXlDkPoegg+qHr7vmm2cK:w96WdvFXlm8qXmm2cK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_d6189cdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6189cdbc46765f124c982b97f99f7251afd1ed03d67829a76b003f31b2a88a0"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-06-24 18:45:58"
  condition:
    hash.sha256(0, filesize) == "d6189cdbc46765f124c982b97f99f7251afd1ed03d67829a76b003f31b2a88a0"
}
```

### Sample 66: `f9557670dd45bda4`

| Field | Value |
|---|---|
| SHA-256 | `f9557670dd45bda485da28f6683f31cce7bc38bf7495389089ee39a8bf3142ed` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-06-24 18:45:29` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4f3bd3ab584605e8bdd0d24d06c80ad` |
| SHA-1 | `98b80688e7a2e3242504febb05d5c41a0e8bf86a` |
| SHA-256 | `f9557670dd45bda485da28f6683f31cce7bc38bf7495389089ee39a8bf3142ed` |
| SHA3-384 | `7e910f0400eb0d753f67fc0cad29cd9ba3c4eaed56cec0cc82d84bb791dba2fad143e509e7a2dacb53f7f29679df56fa` |
| IMPHASH | `4d0fb8dc9ee470058274f448bebbb85f` |
| TLSH | `T12EB78D0773E601A6E5B3A1398A9B4103E772B4575731CBDB325C43142FABFE09A7A760` |
| SSDEEP | `393216:f1Du8BtuBw2FEL3Z3aLUoQvo6LP/SgbSpYvKEh1EdKwlGQKPJuGsiTfREsrgCYfR:fMguj8Q4VfviqFTrYp` |
| ICON-DHASH | `f89efcf8f971f2e0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_066_f9557670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9557670dd45bda485da28f6683f31cce7bc38bf7495389089ee39a8bf3142ed"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 18:45:29"
  condition:
    hash.sha256(0, filesize) == "f9557670dd45bda485da28f6683f31cce7bc38bf7495389089ee39a8bf3142ed"
}
```

### Sample 67: `044f25e5c9eb2875`

| Field | Value |
|---|---|
| SHA-256 | `044f25e5c9eb287519556b0e7a67cdb4e94965dc0d39acd33d5fdcf2d428b612` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-06-24 18:34:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1e3138d66fa2672ec67412091c2b291` |
| SHA-1 | `fcf68a2ac42e1508af5397a35093848383b423f3` |
| SHA-256 | `044f25e5c9eb287519556b0e7a67cdb4e94965dc0d39acd33d5fdcf2d428b612` |
| SHA3-384 | `38774e847e46b6f6455ceb6dffcc9aa3b387727db8a64293212bfb397ac29d2b7e040c3fe308b260509eae06dc8a5819` |
| TLSH | `T15E737D0173180E53C5276A70683F2BC1C355EAA521B9DB456A0F7B4FC9B2D72C58AEEC` |
| SSDEEP | `1536:l4un2nU/BV/J0JCs5Y9uH0e2J3fNdZKE0khMNo5uf6+qQ4/hIUK1cI:B9jKkma9X/hIF1v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_044f25e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044f25e5c9eb287519556b0e7a67cdb4e94965dc0d39acd33d5fdcf2d428b612"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-24 18:34:57"
  condition:
    hash.sha256(0, filesize) == "044f25e5c9eb287519556b0e7a67cdb4e94965dc0d39acd33d5fdcf2d428b612"
}
```

### Sample 68: `ad21baf3b79af368`

| Field | Value |
|---|---|
| SHA-256 | `ad21baf3b79af3680215d48448c86f38b95ba04b49f0dfa837f9dca39f8023d0` |
| Family label | `Mirai` |
| File name | `data_mipsel` |
| File type | `elf` |
| First seen | `2026-06-24 18:27:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c65f940ab2d977d6d86ea719c6a1fd7f` |
| SHA-1 | `94103aaebb499ada8f1b5d4e25265f8e1ed2b5f1` |
| SHA-256 | `ad21baf3b79af3680215d48448c86f38b95ba04b49f0dfa837f9dca39f8023d0` |
| SHA3-384 | `a9f82d1ec5ce9265ac7c62a197f88577134a843a54e431db13c93c9285312f466c5aa50f4c2dbdf52c44f8097d437ad0` |
| TLSH | `T1E0F3E70AAF610FF7E8ABDD7702E90B1129CCA91B25B53F797534E814B50A18B49E3C74` |
| SSDEEP | `1536:wrsl7+ms+CsvE9PtXp/d7V5239RKswhB10T9TmkQ0bKI81XzAIdUgaNpbiLZYoCM:17kuEV3ADOBvjrUZbiLYE6DxrrC1ET` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_ad21baf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad21baf3b79af3680215d48448c86f38b95ba04b49f0dfa837f9dca39f8023d0"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-06-24 18:27:56"
  condition:
    hash.sha256(0, filesize) == "ad21baf3b79af3680215d48448c86f38b95ba04b49f0dfa837f9dca39f8023d0"
}
```

### Sample 69: `f7cdecce2caa3c5c`

| Field | Value |
|---|---|
| SHA-256 | `f7cdecce2caa3c5cc733c6738b59f9515f618e70ab339f87304833e62eb2bc6c` |
| Family label | `Mirai` |
| File name | `data_mipsel-uclibc` |
| File type | `elf` |
| First seen | `2026-06-24 18:26:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9068444dd6167faa7dfc6155c2799d0f` |
| SHA-1 | `73adbfa2c2b975910c975181435d97485b4a8ec9` |
| SHA-256 | `f7cdecce2caa3c5cc733c6738b59f9515f618e70ab339f87304833e62eb2bc6c` |
| SHA3-384 | `99e3a980fa8445a79dfd89a4e8f13d4c3f84496ab52ffe5f055960f3c4836b390dde9ea0e67b74740e9f0129bd48b573` |
| TLSH | `T164145B47EE890EDFC45BCEB086AF436B19E755AB48D1F1F5443C8C0D385D29A46E3A88` |
| SSDEEP | `6144:2snvMdv+htzOxW+GFF/QBwYrZbgmMfaLqLW9:LkglIW+GF9nhCLyW9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_f7cdecce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7cdecce2caa3c5cc733c6738b59f9515f618e70ab339f87304833e62eb2bc6c"
    family = "Mirai"
    file_name = "data_mipsel-uclibc"
    file_type = "elf"
    first_seen = "2026-06-24 18:26:02"
  condition:
    hash.sha256(0, filesize) == "f7cdecce2caa3c5cc733c6738b59f9515f618e70ab339f87304833e62eb2bc6c"
}
```

### Sample 70: `dce3c037e491b823`

| Field | Value |
|---|---|
| SHA-256 | `dce3c037e491b823b2a62546116bad572cc64a03441d47f19104dfe541c1e820` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-06-24 18:23:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdbd1fb62742a3c73d83735cb02cde6f` |
| SHA-1 | `1e0b2ef96707aaf9560cda2d148648da28bd434c` |
| SHA-256 | `dce3c037e491b823b2a62546116bad572cc64a03441d47f19104dfe541c1e820` |
| SHA3-384 | `9e54fd9719ed30df2f78442299fe220d9fbd6efe3e56f4211435d90ac45e051ed949613b0f8f35add97c9385c8dcf194` |
| TLSH | `T1E0836C377D785927C4C4A67E22E74330B5F7174525B8CA2EBC324EADBB006A02267776` |
| SSDEEP | `1536:Y7iMHMetxZecz9fj4SzGo/OrBj6uCKgsjo+5z:ivHtZ9b4wn4BjtCKdjoS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_dce3c037
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dce3c037e491b823b2a62546116bad572cc64a03441d47f19104dfe541c1e820"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-06-24 18:23:02"
  condition:
    hash.sha256(0, filesize) == "dce3c037e491b823b2a62546116bad572cc64a03441d47f19104dfe541c1e820"
}
```

### Sample 71: `e132e56a921766f7`

| Field | Value |
|---|---|
| SHA-256 | `e132e56a921766f78e271a4446e5205b488c741a7719ae0f5227a43458e6f493` |
| Family label | `unknown` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-06-24 18:21:57` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7839f034cc3dfda89cf9da15cf009027` |
| SHA-1 | `10e6f35fbd0683b35cbd899767e0487c41af9412` |
| SHA-256 | `e132e56a921766f78e271a4446e5205b488c741a7719ae0f5227a43458e6f493` |
| SHA3-384 | `c379e3a457999e24c6ae16ea3cddf56d21a5cb14763d5df1a8d8fb18c53695b292cb8580235254f236283ec33f793350` |
| TLSH | `T109E3D6169F510EBBCCAFDD3706E90A0639CC911722A43B753674D938F54E94B4AE3CA8` |
| SSDEEP | `1536:euL3auKI6UtSwCbQZAIuiEa/H1A3mfu3nIDGwPaL/gcrTnyqXWLZQx+L2ir75W:ee2IKUZAB3A2LgcfyqXgQEN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_e132e56a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e132e56a921766f78e271a4446e5205b488c741a7719ae0f5227a43458e6f493"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-06-24 18:21:57"
  condition:
    hash.sha256(0, filesize) == "e132e56a921766f78e271a4446e5205b488c741a7719ae0f5227a43458e6f493"
}
```

### Sample 72: `275888c797b3b353`

| Field | Value |
|---|---|
| SHA-256 | `275888c797b3b35381780c251c8687e0ac978e52d5339d208df7696dd9f1aa6f` |
| Family label | `Mirai` |
| File name | `data_powerpc` |
| File type | `elf` |
| First seen | `2026-06-24 18:15:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `506cdc7a4e85ea21f0acefbb029a5383` |
| SHA-1 | `89cd6f3fbe14af15e46f4dc6f7ae344d34bc269e` |
| SHA-256 | `275888c797b3b35381780c251c8687e0ac978e52d5339d208df7696dd9f1aa6f` |
| SHA3-384 | `61ff63c3b786c7805b6d9d6db1c1c4f7754e9422818245138d68aa2285c983acfc7d26f93fe644af99aa06f4e344cd5e` |
| TLSH | `T1FAC32802770D0F43D1232CF02B7B1BE18799BEA619F4E684B51EBEC652759B62146ECC` |
| SSDEEP | `3072:0f47FF6zJ3YjxfWRThpvO41rKinCHuMoi:O4S1IjoR1BOWrvCOMoi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_275888c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "275888c797b3b35381780c251c8687e0ac978e52d5339d208df7696dd9f1aa6f"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-06-24 18:15:13"
  condition:
    hash.sha256(0, filesize) == "275888c797b3b35381780c251c8687e0ac978e52d5339d208df7696dd9f1aa6f"
}
```

### Sample 73: `3f387aece33e0614`

| Field | Value |
|---|---|
| SHA-256 | `3f387aece33e0614bbd42c04b6e4934c8fa081e10ca07d8aaf1f8c3c750d748a` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-06-24 18:14:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a6a0ad5d5dc3f4c55114fb81ccfe02d` |
| SHA-1 | `27fd6b3959f94c8139fa1b5be115f4ad8ae39e41` |
| SHA-256 | `3f387aece33e0614bbd42c04b6e4934c8fa081e10ca07d8aaf1f8c3c750d748a` |
| SHA3-384 | `d329a8f9e1ba5a147f06e46ac545a3267af4c009e00d3aeb4edb350c956d2f82eb633f6b93b20ecf61dc9caca65ef8d2` |
| TLSH | `T1A1B3F945F8508B17C6C661BBFF4E438D7B261758D3EE32029D25AF60379B96B0E3A142` |
| TELFHASH | `t1c7f050121e4c048c52f4cd4942be710534d071ee761515202fbbf9f94372945147182d` |
| SSDEEP | `1536:JUNmnXmIcJOrL4V/++7LlmmngdEOv3t3X6n9JZl3awyw0WUR3aFc5su0BDvFT:6wn2Ic44rtmlzHcnDPBB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_3f387aec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f387aece33e0614bbd42c04b6e4934c8fa081e10ca07d8aaf1f8c3c750d748a"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-24 18:14:18"
  condition:
    hash.sha256(0, filesize) == "3f387aece33e0614bbd42c04b6e4934c8fa081e10ca07d8aaf1f8c3c750d748a"
}
```

### Sample 74: `5df2b81fbb3c4412`

| Field | Value |
|---|---|
| SHA-256 | `5df2b81fbb3c441259eb797cf9df2311e8d7cfe89be820cfcbbde8f4f8609a23` |
| Family label | `unknown` |
| File name | `app.apk` |
| File type | `apk` |
| First seen | `2026-06-24 18:12:57` |
| Reporter | `BastianHein_` |
| Tags | `apk, Dogerat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fec3116699e7df05e94699da9ccd153a` |
| SHA-1 | `fa751e39341e597d87120b363e5eee95c905b4a6` |
| SHA-256 | `5df2b81fbb3c441259eb797cf9df2311e8d7cfe89be820cfcbbde8f4f8609a23` |
| SHA3-384 | `49034bc5c971be307ce06e041c25950125323b138ba172236546d105beb2f6e5d509768357c6b8a30a07a0ed0a3cdfb5` |
| TLSH | `T17BB61257F7445A1AC477907218AE1331224B0D4ACA439B877A1C771C3BB7AE81F9ABDC` |
| SSDEEP | `196608:kiHSBZABRBSt+6XwKVmDiXnf4WNE7UDaTODMSeVMo1omLiKarrZiksNg2mpp:tWqBmtXXP7XnfIoDaTODMSGWCCrZwNA3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_5df2b81f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df2b81fbb3c441259eb797cf9df2311e8d7cfe89be820cfcbbde8f4f8609a23"
    family = "unknown"
    file_name = "app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 18:12:57"
  condition:
    hash.sha256(0, filesize) == "5df2b81fbb3c441259eb797cf9df2311e8d7cfe89be820cfcbbde8f4f8609a23"
}
```

### Sample 75: `bbd6c516a908658a`

| Field | Value |
|---|---|
| SHA-256 | `bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7` |
| Family label | `IRATA` |
| File name | `AndroidAuto.apk` |
| File type | `apk` |
| First seen | `2026-06-24 18:12:43` |
| Reporter | `BastianHein_` |
| Tags | `apk, Irata, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3960b401fc189fd957564c0348550f2b` |
| SHA-1 | `ce75c2b0b449f81be11284adac579a70bcc7d1e3` |
| SHA-256 | `bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7` |
| SHA3-384 | `484e15382b4fb6d0d23e645ef4dff704bdc5a3aa65dff3f9834fdf352ece110919795eb3d643a20fe1e9b330f69c622f` |
| TLSH | `T139562346FA93E89ACCF6C33140B60B39613A1E2AD34793476375B6F468BBAE447471C1` |
| SSDEEP | `98304:YctGbZgi40QT8nBP2BPv3tVooAlHAVdrwr1/RkgOqJd4bS306zShQvOsBMFIk:1nynBelvtVN161/RkgOSBMQvDMqk` |

#### Technical Assessment

- The sample is tracked as `IRATA` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_IRATA_075_bbd6c516
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
    family = "IRATA"
    file_name = "AndroidAuto.apk"
    file_type = "apk"
    first_seen = "2026-06-24 18:12:43"
  condition:
    hash.sha256(0, filesize) == "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
}
```

### Sample 76: `1cdb114f0cc895f1`

| Field | Value |
|---|---|
| SHA-256 | `1cdb114f0cc895f1f6ce5d5b5321a0c1783cffda1019d88bd599a82a6b3a6241` |
| Family label | `unknown` |
| File name | `InjStandoff.apk` |
| File type | `apk` |
| First seen | `2026-06-24 18:12:19` |
| Reporter | `BastianHein_` |
| Tags | `apk, signed, Slocker` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aeee39349eea3c3e68be7a2acf882952` |
| SHA-1 | `0cdb9708e76bef7c69748ed1f000df201b498fea` |
| SHA-256 | `1cdb114f0cc895f1f6ce5d5b5321a0c1783cffda1019d88bd599a82a6b3a6241` |
| SHA3-384 | `4687b359353805bc006b0ba56439a3f5e1bf460e8f05f46a1582dbbc378dd1753160151f840afa66f6f1cdbbad06bc81` |
| TLSH | `T166A7330D7DD33D62D69864BB3FFA98147D385248919B8B13CB0589D9E4F0FDB7A01A22` |
| SSDEEP | `786432:qpYKAPvCfxM3Dvk0HE5RpYKAPvCfxM3Dvk0HE5ZpYKAPvCfxM3Dvk0HE5V:q4PvCEDcC44PvCEDcCi4PvCEDcC8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_1cdb114f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cdb114f0cc895f1f6ce5d5b5321a0c1783cffda1019d88bd599a82a6b3a6241"
    family = "unknown"
    file_name = "InjStandoff.apk"
    file_type = "apk"
    first_seen = "2026-06-24 18:12:19"
  condition:
    hash.sha256(0, filesize) == "1cdb114f0cc895f1f6ce5d5b5321a0c1783cffda1019d88bd599a82a6b3a6241"
}
```

### Sample 77: `f57630706be24a40`

| Field | Value |
|---|---|
| SHA-256 | `f57630706be24a400ea068b5b0b592a3f5c864b178962d18bfdbca16e4674433` |
| Family label | `Mirai` |
| File name | `data_x86` |
| File type | `elf` |
| First seen | `2026-06-24 18:09:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1380b8f5ba844f659de4ee16f12be512` |
| SHA-1 | `b35472f9f828fe2400c2d31cd9cd13f6729d00af` |
| SHA-256 | `f57630706be24a400ea068b5b0b592a3f5c864b178962d18bfdbca16e4674433` |
| SHA3-384 | `0804f0a37cdfe0bf4246e4ac2e86683e91f4c9a1843ce3b93d6a7889b251013cf4bf05d069bb44bc9f4ba92232f1c8cf` |
| TLSH | `T19D157D9DEB87E0F1F26340F1025ED7F64534A1265013FAF6EF4A266374327A16F1A21A` |
| TELFHASH | `t1a5e148b725a958ec67e08501825b7220ce2ad13b26f0397345f364e17a73e036f36d79` |
| SSDEEP | `24576:TBnzMh3oh7XpVXlbKFpGixJbYajrpVJH:2h3oh7Xp3bKF17vV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_f5763070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f57630706be24a400ea068b5b0b592a3f5c864b178962d18bfdbca16e4674433"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-06-24 18:09:56"
  condition:
    hash.sha256(0, filesize) == "f57630706be24a400ea068b5b0b592a3f5c864b178962d18bfdbca16e4674433"
}
```

### Sample 78: `40cf34f1ed84309b`

| Field | Value |
|---|---|
| SHA-256 | `40cf34f1ed84309b775b25fb25f0ea0353839f988c757f1fa865c7978ffb332b` |
| Family label | `unknown` |
| File name | `o` |
| File type | `ps1` |
| First seen | `2026-06-24 18:08:04` |
| Reporter | `monitorsg` |
| Tags | `KongTuke, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `164f4b0e2ee416a4a8adad6a8f12122b` |
| SHA-1 | `6c25d1a0344f70d52b5be88c786771174b6c9faf` |
| SHA-256 | `40cf34f1ed84309b775b25fb25f0ea0353839f988c757f1fa865c7978ffb332b` |
| SHA3-384 | `aa8b383301b1209f9e4e65d1374067414049a76d325cac6a56461ada85a41ec6a2f9f9f54a3ce4df25af643f1b9ef51f` |
| TLSH | `T1BA41F8F6FAA3F478760B48E65B829134A7B01497B044ACC4754E60E01F85423CB84ACF` |
| SSDEEP | `48:4GHdsoBG48ShTR8mUnPoS+w3ZeLytVlyOBjgRv2fL:4Esob5qmUeO4LyJy2UOL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_40cf34f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40cf34f1ed84309b775b25fb25f0ea0353839f988c757f1fa865c7978ffb332b"
    family = "unknown"
    file_name = "o"
    file_type = "ps1"
    first_seen = "2026-06-24 18:08:04"
  condition:
    hash.sha256(0, filesize) == "40cf34f1ed84309b775b25fb25f0ea0353839f988c757f1fa865c7978ffb332b"
}
```

### Sample 79: `13f7ccac229f5aea`

| Field | Value |
|---|---|
| SHA-256 | `13f7ccac229f5aeada38ace5adcc4dd048b69abc7243509be408e7f7eb5587c3` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-06-24 18:05:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2052759947415b997a2dd310935006f0` |
| SHA-1 | `a130e975153a840f792c41abef5264fe9cdc0b42` |
| SHA-256 | `13f7ccac229f5aeada38ace5adcc4dd048b69abc7243509be408e7f7eb5587c3` |
| SHA3-384 | `91221183b022732d21b8ae2a4de778d1df030ab19fef704eac8357eab97793ac16f81c8dc5639ff40dbcbfcf9c902cdb` |
| TLSH | `T18B537C84BB83D8B6FD8701B6657BA7624336D43D1019DB46D32EA83ADC63910D71B3AC` |
| TELFHASH | `t1cd31e0a27e6108fcb3d1ac8fc70aa693db29caa71a2165bb44f527413bf11719231931` |
| SSDEEP | `768:q+J2PJvxISh/HukqslcTqPZvgCvmk8PbAXk8lFh4fT55SeohA6w3zJI0J:MPJ+SVHAsiOZ8cXRLQl5StUT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_13f7ccac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13f7ccac229f5aeada38ace5adcc4dd048b69abc7243509be408e7f7eb5587c3"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-24 18:05:57"
  condition:
    hash.sha256(0, filesize) == "13f7ccac229f5aeada38ace5adcc4dd048b69abc7243509be408e7f7eb5587c3"
}
```

### Sample 80: `db3decc3f228ac79`

| Field | Value |
|---|---|
| SHA-256 | `db3decc3f228ac7982ed03612b7667e2a9edbadf777939a083b1ef7a59634aa8` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-06-24 18:05:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5723c08f643e49975d39ade9d7908e9` |
| SHA-1 | `fec1e786f68f7ada72ac81235f3c19d69ebe13e6` |
| SHA-256 | `db3decc3f228ac7982ed03612b7667e2a9edbadf777939a083b1ef7a59634aa8` |
| SHA3-384 | `7b4850c3192c5f474717a6fa1b711c287db395cff84eff7c2b68cb47cb8de26a104660e082241bb14b4e62bc2d81585e` |
| TLSH | `T149A3F945F8508B17C6C611BBFF4E438D7B2A1758D3EE72029D256F60379B9AB0E3A142` |
| TELFHASH | `t1fff050110c982bdc67d4e542415eb5543d4429793db61659afdf2d4f8373ac51420b3d` |
| SSDEEP | `1536:u36ZDSHEVQ5JRo/4VDu+7XBTl9dDOXC6+YS0dszldrwywF9cU9otMQsIcUqET:MiSHIQ5M4Q+lTDu3S8BIVB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_db3decc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3decc3f228ac7982ed03612b7667e2a9edbadf777939a083b1ef7a59634aa8"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-24 18:05:56"
  condition:
    hash.sha256(0, filesize) == "db3decc3f228ac7982ed03612b7667e2a9edbadf777939a083b1ef7a59634aa8"
}
```

### Sample 81: `f8f2f5914ac8f886`

| Field | Value |
|---|---|
| SHA-256 | `f8f2f5914ac8f8864a1204a58c9a38e4ab639c43f8722824990475bbf2dba223` |
| Family label | `Mirai` |
| File name | `data_mips-uclibc` |
| File type | `elf` |
| First seen | `2026-06-24 18:04:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c98fe10af12aa999e6e31d2b35b7a048` |
| SHA-1 | `97098815531806eb837445d5e0887cfd732d6cbe` |
| SHA-256 | `f8f2f5914ac8f8864a1204a58c9a38e4ab639c43f8722824990475bbf2dba223` |
| SHA3-384 | `c9de8848a8f82e373968da21034ea3af6588f8098bb4968eaa6b0f5e9fbf75d3082548cbe09aa3948bc7113a273d3e26` |
| TLSH | `T136142C137B324FA0D366D5720BB38B5A59EB01811EE258D1936CDB143A20AED685FFF4` |
| TELFHASH | `t15a31d008497823f0a7754c9e1aedff77e5a130df6a226d378e00e96da76d9825d00c1c` |
| SSDEEP | `3072:CLMCXp2oJjHRLgyrHwbpW/4cZUKb0Y+NLOt89siqA9hbav1p+:C/X8GDRLgySa4i0vN6ziqIbava` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_f8f2f591
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8f2f5914ac8f8864a1204a58c9a38e4ab639c43f8722824990475bbf2dba223"
    family = "Mirai"
    file_name = "data_mips-uclibc"
    file_type = "elf"
    first_seen = "2026-06-24 18:04:55"
  condition:
    hash.sha256(0, filesize) == "f8f2f5914ac8f8864a1204a58c9a38e4ab639c43f8722824990475bbf2dba223"
}
```

### Sample 82: `d0d085ef9ac0061f`

| Field | Value |
|---|---|
| SHA-256 | `d0d085ef9ac0061f0ccb137d87d0a5b717f94d0fa619646b7502ca9947170df9` |
| Family label | `Mirai` |
| File name | `data_arm5` |
| File type | `elf` |
| First seen | `2026-06-24 18:01:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `70cc15ad411bd679c2650c72880f8d18` |
| SHA-1 | `ce2c4a9e46e36030106414a730ae88c975460acb` |
| SHA-256 | `d0d085ef9ac0061f0ccb137d87d0a5b717f94d0fa619646b7502ca9947170df9` |
| SHA3-384 | `d98f19fc6894e94e6c7328f264f755c9d8d3d2c1dc8395c64a9d49ea0ff940536cb024a38a86631876e472b043cc4098` |
| TLSH | `T11AB30952BE419B13C5C321F6FBAE42593B136B7CD7EA3202AD24BF50274B8DA0E36551` |
| TELFHASH | `t133c08c8703221c8ea3cc900ec597b81822eebca62a48906cb6088103d0324a2342e82e` |
| SSDEEP | `1536:iIsNPt74tuBdSzB4IMXHT/AuZkDofTc63urTdjmukzE9JgxNSZG8O0OMaBV1SSB/:gNFNBdz+Dox3uPhDQE9GyiBT8NU166` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_d0d085ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0d085ef9ac0061f0ccb137d87d0a5b717f94d0fa619646b7502ca9947170df9"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-06-24 18:01:05"
  condition:
    hash.sha256(0, filesize) == "d0d085ef9ac0061f0ccb137d87d0a5b717f94d0fa619646b7502ca9947170df9"
}
```

### Sample 83: `7978b25841d7508b`

| Field | Value |
|---|---|
| SHA-256 | `7978b25841d7508bae82fad292aa21a8ac3259a56e5ab5b5156b121e34fc4eb0` |
| Family label | `Mirai` |
| File name | `data_mips` |
| File type | `elf` |
| First seen | `2026-06-24 17:59:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98ed0d4724bfb1cc6bc9d46de7515eb6` |
| SHA-1 | `362224d0b2e9039fa7e90ffadaeb2c6535c25675` |
| SHA-256 | `7978b25841d7508bae82fad292aa21a8ac3259a56e5ab5b5156b121e34fc4eb0` |
| SHA3-384 | `92d0b474dd08a109ea458eacac80390b5dcdc697e54964c6fddb9843a63b8f252d2198d67a35504b93f32268c3b57bb9` |
| TLSH | `T1E3F3A64A6F228F7EF369877147F78E31975877E616E1C680E1ACD5401E202CE641FBA8` |
| TELFHASH | `t11741b21c0db413a0a7356c59085dfb67d6a730da7e262c238b11e86aab6df835e21c0c` |
| SSDEEP | `3072:egggXEauOS+rXNjfyVKqaQof+Fyj6PHYQA/xJv1/vrnESlG:PggXEb8rdja3u+jGpJV7ESU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_7978b258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7978b25841d7508bae82fad292aa21a8ac3259a56e5ab5b5156b121e34fc4eb0"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-06-24 17:59:52"
  condition:
    hash.sha256(0, filesize) == "7978b25841d7508bae82fad292aa21a8ac3259a56e5ab5b5156b121e34fc4eb0"
}
```

### Sample 84: `4ede67d8728623fa`

| Field | Value |
|---|---|
| SHA-256 | `4ede67d8728623fad8c9a6af242693aa8e97160d9040a9c0c64c0d9dc6916a79` |
| Family label | `unknown` |
| File name | `TgWsProxy_windows8.exe` |
| File type | `exe` |
| First seen | `2026-06-24 17:51:41` |
| Reporter | `KnownSpotter` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95baeb9033c86d4b8270f8a190a18283` |
| SHA-1 | `c3d4aadf9a5dbfa1b8e1a511f2bf709c83e7d86f` |
| SHA-256 | `4ede67d8728623fad8c9a6af242693aa8e97160d9040a9c0c64c0d9dc6916a79` |
| SHA3-384 | `3ac7c57b4467ef12afd5ae006a6f9630c3a889f618ad81d0b6b72185ed3dc837fe1545d0f23b0cca030c109f7c4bebf7` |
| IMPHASH | `965e162fe6366ee377aa9bc80bdd5c65` |
| TLSH | `T13327339DB3F204FAD8E9413AA1E686926BD674E643B4C7C72FE108934E172E5DE34740` |
| SSDEEP | `393216:hY9udZVYtKXpW8uEBYFxVHFFL0M91+TtIiFRCuARuA3dS9QVdyKJdt9XEEWr3XEA:xcYW8dYFrHFFL0S1QtIcCuAHsMdyKNdq` |
| ICON-DHASH | `71ccb2b292b2ccf0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_4ede67d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ede67d8728623fad8c9a6af242693aa8e97160d9040a9c0c64c0d9dc6916a79"
    family = "unknown"
    file_name = "TgWsProxy_windows8.exe"
    file_type = "exe"
    first_seen = "2026-06-24 17:51:41"
  condition:
    hash.sha256(0, filesize) == "4ede67d8728623fad8c9a6af242693aa8e97160d9040a9c0c64c0d9dc6916a79"
}
```

### Sample 85: `a16cc8566e42b514`

| Field | Value |
|---|---|
| SHA-256 | `a16cc8566e42b514ce9acb6d1a220487fd5aa2a6c75a1a16a4cff0e7ca8f6397` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-06-24 17:43:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36d95ae1ad6d54ee9d0e487df3d1d619` |
| SHA-1 | `7c95d4a7025fba6ed98cad0b06c77def61b1d9ea` |
| SHA-256 | `a16cc8566e42b514ce9acb6d1a220487fd5aa2a6c75a1a16a4cff0e7ca8f6397` |
| SHA3-384 | `0f73dc4bdb3b94a6da97188546fbe0ba7cf197ee097f5f7457fd5fb5de2662ff65a0d846df4a170a970fcbb5dde9b42c` |
| TLSH | `T16C634B95EA83D4F0DC0611B018A7F73B6B33E4650134AA4BE76DF77BAC12722A50579C` |
| TELFHASH | `t1df2133f61ebd18a8f7d48804c35e6e517ebe9677745077e10473693032e7902607ac3a` |
| SSDEEP | `1536:pvFE8bpGRfA9Vr+GyZ42YfXUUl2hdMh5h/jhF0kQCbsn89:J68V2srm4P5zv5Qk4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_a16cc856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a16cc8566e42b514ce9acb6d1a220487fd5aa2a6c75a1a16a4cff0e7ca8f6397"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-06-24 17:43:56"
  condition:
    hash.sha256(0, filesize) == "a16cc8566e42b514ce9acb6d1a220487fd5aa2a6c75a1a16a4cff0e7ca8f6397"
}
```

### Sample 86: `f5c30c7628c95911`

| Field | Value |
|---|---|
| SHA-256 | `f5c30c7628c9591190ebd779042b73f9fa4cb8e8ee252e77fccaf5049c9e7002` |
| Family label | `BtmobRAT` |
| File name | `Silver Horizon.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:42:13` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f0b53bf8c81ec9b8bd78ff6a57f8c525` |
| SHA-1 | `305f2db644c5a52640f6347ed05539eff3ff3988` |
| SHA-256 | `f5c30c7628c9591190ebd779042b73f9fa4cb8e8ee252e77fccaf5049c9e7002` |
| SHA3-384 | `dd585e902f5fd520f5a63b3834611fb5f7df4908edd5e4c0158894c7dd63fb9202d81bbabcf1c87a2007871ad691528e` |
| TLSH | `T17147238BFB84991BF4F753B641369322C44B4C268B439BC76A54323C19B75D42F9EAC8` |
| SSDEEP | `393216:CseJ87DZSD6O448Vfv4n5EqsfSNAqUQ1FvBwmsOmw3gMqE/5YS4QaehOtb0atH2S:CTJ8fk9eve5E1QLCmN+MlT4HecyY2Mb` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_086_f5c30c76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c30c7628c9591190ebd779042b73f9fa4cb8e8ee252e77fccaf5049c9e7002"
    family = "BtmobRAT"
    file_name = "Silver Horizon.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:42:13"
  condition:
    hash.sha256(0, filesize) == "f5c30c7628c9591190ebd779042b73f9fa4cb8e8ee252e77fccaf5049c9e7002"
}
```

### Sample 87: `d9ddf328b6151bb6`

| Field | Value |
|---|---|
| SHA-256 | `d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38` |
| Family label | `BtmobRAT` |
| File name | `PAINELDO7.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:41:44` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c4faae928119a417617c77db1808ca7` |
| SHA-1 | `96895eee6c0650d57f5e5ce7399feccd9edf6e24` |
| SHA-256 | `d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38` |
| SHA3-384 | `5531c664d38211144a1aa3d7f47b21bb48c49ea5e0530afd0abf728c26138de980baf5dbee51c590998863782d1fd7e7` |
| TLSH | `T13796024BFB84882BD4F353B2417A5321554B4C668B438BC7AD44323C28B7AD46F9ABDD` |
| SSDEEP | `196608:LrUZX9GasrObxh9ee4Er5Ga77n5XqdetC/POMWxQaq:nUF9Hssrh4Yca/n5Xq7POM5aq` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_087_d9ddf328
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
    family = "BtmobRAT"
    file_name = "PAINELDO7.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:41:44"
  condition:
    hash.sha256(0, filesize) == "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
}
```

### Sample 88: `08f6c55dd50c9be0`

| Field | Value |
|---|---|
| SHA-256 | `08f6c55dd50c9be03504c3c220728b9a141f711ff556191f2e35035caef7938d` |
| Family label | `BtmobRAT` |
| File name | `watcher.lords.upp.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:41:17` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d314e18982e309cda297fbcf8226e40f` |
| SHA-1 | `e96cd5e41251682ed73f3653fa67912169624d50` |
| SHA-256 | `08f6c55dd50c9be03504c3c220728b9a141f711ff556191f2e35035caef7938d` |
| SHA3-384 | `a4b8484bb4496fcd017eaeb1cc5efb9a8ba5d5bb0dd0dc307e622134d23bba45be8fc921f521c873425b15f26fe3b687` |
| TLSH | `T162C60147FB458A5AC0FB83F249371B5116270EA68B4397C76960397D3C736D06F8AA8C` |
| SSDEEP | `196608:yWSPrNHv8e+T2sGBpjZ3RBKuZEFSjL8ehf+MDC0OY2b3R7BWyM3b:5qZoCsQptBBKQEQjL8eor072h7BWHr` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_088_08f6c55d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f6c55dd50c9be03504c3c220728b9a141f711ff556191f2e35035caef7938d"
    family = "BtmobRAT"
    file_name = "watcher.lords.upp.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:41:17"
  condition:
    hash.sha256(0, filesize) == "08f6c55dd50c9be03504c3c220728b9a141f711ff556191f2e35035caef7938d"
}
```

### Sample 89: `01ffd5d2a96c9585`

| Field | Value |
|---|---|
| SHA-256 | `01ffd5d2a96c9585ff3e1b7850b39f1304f1dcd0156f07b7d446854473bb6e8f` |
| Family label | `BtmobRAT` |
| File name | `watchdog.streamguard.shuffler.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:40:58` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69300c7ada04bfc3cf7bf693a32f61b7` |
| SHA-1 | `27cae34f6618979353a61e583d57a176ca9e2319` |
| SHA-256 | `01ffd5d2a96c9585ff3e1b7850b39f1304f1dcd0156f07b7d446854473bb6e8f` |
| SHA3-384 | `34b83c322593ce663d76720f50f9b3b7cd4ae0647cc004828598b5371196dc61e76bf7879b215b4c3b8974f56f21b0d8` |
| TLSH | `T161C60143FB058A9AC0F783F24937176126270EB68B4397C76960797D3D736D06E8A98C` |
| SSDEEP | `196608:CiNXNAJFgx4xf5G9198+5uHTgvOIdB4MK61HgCM3Rr8r26oG2trBGKInFlTHjsbE:VN9Ad158IHsvOIdwjCMhwr2Xjr0VlbYo` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_089_01ffd5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ffd5d2a96c9585ff3e1b7850b39f1304f1dcd0156f07b7d446854473bb6e8f"
    family = "BtmobRAT"
    file_name = "watchdog.streamguard.shuffler.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:40:58"
  condition:
    hash.sha256(0, filesize) == "01ffd5d2a96c9585ff3e1b7850b39f1304f1dcd0156f07b7d446854473bb6e8f"
}
```

### Sample 90: `79e5be7312647724`

| Field | Value |
|---|---|
| SHA-256 | `79e5be731264772458094ecc3a5f0b43f87a52f0bea15f1ecf42ab90b8a9edb5` |
| Family label | `BtmobRAT` |
| File name | `simulator.quantizer.transformer.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:40:38` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e65021b786c6b78a48aa3329a3141ba0` |
| SHA-1 | `88ea5ef09da98d42ad5985af64f162d2ccccd76d` |
| SHA-256 | `79e5be731264772458094ecc3a5f0b43f87a52f0bea15f1ecf42ab90b8a9edb5` |
| SHA3-384 | `9f88c80f986c28e318fd3b97cdd85550f73e5b874c9a7ee1b8875ce76d0785ed26261a1e12d3506f9051d8a5b514e635` |
| TLSH | `T172C60143FB448A5AC0F787F259372BA116270E668B4397C76960397D2C737D06F8A98C` |
| SSDEEP | `196608:CcvuTYEkO3yZuPyAvGjXj8lvko57RWYGyxT5mSn0d7T0K3:BWkvO3yMPybzyvdNRzBxdmYCMM` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_090_79e5be73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79e5be731264772458094ecc3a5f0b43f87a52f0bea15f1ecf42ab90b8a9edb5"
    family = "BtmobRAT"
    file_name = "simulator.quantizer.transformer.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:40:38"
  condition:
    hash.sha256(0, filesize) == "79e5be731264772458094ecc3a5f0b43f87a52f0bea15f1ecf42ab90b8a9edb5"
}
```

### Sample 91: `9286b69febddf2e6`

| Field | Value |
|---|---|
| SHA-256 | `9286b69febddf2e6240ce739d5814ad696f1589635802904f7213bc98cae97f8` |
| Family label | `BtmobRAT` |
| File name | `service.lonce.app.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:40:16` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebbdcb70608a8e7d52f834f3b583400b` |
| SHA-1 | `8b6b42e91e4912c878f9fa18eadddf567bb3707e` |
| SHA-256 | `9286b69febddf2e6240ce739d5814ad696f1589635802904f7213bc98cae97f8` |
| SHA3-384 | `46042addeabaa661800c5f748ea3f6428f14438e828e2cd3c45dd7aba0a788e4392ffba64cc7c592f4e022d0fe2d7c45` |
| TLSH | `T171E62352BB461618E4F78B324A32129123364DB34B13934B7AB27D7CAC77BD0DBD1A94` |
| SSDEEP | `393216:ix0fkaKSDkB0l37Cpls9CXCpIHIK3RoGpNZ7pKvzK6Bw:DfkaBPl2btHD3RdT+4` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_091_9286b69f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9286b69febddf2e6240ce739d5814ad696f1589635802904f7213bc98cae97f8"
    family = "BtmobRAT"
    file_name = "service.lonce.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:40:16"
  condition:
    hash.sha256(0, filesize) == "9286b69febddf2e6240ce739d5814ad696f1589635802904f7213bc98cae97f8"
}
```

### Sample 92: `cee907c40ab5b20e`

| Field | Value |
|---|---|
| SHA-256 | `cee907c40ab5b20ee6ee235e433134042b3803e9e3e84c3e2d3211989799098c` |
| Family label | `BtmobRAT` |
| File name | `notifier.lonce.app.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:39:53` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `342fee77354ff26d4993258afd930ef7` |
| SHA-1 | `5564169b17783b80f1e5d91b24b0a425c2629e48` |
| SHA-256 | `cee907c40ab5b20ee6ee235e433134042b3803e9e3e84c3e2d3211989799098c` |
| SHA3-384 | `c6fbf400aae511bf3820f3fb5903fb7893110966e8637cac690652b663c6e895d13056f8c7d46b8d44e368243f15193d` |
| TLSH | `T149C60147FB448A5AC0F787F24933176126270E768B4397C769643A7D3C736E06E8A68C` |
| SSDEEP | `196608:sTXRV1HSFEIs+gXkONXT+5UfY61/dc7/GQWADe+CcH3PjX/ROhwzQ:sTn1Hlh+gXDjkUfB1/dy/fKy3bRS` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_092_cee907c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee907c40ab5b20ee6ee235e433134042b3803e9e3e84c3e2d3211989799098c"
    family = "BtmobRAT"
    file_name = "notifier.lonce.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:39:53"
  condition:
    hash.sha256(0, filesize) == "cee907c40ab5b20ee6ee235e433134042b3803e9e3e84c3e2d3211989799098c"
}
```

### Sample 93: `527dfcb599a8700c`

| Field | Value |
|---|---|
| SHA-256 | `527dfcb599a8700cb6ee1e875ef2ee64fbd95d1d7a5dbd35e9093b266e53243e` |
| Family label | `BtmobRAT` |
| File name | `nors.tv.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:39:32` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efd7f9f160e59667463a0553f0178331` |
| SHA-1 | `60335f1888cd9b0817e05a6c09648cda37b8e4e3` |
| SHA-256 | `527dfcb599a8700cb6ee1e875ef2ee64fbd95d1d7a5dbd35e9093b266e53243e` |
| SHA3-384 | `58da9bc7fc3e61062f5d62fc8f12910d565f6168b543b5a0f4577f0058b4c81d79bd434af76f224c8902fdc95baad977` |
| TLSH | `T1B5E62342B7424519E8F78A334B33629123365CB38B5353477EB17DBCAC726E4EB81998` |
| SSDEEP | `393216:dSCGi0VmgK6YFvcYBdoJcxLfSo0e6aJR9:dSCGiVgK6i3oJqLfSI6aJR9` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_093_527dfcb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "527dfcb599a8700cb6ee1e875ef2ee64fbd95d1d7a5dbd35e9093b266e53243e"
    family = "BtmobRAT"
    file_name = "nors.tv.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:39:32"
  condition:
    hash.sha256(0, filesize) == "527dfcb599a8700cb6ee1e875ef2ee64fbd95d1d7a5dbd35e9093b266e53243e"
}
```

### Sample 94: `edb533e4dece48c8`

| Field | Value |
|---|---|
| SHA-256 | `edb533e4dece48c883f149b911c2042ff897205b8d8cb370586e54ae145b77b7` |
| Family label | `BtmobRAT` |
| File name | `merger.lonce.app.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:39:09` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0a8ac852230226308bbeafaef2d9d69` |
| SHA-1 | `291fe007cfa5e375c25090d564414e03d3133f88` |
| SHA-256 | `edb533e4dece48c883f149b911c2042ff897205b8d8cb370586e54ae145b77b7` |
| SHA3-384 | `fb75aa4c6b7b948732043b2377ffdc770440f5d3097351d3e9ea9ea151305351940b487b00442db387d6222e5cd960d6` |
| TLSH | `T1A3C60247FB088A56C0F783F259331B5126270E668B4397C76960397D3D736E06EDAA8C` |
| SSDEEP | `196608:EWCVxQwYiq3a8zAsXWoOFR7Z5Vua85RUcFBCUdiM3JGldoHEw9B0irpRpNxnkZsR:m4wYiq3a8zAIFYlkRUc3CQiCJGb+Ew9d` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_094_edb533e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edb533e4dece48c883f149b911c2042ff897205b8d8cb370586e54ae145b77b7"
    family = "BtmobRAT"
    file_name = "merger.lonce.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:39:09"
  condition:
    hash.sha256(0, filesize) == "edb533e4dece48c883f149b911c2042ff897205b8d8cb370586e54ae145b77b7"
}
```

### Sample 95: `e0ed71b95a459126`

| Field | Value |
|---|---|
| SHA-256 | `e0ed71b95a459126cef8c8d8627794ccb6aae93cc25a060bb8ee73b84c82a2dd` |
| Family label | `BtmobRAT` |
| File name | `loce.tv.app.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:38:49` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efa05e0f252416296b77b7c0eefee665` |
| SHA-1 | `dc6c4cd6d9d799f7292f668297ff0f32c05be155` |
| SHA-256 | `e0ed71b95a459126cef8c8d8627794ccb6aae93cc25a060bb8ee73b84c82a2dd` |
| SHA3-384 | `034d45867e5fa87b2d49c4dbbbcc6c6327b19e30380038769f03a59cf0d023671402867f8ab17cb7af5c1e5e92c82134` |
| TLSH | `T152C60143FB008A5AC0F783B249371BA126270E668B4397C76964397D7D736D46FCA6C8` |
| SSDEEP | `196608:PIaiDkuViT6WW3xbX9bJd7Em3f0OkH/BrserOFsoeXkZaWTVWHVuqa9ROEj1bcUh:PIaiDkubFbJam3f0rZ42OFsBXkZpmVLs` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_095_e0ed71b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0ed71b95a459126cef8c8d8627794ccb6aae93cc25a060bb8ee73b84c82a2dd"
    family = "BtmobRAT"
    file_name = "loce.tv.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:38:49"
  condition:
    hash.sha256(0, filesize) == "e0ed71b95a459126cef8c8d8627794ccb6aae93cc25a060bb8ee73b84c82a2dd"
}
```

### Sample 96: `69fb412d697c8788`

| Field | Value |
|---|---|
| SHA-256 | `69fb412d697c8788d8d864be990714b7320dd69f1dd6397dab7e3eb34c1ace25` |
| Family label | `BtmobRAT` |
| File name | `kraps.semag.ygrenes.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:38:30` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6206e485622a984e9add4c03fae33363` |
| SHA-1 | `3621cbbce90e28b27effc2804c7e9f318bf19fe2` |
| SHA-256 | `69fb412d697c8788d8d864be990714b7320dd69f1dd6397dab7e3eb34c1ace25` |
| SHA3-384 | `db03c65ec62ad3ad5d202a87bdfc603e82149405f1e7261cba656ab68dd2464049ca52ad61aa985a0c697f9f50119244` |
| TLSH | `T1D9C60247FB048A56C0F783F2593757A026670EA68B4397C76960397D3C736D06E8AACC` |
| SSDEEP | `196608:YZZSOZN+vDgJh6tG0+rdTg04pjecZoQJPYQle3Xbpod2LH7H6mN5lFU8jZyswgJM:2ZCG0+20oeBQV7leHbpo+HTNnqIyHgib` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_096_69fb412d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69fb412d697c8788d8d864be990714b7320dd69f1dd6397dab7e3eb34c1ace25"
    family = "BtmobRAT"
    file_name = "kraps.semag.ygrenes.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:38:30"
  condition:
    hash.sha256(0, filesize) == "69fb412d697c8788d8d864be990714b7320dd69f1dd6397dab7e3eb34c1ace25"
}
```

### Sample 97: `1353050f3ca901d6`

| Field | Value |
|---|---|
| SHA-256 | `1353050f3ca901d67d1957feaeef6e9425e33d92f343ef69e36f66e4116b7563` |
| Family label | `BtmobRAT` |
| File name | `decoder.detector.service.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:38:04` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8833824ba0a0417fc5e1014363154cbf` |
| SHA-1 | `9431f06bb6573a3d22245242ff2a6d16eb2f7e0a` |
| SHA-256 | `1353050f3ca901d67d1957feaeef6e9425e33d92f343ef69e36f66e4116b7563` |
| SHA3-384 | `a35ee366b4b352eb4b8cb8af22e37b2d76d5ef4208068af6ea74b808c3e560ac169ff539c50dc20a05c6719447288c4e` |
| TLSH | `T119E62352BB821628E8F387324A76239123364DB38B5367477EB23D7CBC737E09691954` |
| SSDEEP | `393216:eWPc91W+Gxj1YHdkbVTbxeCAphiTdI75MCEVrhDkr1:eOuGfYHdsRImI7aJrK1` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_097_1353050f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1353050f3ca901d67d1957feaeef6e9425e33d92f343ef69e36f66e4116b7563"
    family = "BtmobRAT"
    file_name = "decoder.detector.service.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:38:04"
  condition:
    hash.sha256(0, filesize) == "1353050f3ca901d67d1957feaeef6e9425e33d92f343ef69e36f66e4116b7563"
}
```

### Sample 98: `51e5372028f8a619`

| Field | Value |
|---|---|
| SHA-256 | `51e5372028f8a61922bcbc94f90fd1285e6895a4a7dffc93447b4bc6b17d045c` |
| Family label | `BtmobRAT` |
| File name | `atsiv.lance.app.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:37:41` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5b5999f313411405c810a221b08bbdd` |
| SHA-1 | `33a00db45ca16cde19259a3fddc6c77b15c2015d` |
| SHA-256 | `51e5372028f8a61922bcbc94f90fd1285e6895a4a7dffc93447b4bc6b17d045c` |
| SHA3-384 | `61206043e2bcf3e28ef982cce4294c7e92880b4b3a961993447f2215a461592b864677a57c1f3ab287e838d6d22b7b74` |
| TLSH | `T19AE62342B7461518E5F38B324A36225567334CF34B23A3477AF27DBCAC72BD09B91A94` |
| SSDEEP | `393216:GNt9gxgWbLJps9U93Rnee71LJHxWCP3/8SMRYAb:C2qWbLJplliMq7b` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_098_51e53720
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51e5372028f8a61922bcbc94f90fd1285e6895a4a7dffc93447b4bc6b17d045c"
    family = "BtmobRAT"
    file_name = "atsiv.lance.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:37:41"
  condition:
    hash.sha256(0, filesize) == "51e5372028f8a61922bcbc94f90fd1285e6895a4a7dffc93447b4bc6b17d045c"
}
```

### Sample 99: `310ee72debb75cef`

| Field | Value |
|---|---|
| SHA-256 | `310ee72debb75cef10f93e7a482873da09ac82814a293a1b9f311b2b656527f3` |
| Family label | `BtmobRAT` |
| File name | `activator.facilitator.subsystem.apk` |
| File type | `apk` |
| First seen | `2026-06-24 17:37:21` |
| Reporter | `BastianHein_` |
| Tags | `apk, btmobrat, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `559e592cc2e73e7800004b6e5ad2f821` |
| SHA-1 | `e1f736c4a49952609ac0b66b9ac4bf3d4fb52b9f` |
| SHA-256 | `310ee72debb75cef10f93e7a482873da09ac82814a293a1b9f311b2b656527f3` |
| SHA3-384 | `d8cce84d7daf2293b139991e7e4b83275e7392d81b9da89e585a9838d69dbd61f99b77e43b9dd91ccb5537a28c87bc7a` |
| TLSH | `T171C60143FB418A5AC0F787F24933576026270EA68B5397C76960397D3D736D06E8AACC` |
| SSDEEP | `196608:7RAW6L0F0CNPLSPQFlQb8pE1Nqj35SQkJRRNmNwCbsgY1h9YNEAKuG:7RKsNOPQLssj3EJAeGhE94/G` |

#### Technical Assessment

- The sample is tracked as `BtmobRAT` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_BtmobRAT_099_310ee72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310ee72debb75cef10f93e7a482873da09ac82814a293a1b9f311b2b656527f3"
    family = "BtmobRAT"
    file_name = "activator.facilitator.subsystem.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:37:21"
  condition:
    hash.sha256(0, filesize) == "310ee72debb75cef10f93e7a482873da09ac82814a293a1b9f311b2b656527f3"
}
```

### Sample 100: `ee9e97d914a0745c`

| Field | Value |
|---|---|
| SHA-256 | `ee9e97d914a0745cd56f138517c8dceaab1626b5a8ec71103c731a28ff0097d5` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-06-24 16:43:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `703c9e56520231b7ec9547d215dc6347` |
| SHA-1 | `4c09debd75a2d66dc2b88f168cb4cc5cbb8d4291` |
| SHA-256 | `ee9e97d914a0745cd56f138517c8dceaab1626b5a8ec71103c731a28ff0097d5` |
| SHA3-384 | `b2e71f72fcdfe1c9efe9bef494f1976252c629a0ade2d6265f8d797c9b717adea24b45a0a9a255d2c51f29b2d6ddf872` |
| TLSH | `T13B63AE97C46B2E44C94666F0B0B5CE39C703951092430EB71A9BDA7A9483DCDB68E7FC` |
| SSDEEP | `768:ZpF5opJTZSBr0Y6EIzUH9LnbxxBAuhXbfXGqLsNy7MKorLnWbCxPlwd:sIr0zEIzabHBAuxbfWW7MtrCbCxP6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_ee9e97d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee9e97d914a0745cd56f138517c8dceaab1626b5a8ec71103c731a28ff0097d5"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-24 16:43:56"
  condition:
    hash.sha256(0, filesize) == "ee9e97d914a0745cd56f138517c8dceaab1626b5a8ec71103c731a28ff0097d5"
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
 * Generated: 2026-06-25T04:37:20.804046+00:00
 */

rule MalwareBazaar_unknown_001_f1a89526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1a895267514b8b63673820a534724b1b9ad41b314be2aa1c458512f0d75a8d3"
    family = "unknown"
    file_name = "menu.exe"
    file_type = "exe"
    first_seen = "2026-06-25 04:33:06"
  condition:
    hash.sha256(0, filesize) == "f1a895267514b8b63673820a534724b1b9ad41b314be2aa1c458512f0d75a8d3"
}

rule MalwareBazaar_RemoteManipulator_002_7f01a050
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f01a05055ec07b287de38a6e92f2a04dc512fe1b6972c16e2412ff27c53ce6a"
    family = "RemoteManipulator"
    file_name = "744c291f1af31190766580c630d0c032.exe"
    file_type = "exe"
    first_seen = "2026-06-25 04:25:06"
  condition:
    hash.sha256(0, filesize) == "7f01a05055ec07b287de38a6e92f2a04dc512fe1b6972c16e2412ff27c53ce6a"
}

rule MalwareBazaar_unknown_003_f8f951f3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443"
    family = "unknown"
    file_name = "f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443.dll"
    file_type = "dll"
    first_seen = "2026-06-25 04:13:41"
  condition:
    hash.sha256(0, filesize) == "f8f951f3a2fa091e6e77ad02f39a28ce1bc2b317ddff3546e3103f6172101443"
}

rule MalwareBazaar_unknown_004_0b2d6d91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11"
    family = "unknown"
    file_name = "0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11.dll"
    file_type = "dll"
    first_seen = "2026-06-25 04:07:02"
  condition:
    hash.sha256(0, filesize) == "0b2d6d916b7c65a1ad734ae0798f48edc2c466165c82e60c8f30e82cf2d0cd11"
}

rule MalwareBazaar_unknown_005_43172e45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "43172e45afb4cef97225b8ed783bd66bd7b06839c6fa95c957d248d67ca1725d"
    family = "unknown"
    file_name = "deploy_softwaretech.sh"
    file_type = "sh"
    first_seen = "2026-06-25 03:55:14"
  condition:
    hash.sha256(0, filesize) == "43172e45afb4cef97225b8ed783bd66bd7b06839c6fa95c957d248d67ca1725d"
}

rule MalwareBazaar_unknown_006_34b1ab13
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34b1ab13d92e0551fb4bd85319cdec417ef110628d6af437b734c81358257254"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-25 03:38:28"
  condition:
    hash.sha256(0, filesize) == "34b1ab13d92e0551fb4bd85319cdec417ef110628d6af437b734c81358257254"
}

rule MalwareBazaar_unknown_007_a8484c9b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a8484c9b65270cb49da643faf17994959a035be72203eb9b4f9e90feb37f75e7"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-25 03:00:16"
  condition:
    hash.sha256(0, filesize) == "a8484c9b65270cb49da643faf17994959a035be72203eb9b4f9e90feb37f75e7"
}

rule MalwareBazaar_unknown_008_1bee14b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1bee14b1afc29e401d0f8f6e559cab82d2b40c6fde24e38bcaf70631795fac21"
    family = "unknown"
    file_name = "文档.exe"
    file_type = "exe"
    first_seen = "2026-06-25 02:21:57"
  condition:
    hash.sha256(0, filesize) == "1bee14b1afc29e401d0f8f6e559cab82d2b40c6fde24e38bcaf70631795fac21"
}

rule MalwareBazaar_Mirai_009_396c4ffc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "396c4ffc3d7428e57ecf71eb3dca8a7f07deee530ed28aad065d9dc83b130662"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-25 01:59:36"
  condition:
    hash.sha256(0, filesize) == "396c4ffc3d7428e57ecf71eb3dca8a7f07deee530ed28aad065d9dc83b130662"
}

rule MalwareBazaar_Mirai_010_6c876f85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c876f85aac3f9ba5ea1d6533ab19b366e6a7be2cab00e8b3abd607c9b8b09a5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-25 01:56:20"
  condition:
    hash.sha256(0, filesize) == "6c876f85aac3f9ba5ea1d6533ab19b366e6a7be2cab00e8b3abd607c9b8b09a5"
}

rule MalwareBazaar_Mirai_011_7e65fbe7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7e65fbe7ff6d5f92090ea2df29477865a234018ec043920471e371fc70fe3ee7"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-25 01:47:13"
  condition:
    hash.sha256(0, filesize) == "7e65fbe7ff6d5f92090ea2df29477865a234018ec043920471e371fc70fe3ee7"
}

rule MalwareBazaar_Mirai_012_ac4de25e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4de25e87b96bd85e9b50e1688cbb6ccef9de8beaac552180fe0547586dc968"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-25 01:47:12"
  condition:
    hash.sha256(0, filesize) == "ac4de25e87b96bd85e9b50e1688cbb6ccef9de8beaac552180fe0547586dc968"
}

rule MalwareBazaar_Mirai_013_7db97598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7db97598eb3c11ab87d56215afc4f053d0db5064d97376cc6278d6af739a2e27"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-06-25 01:28:19"
  condition:
    hash.sha256(0, filesize) == "7db97598eb3c11ab87d56215afc4f053d0db5064d97376cc6278d6af739a2e27"
}

rule MalwareBazaar_Mirai_014_18372ae3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18372ae33ff340d0c683a4b40f85ce0573bdfb448a8ede0ca1ce031d53a4df87"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-25 01:27:15"
  condition:
    hash.sha256(0, filesize) == "18372ae33ff340d0c683a4b40f85ce0573bdfb448a8ede0ca1ce031d53a4df87"
}

rule MalwareBazaar_Mirai_015_4ba0eea1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ba0eea142e43246981a2d7b7f06479affeec4ccf57aaa64b452e77075606a17"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-25 01:23:17"
  condition:
    hash.sha256(0, filesize) == "4ba0eea142e43246981a2d7b7f06479affeec4ccf57aaa64b452e77075606a17"
}

rule MalwareBazaar_Mirai_016_5a879507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5a8795076e41edd2aa2850f7945b06dfe27059a08eed47450e9fc83c108995f5"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-06-25 01:21:34"
  condition:
    hash.sha256(0, filesize) == "5a8795076e41edd2aa2850f7945b06dfe27059a08eed47450e9fc83c108995f5"
}

rule MalwareBazaar_Mirai_017_c686e9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c686e9d277411bee3f43666fe898cddb7cdf55971b576eb1c30b45f820cd67f3"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-06-25 01:08:32"
  condition:
    hash.sha256(0, filesize) == "c686e9d277411bee3f43666fe898cddb7cdf55971b576eb1c30b45f820cd67f3"
}

rule MalwareBazaar_Mirai_018_4df5911b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4df5911bd816cd345e4f2f96e55c7026b6f305e40de436a5b928b05f145146c2"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-25 00:49:19"
  condition:
    hash.sha256(0, filesize) == "4df5911bd816cd345e4f2f96e55c7026b6f305e40de436a5b928b05f145146c2"
}

rule MalwareBazaar_Mirai_019_1e315996
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e31599608087395f5f717647667581f5d90107bab7517fc4e4d26ecde9e2534"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-25 00:39:05"
  condition:
    hash.sha256(0, filesize) == "1e31599608087395f5f717647667581f5d90107bab7517fc4e4d26ecde9e2534"
}

rule MalwareBazaar_Mirai_020_2e844129
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e8441299af33b3ad8701c04b159d8a0ff5bfca6d6f1d8bc0f0bfa0c50130b15"
    family = "Mirai"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-06-25 00:35:23"
  condition:
    hash.sha256(0, filesize) == "2e8441299af33b3ad8701c04b159d8a0ff5bfca6d6f1d8bc0f0bfa0c50130b15"
}

rule MalwareBazaar_Mirai_021_aa14067a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa14067a93d55af1624194f22ea30de722bbc81e133c5919be4129b4deca91d6"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-25 00:33:12"
  condition:
    hash.sha256(0, filesize) == "aa14067a93d55af1624194f22ea30de722bbc81e133c5919be4129b4deca91d6"
}

rule MalwareBazaar_unknown_022_a852f895
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344"
    family = "unknown"
    file_name = "a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344"
    file_type = "elf"
    first_seen = "2026-06-25 00:31:11"
  condition:
    hash.sha256(0, filesize) == "a852f8958a507f7823fed1a0610df893b90758affeee2196fb9bddadbac06344"
}

rule MalwareBazaar_unknown_023_5ebed0bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ebed0bd0c875ada468c98854eb88f6244461eea138933380e696f27c67a91be"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-25 00:18:13"
  condition:
    hash.sha256(0, filesize) == "5ebed0bd0c875ada468c98854eb88f6244461eea138933380e696f27c67a91be"
}

rule MalwareBazaar_Mirai_024_fe08f7fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe08f7fddb6b9bf9757d47f6fb1f1b82a54490e10db140b7d8fbb11b3baaa6a4"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-06-25 00:09:21"
  condition:
    hash.sha256(0, filesize) == "fe08f7fddb6b9bf9757d47f6fb1f1b82a54490e10db140b7d8fbb11b3baaa6a4"
}

rule MalwareBazaar_Mirai_025_a880b428
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a880b428d160b7e38557c282c58387db908c982d905259a17d12c29bc2cae1a3"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-25 00:05:17"
  condition:
    hash.sha256(0, filesize) == "a880b428d160b7e38557c282c58387db908c982d905259a17d12c29bc2cae1a3"
}

rule MalwareBazaar_Mirai_026_063e70eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "063e70ebc453de4191e8b37a8508763cccd328fb44c9309ed44c4c13b729f4a2"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-25 00:03:13"
  condition:
    hash.sha256(0, filesize) == "063e70ebc453de4191e8b37a8508763cccd328fb44c9309ed44c4c13b729f4a2"
}

rule MalwareBazaar_unknown_027_faecc582
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 23:47:57"
  condition:
    hash.sha256(0, filesize) == "faecc582b335ed2b680ea464419c30943a04c05117ba76cefdd453ec983febbe"
}

rule MalwareBazaar_Mirai_028_7fb004cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fb004cc7b621d44c3524a65439f97cc8bf856359100f439f5ce8cfb6caf774a"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-24 23:25:13"
  condition:
    hash.sha256(0, filesize) == "7fb004cc7b621d44c3524a65439f97cc8bf856359100f439f5ce8cfb6caf774a"
}

rule MalwareBazaar_unknown_029_c762e76a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c762e76a878329177113d991e1d1bceca046cc101f5f7429fc098f8009828b12"
    family = "unknown"
    file_name = "tbk"
    file_type = "sh"
    first_seen = "2026-06-24 22:09:22"
  condition:
    hash.sha256(0, filesize) == "c762e76a878329177113d991e1d1bceca046cc101f5f7429fc098f8009828b12"
}

rule MalwareBazaar_unknown_030_f4d3a989
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d3a9898f156bd443ba241ab0a9e2c22ace7439cbe2e5086695d4e3a01a98fd"
    family = "unknown"
    file_name = "lterouter"
    file_type = "sh"
    first_seen = "2026-06-24 21:56:57"
  condition:
    hash.sha256(0, filesize) == "f4d3a9898f156bd443ba241ab0a9e2c22ace7439cbe2e5086695d4e3a01a98fd"
}

rule MalwareBazaar_unknown_031_eb1fa049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eb1fa0496503a61c43d02e4378556049b0301941ed48eac154b55aa2f8434b28"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-24 21:48:55"
  condition:
    hash.sha256(0, filesize) == "eb1fa0496503a61c43d02e4378556049b0301941ed48eac154b55aa2f8434b28"
}

rule MalwareBazaar_RustyStealer_032_a64eee9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 21:27:22"
  condition:
    hash.sha256(0, filesize) == "a64eee9ab72607f0f5b69d6bb3871586767b8b3e46f23d3154833bada493afb5"
}

rule MalwareBazaar_unknown_033_72d80252
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316"
    family = "unknown"
    file_name = "PrestigeClient.jar"
    file_type = "jar"
    first_seen = "2026-06-24 21:04:36"
  condition:
    hash.sha256(0, filesize) == "72d80252032723c3b7f9c04be3fcdf69e96dad41cd8b7968266b296643357316"
}

rule MalwareBazaar_unknown_034_f5952b16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92"
    family = "unknown"
    file_name = "gRvidixkmlMIeXBedzwX.vbs"
    file_type = "vbs"
    first_seen = "2026-06-24 21:03:41"
  condition:
    hash.sha256(0, filesize) == "f5952b1650e8d5e9a480c32c8c0b53dd4a14f4cdc320e8949d721f5881955f92"
}

rule MalwareBazaar_unknown_035_7c8ddbd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c8ddbd9294e581b2266ab50e6075e40ad2bd39f61d44fca52910e9b9634a46e"
    family = "unknown"
    file_name = "ijevhpezl1vxjabh.dll"
    file_type = "exe"
    first_seen = "2026-06-24 21:03:35"
  condition:
    hash.sha256(0, filesize) == "7c8ddbd9294e581b2266ab50e6075e40ad2bd39f61d44fca52910e9b9634a46e"
}

rule MalwareBazaar_Formbook_036_b710e94d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b710e94d81dab6603ad14a45ee82926305bfb35f848d9108d4fc31eaf5161707"
    family = "Formbook"
    file_name = "09786y7662026-DMS108997.bat"
    file_type = "exe"
    first_seen = "2026-06-24 20:57:30"
  condition:
    hash.sha256(0, filesize) == "b710e94d81dab6603ad14a45ee82926305bfb35f848d9108d4fc31eaf5161707"
}

rule MalwareBazaar_Mirai_037_07f1818f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07f1818fddf2e3fcde507aab8cded1356890eeabe10ea4b2941cc10df7e6e626"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-24 20:51:21"
  condition:
    hash.sha256(0, filesize) == "07f1818fddf2e3fcde507aab8cded1356890eeabe10ea4b2941cc10df7e6e626"
}

rule MalwareBazaar_Mirai_038_0e838c6a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e838c6a588d00c029ea5e469e55e121688df7a6e8af7b75e53504dc81631cb5"
    family = "Mirai"
    file_name = "ml"
    file_type = "elf"
    first_seen = "2026-06-24 20:51:20"
  condition:
    hash.sha256(0, filesize) == "0e838c6a588d00c029ea5e469e55e121688df7a6e8af7b75e53504dc81631cb5"
}

rule MalwareBazaar_Mirai_039_2122acaa
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2122acaa42afef0b94d57ae665aad3e63bab5a28c07d03378feab8a4001312f4"
    family = "Mirai"
    file_name = "data_arm4"
    file_type = "elf"
    first_seen = "2026-06-24 20:46:33"
  condition:
    hash.sha256(0, filesize) == "2122acaa42afef0b94d57ae665aad3e63bab5a28c07d03378feab8a4001312f4"
}

rule MalwareBazaar_unknown_040_38653b45
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38653b45cc1ad44b143751d4cf64d1924b4b22bef833b8c8e341b2ba4b5e1470"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 20:39:40"
  condition:
    hash.sha256(0, filesize) == "38653b45cc1ad44b143751d4cf64d1924b4b22bef833b8c8e341b2ba4b5e1470"
}

rule MalwareBazaar_unknown_041_2ec5ae79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ec5ae79d9e5f7a8a0026fb8f4e6a4fa059991884bbae53c91e5753ee139ac4a"
    family = "unknown"
    file_name = "Canon.dll"
    file_type = "dll"
    first_seen = "2026-06-24 20:32:25"
  condition:
    hash.sha256(0, filesize) == "2ec5ae79d9e5f7a8a0026fb8f4e6a4fa059991884bbae53c91e5753ee139ac4a"
}

rule MalwareBazaar_Mirai_042_34feec85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34feec85340a025234d379a0095489f526181765b6bee67cbb4d3e07000f7086"
    family = "Mirai"
    file_name = "data_aarch64"
    file_type = "elf"
    first_seen = "2026-06-24 20:29:54"
  condition:
    hash.sha256(0, filesize) == "34feec85340a025234d379a0095489f526181765b6bee67cbb4d3e07000f7086"
}

rule MalwareBazaar_Mirai_043_d0310e98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0310e982b671884e67580d627b1ad9dbaeaf2f68fef0611526615604ed93449"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-06-24 20:26:01"
  condition:
    hash.sha256(0, filesize) == "d0310e982b671884e67580d627b1ad9dbaeaf2f68fef0611526615604ed93449"
}

rule MalwareBazaar_Mirai_044_4d970ab8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d970ab8897787064a00c021896b429d2ee7d60cc1c3e3af34448c3692abb342"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-24 20:25:00"
  condition:
    hash.sha256(0, filesize) == "4d970ab8897787064a00c021896b429d2ee7d60cc1c3e3af34448c3692abb342"
}

rule MalwareBazaar_Mirai_045_d3f57383
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3f573839eb3a0ca6c7f6a53085d1eb9b8cc258f63aa404946b4cf1c4e8db7cd"
    family = "Mirai"
    file_name = "data_arm6"
    file_type = "elf"
    first_seen = "2026-06-24 20:22:55"
  condition:
    hash.sha256(0, filesize) == "d3f573839eb3a0ca6c7f6a53085d1eb9b8cc258f63aa404946b4cf1c4e8db7cd"
}

rule MalwareBazaar_Mirai_046_73c99c65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73c99c65a819726ba3e1d68ed2ec58b941a705c393c05934ff351575bbf74940"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-24 20:17:53"
  condition:
    hash.sha256(0, filesize) == "73c99c65a819726ba3e1d68ed2ec58b941a705c393c05934ff351575bbf74940"
}

rule MalwareBazaar_Mirai_047_c8e59f57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8e59f57038524cdd3f42fd80d4c721d0d2356e4f616079cd78ed90bb24edaa2"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-24 20:08:54"
  condition:
    hash.sha256(0, filesize) == "c8e59f57038524cdd3f42fd80d4c721d0d2356e4f616079cd78ed90bb24edaa2"
}

rule MalwareBazaar_Mirai_048_042fe062
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "042fe062e97f7a321a0e88046dd1ada8a7cb41b449e2cad27db8ad8be50ce9f4"
    family = "Mirai"
    file_name = "data_arm7"
    file_type = "elf"
    first_seen = "2026-06-24 19:59:52"
  condition:
    hash.sha256(0, filesize) == "042fe062e97f7a321a0e88046dd1ada8a7cb41b449e2cad27db8ad8be50ce9f4"
}

rule MalwareBazaar_Mirai_049_b66cde24
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b66cde24a585798b61132a8fce61bbd704169264b9bf497cacd5ed4f0804453d"
    family = "Mirai"
    file_name = "data_x86_64"
    file_type = "elf"
    first_seen = "2026-06-24 19:58:54"
  condition:
    hash.sha256(0, filesize) == "b66cde24a585798b61132a8fce61bbd704169264b9bf497cacd5ed4f0804453d"
}

rule MalwareBazaar_unknown_050_04614935
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "04614935b46d278acf30fbd275dfa2b55e19a1a96ece17be852325305469343e"
    family = "unknown"
    file_name = "bbc"
    file_type = "sh"
    first_seen = "2026-06-24 19:51:52"
  condition:
    hash.sha256(0, filesize) == "04614935b46d278acf30fbd275dfa2b55e19a1a96ece17be852325305469343e"
}

rule MalwareBazaar_Stealc_051_1737369b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1737369bee038e31b39e2cb66b9dd18ecbec92a7be1324adc16060682141f2fd"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 19:51:20"
  condition:
    hash.sha256(0, filesize) == "1737369bee038e31b39e2cb66b9dd18ecbec92a7be1324adc16060682141f2fd"
}

rule MalwareBazaar_unknown_052_c5dc6d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
    family = "unknown"
    file_name = "???_??????+.apk"
    file_type = "apk"
    first_seen = "2026-06-24 19:50:46"
  condition:
    hash.sha256(0, filesize) == "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
}

rule MalwareBazaar_Mirai_053_68bd1963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68bd19635359188ea8ab42541ba0e573b34a1819fde6115e8dced39c4ebd97b9"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-06-24 19:49:52"
  condition:
    hash.sha256(0, filesize) == "68bd19635359188ea8ab42541ba0e573b34a1819fde6115e8dced39c4ebd97b9"
}

rule MalwareBazaar_Mirai_054_ef5d4d0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef5d4d0fbfd73d3e50607ac5f62287ec6f9045ce6fb5940afeab6bb2601b0cb6"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-06-24 19:49:50"
  condition:
    hash.sha256(0, filesize) == "ef5d4d0fbfd73d3e50607ac5f62287ec6f9045ce6fb5940afeab6bb2601b0cb6"
}

rule MalwareBazaar_Mirai_055_94fdbdfe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94fdbdfea6c70f8d83acf32f495584ff7a25c9270bfb36fe045eb43efb7ac04d"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-06-24 19:48:52"
  condition:
    hash.sha256(0, filesize) == "94fdbdfea6c70f8d83acf32f495584ff7a25c9270bfb36fe045eb43efb7ac04d"
}

rule MalwareBazaar_unknown_056_4778d350
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8"
    family = "unknown"
    file_name = "4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8"
    file_type = "exe"
    first_seen = "2026-06-24 19:43:55"
  condition:
    hash.sha256(0, filesize) == "4778d350b0175cac5f08e53a51abe758ff8f62ccc00f296b2f6f950b54a1ddc8"
}

rule MalwareBazaar_Mirai_057_1ca3b901
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ca3b901935fead67478eae99eaf7061c871fc0fcea3403086a0c5cc154c1f3f"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-06-24 19:43:54"
  condition:
    hash.sha256(0, filesize) == "1ca3b901935fead67478eae99eaf7061c871fc0fcea3403086a0c5cc154c1f3f"
}

rule MalwareBazaar_unknown_058_34d2e47f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d2e47fa8f6b64e346623b4ed66898b86d53891900b953e69f02e2b3ffb2cc9"
    family = "unknown"
    file_name = "dropper_34d2e47f.sh"
    file_type = "sh"
    first_seen = "2026-06-24 19:34:03"
  condition:
    hash.sha256(0, filesize) == "34d2e47fa8f6b64e346623b4ed66898b86d53891900b953e69f02e2b3ffb2cc9"
}

rule MalwareBazaar_Mirai_059_404df61a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "404df61aa1d3bfcfc14288b9cc0131642cbafb31256f28c5fd7e5ef51bbe2d69"
    family = "Mirai"
    file_name = "bot_404df61a.elf"
    file_type = "elf"
    first_seen = "2026-06-24 19:34:00"
  condition:
    hash.sha256(0, filesize) == "404df61aa1d3bfcfc14288b9cc0131642cbafb31256f28c5fd7e5ef51bbe2d69"
}

rule MalwareBazaar_unknown_060_533ab567
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "533ab567dfbbdae5fde5bf1443f2291a169da6de448d08bbf950ead27ccf0582"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-06-24 19:33:52"
  condition:
    hash.sha256(0, filesize) == "533ab567dfbbdae5fde5bf1443f2291a169da6de448d08bbf950ead27ccf0582"
}

rule MalwareBazaar_Mirai_061_ffb744e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb744e91515a6bdb0bf0588065455efd591250c882026b6c16f6afca11ca98f"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-06-24 19:28:53"
  condition:
    hash.sha256(0, filesize) == "ffb744e91515a6bdb0bf0588065455efd591250c882026b6c16f6afca11ca98f"
}

rule MalwareBazaar_Mirai_062_e4697c70
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4697c702263e186097be61c198ffc5a148631b1d3db08f2b515c1b742f8e919"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-06-24 19:20:59"
  condition:
    hash.sha256(0, filesize) == "e4697c702263e186097be61c198ffc5a148631b1d3db08f2b515c1b742f8e919"
}

rule MalwareBazaar_Mirai_063_59130212
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5913021291f2e43955ccf5a4dd9b0daf462fc378b60dbc02b26271bf700939a8"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-06-24 18:49:56"
  condition:
    hash.sha256(0, filesize) == "5913021291f2e43955ccf5a4dd9b0daf462fc378b60dbc02b26271bf700939a8"
}

rule MalwareBazaar_unknown_064_a485a98f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a485a98f07b6c3357436071164908a99f6a2e13d86d39e53ae9897e7e21ecf4f"
    family = "unknown"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-06-24 18:47:03"
  condition:
    hash.sha256(0, filesize) == "a485a98f07b6c3357436071164908a99f6a2e13d86d39e53ae9897e7e21ecf4f"
}

rule MalwareBazaar_Mirai_065_d6189cdb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6189cdbc46765f124c982b97f99f7251afd1ed03d67829a76b003f31b2a88a0"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-06-24 18:45:58"
  condition:
    hash.sha256(0, filesize) == "d6189cdbc46765f124c982b97f99f7251afd1ed03d67829a76b003f31b2a88a0"
}

rule MalwareBazaar_unknown_066_f9557670
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f9557670dd45bda485da28f6683f31cce7bc38bf7495389089ee39a8bf3142ed"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-06-24 18:45:29"
  condition:
    hash.sha256(0, filesize) == "f9557670dd45bda485da28f6683f31cce7bc38bf7495389089ee39a8bf3142ed"
}

rule MalwareBazaar_Mirai_067_044f25e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "044f25e5c9eb287519556b0e7a67cdb4e94965dc0d39acd33d5fdcf2d428b612"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-06-24 18:34:57"
  condition:
    hash.sha256(0, filesize) == "044f25e5c9eb287519556b0e7a67cdb4e94965dc0d39acd33d5fdcf2d428b612"
}

rule MalwareBazaar_Mirai_068_ad21baf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad21baf3b79af3680215d48448c86f38b95ba04b49f0dfa837f9dca39f8023d0"
    family = "Mirai"
    file_name = "data_mipsel"
    file_type = "elf"
    first_seen = "2026-06-24 18:27:56"
  condition:
    hash.sha256(0, filesize) == "ad21baf3b79af3680215d48448c86f38b95ba04b49f0dfa837f9dca39f8023d0"
}

rule MalwareBazaar_Mirai_069_f7cdecce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7cdecce2caa3c5cc733c6738b59f9515f618e70ab339f87304833e62eb2bc6c"
    family = "Mirai"
    file_name = "data_mipsel-uclibc"
    file_type = "elf"
    first_seen = "2026-06-24 18:26:02"
  condition:
    hash.sha256(0, filesize) == "f7cdecce2caa3c5cc733c6738b59f9515f618e70ab339f87304833e62eb2bc6c"
}

rule MalwareBazaar_Mirai_070_dce3c037
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dce3c037e491b823b2a62546116bad572cc64a03441d47f19104dfe541c1e820"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-06-24 18:23:02"
  condition:
    hash.sha256(0, filesize) == "dce3c037e491b823b2a62546116bad572cc64a03441d47f19104dfe541c1e820"
}

rule MalwareBazaar_unknown_071_e132e56a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e132e56a921766f78e271a4446e5205b488c741a7719ae0f5227a43458e6f493"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-06-24 18:21:57"
  condition:
    hash.sha256(0, filesize) == "e132e56a921766f78e271a4446e5205b488c741a7719ae0f5227a43458e6f493"
}

rule MalwareBazaar_Mirai_072_275888c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "275888c797b3b35381780c251c8687e0ac978e52d5339d208df7696dd9f1aa6f"
    family = "Mirai"
    file_name = "data_powerpc"
    file_type = "elf"
    first_seen = "2026-06-24 18:15:13"
  condition:
    hash.sha256(0, filesize) == "275888c797b3b35381780c251c8687e0ac978e52d5339d208df7696dd9f1aa6f"
}

rule MalwareBazaar_Mirai_073_3f387aec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f387aece33e0614bbd42c04b6e4934c8fa081e10ca07d8aaf1f8c3c750d748a"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-06-24 18:14:18"
  condition:
    hash.sha256(0, filesize) == "3f387aece33e0614bbd42c04b6e4934c8fa081e10ca07d8aaf1f8c3c750d748a"
}

rule MalwareBazaar_unknown_074_5df2b81f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5df2b81fbb3c441259eb797cf9df2311e8d7cfe89be820cfcbbde8f4f8609a23"
    family = "unknown"
    file_name = "app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 18:12:57"
  condition:
    hash.sha256(0, filesize) == "5df2b81fbb3c441259eb797cf9df2311e8d7cfe89be820cfcbbde8f4f8609a23"
}

rule MalwareBazaar_IRATA_075_bbd6c516
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
    family = "IRATA"
    file_name = "AndroidAuto.apk"
    file_type = "apk"
    first_seen = "2026-06-24 18:12:43"
  condition:
    hash.sha256(0, filesize) == "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
}

rule MalwareBazaar_unknown_076_1cdb114f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1cdb114f0cc895f1f6ce5d5b5321a0c1783cffda1019d88bd599a82a6b3a6241"
    family = "unknown"
    file_name = "InjStandoff.apk"
    file_type = "apk"
    first_seen = "2026-06-24 18:12:19"
  condition:
    hash.sha256(0, filesize) == "1cdb114f0cc895f1f6ce5d5b5321a0c1783cffda1019d88bd599a82a6b3a6241"
}

rule MalwareBazaar_Mirai_077_f5763070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f57630706be24a400ea068b5b0b592a3f5c864b178962d18bfdbca16e4674433"
    family = "Mirai"
    file_name = "data_x86"
    file_type = "elf"
    first_seen = "2026-06-24 18:09:56"
  condition:
    hash.sha256(0, filesize) == "f57630706be24a400ea068b5b0b592a3f5c864b178962d18bfdbca16e4674433"
}

rule MalwareBazaar_unknown_078_40cf34f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "40cf34f1ed84309b775b25fb25f0ea0353839f988c757f1fa865c7978ffb332b"
    family = "unknown"
    file_name = "o"
    file_type = "ps1"
    first_seen = "2026-06-24 18:08:04"
  condition:
    hash.sha256(0, filesize) == "40cf34f1ed84309b775b25fb25f0ea0353839f988c757f1fa865c7978ffb332b"
}

rule MalwareBazaar_Mirai_079_13f7ccac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "13f7ccac229f5aeada38ace5adcc4dd048b69abc7243509be408e7f7eb5587c3"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-06-24 18:05:57"
  condition:
    hash.sha256(0, filesize) == "13f7ccac229f5aeada38ace5adcc4dd048b69abc7243509be408e7f7eb5587c3"
}

rule MalwareBazaar_Mirai_080_db3decc3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db3decc3f228ac7982ed03612b7667e2a9edbadf777939a083b1ef7a59634aa8"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-06-24 18:05:56"
  condition:
    hash.sha256(0, filesize) == "db3decc3f228ac7982ed03612b7667e2a9edbadf777939a083b1ef7a59634aa8"
}

rule MalwareBazaar_Mirai_081_f8f2f591
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f8f2f5914ac8f8864a1204a58c9a38e4ab639c43f8722824990475bbf2dba223"
    family = "Mirai"
    file_name = "data_mips-uclibc"
    file_type = "elf"
    first_seen = "2026-06-24 18:04:55"
  condition:
    hash.sha256(0, filesize) == "f8f2f5914ac8f8864a1204a58c9a38e4ab639c43f8722824990475bbf2dba223"
}

rule MalwareBazaar_Mirai_082_d0d085ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0d085ef9ac0061f0ccb137d87d0a5b717f94d0fa619646b7502ca9947170df9"
    family = "Mirai"
    file_name = "data_arm5"
    file_type = "elf"
    first_seen = "2026-06-24 18:01:05"
  condition:
    hash.sha256(0, filesize) == "d0d085ef9ac0061f0ccb137d87d0a5b717f94d0fa619646b7502ca9947170df9"
}

rule MalwareBazaar_Mirai_083_7978b258
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7978b25841d7508bae82fad292aa21a8ac3259a56e5ab5b5156b121e34fc4eb0"
    family = "Mirai"
    file_name = "data_mips"
    file_type = "elf"
    first_seen = "2026-06-24 17:59:52"
  condition:
    hash.sha256(0, filesize) == "7978b25841d7508bae82fad292aa21a8ac3259a56e5ab5b5156b121e34fc4eb0"
}

rule MalwareBazaar_unknown_084_4ede67d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4ede67d8728623fad8c9a6af242693aa8e97160d9040a9c0c64c0d9dc6916a79"
    family = "unknown"
    file_name = "TgWsProxy_windows8.exe"
    file_type = "exe"
    first_seen = "2026-06-24 17:51:41"
  condition:
    hash.sha256(0, filesize) == "4ede67d8728623fad8c9a6af242693aa8e97160d9040a9c0c64c0d9dc6916a79"
}

rule MalwareBazaar_Mirai_085_a16cc856
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a16cc8566e42b514ce9acb6d1a220487fd5aa2a6c75a1a16a4cff0e7ca8f6397"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-06-24 17:43:56"
  condition:
    hash.sha256(0, filesize) == "a16cc8566e42b514ce9acb6d1a220487fd5aa2a6c75a1a16a4cff0e7ca8f6397"
}

rule MalwareBazaar_BtmobRAT_086_f5c30c76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5c30c7628c9591190ebd779042b73f9fa4cb8e8ee252e77fccaf5049c9e7002"
    family = "BtmobRAT"
    file_name = "Silver Horizon.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:42:13"
  condition:
    hash.sha256(0, filesize) == "f5c30c7628c9591190ebd779042b73f9fa4cb8e8ee252e77fccaf5049c9e7002"
}

rule MalwareBazaar_BtmobRAT_087_d9ddf328
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
    family = "BtmobRAT"
    file_name = "PAINELDO7.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:41:44"
  condition:
    hash.sha256(0, filesize) == "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
}

rule MalwareBazaar_BtmobRAT_088_08f6c55d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08f6c55dd50c9be03504c3c220728b9a141f711ff556191f2e35035caef7938d"
    family = "BtmobRAT"
    file_name = "watcher.lords.upp.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:41:17"
  condition:
    hash.sha256(0, filesize) == "08f6c55dd50c9be03504c3c220728b9a141f711ff556191f2e35035caef7938d"
}

rule MalwareBazaar_BtmobRAT_089_01ffd5d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01ffd5d2a96c9585ff3e1b7850b39f1304f1dcd0156f07b7d446854473bb6e8f"
    family = "BtmobRAT"
    file_name = "watchdog.streamguard.shuffler.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:40:58"
  condition:
    hash.sha256(0, filesize) == "01ffd5d2a96c9585ff3e1b7850b39f1304f1dcd0156f07b7d446854473bb6e8f"
}

rule MalwareBazaar_BtmobRAT_090_79e5be73
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79e5be731264772458094ecc3a5f0b43f87a52f0bea15f1ecf42ab90b8a9edb5"
    family = "BtmobRAT"
    file_name = "simulator.quantizer.transformer.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:40:38"
  condition:
    hash.sha256(0, filesize) == "79e5be731264772458094ecc3a5f0b43f87a52f0bea15f1ecf42ab90b8a9edb5"
}

rule MalwareBazaar_BtmobRAT_091_9286b69f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9286b69febddf2e6240ce739d5814ad696f1589635802904f7213bc98cae97f8"
    family = "BtmobRAT"
    file_name = "service.lonce.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:40:16"
  condition:
    hash.sha256(0, filesize) == "9286b69febddf2e6240ce739d5814ad696f1589635802904f7213bc98cae97f8"
}

rule MalwareBazaar_BtmobRAT_092_cee907c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cee907c40ab5b20ee6ee235e433134042b3803e9e3e84c3e2d3211989799098c"
    family = "BtmobRAT"
    file_name = "notifier.lonce.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:39:53"
  condition:
    hash.sha256(0, filesize) == "cee907c40ab5b20ee6ee235e433134042b3803e9e3e84c3e2d3211989799098c"
}

rule MalwareBazaar_BtmobRAT_093_527dfcb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "527dfcb599a8700cb6ee1e875ef2ee64fbd95d1d7a5dbd35e9093b266e53243e"
    family = "BtmobRAT"
    file_name = "nors.tv.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:39:32"
  condition:
    hash.sha256(0, filesize) == "527dfcb599a8700cb6ee1e875ef2ee64fbd95d1d7a5dbd35e9093b266e53243e"
}

rule MalwareBazaar_BtmobRAT_094_edb533e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "edb533e4dece48c883f149b911c2042ff897205b8d8cb370586e54ae145b77b7"
    family = "BtmobRAT"
    file_name = "merger.lonce.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:39:09"
  condition:
    hash.sha256(0, filesize) == "edb533e4dece48c883f149b911c2042ff897205b8d8cb370586e54ae145b77b7"
}

rule MalwareBazaar_BtmobRAT_095_e0ed71b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0ed71b95a459126cef8c8d8627794ccb6aae93cc25a060bb8ee73b84c82a2dd"
    family = "BtmobRAT"
    file_name = "loce.tv.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:38:49"
  condition:
    hash.sha256(0, filesize) == "e0ed71b95a459126cef8c8d8627794ccb6aae93cc25a060bb8ee73b84c82a2dd"
}

rule MalwareBazaar_BtmobRAT_096_69fb412d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "69fb412d697c8788d8d864be990714b7320dd69f1dd6397dab7e3eb34c1ace25"
    family = "BtmobRAT"
    file_name = "kraps.semag.ygrenes.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:38:30"
  condition:
    hash.sha256(0, filesize) == "69fb412d697c8788d8d864be990714b7320dd69f1dd6397dab7e3eb34c1ace25"
}

rule MalwareBazaar_BtmobRAT_097_1353050f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1353050f3ca901d67d1957feaeef6e9425e33d92f343ef69e36f66e4116b7563"
    family = "BtmobRAT"
    file_name = "decoder.detector.service.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:38:04"
  condition:
    hash.sha256(0, filesize) == "1353050f3ca901d67d1957feaeef6e9425e33d92f343ef69e36f66e4116b7563"
}

rule MalwareBazaar_BtmobRAT_098_51e53720
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51e5372028f8a61922bcbc94f90fd1285e6895a4a7dffc93447b4bc6b17d045c"
    family = "BtmobRAT"
    file_name = "atsiv.lance.app.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:37:41"
  condition:
    hash.sha256(0, filesize) == "51e5372028f8a61922bcbc94f90fd1285e6895a4a7dffc93447b4bc6b17d045c"
}

rule MalwareBazaar_BtmobRAT_099_310ee72d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "310ee72debb75cef10f93e7a482873da09ac82814a293a1b9f311b2b656527f3"
    family = "BtmobRAT"
    file_name = "activator.facilitator.subsystem.apk"
    file_type = "apk"
    first_seen = "2026-06-24 17:37:21"
  condition:
    hash.sha256(0, filesize) == "310ee72debb75cef10f93e7a482873da09ac82814a293a1b9f311b2b656527f3"
}

rule MalwareBazaar_Mirai_100_ee9e97d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee9e97d914a0745cd56f138517c8dceaab1626b5a8ec71103c731a28ff0097d5"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-06-24 16:43:56"
  condition:
    hash.sha256(0, filesize) == "ee9e97d914a0745cd56f138517c8dceaab1626b5a8ec71103c731a28ff0097d5"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

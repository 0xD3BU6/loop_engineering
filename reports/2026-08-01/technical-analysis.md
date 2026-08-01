# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-01

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 662 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 662 |
| Unique family labels | 6 |
| Unique file types | 6 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 61 |
| unknown | 34 |
| CoinMiner | 2 |
| Stealc | 1 |
| NanoCore | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 64 |
| exe | 24 |
| sh | 9 |
| hta | 1 |
| unknown | 1 |
| msi | 1 |

## Per-Sample Analysis

### Sample 1: `514b8816af6639c6`

| Field | Value |
|---|---|
| SHA-256 | `514b8816af6639c6185f03cb2969e7855f1883b6d8a651c7e218269435795b9a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-08-01 03:52:31` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f431bab8484871c918874b91d60665ca` |
| SHA-1 | `df2ca5aac70682ca84c50ca5eb02d55565a7ae16` |
| SHA-256 | `514b8816af6639c6185f03cb2969e7855f1883b6d8a651c7e218269435795b9a` |
| SHA3-384 | `fcd054a479ad1461a77fe3873ff3737c27b23c28c10a7f153c1d50dd96fa1b57f2ee6aa32bb2c7509ae7f6a72c721f5d` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T192E633081AD016EFE9B3817DFBD219C5E068BC314BB2C4CF47A856AA5F532D09C3E656` |
| SSDEEP | `393216:Nmgc/5Sttlvdd77aUplxrXMCHWUjtcuI3/PGTAI:ggcQttpO4lXMb8aH/O7` |
| ICON-DHASH | `19dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_514b8816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "514b8816af6639c6185f03cb2969e7855f1883b6d8a651c7e218269435795b9a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 03:52:31"
  condition:
    hash.sha256(0, filesize) == "514b8816af6639c6185f03cb2969e7855f1883b6d8a651c7e218269435795b9a"
}
```

### Sample 2: `cafcc76c5d1e97e3`

| Field | Value |
|---|---|
| SHA-256 | `cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10` |
| Family label | `unknown` |
| File name | `MM2DUPE.exe` |
| File type | `exe` |
| First seen | `2026-08-01 03:27:34` |
| Reporter | `hexinglarps` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5d203aa2c95d96736d44cb35fff96fe` |
| SHA-1 | `6c37d6d05ab8ba5efa827a4edeb15e03a9b6dcc5` |
| SHA-256 | `cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10` |
| SHA3-384 | `70d8871db46416a4567a9bd3dabbde9ee8824918deca6049ae1caedc93c2aa1820a83c0f22249e7b7d8a93688dd6f1ee` |
| IMPHASH | `44d4eec854a3d541453f2cd97e7d6cf2` |
| TLSH | `T164D633AA3A03432DD507C0355A165078C8E5B8B36765A498DBEB70D75AFF3970E03F2A` |
| SSDEEP | `393216:2owNtJl2UxWNKGvN+BvtPAsUk2/hAEPu5M:2owtJl25NK5963PuW` |
| ICON-DHASH | `0000000000000000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_cafcc76c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10"
    family = "unknown"
    file_name = "MM2DUPE.exe"
    file_type = "exe"
    first_seen = "2026-08-01 03:27:34"
  condition:
    hash.sha256(0, filesize) == "cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10"
}
```

### Sample 3: `4c17b8c2d287de19`

| Field | Value |
|---|---|
| SHA-256 | `4c17b8c2d287de19641026b61af6567c2f08f65888fd7a620a919e83a2c08895` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 03:16:57` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11babc5c7dd1f8853b4c0b222bc91ae9` |
| SHA-1 | `b85a2a863e9234de3aa1a3d8b12a6023b5561b16` |
| SHA-256 | `4c17b8c2d287de19641026b61af6567c2f08f65888fd7a620a919e83a2c08895` |
| SHA3-384 | `c067c6966cd532d485d3776d4522d0608894a4b549cabdd96585fafd95f9a41b546e074814db400393d68b14c6f66f5d` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1B53633A665D92836E487CBFCB282A07EB6BA77A5C9257D033FCC55098D1BE24153C3C4` |
| SSDEEP | `98304:anvDBCTlzx2tA0+39rs0nIo/lMmleWJQcGEBwuUa/HDlcVdsJkRPHZor:cvDYb2tA0+zIIyO5JQc2a/DltkRP` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_003_4c17b8c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c17b8c2d287de19641026b61af6567c2f08f65888fd7a620a919e83a2c08895"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:57"
  condition:
    hash.sha256(0, filesize) == "4c17b8c2d287de19641026b61af6567c2f08f65888fd7a620a919e83a2c08895"
}
```

### Sample 4: `e378df570301e2a7`

| Field | Value |
|---|---|
| SHA-256 | `e378df570301e2a7cf4d1a79508a41acae37df09d2ea0460902e2edb49d6533c` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 03:16:46` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d3845b911891c68c72b835152be7505` |
| SHA-1 | `483a6604c0ad33c5a6ae390822d8c0b88196aba6` |
| SHA-256 | `e378df570301e2a7cf4d1a79508a41acae37df09d2ea0460902e2edb49d6533c` |
| SHA3-384 | `ebbb75ef4bd629c634f42c60dc2f8e053b933660d3eea7a51cd76f285242716c0cf5229d35e0fd5d8d6c11494507f8e5` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1B9D52398B4F619B4C43BC3B19F92E83DB049375596908E93FBCC6A109E13A546C3B376` |
| SSDEEP | `49152:05EC+S6HQoPCRKzdP66lp8ttw74RLIqeCAub3kD5OVIWjCmfyDrwz1bLAK/iRlDf:U3KaRS66fy84mqXAub3cWIDrO1M0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_e378df57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e378df570301e2a7cf4d1a79508a41acae37df09d2ea0460902e2edb49d6533c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:46"
  condition:
    hash.sha256(0, filesize) == "e378df570301e2a7cf4d1a79508a41acae37df09d2ea0460902e2edb49d6533c"
}
```

### Sample 5: `2804f625bda3a9b1`

| Field | Value |
|---|---|
| SHA-256 | `2804f625bda3a9b17c21df3bda03807ba0dc74c4c7c3333f59a5c18c7497858b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 03:16:39` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53b7d64e827f66ef11fc6f14963e7681` |
| SHA-1 | `7e6cb6f7263da1a97b8efabe4b46a6642e5eb840` |
| SHA-256 | `2804f625bda3a9b17c21df3bda03807ba0dc74c4c7c3333f59a5c18c7497858b` |
| SHA3-384 | `f57b0f45e522df6f8483ca2292d0e0b33dc07e64e1f0038b038818f4d832aef8b6249050cbe61738f75263eee1a2ecbd` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T14AD522CEFDE27234E47AC3B7429375AEB029778442209D5E72C82B106D935287C7B769` |
| SSDEEP | `49152:xCmWwcxavhd5l6PAb8dReRThheAj+CMsRboNP1V70GQtAzqFhDTKGBI4I6vma3X:xj2A5oGHhRor70GKJvDTu63X` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_2804f625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2804f625bda3a9b17c21df3bda03807ba0dc74c4c7c3333f59a5c18c7497858b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:39"
  condition:
    hash.sha256(0, filesize) == "2804f625bda3a9b17c21df3bda03807ba0dc74c4c7c3333f59a5c18c7497858b"
}
```

### Sample 6: `392a891929839c17`

| Field | Value |
|---|---|
| SHA-256 | `392a891929839c17887143fe1125f845763335821a61b83cf6a2a291d79b1885` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 03:16:23` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3859c0331e6ee54c764d467c3557ce4a` |
| SHA-1 | `44a6f251a273f9f74f500183c235d06c52074dc5` |
| SHA-256 | `392a891929839c17887143fe1125f845763335821a61b83cf6a2a291d79b1885` |
| SHA3-384 | `4898681a43e838c12b7c61746f4e693e479162df81cc14bfb24a75301fd9dca458edb312c30b524af7cb1a024552427d` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1E5D52399B8B72AB4C47BC7B58F82E06D711C7B918B708D577ACC2D006D23958AC393B5` |
| SSDEEP | `49152:73iOI/MWj+da1MDudnrWp4XmX0CjFlIP7PoE18a6teGeElCjPLO6rAvb:+OI/CdbudyX0WlZ4fzjO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_392a8919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392a891929839c17887143fe1125f845763335821a61b83cf6a2a291d79b1885"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:23"
  condition:
    hash.sha256(0, filesize) == "392a891929839c17887143fe1125f845763335821a61b83cf6a2a291d79b1885"
}
```

### Sample 7: `92b146eff8d54fff`

| Field | Value |
|---|---|
| SHA-256 | `92b146eff8d54fff90445bd258e0e5a42f1277e213b9fa0137c7ab5074c01a46` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-08-01 02:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05b59210318a43454ae46648ad6deadb` |
| SHA-1 | `774a6157c2f566d6507b1fce08fa1fd486725d91` |
| SHA-256 | `92b146eff8d54fff90445bd258e0e5a42f1277e213b9fa0137c7ab5074c01a46` |
| SHA3-384 | `c4b548e1c29df6781ae2406a885c9f7a2cb135192197146781bd58016feca671d23d8cad3ec44ac229602198a97e37d1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T198E6334C5DD006FEEAA3853CDEE20192A9AA7C364F31CDDB8790D6626C572E04C7D762` |
| SSDEEP | `393216:EJcUcFrddsj0kxTwW8VphpXPXMCHWUjTcuI3/PGTAI:EJJLxH8fhBXMb8QH/O7` |
| ICON-DHASH | `50f0d4d8d8e4f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_92b146ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92b146eff8d54fff90445bd258e0e5a42f1277e213b9fa0137c7ab5074c01a46"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 02:52:28"
  condition:
    hash.sha256(0, filesize) == "92b146eff8d54fff90445bd258e0e5a42f1277e213b9fa0137c7ab5074c01a46"
}
```

### Sample 8: `faf518894303e8ee`

| Field | Value |
|---|---|
| SHA-256 | `faf518894303e8eed32039d755927a3ccb42504f0ed2527a7cb7f05300900f98` |
| Family label | `Mirai` |
| File name | `xmr_miner_arm64` |
| File type | `elf` |
| First seen | `2026-08-01 02:26:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db57135458954fe78233fb877bbfe483` |
| SHA-1 | `5df69936d29ee81e80786398cf4b638a9dfd13db` |
| SHA-256 | `faf518894303e8eed32039d755927a3ccb42504f0ed2527a7cb7f05300900f98` |
| SHA3-384 | `3604cfcb7621320ba0843e7df50a54e023a328dd17203e799b1e4f3a9a0309c95487ac49426db229bbdaefa4b98ef6b7` |
| TLSH | `T195F2E71BE1A04D3DC8D4D131CA5BD22216B1A475EE32262F3A8862F73F8A75C497EF15` |
| TELFHASH | `t131e0c00566320f1acbd130306c0e47b16421c31784328b144f61c280647e04ef218d97` |
| SSDEEP | `768:VU+101TLD7zrjbTLD7zrjOm+WuGe2Om+WuGe2Om+WuGe2Om+WuGe25BpxZhJR5Bu:VU+vKE38PCmIP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_faf51889
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf518894303e8eed32039d755927a3ccb42504f0ed2527a7cb7f05300900f98"
    family = "Mirai"
    file_name = "xmr_miner_arm64"
    file_type = "elf"
    first_seen = "2026-08-01 02:26:42"
  condition:
    hash.sha256(0, filesize) == "faf518894303e8eed32039d755927a3ccb42504f0ed2527a7cb7f05300900f98"
}
```

### Sample 9: `a58ad957ea509d4b`

| Field | Value |
|---|---|
| SHA-256 | `a58ad957ea509d4bb8f3a0a274601df61d49e26a605ca2df559d7e7cf1d024c5` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-01 02:14:37` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b44a28b1ecdfbc123c404737740d1420` |
| SHA-1 | `8377dd64472b3a8557f470a52d91f4623c395e92` |
| SHA-256 | `a58ad957ea509d4bb8f3a0a274601df61d49e26a605ca2df559d7e7cf1d024c5` |
| SHA3-384 | `54e2df51f126807fb247dc58b1f821e2cfd633d66993389744b0082204314d2727ee2efa82222a68c779f8ea08e9a42c` |
| TLSH | `T1A6235C6516867C24AE98C4361C7E2F0CB9AD43E6324452EE7FCB3CF68C4A6ADD10971D` |
| SSDEEP | `768:u+T9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:u+0cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_a58ad957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a58ad957ea509d4bb8f3a0a274601df61d49e26a605ca2df559d7e7cf1d024c5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-01 02:14:37"
  condition:
    hash.sha256(0, filesize) == "a58ad957ea509d4bb8f3a0a274601df61d49e26a605ca2df559d7e7cf1d024c5"
}
```

### Sample 10: `436f164de1640f91`

| Field | Value |
|---|---|
| SHA-256 | `436f164de1640f910005be2aa5e9c0343abeca108d789273e7aa9703cd653b49` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-08-01 02:01:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `549facb387e166f1bfecfd17adf33d54` |
| SHA-1 | `b7f363ea1742be604a269658c49fc17909c9bc46` |
| SHA-256 | `436f164de1640f910005be2aa5e9c0343abeca108d789273e7aa9703cd653b49` |
| SHA3-384 | `d0709469dc6b5ecd66ec9debdff0b7440bfd269401ef8aeeb1a29452b63d5b5883f8df7a2db3133eff05b7f93ab6c3db` |
| TLSH | `T1ACE31956F8819B11D5C151BEFF0E128E73131B7CE2DE72129D24AB707B8A8BB0E3A515` |
| TELFHASH | `t1df114435cf6804dce3c9c04450df223e5ed8713e1e6414067ae1ab9ec1135e2b93d82e` |
| SSDEEP | `3072:1QsfiGl6QbwSbhttz4jaC+tHweKNk66CO5jTPXEvUK9Q:1QaiZkwCttzaavtQxq66CO53XEv3Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_436f164d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "436f164de1640f910005be2aa5e9c0343abeca108d789273e7aa9703cd653b49"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-01 02:01:31"
  condition:
    hash.sha256(0, filesize) == "436f164de1640f910005be2aa5e9c0343abeca108d789273e7aa9703cd653b49"
}
```

### Sample 11: `9f11e24531de2a3e`

| Field | Value |
|---|---|
| SHA-256 | `9f11e24531de2a3e5de458d335485805c725ca08ee27d60b66887676c36f0537` |
| Family label | `Mirai` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-08-01 02:01:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d40471aa330a6759937e5865b2dae1c0` |
| SHA-1 | `8c0ff7c24a247290a2e5b07990987814a57aae03` |
| SHA-256 | `9f11e24531de2a3e5de458d335485805c725ca08ee27d60b66887676c36f0537` |
| SHA3-384 | `2335beb6d4e93cb11f830fd084d7413ed3b7533ac2fe9458db098309cfb96ccfa6b9ab09a3a3b052226377550a4b698f` |
| TLSH | `T1FCD30A45F9404F17C6C265BBFF4E438D772A17A8D2EE72039A256F20379B95B0E3A142` |
| TELFHASH | `t1cc11f3a1465c58dd76f5834d52cfb1276a1e30fe2d361430be6eb7cec543ae51818809` |
| SSDEEP | `3072:yNhorO9tS34s3XyWhwedcga4bZAbwTZBr:yNupIKXyWhwEcglbG0TZBr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_9f11e245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f11e24531de2a3e5de458d335485805c725ca08ee27d60b66887676c36f0537"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-01 02:01:30"
  condition:
    hash.sha256(0, filesize) == "9f11e24531de2a3e5de458d335485805c725ca08ee27d60b66887676c36f0537"
}
```

### Sample 12: `b5fa45952fa3bb42`

| Field | Value |
|---|---|
| SHA-256 | `b5fa45952fa3bb422b1d85d52a6a29690837ec079b72c678f883221e83f96aea` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-01 01:58:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e163b085590e23a495c5f34770d76232` |
| SHA-1 | `77e38065a014df1a6f699e8fb4f05810ff09672b` |
| SHA-256 | `b5fa45952fa3bb422b1d85d52a6a29690837ec079b72c678f883221e83f96aea` |
| SHA3-384 | `264512754220ebce7cec8bc83b1837f590f7ac18c75e876bed078818c9b492549ec87cc0ea1f9ccbce5687cd91f18ee5` |
| TLSH | `T18304961A6F228FBDF268C73447F74A35975D23D627E1D684D2ACC1142F2029E641FBA8` |
| TELFHASH | `t13541a218097817b0a3756c9d49ddfb36d6a330da7f262c338e51e86aeb69a434d10c0c` |
| SSDEEP | `3072:n5yS5Sc6pcv3tHZfvaYuHvTh9eLvwRvajv77WXjXpc:n5yS5ScVftHcYU7nFv0fWX7pc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_b5fa4595
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5fa45952fa3bb422b1d85d52a6a29690837ec079b72c678f883221e83f96aea"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-01 01:58:21"
  condition:
    hash.sha256(0, filesize) == "b5fa45952fa3bb422b1d85d52a6a29690837ec079b72c678f883221e83f96aea"
}
```

### Sample 13: `efcf7d27639d35b7`

| Field | Value |
|---|---|
| SHA-256 | `efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de` |
| Family label | `unknown` |
| File name | `efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de` |
| File type | `sh` |
| First seen | `2026-08-01 01:56:19` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89681015d18fdd736bf3703a44aa73b1` |
| SHA-1 | `17445b7ed339944538124114645930efb8709ac8` |
| SHA-256 | `efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de` |
| SHA3-384 | `f511e87e9ad2566ff4fe86ce351e989208cea1af5baffe2d32acbf09e67832c57c1abd6f552c86941fd9533b951d1988` |
| TLSH | `T1F7B092E962761E80F0285A05709A1C51BA868AA595586A69F88848BACD49601F106B15` |
| SSDEEP | `3:TKH4vGBwkSDETLtWiL71u9GN3+GuVjLWgKoKWnQDFpKSbn:hBD6xXL7mGEjuXVDFbb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_efcf7d27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de"
    family = "unknown"
    file_name = "efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de"
    file_type = "sh"
    first_seen = "2026-08-01 01:56:19"
  condition:
    hash.sha256(0, filesize) == "efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de"
}
```

### Sample 14: `628e33326d90400f`

| Field | Value |
|---|---|
| SHA-256 | `628e33326d90400f5921db3d3d07d0b10779961a5ca5660a5689e65c0c6ef6c3` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-08-01 01:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9cc5822efd55adba42794e38c9926368` |
| SHA-1 | `5d47b8ecb38fbbb6b5efb828fa2f8f5279972c03` |
| SHA-256 | `628e33326d90400f5921db3d3d07d0b10779961a5ca5660a5689e65c0c6ef6c3` |
| SHA3-384 | `770f0846e07f0b959a9af2afb290005def867f8bc21aa97250450222872615571d0b0a2a826d8fab45b756eb41cfc258` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1F3E6338CEEF011EEEAB3913DEDE105A1E665B8762374C5DF061986A17E133E04C39B16` |
| SSDEEP | `393216:gFVaEc5cy3pxMTfI7tiXMCHWUjEcuI3/PGTAI:g7TmBJiXMb8RH/O7` |
| ICON-DHASH | `71f0e4d4e6e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_628e3332
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "628e33326d90400f5921db3d3d07d0b10779961a5ca5660a5689e65c0c6ef6c3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 01:52:33"
  condition:
    hash.sha256(0, filesize) == "628e33326d90400f5921db3d3d07d0b10779961a5ca5660a5689e65c0c6ef6c3"
}
```

### Sample 15: `4c7ac675d6469a80`

| Field | Value |
|---|---|
| SHA-256 | `4c7ac675d6469a808bdcc5feb6331e5771e7e221a357baf6a5617702076ffd6b` |
| Family label | `unknown` |
| File name | `don12089.hta` |
| File type | `hta` |
| First seen | `2026-08-01 01:50:40` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc3138f5d95ffc71195125413c33ad3b` |
| SHA-1 | `db8d98ea09e2af744bd106f8c44fa7619546ed1b` |
| SHA-256 | `4c7ac675d6469a808bdcc5feb6331e5771e7e221a357baf6a5617702076ffd6b` |
| SHA3-384 | `2f3e02fcaa9bdec6ca9707aefde796c3bdb497289dab60e183d07fa0353c89d9c366db839337d93b3eeadba9d169fb14` |
| TLSH | `T16F32F8DCFEE572A0F31303CE37AB292A122460D72008C5C5F98D9DE57F467998627A5A` |
| SSDEEP | `192:sXHNsGeTHQpD+da6+888+UV7tDoj/pxz25JYb5kq15HdtI74dthOO:sXX+/DV7k/325Wyqpt84dTOO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_4c7ac675
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c7ac675d6469a808bdcc5feb6331e5771e7e221a357baf6a5617702076ffd6b"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-08-01 01:50:40"
  condition:
    hash.sha256(0, filesize) == "4c7ac675d6469a808bdcc5feb6331e5771e7e221a357baf6a5617702076ffd6b"
}
```

### Sample 16: `bd841b12f1183e8f`

| Field | Value |
|---|---|
| SHA-256 | `bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87` |
| Family label | `unknown` |
| File name | `bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87` |
| File type | `sh` |
| First seen | `2026-08-01 01:50:02` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7524f4675c910ac0328d2f0e6ff01ab9` |
| SHA-1 | `3a89be0b7e0320c0265caeaa3a7146833988406a` |
| SHA-256 | `bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87` |
| SHA3-384 | `9cd44fc82632ac28faa6a2bd13715bc5a50c2f66f652c5a687648b8c895f0b3761c13ed02d87f1c3c6ef84ff96e37d36` |
| TLSH | `T14AA012C5067906C4C0144D0274B30D10B018814414008628984808378551701B102E05` |
| SSDEEP | `3:TKH4vGBwkSDETLtWiL73eaK+EOoz:hBD6xXL7LIz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_bd841b12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87"
    family = "unknown"
    file_name = "bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87"
    file_type = "sh"
    first_seen = "2026-08-01 01:50:02"
  condition:
    hash.sha256(0, filesize) == "bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87"
}
```

### Sample 17: `137696672595176c`

| Field | Value |
|---|---|
| SHA-256 | `137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94` |
| Family label | `Mirai` |
| File name | `137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94` |
| File type | `elf` |
| First seen | `2026-08-01 01:47:45` |
| Reporter | `c2hunter` |
| Tags | `elf, Mirai, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e9e80314352b15291281aecf037068f` |
| SHA-1 | `da640f173e8cb6c6cee6a73584ff8710179d0f59` |
| SHA-256 | `137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94` |
| SHA3-384 | `89ed35fc1b882bb25d80469112753213d2ab4a1f646d00faa5ae5a4296bb6a8780d2197d98e7eda51ea797daefed9b06` |
| TLSH | `T11E142B05E6404B53C0D327BAF7CB434A73239B54A7EB73059628ABB43BC679E5F22506` |
| TELFHASH | `t1df3142a9a23c81654db15c08ddad17b6444bd32217d0bb26ff1ac8cc582a80ee535d1f` |
| SSDEEP | `3072:enBrwO2vLsNGwJ3eTaEy+CC3KpWTF2E7I15uFxGHrM/RW6KQejQZGRuM:Kw1okwJuTaEy+CC6c85ujgrM/RrKoGgM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_13769667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94"
    family = "Mirai"
    file_name = "137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94"
    file_type = "elf"
    first_seen = "2026-08-01 01:47:45"
  condition:
    hash.sha256(0, filesize) == "137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94"
}
```

### Sample 18: `cd89fa8fe43679b7`

| Field | Value |
|---|---|
| SHA-256 | `cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55` |
| Family label | `unknown` |
| File name | `cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55` |
| File type | `sh` |
| First seen | `2026-08-01 01:47:43` |
| Reporter | `c2hunter` |
| Tags | `sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `682809e141e6c8066a7758cc4bff1a8f` |
| SHA-1 | `a40584d847775d9918dadc955e6cb67c714e7875` |
| SHA-256 | `cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55` |
| SHA3-384 | `4dc5e8d674c767a488ffcff010c56c99a8e86ce34147529240f9591c41fd8cd8ebf2ab349b160813bf257dc2aaeb9b4b` |
| TLSH | `T143E092E1B1F00BF1F0194E1BB3461D10A9CB0A7A0AA4B590E885BD776A2851AF106F32` |
| SSDEEP | `6:hJAcxX2xXL7RKB5DRF1E3FAsxXLXDIe+xXL7RKB5DIewbsrdun1oEQ:X2dL7RajF1cFjdLEe+dL7RaGeLduW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_018_cd89fa8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55"
    family = "unknown"
    file_name = "cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55"
    file_type = "sh"
    first_seen = "2026-08-01 01:47:43"
  condition:
    hash.sha256(0, filesize) == "cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55"
}
```

### Sample 19: `be93cf8050a0ec8b`

| Field | Value |
|---|---|
| SHA-256 | `be93cf8050a0ec8bc1d142cc6d3106cbcf80633217539a98dfc81f5239fb873a` |
| Family label | `unknown` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-08-01 01:46:22` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40a5a6f260f05774bc4a1fbe452036a9` |
| SHA-1 | `9bd2b49c43b189eef33393ff22eca9f746fd79e4` |
| SHA-256 | `be93cf8050a0ec8bc1d142cc6d3106cbcf80633217539a98dfc81f5239fb873a` |
| SHA3-384 | `c3c923630043e5d543b2d2b40b9a44cad025f16cc68c66102de5e1a1df21531c28f836d1ac6cab8b1247d5d65cbbfa20` |
| TLSH | `T173233962D6FA9D42CBE07A7A02F303E3C1DA9B144394DA1FDDD11FA58F46B108C56A9C` |
| TELFHASH | `t154f05944ed3d8e0e46e25d30cc7d5b51e1a3456352a08775df45d9c0493e514f219e1e` |
| SSDEEP | `768:7K+r9HH4nnn6WVkNAkr9HH4nnn/I9RN2ElJP01BFrOqCM7IqRBQGYtiOI1YS4a:7K+r9n4n6WM3r9n4ng932WJKBFrTRIqP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_be93cf80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be93cf8050a0ec8bc1d142cc6d3106cbcf80633217539a98dfc81f5239fb873a"
    family = "unknown"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-01 01:46:22"
  condition:
    hash.sha256(0, filesize) == "be93cf8050a0ec8bc1d142cc6d3106cbcf80633217539a98dfc81f5239fb873a"
}
```

### Sample 20: `59b08987027ffc89`

| Field | Value |
|---|---|
| SHA-256 | `59b08987027ffc89bf36cab40c252b784077ce810b606dd4cf411f2c727a66e4` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-08-01 01:36:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b918a5e3f2867f1953d9eee625d0713d` |
| SHA-1 | `94332dfa9e8138d5ca4a50088efb049f6c3062a9` |
| SHA-256 | `59b08987027ffc89bf36cab40c252b784077ce810b606dd4cf411f2c727a66e4` |
| SHA3-384 | `bfba8bec6ac90daa5d0fe1003debdd6787bad2657c9d869860d98e7cf6e99101d3742bea88bc810472d815ceea925b29` |
| TLSH | `T105C3F909AB614FFBE86FCD3746E90B0525CC551722A83F7A3574D828F64B64B4AE3870` |
| SSDEEP | `1536:FtJ6cGVoxBFf+g6z3jLH514RXJMneY0+YdW0OKh56HposWZ5uRrKnr1FWLlykhgO:XJ6cGVoJ6TnMX6HbWCZuqlzUK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_59b08987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b08987027ffc89bf36cab40c252b784077ce810b606dd4cf411f2c727a66e4"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 01:36:40"
  condition:
    hash.sha256(0, filesize) == "59b08987027ffc89bf36cab40c252b784077ce810b606dd4cf411f2c727a66e4"
}
```

### Sample 21: `8799a504a33507c9`

| Field | Value |
|---|---|
| SHA-256 | `8799a504a33507c9aa0e7e56990c564e3a73c9f5ae352704a635495ae620f547` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-08-01 01:35:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0ab467f7fc994500b6bae22ed3ad5aa` |
| SHA-1 | `35e014ba0c1b9079ffa4320521bbb9d6227b334a` |
| SHA-256 | `8799a504a33507c9aa0e7e56990c564e3a73c9f5ae352704a635495ae620f547` |
| SHA3-384 | `3330ea68a4cd6c117aa18e6e37a4ed4cd022bdf254cfd1aa6246650d52f70d1d345f8d82e00eccafb5ac4bfe36df4a47` |
| TLSH | `T10513F1AFCA08FAB7CC2C0D7E82E55F695944B4C062DD5FB55314C84CB22A8BD989D43B` |
| SSDEEP | `768:q9e/q30uxUxrhg4cy4tUhP2Dh0TvVNCZrroAHhwu1PkbWi:I2drhnJYUpuh0hN0Cu16` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_8799a504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8799a504a33507c9aa0e7e56990c564e3a73c9f5ae352704a635495ae620f547"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 01:35:47"
  condition:
    hash.sha256(0, filesize) == "8799a504a33507c9aa0e7e56990c564e3a73c9f5ae352704a635495ae620f547"
}
```

### Sample 22: `a21a25390ada2dcb`

| Field | Value |
|---|---|
| SHA-256 | `a21a25390ada2dcbc1b268a4ad45399e67af9e8bd540c9a313e1011e64229977` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-01 01:32:50` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1521e5ba67ca731ab86b379b6f31c76` |
| SHA-1 | `4a9db92d0fe5200082d11b13fd527ef82ad32bc4` |
| SHA-256 | `a21a25390ada2dcbc1b268a4ad45399e67af9e8bd540c9a313e1011e64229977` |
| SHA3-384 | `9180138a1780c13ebe47bc8a574d057a9e64bd771dfb2ccb26d033b211e8af6de272d5a904e997d0d29cd9fa5afb7487` |
| TLSH | `T114236C6516857C14AA98C4375C7E2F0CBDAD43E6314492EE7FCB3CF28C4AAAD920875D` |
| SSDEEP | `768:29NyXsZztCk9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:2HusZccr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_a21a2539
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a21a25390ada2dcbc1b268a4ad45399e67af9e8bd540c9a313e1011e64229977"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-01 01:32:50"
  condition:
    hash.sha256(0, filesize) == "a21a25390ada2dcbc1b268a4ad45399e67af9e8bd540c9a313e1011e64229977"
}
```

### Sample 23: `c23cb82c4e48e91f`

| Field | Value |
|---|---|
| SHA-256 | `c23cb82c4e48e91f71b389cb16d419510a15bd1ebd9b3e53a7fd8f38960745a5` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 01:31:47` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e33cd1b6164332e4b88287ec5a3a402b` |
| SHA-1 | `85957d0307ac37f5957a98bd4b8e8e6e7e471363` |
| SHA-256 | `c23cb82c4e48e91f71b389cb16d419510a15bd1ebd9b3e53a7fd8f38960745a5` |
| SHA3-384 | `4455fa7c3a814778ad8f8bb104f3f7e4275a684e5173ea46f35c6aec9c1455e4a76dc980db6335ace575459e4658179b` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T18236336968CBA17CC003CBB49D1379FD723E7B618461BC1A77CD2A505FAAD20953E782` |
| SSDEEP | `98304:5zSOB7+/SVObiG4xYyngKK02wN2L0glfALt4Jhe6yk5i9Dj:5nySYkxYyngKK8N2LzfALu3e05i9` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_023_c23cb82c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23cb82c4e48e91f71b389cb16d419510a15bd1ebd9b3e53a7fd8f38960745a5"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:47"
  condition:
    hash.sha256(0, filesize) == "c23cb82c4e48e91f71b389cb16d419510a15bd1ebd9b3e53a7fd8f38960745a5"
}
```

### Sample 24: `4cef725a2fd96211`

| Field | Value |
|---|---|
| SHA-256 | `4cef725a2fd962110be3b7ad4e01518a78d3bec24e7d078a5fbe1b35f38d9d2a` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 01:31:40` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cff3a9e9ad28ef4ed30af09ad3d55586` |
| SHA-1 | `a97365e84cc6c593aac2edf58dad704936177b38` |
| SHA-256 | `4cef725a2fd962110be3b7ad4e01518a78d3bec24e7d078a5fbe1b35f38d9d2a` |
| SHA3-384 | `f8a439f41d56907eb82bf931b737487bec6c7eef0ee156dc05642c7d19a1c785f201f58eb14a15b6c571c9cfdd0d61d4` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T15AD523CBB8B20938C47BC3B68F92F07EB01A77458B2A9D97769E6D408E134546C36771` |
| SSDEEP | `49152:0VAQsnJFqw4RJiLf6MoeOBM6mC72zLIFg0n7SLKRwvxsjvX5ygafusWE:4sJFq94MP3mWg07SLKRwv8RyhfFWE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_4cef725a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cef725a2fd962110be3b7ad4e01518a78d3bec24e7d078a5fbe1b35f38d9d2a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:40"
  condition:
    hash.sha256(0, filesize) == "4cef725a2fd962110be3b7ad4e01518a78d3bec24e7d078a5fbe1b35f38d9d2a"
}
```

### Sample 25: `a9c3e1b23a6a1020`

| Field | Value |
|---|---|
| SHA-256 | `a9c3e1b23a6a102016c0a8c35b198e4401bf75cb28e4ef8b9ddd5d0e93a09c5b` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 01:31:33` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75167ba41e8b6fc13574b3e67392052a` |
| SHA-1 | `cb965dfcf5164b65ab50844ddfbf311ed1d07a9b` |
| SHA-256 | `a9c3e1b23a6a102016c0a8c35b198e4401bf75cb28e4ef8b9ddd5d0e93a09c5b` |
| SHA3-384 | `e9a69966d834b5476daff9577af18314b693f7d789dc784f6ed1a49142a11182af88612f61c1b3b78aaa324ea2faa9d8` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T134D52289FDEB6670F472C7F747A321AC706A379446B44C5EB2D86B006E52528AC37339` |
| SSDEEP | `49152:C9YcUwTswSecahmiW5stBw3Ec1h99wn0ampZbHwjx1U7jDnQz4t6qXc:2TsVmTRaL1n9HfbHwN1Uf7QzV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_025_a9c3e1b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9c3e1b23a6a102016c0a8c35b198e4401bf75cb28e4ef8b9ddd5d0e93a09c5b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:33"
  condition:
    hash.sha256(0, filesize) == "a9c3e1b23a6a102016c0a8c35b198e4401bf75cb28e4ef8b9ddd5d0e93a09c5b"
}
```

### Sample 26: `6e67cde5f83e4a64`

| Field | Value |
|---|---|
| SHA-256 | `6e67cde5f83e4a64ba7a626f46240979a840163e1595b7219ee850fac6826444` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 01:31:22` |
| Reporter | `Bitsight` |
| Tags | `42d208560b5e968930dcedab3c2bf57b, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8b86395d8a22cd2a2c1390152967eec5` |
| SHA-1 | `0f2610beb966308b2724d4e92b7d80a2a061a865` |
| SHA-256 | `6e67cde5f83e4a64ba7a626f46240979a840163e1595b7219ee850fac6826444` |
| SHA3-384 | `94d684b2d095a8d620e1fde04d9cc6cfbb5e7b96e958ef730d826ddb7b3f8ac6c157a84d763d07d17596466ba6c2c1b8` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1B0D5235A7EF229B8C83BC7B24E92F87D716977818B718D4736CE69008D229446C3677C` |
| SSDEEP | `49152:6Yt35eXglox8v8XZotRBHCa8hu7DKPBP3mIxMeHSZc+Ta0mhtLBm/iQr:6YhKMo4via8hmDKptad6W` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_026_6e67cde5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e67cde5f83e4a64ba7a626f46240979a840163e1595b7219ee850fac6826444"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:22"
  condition:
    hash.sha256(0, filesize) == "6e67cde5f83e4a64ba7a626f46240979a840163e1595b7219ee850fac6826444"
}
```

### Sample 27: `bca1a1ab6f8af45d`

| Field | Value |
|---|---|
| SHA-256 | `bca1a1ab6f8af45dc8b855a33d9fd8bd1e2658903428933a23ddd266a94cd293` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-08-01 01:28:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `346a823dfd25c9ca3627aea29290b010` |
| SHA-1 | `84204134091e117a90a34af0ed82bd8761b75b79` |
| SHA-256 | `bca1a1ab6f8af45dc8b855a33d9fd8bd1e2658903428933a23ddd266a94cd293` |
| SHA3-384 | `ed0d5d8aa810688b26e33a0c76fced68548ad52b288a940c9a371d23fde13fd72e405d345f164f7a75db08a05a470e41` |
| TLSH | `T1ACC35A63CC296E6CC664D6B5B0708F792B53A661914B5FBE187BC3788083C8DF6057B8` |
| SSDEEP | `1536:X+hsbaO4pi43PhWlrlHfC5RK4V7l7BT/pHqQeB/deMWVbWe8lhX98EMO5:uSd4p5pe1fr4f5pHqQC1eMWVWDXOEF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_bca1a1ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca1a1ab6f8af45dc8b855a33d9fd8bd1e2658903428933a23ddd266a94cd293"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-01 01:28:30"
  condition:
    hash.sha256(0, filesize) == "bca1a1ab6f8af45dc8b855a33d9fd8bd1e2658903428933a23ddd266a94cd293"
}
```

### Sample 28: `000d6d9e36795845`

| Field | Value |
|---|---|
| SHA-256 | `000d6d9e36795845c30894f29e7c3be7db37e1127e0a1e2b3cfcebd45e9cd9e0` |
| Family label | `unknown` |
| File name | `i486` |
| File type | `elf` |
| First seen | `2026-08-01 01:26:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49e5c59818aa9de1822c6493a83e0926` |
| SHA-1 | `a15fc14ac1434df8d027e00d6d68ddf012cdf579` |
| SHA-256 | `000d6d9e36795845c30894f29e7c3be7db37e1127e0a1e2b3cfcebd45e9cd9e0` |
| SHA3-384 | `13dc3d618802203a10d97e57f426060b786e8168bdbba02b7e8bb42677da40433eb415e060ade9cf83777b6fc85a7471` |
| TLSH | `T103836D89F793E0F4DD4705B1106BB77E8B30DE125024DE6BDB94BD72AC32A02A11A76C` |
| TELFHASH | `t15c4126f62df908e8b3d05d0dd38e1be20e6cf13f5510b66647b2a84127e6f919166c38` |
| SSDEEP | `1536:mJPx87Gy00Ea/ZvmmvWFqnHoQWach2NUc31E+2QBweqZqr:mJZE/sa/RmmvWBVmC4/1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_028_000d6d9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "000d6d9e36795845c30894f29e7c3be7db37e1127e0a1e2b3cfcebd45e9cd9e0"
    family = "unknown"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-01 01:26:39"
  condition:
    hash.sha256(0, filesize) == "000d6d9e36795845c30894f29e7c3be7db37e1127e0a1e2b3cfcebd45e9cd9e0"
}
```

### Sample 29: `6ae2d6cbbd86fc97`

| Field | Value |
|---|---|
| SHA-256 | `6ae2d6cbbd86fc97aaf932ed79fb683e2d08abe278cd10d9a634d6be20f9946e` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-01 01:18:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a421ddb5ac8c7c312dbd021e5e06620` |
| SHA-1 | `7e2b23096ed3853d077ed0d1a071114cbe6735e8` |
| SHA-256 | `6ae2d6cbbd86fc97aaf932ed79fb683e2d08abe278cd10d9a634d6be20f9946e` |
| SHA3-384 | `4f2d753c87121afb785bc9501a5d9bcda616ae13d9fb1da5a617913aecac440cfc21e506d76dd65d95e24324a04cc637` |
| TLSH | `T1AA04E91AAF510EBBCCAFDE3701E90A0635CCA55722A43B353674D524F54BA4B4AE3C78` |
| SSDEEP | `3072:hdaIa6aKWyE0fKasTT53cZnnxOMQHFL3HFN7g1asTLJ:DaiWhBhTT5sFnxOpN1cDTL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_6ae2d6cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ae2d6cbbd86fc97aaf932ed79fb683e2d08abe278cd10d9a634d6be20f9946e"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-01 01:18:34"
  condition:
    hash.sha256(0, filesize) == "6ae2d6cbbd86fc97aaf932ed79fb683e2d08abe278cd10d9a634d6be20f9946e"
}
```

### Sample 30: `406a984d952108f1`

| Field | Value |
|---|---|
| SHA-256 | `406a984d952108f1d06e42046a354b4c279ea58b691a211209501cd073c180e3` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-08-01 01:15:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `569072236d990b9dedbaaee0693acc86` |
| SHA-1 | `87dfc02c2f3363d6dce2fcd41c8ec587af82aa08` |
| SHA-256 | `406a984d952108f1d06e42046a354b4c279ea58b691a211209501cd073c180e3` |
| SHA3-384 | `7987f49f9c7768d432e9c0f5afdc276133066c575665802d229a774fc82969777f074c56e06b531a20224a1bb430b861` |
| TLSH | `T1D8F319C7F900EAB6F809E3374853090AB130B7A244925A777257357FEC3E199157BE8A` |
| SSDEEP | `3072:aTrLgNLHffqiA8bySwH/JKC/fSUDdt01+ELrlVKjbiHLTrMnQej:mrsJCQbySm/Jt/f9DmBLr3LTwQej` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_406a984d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "406a984d952108f1d06e42046a354b4c279ea58b691a211209501cd073c180e3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-01 01:15:25"
  condition:
    hash.sha256(0, filesize) == "406a984d952108f1d06e42046a354b4c279ea58b691a211209501cd073c180e3"
}
```

### Sample 31: `6d99352ccf8ef3de`

| Field | Value |
|---|---|
| SHA-256 | `6d99352ccf8ef3dec20ee396418f4963722c0d65bdc88924a0eea9a42be7e49c` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-08-01 01:12:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3b0e2d866047ce737757a09121ceac63` |
| SHA-1 | `358544fa703944d6c5f0643146e96c3790233689` |
| SHA-256 | `6d99352ccf8ef3dec20ee396418f4963722c0d65bdc88924a0eea9a42be7e49c` |
| SHA3-384 | `a75a64e6eeda692c618aad7cddbce3a212e265a2d3d2c9b835ec3e631b5208a91374be9742b3f33c951a47abd49d5c2a` |
| TLSH | `T196C30649FD41AF01D5D635FEFA4E028933531BACE3FE7202AA245B2127CAA5B0F76505` |
| TELFHASH | `t1eef02473b6a125d827c4a38460ee631a48ec30aa1f12581182dd1f0bd553590b53fd26` |
| SSDEEP | `3072:8gf375D/g1qiv166MksagAwdTej/MkXEbKZSpUQN6T:8W7xhE1NDsagfdTej/jqKopUQN6T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_6d99352c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d99352ccf8ef3dec20ee396418f4963722c0d65bdc88924a0eea9a42be7e49c"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-01 01:12:26"
  condition:
    hash.sha256(0, filesize) == "6d99352ccf8ef3dec20ee396418f4963722c0d65bdc88924a0eea9a42be7e49c"
}
```

### Sample 32: `5ac57ece78df250d`

| Field | Value |
|---|---|
| SHA-256 | `5ac57ece78df250d7ced1a49a74b1084f7455d8559e50a8afc08439c5ac20f9f` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-01 01:06:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71b8f6861d497efd8ab16017560fcfb3` |
| SHA-1 | `8562a9866dca2355f5bcfb8dcd56adc329d9a700` |
| SHA-256 | `5ac57ece78df250d7ced1a49a74b1084f7455d8559e50a8afc08439c5ac20f9f` |
| SHA3-384 | `5785751604e13a638bdff2d1d62cd376fb88755ff788c97acbe3c9d616f2816e34649d9383984b56a020a950ba591ee9` |
| TLSH | `T17B145BA9BA0F6C41F1C2D3F9DE8C83E13A1735E3C7778971781212EDDAA39D95A90502` |
| SSDEEP | `3072:cpKuyvJ1bquJiwwRrTr3bidlS7JyGTiTpQ4MsHnoq:cQbvJZquJiwGr/3udI7JfWQ4xnoq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_5ac57ece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac57ece78df250d7ced1a49a74b1084f7455d8559e50a8afc08439c5ac20f9f"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-01 01:06:30"
  condition:
    hash.sha256(0, filesize) == "5ac57ece78df250d7ced1a49a74b1084f7455d8559e50a8afc08439c5ac20f9f"
}
```

### Sample 33: `318391f558f280af`

| Field | Value |
|---|---|
| SHA-256 | `318391f558f280af8e93bec63a3c85100fdf2a12343f6ac8b8ae9178f68a64ca` |
| Family label | `Mirai` |
| File name | `nz.spc` |
| File type | `elf` |
| First seen | `2026-08-01 01:06:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cebe7426b151711990ff0f49d3f1206` |
| SHA-1 | `9ecb3474c1096b107272fd3ec9a03b3544d03912` |
| SHA-256 | `318391f558f280af8e93bec63a3c85100fdf2a12343f6ac8b8ae9178f68a64ca` |
| SHA3-384 | `307a2cd7c23aac7c467d62ee9fdf9102717286431bf3b51e3335b2cef4a0fd2e37d415e67ee9ea6d1bb06967f8ca863c` |
| TLSH | `T1BD934922FD79193BC4C4A57722E34335F2F6478A24A88A1F7D610E8DBF2564022A77F5` |
| SSDEEP | `1536:nh6LzKznyY0IXsJEkrD+n+x9p/uFlyOuut1Wo95rIp//+AtSOtWK:h6Szn+Y/WoPr8Fb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_318391f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "318391f558f280af8e93bec63a3c85100fdf2a12343f6ac8b8ae9178f68a64ca"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-08-01 01:06:29"
  condition:
    hash.sha256(0, filesize) == "318391f558f280af8e93bec63a3c85100fdf2a12343f6ac8b8ae9178f68a64ca"
}
```

### Sample 34: `049ec70afdef0fa3`

| Field | Value |
|---|---|
| SHA-256 | `049ec70afdef0fa35e253e84c5323fae581db3b1159cc69f9ccd5cfc51536a12` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-01 01:05:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12f6fb6fb0df36cfd63b4918182a3301` |
| SHA-1 | `17b52127f3cd77f8dfc067ac87e0eb720109126f` |
| SHA-256 | `049ec70afdef0fa35e253e84c5323fae581db3b1159cc69f9ccd5cfc51536a12` |
| SHA3-384 | `48e1148266bffced691ac19b433f34430b09b02b701a4692acc4cbbf5f1118ed457a3c92c64c1ae3d42b499c88144b7b` |
| TLSH | `T16E836BC2B747D0F0F9160635217BEB364673E13E0069DA82D769DC32ED12641EB6A3AD` |
| TELFHASH | `t1f0312afb1f7e0cf8f3d0a850c31e5fd15a19e67b495136b54572982822abdc194bac38` |
| SSDEEP | `1536:dIEpuaRPFkawuFxDMHRTLzjRBbE3kcE4+LDVyfDlyOCBZ:dwaFkawyxDM9LzjbE3tEnfwAOCBZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_049ec70a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049ec70afdef0fa35e253e84c5323fae581db3b1159cc69f9ccd5cfc51536a12"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-01 01:05:41"
  condition:
    hash.sha256(0, filesize) == "049ec70afdef0fa35e253e84c5323fae581db3b1159cc69f9ccd5cfc51536a12"
}
```

### Sample 35: `d3e23fc669e19733`

| Field | Value |
|---|---|
| SHA-256 | `d3e23fc669e19733d228929d75aa4a4b1751f51ff1c37ab1a232830c46468e42` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-08-01 01:04:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73e10a5388b1cddb9d27f230b71c5218` |
| SHA-1 | `945632c172f09b7d7534aad63adbd897db668c51` |
| SHA-256 | `d3e23fc669e19733d228929d75aa4a4b1751f51ff1c37ab1a232830c46468e42` |
| SHA3-384 | `a77e04c0ea6138e8f6f40a8344ae08289c9829bd69fc432a2327693666f8dc6c81d915c19914c99e3e8b52937fbe4da5` |
| TLSH | `T18603F23B36ED07D5E935727855E72B7E0480321F90E9ABA4D6E5D02254A0F92763C3E1` |
| SSDEEP | `768:mAOfJjljkAJyWrt2zM8pAwiHQ7ECJHtUt0FjfPrOJrVC3XJqqpnbcuyD7UHQRja:POzQAsyt2zFpAwA7CJNUEPyiJJnouy81` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_d3e23fc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3e23fc669e19733d228929d75aa4a4b1751f51ff1c37ab1a232830c46468e42"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-01 01:04:37"
  condition:
    hash.sha256(0, filesize) == "d3e23fc669e19733d228929d75aa4a4b1751f51ff1c37ab1a232830c46468e42"
}
```

### Sample 36: `7f697ed4ca05f453`

| Field | Value |
|---|---|
| SHA-256 | `7f697ed4ca05f453a3d6ec8d8bdfd6cb70453e992a6daf2e2d4b08cdef618115` |
| Family label | `Mirai` |
| File name | `nz.m68k` |
| File type | `elf` |
| First seen | `2026-08-01 01:02:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `82da44c556166c7aa7891ae40617f033` |
| SHA-1 | `eefd8b4cff61eab7fee8a3c6490f7da06c018ad3` |
| SHA-256 | `7f697ed4ca05f453a3d6ec8d8bdfd6cb70453e992a6daf2e2d4b08cdef618115` |
| SHA3-384 | `ccd7d53859c1946ab34347f68f8e81125f6f276baf4281e789fc554349833092097cb8e908b3f03eaa7c277eb0c45de7` |
| TLSH | `T1E3A348D7F401DDBDF84ADB7B4453090AB131E3A20A831F36626BB967E8751981933F82` |
| SSDEEP | `3072:P+7JJsnct9P+PIMOe6pn3tuCZCg9EvVnC:P+7gct9wOXn3tDZuvVnC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_7f697ed4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f697ed4ca05f453a3d6ec8d8bdfd6cb70453e992a6daf2e2d4b08cdef618115"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-08-01 01:02:36"
  condition:
    hash.sha256(0, filesize) == "7f697ed4ca05f453a3d6ec8d8bdfd6cb70453e992a6daf2e2d4b08cdef618115"
}
```

### Sample 37: `b00dd207b70c2e65`

| Field | Value |
|---|---|
| SHA-256 | `b00dd207b70c2e6593aa6797d94cf023b41c5755da93787830dc15b383675b24` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-08-01 01:01:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac864c8da688a7e871618e9518ae8eb2` |
| SHA-1 | `2e5bbc040321d91d53e2ad31119262f06fb62624` |
| SHA-256 | `b00dd207b70c2e6593aa6797d94cf023b41c5755da93787830dc15b383675b24` |
| SHA3-384 | `a70a5a055d2c32244d51dd2a03e4b39de8c9350623db4d5e927252505fc7c2b0d41bd102ff5803daa7c542c0a5765b82` |
| TLSH | `T153837DC6E743C4F4E8528973217BE7328A73E53D102DEE83D769A932ED12501D66A39C` |
| TELFHASH | `t13f31a8f71eba5df8b7d06400d31e5b522969d67b186036625673c82022beed290bac39` |
| SSDEEP | `1536:bAxTtfhenc5SWTpCClxqVVk/13HWCsBjJe7s4TtAsV:bALIuSkpCClxq4/13HlsBdarp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_b00dd207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b00dd207b70c2e6593aa6797d94cf023b41c5755da93787830dc15b383675b24"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-01 01:01:47"
  condition:
    hash.sha256(0, filesize) == "b00dd207b70c2e6593aa6797d94cf023b41c5755da93787830dc15b383675b24"
}
```

### Sample 38: `c1abcf5afb316cd4`

| Field | Value |
|---|---|
| SHA-256 | `c1abcf5afb316cd4e384e8f7db4f08233850fd6a3bcf0e97c7504a6dea72b077` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-08-01 01:00:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4fe527879cb447894c4d1c3f2b5963b` |
| SHA-1 | `3888a2bf8f8a896d850ac8e340293916df232300` |
| SHA-256 | `c1abcf5afb316cd4e384e8f7db4f08233850fd6a3bcf0e97c7504a6dea72b077` |
| SHA3-384 | `287ecd7b1b4c3173329722dfdb3a9b74a7a0452d10d6131b1f8b9b2826512dec576620014203fd005db83a7afb552a19` |
| TLSH | `T19903F163D8FC4B50C51F513D108FB11F0E145697D83249A1D599A7B29FF2F9A6F182B0` |
| SSDEEP | `768:A5UcnRyjFbZGbR6AZTJa/z0hb0hxnKm6B2f60owOc+aHnbcuyD7UGQRj8:A5UoyjFbZGPwz0BeKfT0xOc+aHnouy8c` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_c1abcf5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1abcf5afb316cd4e384e8f7db4f08233850fd6a3bcf0e97c7504a6dea72b077"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-01 01:00:48"
  condition:
    hash.sha256(0, filesize) == "c1abcf5afb316cd4e384e8f7db4f08233850fd6a3bcf0e97c7504a6dea72b077"
}
```

### Sample 39: `12ee92d529a70427`

| Field | Value |
|---|---|
| SHA-256 | `12ee92d529a704272662846f7752c077141070067246a4a9028309cee67583d0` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-08-01 01:00:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcfdcbde7e0414492d82a7b084cdf7f1` |
| SHA-1 | `7b5d6035d0927e3d0c1882621a8e7406f7a910d6` |
| SHA-256 | `12ee92d529a704272662846f7752c077141070067246a4a9028309cee67583d0` |
| SHA3-384 | `4a8f0abff93bd8e0dbe8903c2d68956102b26f28b1eaeb07c2b1867f290d791fd86f948117c0cb85fea7446138efa7b0` |
| TLSH | `T118D34B06B71D0943E2633EF43B3F27E193DF9A8124E4E740251FAA8A9271D325586EDD` |
| SSDEEP | `1536:n4ODLHU7xnVw3JomQhgH0HFksumWTzcdGn/DD4TOuwOpvA/bNfYBvOdddmS1ebsi:4k+xVXmZHn/DkT7m/HQEspp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_12ee92d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12ee92d529a704272662846f7752c077141070067246a4a9028309cee67583d0"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-01 01:00:46"
  condition:
    hash.sha256(0, filesize) == "12ee92d529a704272662846f7752c077141070067246a4a9028309cee67583d0"
}
```

### Sample 40: `08e678b14630558b`

| Field | Value |
|---|---|
| SHA-256 | `08e678b14630558ba49781753227f1adc0534ea1d27ecf2b1c26a9eea89e23bb` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-08-01 00:52:32` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da217013547b09f4b6d27d40a2643f65` |
| SHA-1 | `f765764e06b3357f6e87f82df42a5bfe4848f44a` |
| SHA-256 | `08e678b14630558ba49781753227f1adc0534ea1d27ecf2b1c26a9eea89e23bb` |
| SHA3-384 | `d5b0065ce9a16e5d5fe8f7d6a9c39323f80ea803fda72be27b07612f2dc170868773bb0c3df4916009e7275f819276b1` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T175E633080FD11698F673423DEDD15258FB66B8B64BB2C6CF474047696F235B08E3A36A` |
| SSDEEP | `393216:cEVhe/VqQUAE8obrGHDBVhXMCHWUjzcuI3/PGTAI:c0e/R5EprMhXMb8wH/O7` |
| ICON-DHASH | `19dcf8f8dcf8e144` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_08e678b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08e678b14630558ba49781753227f1adc0534ea1d27ecf2b1c26a9eea89e23bb"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 00:52:32"
  condition:
    hash.sha256(0, filesize) == "08e678b14630558ba49781753227f1adc0534ea1d27ecf2b1c26a9eea89e23bb"
}
```

### Sample 41: `3eb3fb3db28bc496`

| Field | Value |
|---|---|
| SHA-256 | `3eb3fb3db28bc4963bf09b9c95da22d3955d642c18c2080bed9d93db7972dad5` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-08-01 00:51:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe4f6b7bd2f874a430d041f35bf8c1e4` |
| SHA-1 | `2cdb7d465bb009e967835c7637463a138c2a3301` |
| SHA-256 | `3eb3fb3db28bc4963bf09b9c95da22d3955d642c18c2080bed9d93db7972dad5` |
| SHA3-384 | `6b14a7723c9126720f9c2f3255e65d59eab326a45192f99d812c34fc9691ef937c7e68fba71bbb5c91f5342b9589592c` |
| TLSH | `T14183AD33C93A0E68E84845B4B0B18FB65763E51580972EF7495AC67AD083EDCF58A3F4` |
| SSDEEP | `1536:Ngynxf8zTGhxM4agiRkKpP7WNhC+RCaVmnjHy7:Nxnx3hUTRLpCXC+RD6s` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_3eb3fb3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eb3fb3db28bc4963bf09b9c95da22d3955d642c18c2080bed9d93db7972dad5"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-08-01 00:51:40"
  condition:
    hash.sha256(0, filesize) == "3eb3fb3db28bc4963bf09b9c95da22d3955d642c18c2080bed9d93db7972dad5"
}
```

### Sample 42: `61719f2880a07b53`

| Field | Value |
|---|---|
| SHA-256 | `61719f2880a07b5387e3717b1bb747feb715b8fcc0da3d06a9aa401c2aee3c2b` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-08-01 00:48:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc96df5b97062ab0c07d7615fbc69af7` |
| SHA-1 | `7990fa762904d4822a5c313de9577dd35a2bd9bc` |
| SHA-256 | `61719f2880a07b5387e3717b1bb747feb715b8fcc0da3d06a9aa401c2aee3c2b` |
| SHA3-384 | `5daf5f32d096678a6e173cf1513ca15b426ad7d920e945de7bd2f038aa46308b8df707236063b6cb6389af0d924d6638` |
| TLSH | `T1A48318C1BA4BC0F5D90748304067F33FCB32D6394061D66EEFAADE65EA73642522629D` |
| TELFHASH | `t19d312cfa297e0cfca7d45940935e1e623d29e77f29a076b046735834336be8150bac39` |
| SSDEEP | `1536:8l8IhK59kLMSb6kbzdWAc6HWiay3Tx9gorF6ShJ0l9:8/hU9ktbjdWnpwTx9dral9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_61719f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61719f2880a07b5387e3717b1bb747feb715b8fcc0da3d06a9aa401c2aee3c2b"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-01 00:48:46"
  condition:
    hash.sha256(0, filesize) == "61719f2880a07b5387e3717b1bb747feb715b8fcc0da3d06a9aa401c2aee3c2b"
}
```

### Sample 43: `266fe39ccb648475`

| Field | Value |
|---|---|
| SHA-256 | `266fe39ccb648475dc6706898a5c990818f85821c63ceb73e85aed90de29da53` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-01 00:48:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b281cd49bc86224d55a5ac372118c27` |
| SHA-1 | `f061f514a4a6d2a383db96e6d62da922be922e39` |
| SHA-256 | `266fe39ccb648475dc6706898a5c990818f85821c63ceb73e85aed90de29da53` |
| SHA3-384 | `02f926ada8d0076a954e0b6958d47a71c76b704901810d45ba9dedcfaff15195241f8c764ebdd1e95e5fbe0ea0bb35c6` |
| TLSH | `T1F1E34A1BB5C1C0FDC8D9C2B84BAAE227DE72B4295134B21E27D86E271F5DE205F6D610` |
| TELFHASH | `t10d5188b03d5e3c9431e77a2a6307d9a988350e6019e135c5ef72ade5ce223c82db5876` |
| SSDEEP | `3072:ZPZ0mPs2gFvTBr1d8Y+seZaU04BzJVMQq7FuTSE7:AuL/0yDTSE7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_266fe39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "266fe39ccb648475dc6706898a5c990818f85821c63ceb73e85aed90de29da53"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:48:43"
  condition:
    hash.sha256(0, filesize) == "266fe39ccb648475dc6706898a5c990818f85821c63ceb73e85aed90de29da53"
}
```

### Sample 44: `0c81a033bfeae782`

| Field | Value |
|---|---|
| SHA-256 | `0c81a033bfeae78241b0df416132c92652abaacb23d01562a2a9acd5aab37f4a` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-08-01 00:47:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46277063a198c1a7b60b1d9da0439b22` |
| SHA-1 | `0f35f97d95b24afc4ef38fc0507aa6b751d6cba6` |
| SHA-256 | `0c81a033bfeae78241b0df416132c92652abaacb23d01562a2a9acd5aab37f4a` |
| SHA3-384 | `d8a7304ad8ef0648e15b1204047228714d6fb131f8d8a146e35f038de8700ad725ab13039aef94b25cf40f3ac33ede35` |
| TLSH | `T1BE431893FD92469BC5C027B6B76F568933A267A5C2DF3323C8140B113BCA94F4E67A41` |
| TELFHASH | `t1a1f0c084fe764f1589e1a574dcbc0360e9436126a5625b20df52cad0883e149d30cd1d` |
| SSDEEP | `1536:PtwV7y6/F57DttbqE1CvEHNelefNKJBCZ:lwV7yEF57OX9l2Nq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_0c81a033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c81a033bfeae78241b0df416132c92652abaacb23d01562a2a9acd5aab37f4a"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:43"
  condition:
    hash.sha256(0, filesize) == "0c81a033bfeae78241b0df416132c92652abaacb23d01562a2a9acd5aab37f4a"
}
```

### Sample 45: `7524f4985f445fa1`

| Field | Value |
|---|---|
| SHA-256 | `7524f4985f445fa1bfeac4b889ae1c7d7de1e79d3c68a5f7768423852902c071` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-08-01 00:47:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd92a9854c12ebd0802c55b1583ba833` |
| SHA-1 | `5d2c41bbed6aab7d3d3d95df26739ddcaffd52c0` |
| SHA-256 | `7524f4985f445fa1bfeac4b889ae1c7d7de1e79d3c68a5f7768423852902c071` |
| SHA3-384 | `50c261ab1c800b263f79eaeb22da29550998c5102659673098bfbdcd58e0b6be9d8ca4b06c95a40eaf6c7f92bb1283e1` |
| TLSH | `T1B813F23AD589CBA8CA0D8171DBAA380724D4F018E939935D9EE81739CD9BF9D16302A1` |
| SSDEEP | `768:P6sry8pGtT5mZj3rJsLJCquQxFK7BnNs9SuneK4m27ssY8ZznbcuyD7UHQRj8:P6srMxubrSLsQxU/68BjZznouy8Hyg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_7524f498
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7524f4985f445fa1bfeac4b889ae1c7d7de1e79d3c68a5f7768423852902c071"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:27"
  condition:
    hash.sha256(0, filesize) == "7524f4985f445fa1bfeac4b889ae1c7d7de1e79d3c68a5f7768423852902c071"
}
```

### Sample 46: `6493187665a905b9`

| Field | Value |
|---|---|
| SHA-256 | `6493187665a905b9b197e0c31b25fbcd5c5b6e6bb0a5da8846aa46c441e406e9` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-01 00:47:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3eecabd8efd4499a6f3f3333092743ed` |
| SHA-1 | `5013cc9b4e723a2e0ae68d1b40931739b1710608` |
| SHA-256 | `6493187665a905b9b197e0c31b25fbcd5c5b6e6bb0a5da8846aa46c441e406e9` |
| SHA3-384 | `855ce74497fd98ded5dd3548c4c5cc5a1bf457d1f531a784e343e7628f728f9e410013b56009f44dc300ba3f89ec2566` |
| TLSH | `T12143F143A165B82DE5A7BA362A3C1DF8D9A33841B309514F319AF77E46630053FE2F11` |
| SSDEEP | `1536:BhSJMeLONyVvtBXJx5SfpruJEHmREss65JfVqleIWkrR:B0OotBXjqr8SsjX3a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_64931876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6493187665a905b9b197e0c31b25fbcd5c5b6e6bb0a5da8846aa46c441e406e9"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:26"
  condition:
    hash.sha256(0, filesize) == "6493187665a905b9b197e0c31b25fbcd5c5b6e6bb0a5da8846aa46c441e406e9"
}
```

### Sample 47: `44cf9c9f306e3134`

| Field | Value |
|---|---|
| SHA-256 | `44cf9c9f306e313493ccba99e676ae31832aa566b237860434815ced14f4cf54` |
| Family label | `Mirai` |
| File name | `nz.arm5` |
| File type | `elf` |
| First seen | `2026-08-01 00:47:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed46e4edf9b900e9234fcdda97f2754d` |
| SHA-1 | `54ee7f0a94e9aaacd527ae7d82804dcc688d5c77` |
| SHA-256 | `44cf9c9f306e313493ccba99e676ae31832aa566b237860434815ced14f4cf54` |
| SHA3-384 | `39bd6de08783b258f18696c9593b754272b29ec2c03fcaaf2dfb600e291677d21d201b0a3a6311a00b1b8ed74e06404a` |
| TLSH | `T177B2D0B077418AF0E6F0843BEF36C7526B89C674E1F97C51263028A555E21B626BE1E2` |
| SSDEEP | `768:GuryFciSNHH3vrUFGzNPVcM5AI/Ms3UozTF:GWyFAHH/rpDcMXJzTF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_44cf9c9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44cf9c9f306e313493ccba99e676ae31832aa566b237860434815ced14f4cf54"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:24"
  condition:
    hash.sha256(0, filesize) == "44cf9c9f306e313493ccba99e676ae31832aa566b237860434815ced14f4cf54"
}
```

### Sample 48: `02f8ce40a3e6af25`

| Field | Value |
|---|---|
| SHA-256 | `02f8ce40a3e6af2558da63721edcd4e25527e44fba26256c65aad9873636e320` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-08-01 00:46:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98ef14c3530595f99b70a736ddcd6770` |
| SHA-1 | `dce640e79dc7f139ef1cb2439ec7806e1d80846f` |
| SHA-256 | `02f8ce40a3e6af2558da63721edcd4e25527e44fba26256c65aad9873636e320` |
| SHA3-384 | `8f523fd20c662a6cc776998955216a18c7086c85f86b6e4fbd163a87126125a52f731c9da81c6660c8843f3c0a2e5c8f` |
| TLSH | `T1B8A31956FD818B61C6C116BAFA1E118E3313177CE2EE73129D146F2077CA96B0E7B846` |
| TELFHASH | `t170f09eba8514a4e9b3eb8299622d003807d471eb263432818feb7fdb245b0d9b61443f` |
| SSDEEP | `1536:d8nqNGSaII5sG0EodMqoorsGUuQWC5dmrateB1oV3UcdiHkghx5d+L769YVgw:ZGSaIjGloouzCXmratjQkgL5d+LG9E` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_02f8ce40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f8ce40a3e6af2558da63721edcd4e25527e44fba26256c65aad9873636e320"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-01 00:46:00"
  condition:
    hash.sha256(0, filesize) == "02f8ce40a3e6af2558da63721edcd4e25527e44fba26256c65aad9873636e320"
}
```

### Sample 49: `a555e7dc11151685`

| Field | Value |
|---|---|
| SHA-256 | `a555e7dc1115168594e7cbedfd1e41cb98d7d7daaee41002b9fe981a3cc16aa5` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-08-01 00:45:58` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `69489f3f0e69a590454bb07b9001c7b7` |
| SHA-1 | `09513414a8a9bc436a3ec7ca5e02138480b5b8d2` |
| SHA-256 | `a555e7dc1115168594e7cbedfd1e41cb98d7d7daaee41002b9fe981a3cc16aa5` |
| SHA3-384 | `329a5a61e3582c7411ee0f8233d146fa809c9b9907530d430daa522442fb73e5d7a1a4b6cbf33b97a98a5ac79d05074a` |
| TLSH | `T12A935D02B70C0E43D1675DF02A3F27D1D3EEA6E121F4F688691F9A8591B2E335586EC9` |
| SSDEEP | `1536:GFsCCOHrTgbrkoUV4SKUgZ5VvHfNa0Y0uM1y3pAzKYbqpSVMuXyCg7cA/kx3B9e:LROHrTZoUqk8wAzV9MVCEOe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_a555e7dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a555e7dc1115168594e7cbedfd1e41cb98d7d7daaee41002b9fe981a3cc16aa5"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:58"
  condition:
    hash.sha256(0, filesize) == "a555e7dc1115168594e7cbedfd1e41cb98d7d7daaee41002b9fe981a3cc16aa5"
}
```

### Sample 50: `b284282059d0cbf9`

| Field | Value |
|---|---|
| SHA-256 | `b284282059d0cbf9f7640624ae54b57018cd5d5e986002fff1bc5a34a8d2765d` |
| Family label | `Mirai` |
| File name | `arc` |
| File type | `elf` |
| First seen | `2026-08-01 00:45:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `390dd4faf0511b5319383a0a51e57e2d` |
| SHA-1 | `7d5d2f153722a0eb059cdbcb9a276fca65204020` |
| SHA-256 | `b284282059d0cbf9f7640624ae54b57018cd5d5e986002fff1bc5a34a8d2765d` |
| SHA3-384 | `08df065e8eb1f76098c3630ab5d03b2d796ff59a22d5d952ab361013d7e488d53d22e49186b3f654980840ec0a8eda7d` |
| TLSH | `T10CE3AF9BF64F1450C82506F81BC75BAD2A2325118E6B95E77C6E373E2A339DF28063D1` |
| SSDEEP | `3072:7FQW4VJUhXr2yvmJyzEteZnO4nGITTgZC5SgersQ0Mq:xQDaRxvmyEgZprTQC5orsaq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_b2842820
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b284282059d0cbf9f7640624ae54b57018cd5d5e986002fff1bc5a34a8d2765d"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:38"
  condition:
    hash.sha256(0, filesize) == "b284282059d0cbf9f7640624ae54b57018cd5d5e986002fff1bc5a34a8d2765d"
}
```

### Sample 51: `815fc69701ef8b1a`

| Field | Value |
|---|---|
| SHA-256 | `815fc69701ef8b1a35dc60bc6ea683fad70c176c26df68c2b65832510ce7bcc9` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-08-01 00:45:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f9badf65aad0509f29d3524bcb30c06` |
| SHA-1 | `f7b6ee92e60db8a4c47fd7c9d8340daf2021bc07` |
| SHA-256 | `815fc69701ef8b1a35dc60bc6ea683fad70c176c26df68c2b65832510ce7bcc9` |
| SHA3-384 | `436433456bddb26f83fcd31693778f8e517a55281c6e90d964be193350a23bfc87d2258226590301ff886c0301bb2440` |
| TLSH | `T187130274D2FCACF1C538593C9E1AE18285ABA7FCD95B245306A910C161C790BFFB8687` |
| SSDEEP | `768:iganv+60ZMMxOUXkNPdIgLwV8GNcYH7Xb10r/ddUMDoVsnYCBwn1+9q3UEL5f:bav+6xMYUWZmNcA1ed/8WnfenNLl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_815fc697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815fc69701ef8b1a35dc60bc6ea683fad70c176c26df68c2b65832510ce7bcc9"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:37"
  condition:
    hash.sha256(0, filesize) == "815fc69701ef8b1a35dc60bc6ea683fad70c176c26df68c2b65832510ce7bcc9"
}
```

### Sample 52: `f28ff115079db6cd`

| Field | Value |
|---|---|
| SHA-256 | `f28ff115079db6cd81b52775a337d2f694b53d130a2c1e52a247585c55ef7e71` |
| Family label | `Mirai` |
| File name | `nz.ppc` |
| File type | `elf` |
| First seen | `2026-08-01 00:45:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d60105c1eb43ec3f7eff025924966220` |
| SHA-1 | `31e10119b42a6ecc9125dabb88e27d7f52f04c56` |
| SHA-256 | `f28ff115079db6cd81b52775a337d2f694b53d130a2c1e52a247585c55ef7e71` |
| SHA3-384 | `acacc9345ace36f829fdcc0d099fb3c99d3cbedb76b0b7e0b1a434915086a1d640724f9b5ab1f2bda4abb7f0e191386e` |
| TLSH | `T1FD03E160E25E0F2EDFAFD4BD8F94E7D63BDA4AE563D1CD7040959201100B825BA5CEC6` |
| SSDEEP | `768:M9mIAsqqVUkJ96hb61ysYZNDkn9fj3yu92Pj0P+D65NeOD4uVcqgw0Ip:UmIJqqVbyVZQ9LyA+D6beOD4u+qgw0Ip` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_f28ff115
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f28ff115079db6cd81b52775a337d2f694b53d130a2c1e52a247585c55ef7e71"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:35"
  condition:
    hash.sha256(0, filesize) == "f28ff115079db6cd81b52775a337d2f694b53d130a2c1e52a247585c55ef7e71"
}
```

### Sample 53: `88846e7c0ddb5563`

| Field | Value |
|---|---|
| SHA-256 | `88846e7c0ddb5563fbba2056644aa06f629450bb805cc518c3eb2d3b66e9668e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-01 00:45:34` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d71bc1ea9445fa7fe103a6d1d111ac35` |
| SHA-1 | `992d536a8cb795b708d7cef73bb55768e1541f26` |
| SHA-256 | `88846e7c0ddb5563fbba2056644aa06f629450bb805cc518c3eb2d3b66e9668e` |
| SHA3-384 | `ef9ad85a511ac492deee64bd9e7d3ec1dbbec02fabcb66c1739f92a381a5af20e58abd47bbc19dca055cdca85bce8b7f` |
| TLSH | `T149C27D956A867C44BEC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:j8vCB+25j6es8RtE9FYpMSUpi+20qUpi+20YQX:j8l25Jtid2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_88846e7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88846e7c0ddb5563fbba2056644aa06f629450bb805cc518c3eb2d3b66e9668e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-01 00:45:34"
  condition:
    hash.sha256(0, filesize) == "88846e7c0ddb5563fbba2056644aa06f629450bb805cc518c3eb2d3b66e9668e"
}
```

### Sample 54: `f774f92ea7a3c5c2`

| Field | Value |
|---|---|
| SHA-256 | `f774f92ea7a3c5c2ddf1275b869a3204a2c9fe7a16d96484f0ff4fa355185fa3` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-08-01 00:44:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35b079eb7047b4df2bba40ebf78fb92d` |
| SHA-1 | `f746aeaecb691dac23870102bc07920070bcad5d` |
| SHA-256 | `f774f92ea7a3c5c2ddf1275b869a3204a2c9fe7a16d96484f0ff4fa355185fa3` |
| SHA3-384 | `bb9d2e55efda811902a5a6989746b02a4eb229cfe84ff40b203f890aeddbd66cca1e35f45f0acec49a48dce520c16047` |
| TLSH | `T15A932952FD814622C6C116B7FB6E428E376613A8E2EE3203DD255F2137CB95B0E7B542` |
| TELFHASH | `t175510efbeb950adc5bd7d284828f51094aec31fd1f083495d608bb4f8582682f62c837` |
| SSDEEP | `1536:S5tDkgSzvqbjFISR0szkdU4zgt9HSkijrPCHCjQlZtQ2v2aJc:S5tDkgUqbjFlV4zsJNijrIC4Fvc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_f774f92e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f774f92ea7a3c5c2ddf1275b869a3204a2c9fe7a16d96484f0ff4fa355185fa3"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-01 00:44:36"
  condition:
    hash.sha256(0, filesize) == "f774f92ea7a3c5c2ddf1275b869a3204a2c9fe7a16d96484f0ff4fa355185fa3"
}
```

### Sample 55: `1460d31f0473b71f`

| Field | Value |
|---|---|
| SHA-256 | `1460d31f0473b71fddf08c397d9cdbad8986b1bef2addbd9e7b9ceeb301280da` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-08-01 00:43:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15d50f94b9a03b3e5576e3f9a8f6bdba` |
| SHA-1 | `1206c81451c75be5b494d29ec72f9ceec7f71573` |
| SHA-256 | `1460d31f0473b71fddf08c397d9cdbad8986b1bef2addbd9e7b9ceeb301280da` |
| SHA3-384 | `93de4794d178b2919ba974096f160f2733f7d70da9fe348f637fb17834da05e38054076268b18f2d1e4a7940c2ed546d` |
| TLSH | `T1EC13F1734919DEB6DCB1DD71EAE516C3802A27FC14FA31331D100638B96649FA8EC56B` |
| SSDEEP | `768:VUpYuVm+KmSuB/x/fsN/cIJZkrxjurJvPcXjaYf6Ys3UozC:qDgmjxH/IJsurJvP4fQzC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_1460d31f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1460d31f0473b71fddf08c397d9cdbad8986b1bef2addbd9e7b9ceeb301280da"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-01 00:43:34"
  condition:
    hash.sha256(0, filesize) == "1460d31f0473b71fddf08c397d9cdbad8986b1bef2addbd9e7b9ceeb301280da"
}
```

### Sample 56: `eddbb347628295fe`

| Field | Value |
|---|---|
| SHA-256 | `eddbb347628295fe95ed818e7b28543562d2cf35c30077f5dd16da4af3ff30df` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-01 00:41:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03f6a7c870f1d1cf4547368d05db5af6` |
| SHA-1 | `99a62953b92a138555eb56fd1bded24a1d3a1ef8` |
| SHA-256 | `eddbb347628295fe95ed818e7b28543562d2cf35c30077f5dd16da4af3ff30df` |
| SHA3-384 | `5ea458e39275678673957c0424af23328183b93edba5bcfa8977ee811bdc8c2226bb7bbcadde91d98adad9ab21d63572` |
| TLSH | `T1D4C27D956A867C44BEC94A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:38vCB+25j6es8R69FYpMSUpi+20qUpi+20YQX:38l25Jsd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_eddbb347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eddbb347628295fe95ed818e7b28543562d2cf35c30077f5dd16da4af3ff30df"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-01 00:41:39"
  condition:
    hash.sha256(0, filesize) == "eddbb347628295fe95ed818e7b28543562d2cf35c30077f5dd16da4af3ff30df"
}
```

### Sample 57: `5c9bc93846185fc3`

| Field | Value |
|---|---|
| SHA-256 | `5c9bc93846185fc378415ead23a05c91bc200d1b76f53166999637de7d21627d` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-08-01 00:40:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `520adc036a757a2f45d5ca75c21c09cb` |
| SHA-1 | `6f221012508d684b00a7121e399ad5ab27c4c211` |
| SHA-256 | `5c9bc93846185fc378415ead23a05c91bc200d1b76f53166999637de7d21627d` |
| SHA3-384 | `89e39f874045c798ad3f9118baf6fd01b1d06dfcb968548a8583428902d9797a21eabd19478b56a36770a2bb58d0a2db` |
| TLSH | `T1D9935B13B9C480FCC849C13087AFB536D963F17E1279B29B73D4EA167E8DE511E6A680` |
| TELFHASH | `t1ab3104b279aa1c90e0ebe9a6b307f1e918350d2005e136f5e9b294f3ef053d54d72856` |
| SSDEEP | `1536:Ac50J45j1WS60TXxMsQa8v6ZyxAwuV1h1ss6fuf55nulEJHWI5:Rf5j1W0TXxZ8uyx4V1h1ss6fS5ncEI6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_5c9bc938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c9bc93846185fc378415ead23a05c91bc200d1b76f53166999637de7d21627d"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:40:48"
  condition:
    hash.sha256(0, filesize) == "5c9bc93846185fc378415ead23a05c91bc200d1b76f53166999637de7d21627d"
}
```

### Sample 58: `6764fb212852e563`

| Field | Value |
|---|---|
| SHA-256 | `6764fb212852e563b0e5e32966f60d05e7e0277cd0e526b32d4c976647372578` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-08-01 00:40:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `194f5735b6a66dfcbf29840c30f13025` |
| SHA-1 | `b9d02433318fd36416006458ae135c3e0fafbf34` |
| SHA-256 | `6764fb212852e563b0e5e32966f60d05e7e0277cd0e526b32d4c976647372578` |
| SHA3-384 | `6d4c1ffc00cc6fa94d6aa283305b474c4f9430f54b9df9585a1e0d2a79c44c5a67714368accaf81567fa9014357e66e2` |
| TLSH | `T1FE13E0ABD137EC32C477B6719B4E4390FF3A2882AA7196AB0D4D19FC090788ABD55704` |
| SSDEEP | `768:dA1khiEVA0waLOirChqyXKe27OarICuNCr3BGkD/Nxx233AYx0Qb:dOEVJy0iB6eOzr9zckJxx2RTb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_6764fb21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6764fb212852e563b0e5e32966f60d05e7e0277cd0e526b32d4c976647372578"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:40:19"
  condition:
    hash.sha256(0, filesize) == "6764fb212852e563b0e5e32966f60d05e7e0277cd0e526b32d4c976647372578"
}
```

### Sample 59: `c1e61d32bd277091`

| Field | Value |
|---|---|
| SHA-256 | `c1e61d32bd277091cf92647cabec47cf3c56d28d7eef2e5b1b95e486f587eea6` |
| Family label | `Mirai` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-01 00:40:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9d51a04c326c34721a2b61c87baa553` |
| SHA-1 | `889d93bc01503fdc6b05c6886cfebd6c9bd6685d` |
| SHA-256 | `c1e61d32bd277091cf92647cabec47cf3c56d28d7eef2e5b1b95e486f587eea6` |
| SHA3-384 | `1813a877c81b4bc49a36bb4902e9b1842f057eb4c40e41a7b085145f8e58660b534b4312013bf03f3c6d08eca27f32d0` |
| TLSH | `T176D30845FC409F17CAC265BBFB5E438D772A1758D3EE72039A256F20378B85A0E3A142` |
| TELFHASH | `t1b811c064ca1404ec39d5d20d54bf611b46d939ba2e3a3425aeacf91ed1a3dd1a12803e` |
| SSDEEP | `3072:yJOhbTdCxd9NcgmEYIw87lzPuJ9q07nOljf:yJQFYL2PEYIwwlzmJk0LOljf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_c1e61d32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e61d32bd277091cf92647cabec47cf3c56d28d7eef2e5b1b95e486f587eea6"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-01 00:40:18"
  condition:
    hash.sha256(0, filesize) == "c1e61d32bd277091cf92647cabec47cf3c56d28d7eef2e5b1b95e486f587eea6"
}
```

### Sample 60: `c2be6ac32851aa53`

| Field | Value |
|---|---|
| SHA-256 | `c2be6ac32851aa53fd921a7dadc1b5470f0a649b8555ff8606853127db855f2c` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-08-01 00:37:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8e731432520e0bb46f196931e81d073` |
| SHA-1 | `d167c65c3d60f704d0396f86cb2e6858721c900e` |
| SHA-256 | `c2be6ac32851aa53fd921a7dadc1b5470f0a649b8555ff8606853127db855f2c` |
| SHA3-384 | `14c9eb33d9bc3df981089c74b5bfd205d59e7022d624a607193b1e2eef1d47defe3c5c3de76079b80479abbe81a81628` |
| TLSH | `T1F5043B46EA404B13C4D32B7ABA9B424633239B64D3EB730699187FF43F8679E4E67501` |
| TELFHASH | `t1c2314e75673994046fa1c864dcfc57b2551b87130784ae32cf3bc8cc181a08ee62ac0f` |
| SSDEEP | `3072:J2PZAbx9v3raBbPUaqNe9k09mNFpGZPvMirZQAM/9BDKpgS:JOZATPraBbPUaqNL090pkP0irZnM/9BA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_c2be6ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2be6ac32851aa53fd921a7dadc1b5470f0a649b8555ff8606853127db855f2c"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:32"
  condition:
    hash.sha256(0, filesize) == "c2be6ac32851aa53fd921a7dadc1b5470f0a649b8555ff8606853127db855f2c"
}
```

### Sample 61: `25ac6e121f01285a`

| Field | Value |
|---|---|
| SHA-256 | `25ac6e121f01285a41d461ca3f5a38b14a7c8148219ccbe270fe52d90c2f104b` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-08-01 00:37:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b934f609340b5bfdb98e3ec8469b50b8` |
| SHA-1 | `48dc9391f1d900fa0de4cdbef2ae385a36ef512d` |
| SHA-256 | `25ac6e121f01285a41d461ca3f5a38b14a7c8148219ccbe270fe52d90c2f104b` |
| SHA3-384 | `bfb0856693bc0da79d0420f3ddbd6943a4bc19127affdc34e74778529862409f6fbd235a811ce80ddd375cd277e1fac5` |
| TLSH | `T1AD13F138E507089FE9D591B91B68A3330E1407A2F94BFC51E2A8D17BAB845777863DF0` |
| SSDEEP | `768:EJH/2hEQv3U7JTuzqzgxoehGqe/aJNtdZ6JRmC8DSbmjidlF2IJgGlzDpbuR1JO:E1ed3U7ibx3h+gNScCvbXd32IVJuA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_25ac6e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25ac6e121f01285a41d461ca3f5a38b14a7c8148219ccbe270fe52d90c2f104b"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:24"
  condition:
    hash.sha256(0, filesize) == "25ac6e121f01285a41d461ca3f5a38b14a7c8148219ccbe270fe52d90c2f104b"
}
```

### Sample 62: `b419f6e0ab5e13bb`

| Field | Value |
|---|---|
| SHA-256 | `b419f6e0ab5e13bbab3bbba935a46020e40da4acfa3112fd3c0e9b2cbe268686` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-08-01 00:37:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `753d12cbd8dca39528136bbe9bf437be` |
| SHA-1 | `d6160a095c2171836d98d0a34a2675455080fba7` |
| SHA-256 | `b419f6e0ab5e13bbab3bbba935a46020e40da4acfa3112fd3c0e9b2cbe268686` |
| SHA3-384 | `11afdfdbfc70e461be051db1e66b4dd30ee1b9e399cd9295f68d66408b31192d285a6711e61583d6dd5b3b3af6a204f9` |
| TLSH | `T1C263F141D020ADEE4E7424B5D72A4DC6A70C1DB8533232F31267A5927DFD9CAF2ADC4A` |
| SSDEEP | `1536:N1dNN8zdeop8GHQQw7I5fwCpzAkSntLeMNrKnuYXMa8pceX:N7NN8zdPDwOfwC9AkSntLeMp8uVa82g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_b419f6e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b419f6e0ab5e13bbab3bbba935a46020e40da4acfa3112fd3c0e9b2cbe268686"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:22"
  condition:
    hash.sha256(0, filesize) == "b419f6e0ab5e13bbab3bbba935a46020e40da4acfa3112fd3c0e9b2cbe268686"
}
```

### Sample 63: `e4a65dd53b6c3ad3`

| Field | Value |
|---|---|
| SHA-256 | `e4a65dd53b6c3ad3eaead696093c360196f75165ce98ddd75bf164b9c4a2af52` |
| Family label | `Mirai` |
| File name | `nz.arc` |
| File type | `elf` |
| First seen | `2026-08-01 00:37:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62a3614f71ce2683f1e2b26ec81dc4b5` |
| SHA-1 | `fb59320a5674b82ff8fd36d2caf7caeb50ab0f69` |
| SHA-256 | `e4a65dd53b6c3ad3eaead696093c360196f75165ce98ddd75bf164b9c4a2af52` |
| SHA3-384 | `a0c0c0c98dda1445d99e3dd834e0edbd36d8e86e551d690c7a910c5e5f748f46284d1dc74fc46d8f6c569b39ed51b572` |
| TLSH | `T1D0C3AEC3FA8714A1C46206F007C71BAE2F93A221CE5FD4E7AC1DB53B5A7A4DA1516781` |
| SSDEEP | `1536:crMjtT/2h9gFinjVljXgPnlWuoPJUmEBYLlJYqFccxs5tFgRCE3/LWJ:crWT/i91XgPln+HEBYLgqFcVgBq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_e4a65dd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4a65dd53b6c3ad3eaead696093c360196f75165ce98ddd75bf164b9c4a2af52"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:21"
  condition:
    hash.sha256(0, filesize) == "e4a65dd53b6c3ad3eaead696093c360196f75165ce98ddd75bf164b9c4a2af52"
}
```

### Sample 64: `11621978916ef99d`

| Field | Value |
|---|---|
| SHA-256 | `11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726` |
| Family label | `Stealc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-01 00:18:11` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX6.file, Stealc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9c1bee9ed7cc87bf6a874b71fea8e178` |
| SHA-1 | `5260b728d1027219cd355b9ded2110897923d00c` |
| SHA-256 | `11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726` |
| SHA3-384 | `151438335252883627458224cdcf431848636bcc9fefc3829b03a176b73db293e02d15f35637b44470eb22d142501931` |
| IMPHASH | `013c74198fc6e42dcf33737d6c40c012` |
| TLSH | `T117A5235386E78C5AE4266734CEE245978732BDA5C668ABDF13E03E8E1F724C1B430752` |
| SSDEEP | `49152:ojYejNFHEFG95gGupygLmV51WPvpLINbmFTtOCYop:ojYeRCA5gGupyh5WvpLIN6TtOCRp` |
| ICON-DHASH | `f1c0eae9d5d0d870` |

#### Technical Assessment

- The sample is tracked as `Stealc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Stealc_064_11621978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 00:18:11"
  condition:
    hash.sha256(0, filesize) == "11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726"
}
```

### Sample 65: `a7f3f9d9d1443772`

| Field | Value |
|---|---|
| SHA-256 | `a7f3f9d9d14437727b3f75617fd2e469af27180be54b90c5a47387f30ba426a7` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-08-01 00:15:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e867ff01638fdf4861b292a19452de7` |
| SHA-1 | `3e7a1efc18b875c9d0bf474ecbe8c6d0885dea7a` |
| SHA-256 | `a7f3f9d9d14437727b3f75617fd2e469af27180be54b90c5a47387f30ba426a7` |
| SHA3-384 | `59895ee2dc83ee28ffa0b2b45521addb8511020e85324930424c8c5d2c01ab82e2e32e0088ea255047c06ccb5e72ddbc` |
| TLSH | `T1C9B3E709EF611EF7E8AFCD370AF9270124CD592A22A97F757530D818B24A28F15E3974` |
| SSDEEP | `3072:bdub7djS5HEC8VQb1KhRhFczcmVRh865xH:bdo7djS5EC3KozcmVRbH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_a7f3f9d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7f3f9d9d14437727b3f75617fd2e469af27180be54b90c5a47387f30ba426a7"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 00:15:54"
  condition:
    hash.sha256(0, filesize) == "a7f3f9d9d14437727b3f75617fd2e469af27180be54b90c5a47387f30ba426a7"
}
```

### Sample 66: `ba059b885edb94a1`

| Field | Value |
|---|---|
| SHA-256 | `ba059b885edb94a1863a5e3989c6ab4dfa2afbeac9da0ed26208305223244591` |
| Family label | `Mirai` |
| File name | `nz.mpsl` |
| File type | `elf` |
| First seen | `2026-08-01 00:14:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `165406a6d7e0ed09d234c71b3f2042df` |
| SHA-1 | `53ba261f3ee4447bc2cfb094a44243b84abe2793` |
| SHA-256 | `ba059b885edb94a1863a5e3989c6ab4dfa2afbeac9da0ed26208305223244591` |
| SHA3-384 | `fa9927eba5979bbf4373d219bab09044833a5600da798dd55f6013c4a17386941ce2972472641065b1df0f903d4db1e1` |
| TLSH | `T1A913E1EFD184781ACD38ACFAD45D07B15549A1C153FB886933689C889B5AD8BE2C90BC` |
| SSDEEP | `768:Ox4mYFaluq7c2hrjYJO5AhCA7ks2Q4kUx8mV8koVL7BJoBOD9ophS44+eWH8:OxhYYuqYZJOFE2T2k8/oQ8heG8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_ba059b88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba059b885edb94a1863a5e3989c6ab4dfa2afbeac9da0ed26208305223244591"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 00:14:36"
  condition:
    hash.sha256(0, filesize) == "ba059b885edb94a1863a5e3989c6ab4dfa2afbeac9da0ed26208305223244591"
}
```

### Sample 67: `8d423e57b2cf148c`

| Field | Value |
|---|---|
| SHA-256 | `8d423e57b2cf148ce393b09c1c67540f591af26b242ec428b4b7986a17fadf30` |
| Family label | `NanoCore` |
| File name | `36DB027CB081301ECED5FE08F94EE9EA.exe` |
| File type | `exe` |
| First seen | `2026-08-01 00:05:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36db027cb081301eced5fe08f94ee9ea` |
| SHA-1 | `1ae40493dea3f1e16aea0db764ce3a8356150050` |
| SHA-256 | `8d423e57b2cf148ce393b09c1c67540f591af26b242ec428b4b7986a17fadf30` |
| SHA3-384 | `f3df41c20a73d4ae962ec8e6c52508d428baf7c270df1d07f01ca5864dc83dbadbcaf5a923484c3f4c8eb28daa07cd1f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16614CF5677A88A2FE2DE86B9711251128379C2E399C3F3DE58D464F78F227E106071E3` |
| SSDEEP | `6144:MLV6Bta6dtJmakIM5U0cFHkf8wa3PNMGd6:MLV6BtpmkjrH3wKlMGY` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_067_8d423e57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d423e57b2cf148ce393b09c1c67540f591af26b242ec428b4b7986a17fadf30"
    family = "NanoCore"
    file_name = "36DB027CB081301ECED5FE08F94EE9EA.exe"
    file_type = "exe"
    first_seen = "2026-08-01 00:05:06"
  condition:
    hash.sha256(0, filesize) == "8d423e57b2cf148ce393b09c1c67540f591af26b242ec428b4b7986a17fadf30"
}
```

### Sample 68: `73cf812efdeafd90`

| Field | Value |
|---|---|
| SHA-256 | `73cf812efdeafd903ef09c847457477950fa2b048c7b592e040c467a2082d091` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 23:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acf824eb101c56f21b2e2aff72f8f414` |
| SHA-1 | `2b15f3ffdd8175271e261af3279798af767ce247` |
| SHA-256 | `73cf812efdeafd903ef09c847457477950fa2b048c7b592e040c467a2082d091` |
| SHA3-384 | `4c27b20a95731ae286a975e42841b5c5286aa69f43b3d530e2e333218774fc89fc330900eb5680c7c4d9bc40c5fbdeea` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T142E6339C9AD042FEEA63523DDDE20A52D464B8715B31C5EB57E84BB25D132E00E3E723` |
| SSDEEP | `393216:PnGwoxTg/R/rbtbrjpJ+jPNpHDtXMCHWUjCcuI3/PGTAI:PEi/ftbrdJ+HjtXMb8/H/O7` |
| ICON-DHASH | `3471f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_73cf812e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73cf812efdeafd903ef09c847457477950fa2b048c7b592e040c467a2082d091"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 23:52:28"
  condition:
    hash.sha256(0, filesize) == "73cf812efdeafd903ef09c847457477950fa2b048c7b592e040c467a2082d091"
}
```

### Sample 69: `b79ded1ac75db0ae`

| Field | Value |
|---|---|
| SHA-256 | `b79ded1ac75db0ae2ea212980b72669235d788cdc7e6fae4cf3818e38154015b` |
| Family label | `Mirai` |
| File name | `nz.sh4` |
| File type | `elf` |
| First seen | `2026-07-31 23:38:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11ee7d52fec4baf54d0a2a008307b302` |
| SHA-1 | `6bcc1f49304b61445124c5dbea7ee34cfd4d91d9` |
| SHA-256 | `b79ded1ac75db0ae2ea212980b72669235d788cdc7e6fae4cf3818e38154015b` |
| SHA3-384 | `fbd624b8b646070a1d0b4eacdb1abbeb276652b6358c12de3f4cd383b74215aab6c37347de16f694d06949a38fbf596f` |
| TLSH | `T1B673AE73CCAA2CA8D55842B4B5B4BE362773E41466871FF71696CA369007EDCF8093B0` |
| SSDEEP | `1536:P/Q0G/PRRILXYHJKtmmHT74t73RCAZuj8FvgsMM:Po0GXRMXSwt5s73RTZuA1FMM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_b79ded1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b79ded1ac75db0ae2ea212980b72669235d788cdc7e6fae4cf3818e38154015b"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-31 23:38:15"
  condition:
    hash.sha256(0, filesize) == "b79ded1ac75db0ae2ea212980b72669235d788cdc7e6fae4cf3818e38154015b"
}
```

### Sample 70: `d1723ecada5f6e8b`

| Field | Value |
|---|---|
| SHA-256 | `d1723ecada5f6e8b6260cf2ff41d7f7f7b99e939db3db5a4b435ad4251ae3f3c` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-31 23:24:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d0883b98603f5918818025e64c26b25a` |
| SHA-1 | `fd5cc8f5aa53730640f5ab08a840dc9636c70197` |
| SHA-256 | `d1723ecada5f6e8b6260cf2ff41d7f7f7b99e939db3db5a4b435ad4251ae3f3c` |
| SHA3-384 | `f6eff7a68fb2fad404f9fa98056e6c7703f36c085b0f9844bd9e85d1765ae11911d63d08bd15fe450acc2261f8c43e69` |
| TLSH | `T187837CC5EAC3C8F5ED2209351272FB2659B2D03E2268EA83C3A9D975EC125C0F557B5C` |
| TELFHASH | `t1e931d4f52a7e08d9a7c4a940c24e4f30385ed7bb155076a109b36978236be81a0bac39` |
| SSDEEP | `1536:dWOLMM5Md23oQY+LWvGO3NAjw19K01dxYQ5FBE:TLxMdabHLoGsNi+9HYQzBE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_d1723eca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1723ecada5f6e8b6260cf2ff41d7f7f7b99e939db3db5a4b435ad4251ae3f3c"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 23:24:29"
  condition:
    hash.sha256(0, filesize) == "d1723ecada5f6e8b6260cf2ff41d7f7f7b99e939db3db5a4b435ad4251ae3f3c"
}
```

### Sample 71: `11f8d35eb01d1d35`

| Field | Value |
|---|---|
| SHA-256 | `11f8d35eb01d1d350b80ebcf49d949cdd9f7f58e6c8009a1c283a1956aa69359` |
| Family label | `Mirai` |
| File name | `debug` |
| File type | `elf` |
| First seen | `2026-07-31 23:23:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9832ff3b5d68ee877bfb085d66d3123` |
| SHA-1 | `a48a597856b5240fffb65851938676b9d2cee89f` |
| SHA-256 | `11f8d35eb01d1d350b80ebcf49d949cdd9f7f58e6c8009a1c283a1956aa69359` |
| SHA3-384 | `757b510b77c6277c0f35ddbdcd24e541fabf2bfdd46b67610a343da44fb58e6f37c051f68750ede271eabe99639de147` |
| TLSH | `T15C13F11BC1BA47D2EAB5113AD9FFE902510CCE21260DDEE7984833AD4487F090A0567F` |
| SSDEEP | `768:DjhJOAdeRX2gWGl/wm+RAj5QOx6OThR1Vl/Jy6dnbcuyD7UHQRju/:DjhJOAdohJoOp1R1VTyEnouy8HyM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_11f8d35e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f8d35eb01d1d350b80ebcf49d949cdd9f7f58e6c8009a1c283a1956aa69359"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 23:23:25"
  condition:
    hash.sha256(0, filesize) == "11f8d35eb01d1d350b80ebcf49d949cdd9f7f58e6c8009a1c283a1956aa69359"
}
```

### Sample 72: `f07605b995cf701e`

| Field | Value |
|---|---|
| SHA-256 | `f07605b995cf701ea40c0d4a535c5c8cc256b004d67d80ee2876ebf0dc0eb680` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 22:52:29` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `10cfffe0424db151ba3a152d52500a30` |
| SHA-1 | `35f5d1fac303bdb3b2b4726644174545a6333199` |
| SHA-256 | `f07605b995cf701ea40c0d4a535c5c8cc256b004d67d80ee2876ebf0dc0eb680` |
| SHA3-384 | `0dabaaf82fb73d055ce5de8d8df23eba55a0cce671fd3dfd7effcc64a3d7103bf76a2c16df31102ad73a3e78db05e5bc` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1A0E633481FD015BEF1B3913CEEE257D6E466B4728370C9EF0B1846A26D072E04A7F65A` |
| SSDEEP | `393216:COqIm0j11l8a+yulZSrFZ91TXMCHWUjPcuI3/PGTAI:CL2dJKWBpXMb8EH/O7` |
| ICON-DHASH | `30f0f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_f07605b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f07605b995cf701ea40c0d4a535c5c8cc256b004d67d80ee2876ebf0dc0eb680"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 22:52:29"
  condition:
    hash.sha256(0, filesize) == "f07605b995cf701ea40c0d4a535c5c8cc256b004d67d80ee2876ebf0dc0eb680"
}
```

### Sample 73: `e8c96feda6791f0a`

| Field | Value |
|---|---|
| SHA-256 | `e8c96feda6791f0acdee4c084e0d438f7792a1d33aa31de036fdb6408ca7db97` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-31 22:52:15` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbde72af760c3522d5acba1a22c135a9` |
| SHA-1 | `e4efda5affefdf6630d305992576acc66ec780f6` |
| SHA-256 | `e8c96feda6791f0acdee4c084e0d438f7792a1d33aa31de036fdb6408ca7db97` |
| SHA3-384 | `41d7315db9396ff546f3c12aa265cdffec7ef79f465951f1b6b5d7c25ca61a3db38143248fd782671652d99d49bf315a` |
| IMPHASH | `be9db20a0a086f6fcf0e952dc3183a39` |
| TLSH | `T1CE969D03E39181ECC46AC1748367AB33EA73F8894634B2AB5BD85B212F66F505F0D759` |
| SSDEEP | `98304:Bw+jWkfRo9uhUUOI0qBainVTwdNyoPWdwU4Bbt+s:+mXCqryF3U4T` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_073_e8c96fed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c96feda6791f0acdee4c084e0d438f7792a1d33aa31de036fdb6408ca7db97"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 22:52:15"
  condition:
    hash.sha256(0, filesize) == "e8c96feda6791f0acdee4c084e0d438f7792a1d33aa31de036fdb6408ca7db97"
}
```

### Sample 74: `1ccfd6555390617b`

| Field | Value |
|---|---|
| SHA-256 | `1ccfd6555390617b416bed0bd48ef3edba47bf042e102f504a2113bc356eeb0f` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-31 22:25:56` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2de0535c878a7b9a8971f74bb77abb91` |
| SHA-1 | `f40d13309750622a184b167fc5205fb4f622b45e` |
| SHA-256 | `1ccfd6555390617b416bed0bd48ef3edba47bf042e102f504a2113bc356eeb0f` |
| SHA3-384 | `20efebe55524b3b3e41adeba4e4d6120deea5ad163ffbcdb87931feee9c54f6c597ff9faa5f2297b39ff8614faa8b6c8` |
| IMPHASH | `2447f2446a419d1ace39af3bf9d1286a` |
| TLSH | `T1665293CEFDE58151E2DDCBB026750776C53937B363C652DFB3A2608A6832804A05DBDA` |
| SSDEEP | `192:pZs5rlB+oOCoFadod/wDl+uFJxT7ShmFhKIb3E:/s5KyooW/wD9FfShO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_1ccfd655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ccfd6555390617b416bed0bd48ef3edba47bf042e102f504a2113bc356eeb0f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 22:25:56"
  condition:
    hash.sha256(0, filesize) == "1ccfd6555390617b416bed0bd48ef3edba47bf042e102f504a2113bc356eeb0f"
}
```

### Sample 75: `4e247c3ac69c652c`

| Field | Value |
|---|---|
| SHA-256 | `4e247c3ac69c652cba2a80e221d0eb18200da8464f90eed71f949db0d3b20b65` |
| Family label | `unknown` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-07-31 22:19:18` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ee5227ba136ff46e55295e664fa60511` |
| SHA-1 | `5fb4310c4c532358eb7f13b98c7332a4f34cfddc` |
| SHA-256 | `4e247c3ac69c652cba2a80e221d0eb18200da8464f90eed71f949db0d3b20b65` |
| SHA3-384 | `a201553ec2931361b7dbe2b12e57d764fd6a5592b6cc54da67f48d37435e15da4a51fe7f45bbd07a9320fb9f72fe7526` |
| TLSH | `T114045B1BB1D088FEC4DAC1B45B9EE536DA71F1291338B15B67C4AE232D4CE306B2DA51` |
| TELFHASH | `t1a561ed302da5396831c7d79ab30ec9aafc7209510de2b8e49f1b7ad0de1778c0d42852` |
| SSDEEP | `3072:v4LCsvl7/SWXA6oG5l54a1HouD27C8AeX201Djt:v4uOlfbRQ1VnR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_4e247c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e247c3ac69c652cba2a80e221d0eb18200da8464f90eed71f949db0d3b20b65"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-31 22:19:18"
  condition:
    hash.sha256(0, filesize) == "4e247c3ac69c652cba2a80e221d0eb18200da8464f90eed71f949db0d3b20b65"
}
```

### Sample 76: `126d2fea7b1ea126`

| Field | Value |
|---|---|
| SHA-256 | `126d2fea7b1ea126a7dfa9d41a532a71ba1d41bb3473f5ba81694b2412059edc` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 21:52:27` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8b41dc9b3b2162b6bdd1eb91c5619a9` |
| SHA-1 | `f8dfca35bc6ad0e15a391eec70a3fa88b0849084` |
| SHA-256 | `126d2fea7b1ea126a7dfa9d41a532a71ba1d41bb3473f5ba81694b2412059edc` |
| SHA3-384 | `4987d1608d6301688687e3022829e448b2b61a5d9ea61f6589a2bc62cc2b0f9e5f1325c74f892b8563dd699666599039` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1DAE63318A6D525FEF6B34238DED21A95E21478251B32CFDB1BE84A157D231E14C3EB23` |
| SSDEEP | `393216:I2oGC4jHk2plZH9d15+/xaXMCHWUjBcuI3/PGTAI:IpGCalb5yxaXMb8WH/O7` |
| ICON-DHASH | `71f0e4d4c4e4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_126d2fea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126d2fea7b1ea126a7dfa9d41a532a71ba1d41bb3473f5ba81694b2412059edc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 21:52:27"
  condition:
    hash.sha256(0, filesize) == "126d2fea7b1ea126a7dfa9d41a532a71ba1d41bb3473f5ba81694b2412059edc"
}
```

### Sample 77: `7a2e6eb5538ae937`

| Field | Value |
|---|---|
| SHA-256 | `7a2e6eb5538ae9371581d9b575345d480483b7c3b7d4fac34fa4a010ecf51414` |
| Family label | `Mirai` |
| File name | `zero.armv6l` |
| File type | `elf` |
| First seen | `2026-07-31 21:28:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a9eb85d688ab70a57b1e2412e87a617` |
| SHA-1 | `083ad41011f7a6daa3f43ce39558145513c18357` |
| SHA-256 | `7a2e6eb5538ae9371581d9b575345d480483b7c3b7d4fac34fa4a010ecf51414` |
| SHA3-384 | `cc82adb1d3d8000d5f57d61ab1eaa08b64c8609d0273e2918972278171e5197c68036e765be1e9cbc9c980b676ef9794` |
| TLSH | `T1E4F30B86BC818B11D1C225B6FE1E124E37135B78E3E972139E146B3D7B4AC7B0A37915` |
| TELFHASH | `t194d02220ebb01a2c03dd00a081c30a08fbe93195220212d48b482b4b0ac2c0fb02080e` |
| SSDEEP | `3072:q8mj3e1wSD0LpzUopDVpXETCDa5NKVcXMXFKl+YW/:MkcpzDbpXuCDaTKVml+YW/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_7a2e6eb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a2e6eb5538ae9371581d9b575345d480483b7c3b7d4fac34fa4a010ecf51414"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-31 21:28:35"
  condition:
    hash.sha256(0, filesize) == "7a2e6eb5538ae9371581d9b575345d480483b7c3b7d4fac34fa4a010ecf51414"
}
```

### Sample 78: `e00b46b3c716a413`

| Field | Value |
|---|---|
| SHA-256 | `e00b46b3c716a4132f806f8c8c40bed2da93cea0e03e3d5901a1ba4f26c03f2a` |
| Family label | `Mirai` |
| File name | `zero.armv6l` |
| File type | `elf` |
| First seen | `2026-07-31 21:28:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `565f1f5dcbee6b75bb863d704595e8a2` |
| SHA-1 | `774680f01f5d594d3282855092bedf45e0b9fcc0` |
| SHA-256 | `e00b46b3c716a4132f806f8c8c40bed2da93cea0e03e3d5901a1ba4f26c03f2a` |
| SHA3-384 | `beee4e8f7fcc17ab96569eb1041a2d73cd32df9a32c056b3c6dfb42a5683454aebee8b6506caf9305b8825a0aab9fe4c` |
| TLSH | `T14743F129683D0974C1B094F1F42816037C4D17ED87E23165C2A4FAD49FEEC9A6AFC5E6` |
| SSDEEP | `1536:52vDZxfXF7xEap92o3buBfyDX3Hw7FRKTLQ:5+N9FtEHCuBfIX34FR0LQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_e00b46b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e00b46b3c716a4132f806f8c8c40bed2da93cea0e03e3d5901a1ba4f26c03f2a"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-31 21:28:27"
  condition:
    hash.sha256(0, filesize) == "e00b46b3c716a4132f806f8c8c40bed2da93cea0e03e3d5901a1ba4f26c03f2a"
}
```

### Sample 79: `6c22bcd5d4db88c5`

| Field | Value |
|---|---|
| SHA-256 | `6c22bcd5d4db88c58e67abeae0d8d91681949e03187c36c290a334c0c3f06b68` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-07-31 21:15:42` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `62b5e7a9e59ee4f2410d44412b8be946` |
| SHA-1 | `7115bf9c3aa4ef80154a15a60cf83c034420fd76` |
| SHA-256 | `6c22bcd5d4db88c58e67abeae0d8d91681949e03187c36c290a334c0c3f06b68` |
| SHA3-384 | `33bbe6b801ce9f0ea566ae5c00baa55f3117c217315a4136ad39f757a9854cbfd81a0239fd10ecdfaac1f7be771e3acf` |
| TLSH | `T129F32B42A652DAB3D4C31FB512A747610633E8291F2BDF41E32DBCB49E5658CF60A72C` |
| TELFHASH | `t1a1713258d43d09e9eea35d19a8692be34993e12926f46b18ff66cdc0081f42df224d0f` |
| SSDEEP | `3072:ouYmo4S/y37i2RvUW367PEcvwyDSIy6z367FaPxaO/D9:oZq37RRv3367E2DSIy6z367FaPxaO/D9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_6c22bcd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c22bcd5d4db88c58e67abeae0d8d91681949e03187c36c290a334c0c3f06b68"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-07-31 21:15:42"
  condition:
    hash.sha256(0, filesize) == "6c22bcd5d4db88c58e67abeae0d8d91681949e03187c36c290a334c0c3f06b68"
}
```

### Sample 80: `fdab9767c681ea28`

| Field | Value |
|---|---|
| SHA-256 | `fdab9767c681ea284a20a1d39634cc3fc14c1e8a399eec963f7f67716ede3e17` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-31 21:00:28` |
| Reporter | `Bitsight` |
| Tags | `9d2ca3, dropped-by-Amadey, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7cb65b6466b0924ba5258d7791255cf` |
| SHA-1 | `afbd6264711bc3213c2546c79bb71cc353c524db` |
| SHA-256 | `fdab9767c681ea284a20a1d39634cc3fc14c1e8a399eec963f7f67716ede3e17` |
| SHA3-384 | `8ac68db820418ead7a4c8c2d1ef621bc1251f59baa3e0053b3b6f8461990985cb0bcbcbe722838830d0b6dccd2527afb` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T143F58C07BC9148F6C0AAA73189B746567B74BC090B3227EB2E90B7782F727C05D36B55` |
| SSDEEP | `49152:d+CKz+2xUzvwWK4IJo1tAlJlMCyk7Gs3nJo3d57644Y3auYRE:dCXJitI7MgBnuYRE` |
| ICON-DHASH | `aae8e8e8e8e8e8aa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_fdab9767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdab9767c681ea284a20a1d39634cc3fc14c1e8a399eec963f7f67716ede3e17"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 21:00:28"
  condition:
    hash.sha256(0, filesize) == "fdab9767c681ea284a20a1d39634cc3fc14c1e8a399eec963f7f67716ede3e17"
}
```

### Sample 81: `220324be3422e4e5`

| Field | Value |
|---|---|
| SHA-256 | `220324be3422e4e57332df0a036f909705cb15d674f88aa45cc282b70a741c15` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-31 20:56:53` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15bb3f4c0df83f4903a00988ae053874` |
| SHA-1 | `3cc55dc5e10677fc710e344e2c01bac29b011e69` |
| SHA-256 | `220324be3422e4e57332df0a036f909705cb15d674f88aa45cc282b70a741c15` |
| SHA3-384 | `53a644653a170d149ed224ea37e71382f8de08f62858da6cfc93f4efd669abf9a7f97fe3a66c23a08ecbdad0c4fd54ec` |
| IMPHASH | `525bf76dfebd3fa14f52df7bc358946a` |
| TLSH | `T19F6733A6E30A896CD9B881F02EF48F7A1DA36D74D67410CD9FB8326F8973160D13D45A` |
| SSDEEP | `786432:ZBpkq99qcH7qa7t4yTZReBJ7hdFLKuOfUufl9l:9kq99qcH7Mqi1zKuU9l` |
| ICON-DHASH | `05c17e2701794949` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_220324be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "220324be3422e4e57332df0a036f909705cb15d674f88aa45cc282b70a741c15"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 20:56:53"
  condition:
    hash.sha256(0, filesize) == "220324be3422e4e57332df0a036f909705cb15d674f88aa45cc282b70a741c15"
}
```

### Sample 82: `44ce13c98ec7bc12`

| Field | Value |
|---|---|
| SHA-256 | `44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305` |
| Family label | `unknown` |
| File name | `44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305` |
| File type | `unknown` |
| First seen | `2026-07-31 20:54:48` |
| Reporter | `c2hunter` |
| Tags | `wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1158c2f2f65e03497ba2b91f7ce53fb` |
| SHA-256 | `44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_082_44ce13c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305"
    family = "unknown"
    file_name = "44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305"
    file_type = "unknown"
    first_seen = "2026-07-31 20:54:48"
  condition:
    hash.sha256(0, filesize) == "44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305"
}
```

### Sample 83: `9250e9fd0d73df09`

| Field | Value |
|---|---|
| SHA-256 | `9250e9fd0d73df09d608a544d27f048089071562ceb40de3600e9b5d85fa5f50` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 20:52:28` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95a4d77ef1bafbbec9f1b862a9604f29` |
| SHA-1 | `bb9ecb1908ad5c0e44cd1bd12cea936e60edd666` |
| SHA-256 | `9250e9fd0d73df09d608a544d27f048089071562ceb40de3600e9b5d85fa5f50` |
| SHA3-384 | `864134e813992b5ee4b25219460493471e7f0f0ea780e3288277b5e78d0706a295166fbea015da952d76f9a0f42747fc` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1BBE633086EE512EEE1F39138EEA21352E568F8750731CBE747A083675E4B0D09A7C56F` |
| SSDEEP | `393216:QwEb3CvFIpRpxBIHyiOTCChV93Xu+duXMCHWUjccuI3/PGTAI:QRzC9IplBwyiOW+3O+duXMb8JH/O7` |
| ICON-DHASH | `71f8f8dccce4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_9250e9fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9250e9fd0d73df09d608a544d27f048089071562ceb40de3600e9b5d85fa5f50"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 20:52:28"
  condition:
    hash.sha256(0, filesize) == "9250e9fd0d73df09d608a544d27f048089071562ceb40de3600e9b5d85fa5f50"
}
```

### Sample 84: `1217b7b48b21d322`

| Field | Value |
|---|---|
| SHA-256 | `1217b7b48b21d322037e4f2b9a54b8f45e8e3674b094a97a2aa042fce3fe2004` |
| Family label | `unknown` |
| File name | `install_c0rd004.msi` |
| File type | `msi` |
| First seen | `2026-07-31 20:23:17` |
| Reporter | `CNGaoLing` |
| Tags | `msi, SilverFox, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `307954de49a162f46f2a3f66deeccee4` |
| SHA-1 | `765b3b082e6b4e88a0a97aa5a85e53f4be9f1fd9` |
| SHA-256 | `1217b7b48b21d322037e4f2b9a54b8f45e8e3674b094a97a2aa042fce3fe2004` |
| SHA3-384 | `2239351d25105f1efd2001cd59bf5a636bad1a79425b05f66877c2235fd6281813d4fce687e8449addc5407f59fb6fff` |
| TLSH | `T12E963386B8C667B6C19FC3B45242282EBC387F917A720D073B9D771769736212B36349` |
| SSDEEP | `196608:r5UgPjavVwl4vlTYmGEhN8R7tw1UfLRZshM:rBjf4vFYmROxLb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_1217b7b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1217b7b48b21d322037e4f2b9a54b8f45e8e3674b094a97a2aa042fce3fe2004"
    family = "unknown"
    file_name = "install_c0rd004.msi"
    file_type = "msi"
    first_seen = "2026-07-31 20:23:17"
  condition:
    hash.sha256(0, filesize) == "1217b7b48b21d322037e4f2b9a54b8f45e8e3674b094a97a2aa042fce3fe2004"
}
```

### Sample 85: `0737e5d164c332f4`

| Field | Value |
|---|---|
| SHA-256 | `0737e5d164c332f41739f7c051b334fe92c897cd76a2520ead36cf044fdbcdc7` |
| Family label | `Mirai` |
| File name | `zero.i486` |
| File type | `elf` |
| First seen | `2026-07-31 20:15:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8dfc32aff3c1cbab557d494e44c32aa2` |
| SHA-1 | `cfa7547ee670ed2c6d4e2886e390ccc10d2ef94b` |
| SHA-256 | `0737e5d164c332f41739f7c051b334fe92c897cd76a2520ead36cf044fdbcdc7` |
| SHA3-384 | `26a0a9a09a7496cc034100fb507f87f650f17a768c173aadf921e380fccea35f22057332b63b8e78ea1264d3de537bc9` |
| TLSH | `T124932A1CE787E9F1C9420AB0205FBB379972D8E12220DDEBE7E47EE699617C15042E5C` |
| TELFHASH | `t1f031d1bab7b50ce42bd05902b28f6b305d5e767f14503a970bf2a415232ba81637bd3d` |
| SSDEEP | `1536:SKApIvpw+f5L8YLku9FhYfrLr0YUhYkS8/4vuEPdJon9/81E9Uf31c7Nrynr:S9pIvpwi5L8Y/FYfrLr0Y4YfVvuFn9/S` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_0737e5d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0737e5d164c332f41739f7c051b334fe92c897cd76a2520ead36cf044fdbcdc7"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-31 20:15:54"
  condition:
    hash.sha256(0, filesize) == "0737e5d164c332f41739f7c051b334fe92c897cd76a2520ead36cf044fdbcdc7"
}
```

### Sample 86: `d96b4ebf15a94575`

| Field | Value |
|---|---|
| SHA-256 | `d96b4ebf15a9457582ce32492e67fd36a8e945db0c89d0e6cd1fd0b0b0a3493c` |
| Family label | `Mirai` |
| File name | `zero.i486` |
| File type | `elf` |
| First seen | `2026-07-31 20:14:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `795ceca1e8ee77349c5e9b555a2a6f5d` |
| SHA-1 | `997f6b2aa7d4f7e33da46b448d5a51c689d9112f` |
| SHA-256 | `d96b4ebf15a9457582ce32492e67fd36a8e945db0c89d0e6cd1fd0b0b0a3493c` |
| SHA3-384 | `88888cf5311e776241192a58a74dd10ccd87d25766d8be40a7fb04fd343e522ba19e6f81be2d20476b8e7a11577d767e` |
| TLSH | `T1F813F187874DC171C13A76F716472A168EE4C43FC20686E4DB9C68BFE438A287D2B596` |
| SSDEEP | `768:1VNaXq8UX4Y0RJV/+1sI6jVWrp1rkXRMKqXy9Hp2Ekwo/JUDZ3BtFeUnbcuyD7Up:13Kq8U/0Rn/MBp1QXONXyP/BoBs9xJnT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_d96b4ebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96b4ebf15a9457582ce32492e67fd36a8e945db0c89d0e6cd1fd0b0b0a3493c"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-31 20:14:23"
  condition:
    hash.sha256(0, filesize) == "d96b4ebf15a9457582ce32492e67fd36a8e945db0c89d0e6cd1fd0b0b0a3493c"
}
```

### Sample 87: `1a5847daf96888be`

| Field | Value |
|---|---|
| SHA-256 | `1a5847daf96888bee8a740811e5d005e6b3fb28c20dce037e682cc6ba6a08647` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-31 20:14:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1eca87522277d933b45e250888f61952` |
| SHA-1 | `601f5b2eef6efd7e9a710d0060aaafb84ac0081c` |
| SHA-256 | `1a5847daf96888bee8a740811e5d005e6b3fb28c20dce037e682cc6ba6a08647` |
| SHA3-384 | `7c54502ce4d7f3b25200d371fed615fa3c9e5b24b9d63a975764817e1cb28ca6940c488112f89a4232b247e6ed8c574b` |
| TLSH | `T16FC27D966A867C44BEC94A3E4CBD2B0D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:m8vCB+25j6es8Rs9FYpMSUpi+20qUpi+20YQX:m8l25J6d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_1a5847da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a5847daf96888bee8a740811e5d005e6b3fb28c20dce037e682cc6ba6a08647"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 20:14:22"
  condition:
    hash.sha256(0, filesize) == "1a5847daf96888bee8a740811e5d005e6b3fb28c20dce037e682cc6ba6a08647"
}
```

### Sample 88: `f7dd053fc6f69cbb`

| Field | Value |
|---|---|
| SHA-256 | `f7dd053fc6f69cbb9e2d70c1d16c9af7c011102b726a1afad2b6bbf55f2ebda9` |
| Family label | `Mirai` |
| File name | `zero.armv7l` |
| File type | `elf` |
| First seen | `2026-07-31 20:13:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dd3ab75a3c0cccd421c7bea1f6c3e82d` |
| SHA-1 | `c5fbf8d5a224661e30e7041be60946c7e96cf97e` |
| SHA-256 | `f7dd053fc6f69cbb9e2d70c1d16c9af7c011102b726a1afad2b6bbf55f2ebda9` |
| SHA3-384 | `0abe1dbe24ce31dd8279b0f275f802ac0023f7677de55b43764e691df31543e292bb4e0a24c80e014027d0f90aff60fd` |
| TLSH | `T1E9D3F789BC814B00D5D636B6FE1E124933534BBCE3F9B1039E145B2E278AD6B0B37A55` |
| TELFHASH | `t154d02373fdd040cc39e30790c1c04218433034c80304281020015a3f62e3dc5740ca03` |
| SSDEEP | `3072:CNKxdRzua/innAupRwY/aaIRjg9Bys3biBvWj:Zp0Au/jyaIRjg9BdavWj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_f7dd053f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7dd053fc6f69cbb9e2d70c1d16c9af7c011102b726a1afad2b6bbf55f2ebda9"
    family = "Mirai"
    file_name = "zero.armv7l"
    file_type = "elf"
    first_seen = "2026-07-31 20:13:35"
  condition:
    hash.sha256(0, filesize) == "f7dd053fc6f69cbb9e2d70c1d16c9af7c011102b726a1afad2b6bbf55f2ebda9"
}
```

### Sample 89: `68c913db3579d18d`

| Field | Value |
|---|---|
| SHA-256 | `68c913db3579d18dbe35e5e1a07c1418844931d44723053daa83e1c900c9a25c` |
| Family label | `Mirai` |
| File name | `zero.armv7l` |
| File type | `elf` |
| First seen | `2026-07-31 20:12:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd54293c5ba5498e9df1f339ed0682b4` |
| SHA-1 | `cd15368c0ed41fc61bb7bec75a7fc1b510145ced` |
| SHA-256 | `68c913db3579d18dbe35e5e1a07c1418844931d44723053daa83e1c900c9a25c` |
| SHA3-384 | `d3211a9f1d920049a1c1c281d2a31962def5bb963cd1ae7febe091e158ef9ef7bfa1c3b0c73b333f1fd47863cf08857b` |
| TLSH | `T1BB33F270019BF822C8502633DEEA495FEF835A34E6F7722560494E3436B954BA36F793` |
| SSDEEP | `1536:U15gMbt1OFRTGuYHNStmtfFHU2EEATiI6V9JutMLu:UCMbL3FJFHfEEATYTuSLu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_68c913db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68c913db3579d18dbe35e5e1a07c1418844931d44723053daa83e1c900c9a25c"
    family = "Mirai"
    file_name = "zero.armv7l"
    file_type = "elf"
    first_seen = "2026-07-31 20:12:40"
  condition:
    hash.sha256(0, filesize) == "68c913db3579d18dbe35e5e1a07c1418844931d44723053daa83e1c900c9a25c"
}
```

### Sample 90: `7c313c014a2718c8`

| Field | Value |
|---|---|
| SHA-256 | `7c313c014a2718c8a0133d8dad005505dfd589ac4b2bc0f749a48108bb5d680b` |
| Family label | `Mirai` |
| File name | `zero.mipsrouter` |
| File type | `elf` |
| First seen | `2026-07-31 20:02:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c263d1ad489bba3d501cd5b009d09a76` |
| SHA-1 | `d567b38a6aca4ae5ab59571c5d1c648b7b1717d9` |
| SHA-256 | `7c313c014a2718c8a0133d8dad005505dfd589ac4b2bc0f749a48108bb5d680b` |
| SHA3-384 | `10897b4829f7f8388a029793ae42293be2c326e349f6140b53f644393b899013abf651ce7bc266e547b26286568dbd43` |
| TLSH | `T1D314C84F6E238F7DF27887344BB75E25675923C623E0D644E1ACC6501E6029E582FFA8` |
| TELFHASH | `t110416118097817f063359c8e069dff7ba6a331db3e222d378e11e45aab69d835d20c0c` |
| SSDEEP | `1536:r2x2FBuL0r8e3b5HDrcWg+aDeWKIf/CQyKmFhTHeM9w1h9M3TQ7xhQe9bpBOrn7j:qX0ICIf/CQyKmFhTX9waAge9DODX` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_7c313c01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c313c014a2718c8a0133d8dad005505dfd589ac4b2bc0f749a48108bb5d680b"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-31 20:02:37"
  condition:
    hash.sha256(0, filesize) == "7c313c014a2718c8a0133d8dad005505dfd589ac4b2bc0f749a48108bb5d680b"
}
```

### Sample 91: `8971bc38f11bb873`

| Field | Value |
|---|---|
| SHA-256 | `8971bc38f11bb873115e0839508cdff8452dc34d993ebaac332e84dad96a45bf` |
| Family label | `Mirai` |
| File name | `zero.mipsrouter` |
| File type | `elf` |
| First seen | `2026-07-31 20:01:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9afa919a87bb3082478d53c1e0c598e` |
| SHA-1 | `7258dd3cebced048a08343e93c8060ff355e8464` |
| SHA-256 | `8971bc38f11bb873115e0839508cdff8452dc34d993ebaac332e84dad96a45bf` |
| SHA3-384 | `6a488031f2c4b511caaed8737bb4b1321af7a9259191421521a084c341ada0c5a7c469e922e70eedd7cb27672adbb2e9` |
| TLSH | `T15A43F1B1AB4005AED03C907249E313943D2ADF991907DE47F21B5FEA8FE9C9125239DE` |
| SSDEEP | `1536:yhtKvd9bZulSA/xHMTiVTSJii+MTKKBOBgQtyVJuy:yu0ZKWVQJqEVQy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_8971bc38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8971bc38f11bb873115e0839508cdff8452dc34d993ebaac332e84dad96a45bf"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-31 20:01:49"
  condition:
    hash.sha256(0, filesize) == "8971bc38f11bb873115e0839508cdff8452dc34d993ebaac332e84dad96a45bf"
}
```

### Sample 92: `b8bc0ed87ec3183f`

| Field | Value |
|---|---|
| SHA-256 | `b8bc0ed87ec3183f801031a5fe354758ba943f06918146b9a92d9bb8a5eec5d3` |
| Family label | `Mirai` |
| File name | `zero.sh4` |
| File type | `elf` |
| First seen | `2026-07-31 19:58:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58a437e1213a8e7f7f887e4b5aeb57e6` |
| SHA-1 | `599f5edf49c5e2461600732975843dc78c6c9d4c` |
| SHA-256 | `b8bc0ed87ec3183f801031a5fe354758ba943f06918146b9a92d9bb8a5eec5d3` |
| SHA3-384 | `c6fa856f493997152db7596b05ffc6665a0441ea80925992d22614a2fccc087d4039e76c47652b35abbe94bfef61a1a7` |
| TLSH | `T141E36C73CC746EACE166FE30A0388ABA1713D494556B9EBB2867C3700057DC8F556BB8` |
| SSDEEP | `3072:a4MiGnBblsrWNS8QDoTYNI8/+vlAMxrXKWK10W5Cih23+Y:agcZlsrWNS8QDoT38/+vlAMZ6btkh3+Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_b8bc0ed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bc0ed87ec3183f801031a5fe354758ba943f06918146b9a92d9bb8a5eec5d3"
    family = "Mirai"
    file_name = "zero.sh4"
    file_type = "elf"
    first_seen = "2026-07-31 19:58:39"
  condition:
    hash.sha256(0, filesize) == "b8bc0ed87ec3183f801031a5fe354758ba943f06918146b9a92d9bb8a5eec5d3"
}
```

### Sample 93: `28657f6526fa6385`

| Field | Value |
|---|---|
| SHA-256 | `28657f6526fa6385d7a3f8ca32c83d4e8bb8be69c34239f081daa3c448c5413c` |
| Family label | `unknown` |
| File name | `milan.sh` |
| File type | `sh` |
| First seen | `2026-07-31 19:52:43` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2773afba04b4a8f51d3558c07ecdd2c4` |
| SHA-1 | `568bfdadaf4aa3ea0d29db1157ff354420703fd9` |
| SHA-256 | `28657f6526fa6385d7a3f8ca32c83d4e8bb8be69c34239f081daa3c448c5413c` |
| SHA3-384 | `415134f6395f87108b1242beb6a204a903e8dcae4404d065f482869334af0b76a44a4a3d427e6a059dcd81eb988f6cf2` |
| TLSH | `T15611A5F2B4A582D1F30D4E2FB7686A446A939AEB19987820F8425D678F1C416701FA37` |
| SSDEEP | `24:tgHdFg+fij3tSijJ1GijREijS/aijFyfijc6:tSF+d/TDRRS/3Yoc6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_28657f65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28657f6526fa6385d7a3f8ca32c83d4e8bb8be69c34239f081daa3c448c5413c"
    family = "unknown"
    file_name = "milan.sh"
    file_type = "sh"
    first_seen = "2026-07-31 19:52:43"
  condition:
    hash.sha256(0, filesize) == "28657f6526fa6385d7a3f8ca32c83d4e8bb8be69c34239f081daa3c448c5413c"
}
```

### Sample 94: `c28a7bf288adab51`

| Field | Value |
|---|---|
| SHA-256 | `c28a7bf288adab51e1371dddf98d10cd81c6099cd346e6093f50b367c2cd0b46` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-31 19:52:27` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b8921f4f4ce4e08916dc4a718038aee` |
| SHA-1 | `cf4605dfe70e8b4bded243ccea537b2a56fbcab7` |
| SHA-256 | `c28a7bf288adab51e1371dddf98d10cd81c6099cd346e6093f50b367c2cd0b46` |
| SHA3-384 | `2a6343cc875a9fa62e8b8997b03df38937b222a2e59bd7615f5e2e47770aea66c2b7479457c10d2edb3d82875535fe35` |
| IMPHASH | `cf72283be50852e418ce6bbb6b645835` |
| TLSH | `T1E2E63308A8D012FDD563503CEEF251D5EAB9B8714776C2EF4BD4C6A2AE231E09439727` |
| SSDEEP | `393216:FdqSWjy2RO26E3rZsul4Lvc1psXMCHWUjMcuI3/PGTAI:FkSey20EbZVrsXMb8ZH/O7` |
| ICON-DHASH | `8878e0c0dcf8f102` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_c28a7bf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c28a7bf288adab51e1371dddf98d10cd81c6099cd346e6093f50b367c2cd0b46"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 19:52:27"
  condition:
    hash.sha256(0, filesize) == "c28a7bf288adab51e1371dddf98d10cd81c6099cd346e6093f50b367c2cd0b46"
}
```

### Sample 95: `15ee716af9c7add1`

| Field | Value |
|---|---|
| SHA-256 | `15ee716af9c7add145999df4ad744e8c58246a74ec7fd194a5dc6378f1b0483e` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-31 19:47:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fecb7cef28e9b443217060ed1092610` |
| SHA-1 | `2591e63729e077163315402f388b959089a8fa2d` |
| SHA-256 | `15ee716af9c7add145999df4ad744e8c58246a74ec7fd194a5dc6378f1b0483e` |
| SHA3-384 | `508b79cd579e74fb1559600cb8aad11db160de9e7ee17991d7b803a54f9e9b417919f544ab365d36fb0dc32ed0f72b0f` |
| TLSH | `T139245D46EB414E13C4D317B9F6AF5149333297A4D3EB730689286FB43B8679E0E67A01` |
| TELFHASH | `t1a2413fb6a73596215b60cd24d8ec57b15a1ec7030684fe33cf36889c141a48ee62bc1f` |
| SSDEEP | `6144:d3Xx9LzryMBaZ6uM8TGByw4RDWrHf0v9qM/9YmPb:d3XxFryMBa8uM8TGByXxC0D/Wmj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_15ee716a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ee716af9c7add145999df4ad744e8c58246a74ec7fd194a5dc6378f1b0483e"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 19:47:25"
  condition:
    hash.sha256(0, filesize) == "15ee716af9c7add145999df4ad744e8c58246a74ec7fd194a5dc6378f1b0483e"
}
```

### Sample 96: `357559d98829cb62`

| Field | Value |
|---|---|
| SHA-256 | `357559d98829cb62fc5cad7b9fe9d7919cfb7ece64a3c890485dfa1c42d4a0ce` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-31 19:47:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e233f003d6334c11d62a4b9686a4c713` |
| SHA-1 | `37e68974d5a6e71146eefc6a6aa5449321fff4e3` |
| SHA-256 | `357559d98829cb62fc5cad7b9fe9d7919cfb7ece64a3c890485dfa1c42d4a0ce` |
| SHA3-384 | `67c586db1ebd4231a475c6c1dd102c6f3e3f74e062fe60d45c5337d8dfe0c31a616d340a2ab7ba2b575ac98951a40e3e` |
| TLSH | `T1A3F3E81E6E618F7DF7A9823447B79E25965C33D63BD1C586D1ACDA001E3028E241FFA8` |
| TELFHASH | `t15c218c1c497412f0a3714c5d66eeff7bd4a030ee5a226d338e11a9aebbad9415c00c1c` |
| SSDEEP | `3072:ytjRaQ3AoR0W6fDJIAk0TeJs5p/cq4zbH7+ChhVBLoqApoe/VPkxZZ6MqaRtdhCR:ytjRaQ3AoR0W6fDJIAk0TeJs5p/cq4zG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_357559d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "357559d98829cb62fc5cad7b9fe9d7919cfb7ece64a3c890485dfa1c42d4a0ce"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-31 19:47:23"
  condition:
    hash.sha256(0, filesize) == "357559d98829cb62fc5cad7b9fe9d7919cfb7ece64a3c890485dfa1c42d4a0ce"
}
```

### Sample 97: `a1d301181d0270ad`

| Field | Value |
|---|---|
| SHA-256 | `a1d301181d0270ad6559cf22daa9e7ee50506fdb116eea167b6dd274f259e26e` |
| Family label | `Mirai` |
| File name | `nz.arm7` |
| File type | `elf` |
| First seen | `2026-07-31 19:46:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `964f60ec500726a2ef4edecf2fce1962` |
| SHA-1 | `c7856c7b6bbc146f28ca320083069b54908aca4b` |
| SHA-256 | `a1d301181d0270ad6559cf22daa9e7ee50506fdb116eea167b6dd274f259e26e` |
| SHA3-384 | `5ddcd12d443cec1146cdd2b33b38008d929feabbbb64847cd08c93f4b9714cc4a3ddb15b0b0ba7b6c35ebb77ed03f6df` |
| TLSH | `T17C73020024E94972CFF498B7E19E1CE6C6410579F4FDC43B6E58424D3F96A18A27EAF2` |
| SSDEEP | `1536:SWiyMKPGFNvfB+zFSZoExzWYYiwLYCqFhNjSMk7IR:SWfHGFVIooA4iwLOhNuIR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_a1d30118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1d301181d0270ad6559cf22daa9e7ee50506fdb116eea167b6dd274f259e26e"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 19:46:46"
  condition:
    hash.sha256(0, filesize) == "a1d301181d0270ad6559cf22daa9e7ee50506fdb116eea167b6dd274f259e26e"
}
```

### Sample 98: `39757f55c492188c`

| Field | Value |
|---|---|
| SHA-256 | `39757f55c492188c04e133bd916b10769a1edc89b9c5067cc57038cdf7cc5048` |
| Family label | `Mirai` |
| File name | `nz.mips` |
| File type | `elf` |
| First seen | `2026-07-31 19:46:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `321789a8b6f56043155b811863005149` |
| SHA-1 | `aa8a5b374b997563be02df9455d2aa092d373641` |
| SHA-256 | `39757f55c492188c04e133bd916b10769a1edc89b9c5067cc57038cdf7cc5048` |
| SHA3-384 | `9657084284a7bf108101f2543ab2879299c19f38768e63d42ca9554fee67a87bc97ba864211b59344fe491eb90445fe0` |
| TLSH | `T18E3302D67B224599C0D1BF7004A157818BF7CBE2C4B6D40B58DBFA63CCB5209B81BAE4` |
| SSDEEP | `768:lzhKQsBMD8HlkaBD8ECYosoGWKSOQSycJRo912P02K8R/v4bn1etRmcuJgGlzDpF:imDH2MGsO+cJRo91oj9R/I1imdVJue` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_39757f55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39757f55c492188c04e133bd916b10769a1edc89b9c5067cc57038cdf7cc5048"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-31 19:46:45"
  condition:
    hash.sha256(0, filesize) == "39757f55c492188c04e133bd916b10769a1edc89b9c5067cc57038cdf7cc5048"
}
```

### Sample 99: `0020d6a69202ba61`

| Field | Value |
|---|---|
| SHA-256 | `0020d6a69202ba61f8a7ff6cc2c332ac297b8761e1a1fde9d658c88085791a62` |
| Family label | `Mirai` |
| File name | `BlahajNet.armv5l` |
| File type | `elf` |
| First seen | `2026-07-31 19:43:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b43109c24e1b31a9b931a1b790335081` |
| SHA-1 | `40581e37ac754df00ba5b987944c2a03e1c7b00b` |
| SHA-256 | `0020d6a69202ba61f8a7ff6cc2c332ac297b8761e1a1fde9d658c88085791a62` |
| SHA3-384 | `5063fc9a067b31c97f8eeebaaa8a49afff33168e3be8e6d3c8ad63a9c1d7ffbc2a30681aa1629572de4a8da2ed58d373` |
| TLSH | `T102441B56BE418F63C5D216F7FBAD428C37166BB9C6EA3102DD207F60278A4DB0E36152` |
| TELFHASH | `t13ab012f00c8526527eaad4e105a34bf0411b5342fb08d7d34bccde7e0c1bcc10505903` |
| SSDEEP | `6144:oJHPlLXR2dShcL9rxYlBde+39KlduQ+NGoLULhfjDNHG:25XRhhM9rxYlBA+32duLK1rDN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_0020d6a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0020d6a69202ba61f8a7ff6cc2c332ac297b8761e1a1fde9d658c88085791a62"
    family = "Mirai"
    file_name = "BlahajNet.armv5l"
    file_type = "elf"
    first_seen = "2026-07-31 19:43:44"
  condition:
    hash.sha256(0, filesize) == "0020d6a69202ba61f8a7ff6cc2c332ac297b8761e1a1fde9d658c88085791a62"
}
```

### Sample 100: `7fec435c8069f75e`

| Field | Value |
|---|---|
| SHA-256 | `7fec435c8069f75ee7661ace5d8ece030c51d25e24426e017df358c8b1cc0207` |
| Family label | `Mirai` |
| File name | `nz.arm6` |
| File type | `elf` |
| First seen | `2026-07-31 19:38:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d1887ee8d302288df6d982a27640074` |
| SHA-1 | `b7ccc62f7e5de7d3d04b27ada4dad8abfa45a627` |
| SHA-256 | `7fec435c8069f75ee7661ace5d8ece030c51d25e24426e017df358c8b1cc0207` |
| SHA3-384 | `bd5e006d930829b5401e1df769c5f6da3f6e1251a6489b965b39c1e505f88efb157e81fcf119025c3ceff722715559c8` |
| TLSH | `T138E33946FC814A21D5D712BEFA2D218E331217B8E3DE72138D245F2477CA59B0E7BA46` |
| TELFHASH | `t121b01203c805a2ce3be4015ac1784013d6b8301d07c09842415bcc262b41051f3321a3` |
| SSDEEP | `3072:6gAg9K8MboRNi8LMh6H/G/rDiOazuFgdim+0/MIH+:6Bgvi8Ld/G/vVaOG+00IH+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_7fec435c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fec435c8069f75ee7661ace5d8ece030c51d25e24426e017df358c8b1cc0207"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-31 19:38:30"
  condition:
    hash.sha256(0, filesize) == "7fec435c8069f75ee7661ace5d8ece030c51d25e24426e017df358c8b1cc0207"
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
 * Generated: 2026-08-01T03:55:14.698854+00:00
 */

rule MalwareBazaar_unknown_001_514b8816
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "514b8816af6639c6185f03cb2969e7855f1883b6d8a651c7e218269435795b9a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 03:52:31"
  condition:
    hash.sha256(0, filesize) == "514b8816af6639c6185f03cb2969e7855f1883b6d8a651c7e218269435795b9a"
}

rule MalwareBazaar_unknown_002_cafcc76c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10"
    family = "unknown"
    file_name = "MM2DUPE.exe"
    file_type = "exe"
    first_seen = "2026-08-01 03:27:34"
  condition:
    hash.sha256(0, filesize) == "cafcc76c5d1e97e3b86529e6564f7d95ca189b70f2fa092dbd1f50a8d16d9c10"
}

rule MalwareBazaar_CoinMiner_003_4c17b8c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c17b8c2d287de19641026b61af6567c2f08f65888fd7a620a919e83a2c08895"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:57"
  condition:
    hash.sha256(0, filesize) == "4c17b8c2d287de19641026b61af6567c2f08f65888fd7a620a919e83a2c08895"
}

rule MalwareBazaar_unknown_004_e378df57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e378df570301e2a7cf4d1a79508a41acae37df09d2ea0460902e2edb49d6533c"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:46"
  condition:
    hash.sha256(0, filesize) == "e378df570301e2a7cf4d1a79508a41acae37df09d2ea0460902e2edb49d6533c"
}

rule MalwareBazaar_unknown_005_2804f625
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2804f625bda3a9b17c21df3bda03807ba0dc74c4c7c3333f59a5c18c7497858b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:39"
  condition:
    hash.sha256(0, filesize) == "2804f625bda3a9b17c21df3bda03807ba0dc74c4c7c3333f59a5c18c7497858b"
}

rule MalwareBazaar_unknown_006_392a8919
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392a891929839c17887143fe1125f845763335821a61b83cf6a2a291d79b1885"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 03:16:23"
  condition:
    hash.sha256(0, filesize) == "392a891929839c17887143fe1125f845763335821a61b83cf6a2a291d79b1885"
}

rule MalwareBazaar_unknown_007_92b146ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92b146eff8d54fff90445bd258e0e5a42f1277e213b9fa0137c7ab5074c01a46"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 02:52:28"
  condition:
    hash.sha256(0, filesize) == "92b146eff8d54fff90445bd258e0e5a42f1277e213b9fa0137c7ab5074c01a46"
}

rule MalwareBazaar_Mirai_008_faf51889
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "faf518894303e8eed32039d755927a3ccb42504f0ed2527a7cb7f05300900f98"
    family = "Mirai"
    file_name = "xmr_miner_arm64"
    file_type = "elf"
    first_seen = "2026-08-01 02:26:42"
  condition:
    hash.sha256(0, filesize) == "faf518894303e8eed32039d755927a3ccb42504f0ed2527a7cb7f05300900f98"
}

rule MalwareBazaar_unknown_009_a58ad957
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a58ad957ea509d4bb8f3a0a274601df61d49e26a605ca2df559d7e7cf1d024c5"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-01 02:14:37"
  condition:
    hash.sha256(0, filesize) == "a58ad957ea509d4bb8f3a0a274601df61d49e26a605ca2df559d7e7cf1d024c5"
}

rule MalwareBazaar_Mirai_010_436f164d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "436f164de1640f910005be2aa5e9c0343abeca108d789273e7aa9703cd653b49"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-08-01 02:01:31"
  condition:
    hash.sha256(0, filesize) == "436f164de1640f910005be2aa5e9c0343abeca108d789273e7aa9703cd653b49"
}

rule MalwareBazaar_Mirai_011_9f11e245
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f11e24531de2a3e5de458d335485805c725ca08ee27d60b66887676c36f0537"
    family = "Mirai"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-08-01 02:01:30"
  condition:
    hash.sha256(0, filesize) == "9f11e24531de2a3e5de458d335485805c725ca08ee27d60b66887676c36f0537"
}

rule MalwareBazaar_Mirai_012_b5fa4595
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5fa45952fa3bb422b1d85d52a6a29690837ec079b72c678f883221e83f96aea"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-01 01:58:21"
  condition:
    hash.sha256(0, filesize) == "b5fa45952fa3bb422b1d85d52a6a29690837ec079b72c678f883221e83f96aea"
}

rule MalwareBazaar_unknown_013_efcf7d27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de"
    family = "unknown"
    file_name = "efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de"
    file_type = "sh"
    first_seen = "2026-08-01 01:56:19"
  condition:
    hash.sha256(0, filesize) == "efcf7d27639d35b75eca73dde46b87ef103031d4c60de2f8d511bc11c49397de"
}

rule MalwareBazaar_unknown_014_628e3332
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "628e33326d90400f5921db3d3d07d0b10779961a5ca5660a5689e65c0c6ef6c3"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 01:52:33"
  condition:
    hash.sha256(0, filesize) == "628e33326d90400f5921db3d3d07d0b10779961a5ca5660a5689e65c0c6ef6c3"
}

rule MalwareBazaar_unknown_015_4c7ac675
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c7ac675d6469a808bdcc5feb6331e5771e7e221a357baf6a5617702076ffd6b"
    family = "unknown"
    file_name = "don12089.hta"
    file_type = "hta"
    first_seen = "2026-08-01 01:50:40"
  condition:
    hash.sha256(0, filesize) == "4c7ac675d6469a808bdcc5feb6331e5771e7e221a357baf6a5617702076ffd6b"
}

rule MalwareBazaar_unknown_016_bd841b12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87"
    family = "unknown"
    file_name = "bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87"
    file_type = "sh"
    first_seen = "2026-08-01 01:50:02"
  condition:
    hash.sha256(0, filesize) == "bd841b12f1183e8f04d34d695f2f7c145f1b7aa5b7480f2722ccddc62b624c87"
}

rule MalwareBazaar_Mirai_017_13769667
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94"
    family = "Mirai"
    file_name = "137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94"
    file_type = "elf"
    first_seen = "2026-08-01 01:47:45"
  condition:
    hash.sha256(0, filesize) == "137696672595176cb5fe237834f9de9194d25e5d9b6e0e3ed9e78daa84b0bc94"
}

rule MalwareBazaar_unknown_018_cd89fa8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55"
    family = "unknown"
    file_name = "cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55"
    file_type = "sh"
    first_seen = "2026-08-01 01:47:43"
  condition:
    hash.sha256(0, filesize) == "cd89fa8fe43679b7ab6e1c7b7bac49585d54676982b35cd41ff5dee37832bf55"
}

rule MalwareBazaar_unknown_019_be93cf80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "be93cf8050a0ec8bc1d142cc6d3106cbcf80633217539a98dfc81f5239fb873a"
    family = "unknown"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-08-01 01:46:22"
  condition:
    hash.sha256(0, filesize) == "be93cf8050a0ec8bc1d142cc6d3106cbcf80633217539a98dfc81f5239fb873a"
}

rule MalwareBazaar_Mirai_020_59b08987
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b08987027ffc89bf36cab40c252b784077ce810b606dd4cf411f2c727a66e4"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 01:36:40"
  condition:
    hash.sha256(0, filesize) == "59b08987027ffc89bf36cab40c252b784077ce810b606dd4cf411f2c727a66e4"
}

rule MalwareBazaar_Mirai_021_8799a504
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8799a504a33507c9aa0e7e56990c564e3a73c9f5ae352704a635495ae620f547"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 01:35:47"
  condition:
    hash.sha256(0, filesize) == "8799a504a33507c9aa0e7e56990c564e3a73c9f5ae352704a635495ae620f547"
}

rule MalwareBazaar_unknown_022_a21a2539
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a21a25390ada2dcbc1b268a4ad45399e67af9e8bd540c9a313e1011e64229977"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-01 01:32:50"
  condition:
    hash.sha256(0, filesize) == "a21a25390ada2dcbc1b268a4ad45399e67af9e8bd540c9a313e1011e64229977"
}

rule MalwareBazaar_CoinMiner_023_c23cb82c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c23cb82c4e48e91f71b389cb16d419510a15bd1ebd9b3e53a7fd8f38960745a5"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:47"
  condition:
    hash.sha256(0, filesize) == "c23cb82c4e48e91f71b389cb16d419510a15bd1ebd9b3e53a7fd8f38960745a5"
}

rule MalwareBazaar_unknown_024_4cef725a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4cef725a2fd962110be3b7ad4e01518a78d3bec24e7d078a5fbe1b35f38d9d2a"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:40"
  condition:
    hash.sha256(0, filesize) == "4cef725a2fd962110be3b7ad4e01518a78d3bec24e7d078a5fbe1b35f38d9d2a"
}

rule MalwareBazaar_unknown_025_a9c3e1b2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9c3e1b23a6a102016c0a8c35b198e4401bf75cb28e4ef8b9ddd5d0e93a09c5b"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:33"
  condition:
    hash.sha256(0, filesize) == "a9c3e1b23a6a102016c0a8c35b198e4401bf75cb28e4ef8b9ddd5d0e93a09c5b"
}

rule MalwareBazaar_unknown_026_6e67cde5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6e67cde5f83e4a64ba7a626f46240979a840163e1595b7219ee850fac6826444"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 01:31:22"
  condition:
    hash.sha256(0, filesize) == "6e67cde5f83e4a64ba7a626f46240979a840163e1595b7219ee850fac6826444"
}

rule MalwareBazaar_Mirai_027_bca1a1ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bca1a1ab6f8af45dc8b855a33d9fd8bd1e2658903428933a23ddd266a94cd293"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-08-01 01:28:30"
  condition:
    hash.sha256(0, filesize) == "bca1a1ab6f8af45dc8b855a33d9fd8bd1e2658903428933a23ddd266a94cd293"
}

rule MalwareBazaar_unknown_028_000d6d9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "000d6d9e36795845c30894f29e7c3be7db37e1127e0a1e2b3cfcebd45e9cd9e0"
    family = "unknown"
    file_name = "i486"
    file_type = "elf"
    first_seen = "2026-08-01 01:26:39"
  condition:
    hash.sha256(0, filesize) == "000d6d9e36795845c30894f29e7c3be7db37e1127e0a1e2b3cfcebd45e9cd9e0"
}

rule MalwareBazaar_Mirai_029_6ae2d6cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ae2d6cbbd86fc97aaf932ed79fb683e2d08abe278cd10d9a634d6be20f9946e"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-01 01:18:34"
  condition:
    hash.sha256(0, filesize) == "6ae2d6cbbd86fc97aaf932ed79fb683e2d08abe278cd10d9a634d6be20f9946e"
}

rule MalwareBazaar_Mirai_030_406a984d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "406a984d952108f1d06e42046a354b4c279ea58b691a211209501cd073c180e3"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-08-01 01:15:25"
  condition:
    hash.sha256(0, filesize) == "406a984d952108f1d06e42046a354b4c279ea58b691a211209501cd073c180e3"
}

rule MalwareBazaar_Mirai_031_6d99352c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6d99352ccf8ef3dec20ee396418f4963722c0d65bdc88924a0eea9a42be7e49c"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-08-01 01:12:26"
  condition:
    hash.sha256(0, filesize) == "6d99352ccf8ef3dec20ee396418f4963722c0d65bdc88924a0eea9a42be7e49c"
}

rule MalwareBazaar_Mirai_032_5ac57ece
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ac57ece78df250d7ced1a49a74b1084f7455d8559e50a8afc08439c5ac20f9f"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-01 01:06:30"
  condition:
    hash.sha256(0, filesize) == "5ac57ece78df250d7ced1a49a74b1084f7455d8559e50a8afc08439c5ac20f9f"
}

rule MalwareBazaar_Mirai_033_318391f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "318391f558f280af8e93bec63a3c85100fdf2a12343f6ac8b8ae9178f68a64ca"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-08-01 01:06:29"
  condition:
    hash.sha256(0, filesize) == "318391f558f280af8e93bec63a3c85100fdf2a12343f6ac8b8ae9178f68a64ca"
}

rule MalwareBazaar_Mirai_034_049ec70a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049ec70afdef0fa35e253e84c5323fae581db3b1159cc69f9ccd5cfc51536a12"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-01 01:05:41"
  condition:
    hash.sha256(0, filesize) == "049ec70afdef0fa35e253e84c5323fae581db3b1159cc69f9ccd5cfc51536a12"
}

rule MalwareBazaar_Mirai_035_d3e23fc6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d3e23fc669e19733d228929d75aa4a4b1751f51ff1c37ab1a232830c46468e42"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-08-01 01:04:37"
  condition:
    hash.sha256(0, filesize) == "d3e23fc669e19733d228929d75aa4a4b1751f51ff1c37ab1a232830c46468e42"
}

rule MalwareBazaar_Mirai_036_7f697ed4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f697ed4ca05f453a3d6ec8d8bdfd6cb70453e992a6daf2e2d4b08cdef618115"
    family = "Mirai"
    file_name = "nz.m68k"
    file_type = "elf"
    first_seen = "2026-08-01 01:02:36"
  condition:
    hash.sha256(0, filesize) == "7f697ed4ca05f453a3d6ec8d8bdfd6cb70453e992a6daf2e2d4b08cdef618115"
}

rule MalwareBazaar_Mirai_037_b00dd207
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b00dd207b70c2e6593aa6797d94cf023b41c5755da93787830dc15b383675b24"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-01 01:01:47"
  condition:
    hash.sha256(0, filesize) == "b00dd207b70c2e6593aa6797d94cf023b41c5755da93787830dc15b383675b24"
}

rule MalwareBazaar_Mirai_038_c1abcf5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1abcf5afb316cd4e384e8f7db4f08233850fd6a3bcf0e97c7504a6dea72b077"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-08-01 01:00:48"
  condition:
    hash.sha256(0, filesize) == "c1abcf5afb316cd4e384e8f7db4f08233850fd6a3bcf0e97c7504a6dea72b077"
}

rule MalwareBazaar_Mirai_039_12ee92d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "12ee92d529a704272662846f7752c077141070067246a4a9028309cee67583d0"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-08-01 01:00:46"
  condition:
    hash.sha256(0, filesize) == "12ee92d529a704272662846f7752c077141070067246a4a9028309cee67583d0"
}

rule MalwareBazaar_unknown_040_08e678b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08e678b14630558ba49781753227f1adc0534ea1d27ecf2b1c26a9eea89e23bb"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-08-01 00:52:32"
  condition:
    hash.sha256(0, filesize) == "08e678b14630558ba49781753227f1adc0534ea1d27ecf2b1c26a9eea89e23bb"
}

rule MalwareBazaar_Mirai_041_3eb3fb3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3eb3fb3db28bc4963bf09b9c95da22d3955d642c18c2080bed9d93db7972dad5"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-08-01 00:51:40"
  condition:
    hash.sha256(0, filesize) == "3eb3fb3db28bc4963bf09b9c95da22d3955d642c18c2080bed9d93db7972dad5"
}

rule MalwareBazaar_Mirai_042_61719f28
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61719f2880a07b5387e3717b1bb747feb715b8fcc0da3d06a9aa401c2aee3c2b"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-01 00:48:46"
  condition:
    hash.sha256(0, filesize) == "61719f2880a07b5387e3717b1bb747feb715b8fcc0da3d06a9aa401c2aee3c2b"
}

rule MalwareBazaar_Mirai_043_266fe39c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "266fe39ccb648475dc6706898a5c990818f85821c63ceb73e85aed90de29da53"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:48:43"
  condition:
    hash.sha256(0, filesize) == "266fe39ccb648475dc6706898a5c990818f85821c63ceb73e85aed90de29da53"
}

rule MalwareBazaar_Mirai_044_0c81a033
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c81a033bfeae78241b0df416132c92652abaacb23d01562a2a9acd5aab37f4a"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:43"
  condition:
    hash.sha256(0, filesize) == "0c81a033bfeae78241b0df416132c92652abaacb23d01562a2a9acd5aab37f4a"
}

rule MalwareBazaar_Mirai_045_7524f498
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7524f4985f445fa1bfeac4b889ae1c7d7de1e79d3c68a5f7768423852902c071"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:27"
  condition:
    hash.sha256(0, filesize) == "7524f4985f445fa1bfeac4b889ae1c7d7de1e79d3c68a5f7768423852902c071"
}

rule MalwareBazaar_Mirai_046_64931876
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6493187665a905b9b197e0c31b25fbcd5c5b6e6bb0a5da8846aa46c441e406e9"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:26"
  condition:
    hash.sha256(0, filesize) == "6493187665a905b9b197e0c31b25fbcd5c5b6e6bb0a5da8846aa46c441e406e9"
}

rule MalwareBazaar_Mirai_047_44cf9c9f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44cf9c9f306e313493ccba99e676ae31832aa566b237860434815ced14f4cf54"
    family = "Mirai"
    file_name = "nz.arm5"
    file_type = "elf"
    first_seen = "2026-08-01 00:47:24"
  condition:
    hash.sha256(0, filesize) == "44cf9c9f306e313493ccba99e676ae31832aa566b237860434815ced14f4cf54"
}

rule MalwareBazaar_Mirai_048_02f8ce40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "02f8ce40a3e6af2558da63721edcd4e25527e44fba26256c65aad9873636e320"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-01 00:46:00"
  condition:
    hash.sha256(0, filesize) == "02f8ce40a3e6af2558da63721edcd4e25527e44fba26256c65aad9873636e320"
}

rule MalwareBazaar_Mirai_049_a555e7dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a555e7dc1115168594e7cbedfd1e41cb98d7d7daaee41002b9fe981a3cc16aa5"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:58"
  condition:
    hash.sha256(0, filesize) == "a555e7dc1115168594e7cbedfd1e41cb98d7d7daaee41002b9fe981a3cc16aa5"
}

rule MalwareBazaar_Mirai_050_b2842820
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b284282059d0cbf9f7640624ae54b57018cd5d5e986002fff1bc5a34a8d2765d"
    family = "Mirai"
    file_name = "arc"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:38"
  condition:
    hash.sha256(0, filesize) == "b284282059d0cbf9f7640624ae54b57018cd5d5e986002fff1bc5a34a8d2765d"
}

rule MalwareBazaar_Mirai_051_815fc697
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "815fc69701ef8b1a35dc60bc6ea683fad70c176c26df68c2b65832510ce7bcc9"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:37"
  condition:
    hash.sha256(0, filesize) == "815fc69701ef8b1a35dc60bc6ea683fad70c176c26df68c2b65832510ce7bcc9"
}

rule MalwareBazaar_Mirai_052_f28ff115
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f28ff115079db6cd81b52775a337d2f694b53d130a2c1e52a247585c55ef7e71"
    family = "Mirai"
    file_name = "nz.ppc"
    file_type = "elf"
    first_seen = "2026-08-01 00:45:35"
  condition:
    hash.sha256(0, filesize) == "f28ff115079db6cd81b52775a337d2f694b53d130a2c1e52a247585c55ef7e71"
}

rule MalwareBazaar_unknown_053_88846e7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88846e7c0ddb5563fbba2056644aa06f629450bb805cc518c3eb2d3b66e9668e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-01 00:45:34"
  condition:
    hash.sha256(0, filesize) == "88846e7c0ddb5563fbba2056644aa06f629450bb805cc518c3eb2d3b66e9668e"
}

rule MalwareBazaar_Mirai_054_f774f92e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f774f92ea7a3c5c2ddf1275b869a3204a2c9fe7a16d96484f0ff4fa355185fa3"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-01 00:44:36"
  condition:
    hash.sha256(0, filesize) == "f774f92ea7a3c5c2ddf1275b869a3204a2c9fe7a16d96484f0ff4fa355185fa3"
}

rule MalwareBazaar_Mirai_055_1460d31f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1460d31f0473b71fddf08c397d9cdbad8986b1bef2addbd9e7b9ceeb301280da"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-08-01 00:43:34"
  condition:
    hash.sha256(0, filesize) == "1460d31f0473b71fddf08c397d9cdbad8986b1bef2addbd9e7b9ceeb301280da"
}

rule MalwareBazaar_unknown_056_eddbb347
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eddbb347628295fe95ed818e7b28543562d2cf35c30077f5dd16da4af3ff30df"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-01 00:41:39"
  condition:
    hash.sha256(0, filesize) == "eddbb347628295fe95ed818e7b28543562d2cf35c30077f5dd16da4af3ff30df"
}

rule MalwareBazaar_Mirai_057_5c9bc938
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c9bc93846185fc378415ead23a05c91bc200d1b76f53166999637de7d21627d"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:40:48"
  condition:
    hash.sha256(0, filesize) == "5c9bc93846185fc378415ead23a05c91bc200d1b76f53166999637de7d21627d"
}

rule MalwareBazaar_Mirai_058_6764fb21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6764fb212852e563b0e5e32966f60d05e7e0277cd0e526b32d4c976647372578"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-08-01 00:40:19"
  condition:
    hash.sha256(0, filesize) == "6764fb212852e563b0e5e32966f60d05e7e0277cd0e526b32d4c976647372578"
}

rule MalwareBazaar_Mirai_059_c1e61d32
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1e61d32bd277091cf92647cabec47cf3c56d28d7eef2e5b1b95e486f587eea6"
    family = "Mirai"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-01 00:40:18"
  condition:
    hash.sha256(0, filesize) == "c1e61d32bd277091cf92647cabec47cf3c56d28d7eef2e5b1b95e486f587eea6"
}

rule MalwareBazaar_Mirai_060_c2be6ac3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2be6ac32851aa53fd921a7dadc1b5470f0a649b8555ff8606853127db855f2c"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:32"
  condition:
    hash.sha256(0, filesize) == "c2be6ac32851aa53fd921a7dadc1b5470f0a649b8555ff8606853127db855f2c"
}

rule MalwareBazaar_Mirai_061_25ac6e12
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "25ac6e121f01285a41d461ca3f5a38b14a7c8148219ccbe270fe52d90c2f104b"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:24"
  condition:
    hash.sha256(0, filesize) == "25ac6e121f01285a41d461ca3f5a38b14a7c8148219ccbe270fe52d90c2f104b"
}

rule MalwareBazaar_Mirai_062_b419f6e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b419f6e0ab5e13bbab3bbba935a46020e40da4acfa3112fd3c0e9b2cbe268686"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:22"
  condition:
    hash.sha256(0, filesize) == "b419f6e0ab5e13bbab3bbba935a46020e40da4acfa3112fd3c0e9b2cbe268686"
}

rule MalwareBazaar_Mirai_063_e4a65dd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4a65dd53b6c3ad3eaead696093c360196f75165ce98ddd75bf164b9c4a2af52"
    family = "Mirai"
    file_name = "nz.arc"
    file_type = "elf"
    first_seen = "2026-08-01 00:37:21"
  condition:
    hash.sha256(0, filesize) == "e4a65dd53b6c3ad3eaead696093c360196f75165ce98ddd75bf164b9c4a2af52"
}

rule MalwareBazaar_Stealc_064_11621978
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726"
    family = "Stealc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-01 00:18:11"
  condition:
    hash.sha256(0, filesize) == "11621978916ef99d1c24cc4c7355d5a05d862dc9769b23f6685a21910d334726"
}

rule MalwareBazaar_Mirai_065_a7f3f9d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a7f3f9d9d14437727b3f75617fd2e469af27180be54b90c5a47387f30ba426a7"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 00:15:54"
  condition:
    hash.sha256(0, filesize) == "a7f3f9d9d14437727b3f75617fd2e469af27180be54b90c5a47387f30ba426a7"
}

rule MalwareBazaar_Mirai_066_ba059b88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba059b885edb94a1863a5e3989c6ab4dfa2afbeac9da0ed26208305223244591"
    family = "Mirai"
    file_name = "nz.mpsl"
    file_type = "elf"
    first_seen = "2026-08-01 00:14:36"
  condition:
    hash.sha256(0, filesize) == "ba059b885edb94a1863a5e3989c6ab4dfa2afbeac9da0ed26208305223244591"
}

rule MalwareBazaar_NanoCore_067_8d423e57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d423e57b2cf148ce393b09c1c67540f591af26b242ec428b4b7986a17fadf30"
    family = "NanoCore"
    file_name = "36DB027CB081301ECED5FE08F94EE9EA.exe"
    file_type = "exe"
    first_seen = "2026-08-01 00:05:06"
  condition:
    hash.sha256(0, filesize) == "8d423e57b2cf148ce393b09c1c67540f591af26b242ec428b4b7986a17fadf30"
}

rule MalwareBazaar_unknown_068_73cf812e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73cf812efdeafd903ef09c847457477950fa2b048c7b592e040c467a2082d091"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 23:52:28"
  condition:
    hash.sha256(0, filesize) == "73cf812efdeafd903ef09c847457477950fa2b048c7b592e040c467a2082d091"
}

rule MalwareBazaar_Mirai_069_b79ded1a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b79ded1ac75db0ae2ea212980b72669235d788cdc7e6fae4cf3818e38154015b"
    family = "Mirai"
    file_name = "nz.sh4"
    file_type = "elf"
    first_seen = "2026-07-31 23:38:15"
  condition:
    hash.sha256(0, filesize) == "b79ded1ac75db0ae2ea212980b72669235d788cdc7e6fae4cf3818e38154015b"
}

rule MalwareBazaar_Mirai_070_d1723eca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1723ecada5f6e8b6260cf2ff41d7f7f7b99e939db3db5a4b435ad4251ae3f3c"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 23:24:29"
  condition:
    hash.sha256(0, filesize) == "d1723ecada5f6e8b6260cf2ff41d7f7f7b99e939db3db5a4b435ad4251ae3f3c"
}

rule MalwareBazaar_Mirai_071_11f8d35e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11f8d35eb01d1d350b80ebcf49d949cdd9f7f58e6c8009a1c283a1956aa69359"
    family = "Mirai"
    file_name = "debug"
    file_type = "elf"
    first_seen = "2026-07-31 23:23:25"
  condition:
    hash.sha256(0, filesize) == "11f8d35eb01d1d350b80ebcf49d949cdd9f7f58e6c8009a1c283a1956aa69359"
}

rule MalwareBazaar_unknown_072_f07605b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f07605b995cf701ea40c0d4a535c5c8cc256b004d67d80ee2876ebf0dc0eb680"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 22:52:29"
  condition:
    hash.sha256(0, filesize) == "f07605b995cf701ea40c0d4a535c5c8cc256b004d67d80ee2876ebf0dc0eb680"
}

rule MalwareBazaar_RustyStealer_073_e8c96fed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8c96feda6791f0acdee4c084e0d438f7792a1d33aa31de036fdb6408ca7db97"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 22:52:15"
  condition:
    hash.sha256(0, filesize) == "e8c96feda6791f0acdee4c084e0d438f7792a1d33aa31de036fdb6408ca7db97"
}

rule MalwareBazaar_unknown_074_1ccfd655
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1ccfd6555390617b416bed0bd48ef3edba47bf042e102f504a2113bc356eeb0f"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 22:25:56"
  condition:
    hash.sha256(0, filesize) == "1ccfd6555390617b416bed0bd48ef3edba47bf042e102f504a2113bc356eeb0f"
}

rule MalwareBazaar_unknown_075_4e247c3a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e247c3ac69c652cba2a80e221d0eb18200da8464f90eed71f949db0d3b20b65"
    family = "unknown"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-07-31 22:19:18"
  condition:
    hash.sha256(0, filesize) == "4e247c3ac69c652cba2a80e221d0eb18200da8464f90eed71f949db0d3b20b65"
}

rule MalwareBazaar_unknown_076_126d2fea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "126d2fea7b1ea126a7dfa9d41a532a71ba1d41bb3473f5ba81694b2412059edc"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 21:52:27"
  condition:
    hash.sha256(0, filesize) == "126d2fea7b1ea126a7dfa9d41a532a71ba1d41bb3473f5ba81694b2412059edc"
}

rule MalwareBazaar_Mirai_077_7a2e6eb5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a2e6eb5538ae9371581d9b575345d480483b7c3b7d4fac34fa4a010ecf51414"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-31 21:28:35"
  condition:
    hash.sha256(0, filesize) == "7a2e6eb5538ae9371581d9b575345d480483b7c3b7d4fac34fa4a010ecf51414"
}

rule MalwareBazaar_Mirai_078_e00b46b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e00b46b3c716a4132f806f8c8c40bed2da93cea0e03e3d5901a1ba4f26c03f2a"
    family = "Mirai"
    file_name = "zero.armv6l"
    file_type = "elf"
    first_seen = "2026-07-31 21:28:27"
  condition:
    hash.sha256(0, filesize) == "e00b46b3c716a4132f806f8c8c40bed2da93cea0e03e3d5901a1ba4f26c03f2a"
}

rule MalwareBazaar_Mirai_079_6c22bcd5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6c22bcd5d4db88c58e67abeae0d8d91681949e03187c36c290a334c0c3f06b68"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-07-31 21:15:42"
  condition:
    hash.sha256(0, filesize) == "6c22bcd5d4db88c58e67abeae0d8d91681949e03187c36c290a334c0c3f06b68"
}

rule MalwareBazaar_unknown_080_fdab9767
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fdab9767c681ea284a20a1d39634cc3fc14c1e8a399eec963f7f67716ede3e17"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 21:00:28"
  condition:
    hash.sha256(0, filesize) == "fdab9767c681ea284a20a1d39634cc3fc14c1e8a399eec963f7f67716ede3e17"
}

rule MalwareBazaar_unknown_081_220324be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "220324be3422e4e57332df0a036f909705cb15d674f88aa45cc282b70a741c15"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-31 20:56:53"
  condition:
    hash.sha256(0, filesize) == "220324be3422e4e57332df0a036f909705cb15d674f88aa45cc282b70a741c15"
}

rule MalwareBazaar_unknown_082_44ce13c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305"
    family = "unknown"
    file_name = "44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305"
    file_type = "unknown"
    first_seen = "2026-07-31 20:54:48"
  condition:
    hash.sha256(0, filesize) == "44ce13c98ec7bc12c921f4d0d25234f7a52e249f32ac5d985d4d1c654fcbc305"
}

rule MalwareBazaar_unknown_083_9250e9fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9250e9fd0d73df09d608a544d27f048089071562ceb40de3600e9b5d85fa5f50"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 20:52:28"
  condition:
    hash.sha256(0, filesize) == "9250e9fd0d73df09d608a544d27f048089071562ceb40de3600e9b5d85fa5f50"
}

rule MalwareBazaar_unknown_084_1217b7b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1217b7b48b21d322037e4f2b9a54b8f45e8e3674b094a97a2aa042fce3fe2004"
    family = "unknown"
    file_name = "install_c0rd004.msi"
    file_type = "msi"
    first_seen = "2026-07-31 20:23:17"
  condition:
    hash.sha256(0, filesize) == "1217b7b48b21d322037e4f2b9a54b8f45e8e3674b094a97a2aa042fce3fe2004"
}

rule MalwareBazaar_Mirai_085_0737e5d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0737e5d164c332f41739f7c051b334fe92c897cd76a2520ead36cf044fdbcdc7"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-31 20:15:54"
  condition:
    hash.sha256(0, filesize) == "0737e5d164c332f41739f7c051b334fe92c897cd76a2520ead36cf044fdbcdc7"
}

rule MalwareBazaar_Mirai_086_d96b4ebf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96b4ebf15a9457582ce32492e67fd36a8e945db0c89d0e6cd1fd0b0b0a3493c"
    family = "Mirai"
    file_name = "zero.i486"
    file_type = "elf"
    first_seen = "2026-07-31 20:14:23"
  condition:
    hash.sha256(0, filesize) == "d96b4ebf15a9457582ce32492e67fd36a8e945db0c89d0e6cd1fd0b0b0a3493c"
}

rule MalwareBazaar_unknown_087_1a5847da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a5847daf96888bee8a740811e5d005e6b3fb28c20dce037e682cc6ba6a08647"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-31 20:14:22"
  condition:
    hash.sha256(0, filesize) == "1a5847daf96888bee8a740811e5d005e6b3fb28c20dce037e682cc6ba6a08647"
}

rule MalwareBazaar_Mirai_088_f7dd053f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7dd053fc6f69cbb9e2d70c1d16c9af7c011102b726a1afad2b6bbf55f2ebda9"
    family = "Mirai"
    file_name = "zero.armv7l"
    file_type = "elf"
    first_seen = "2026-07-31 20:13:35"
  condition:
    hash.sha256(0, filesize) == "f7dd053fc6f69cbb9e2d70c1d16c9af7c011102b726a1afad2b6bbf55f2ebda9"
}

rule MalwareBazaar_Mirai_089_68c913db
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68c913db3579d18dbe35e5e1a07c1418844931d44723053daa83e1c900c9a25c"
    family = "Mirai"
    file_name = "zero.armv7l"
    file_type = "elf"
    first_seen = "2026-07-31 20:12:40"
  condition:
    hash.sha256(0, filesize) == "68c913db3579d18dbe35e5e1a07c1418844931d44723053daa83e1c900c9a25c"
}

rule MalwareBazaar_Mirai_090_7c313c01
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c313c014a2718c8a0133d8dad005505dfd589ac4b2bc0f749a48108bb5d680b"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-31 20:02:37"
  condition:
    hash.sha256(0, filesize) == "7c313c014a2718c8a0133d8dad005505dfd589ac4b2bc0f749a48108bb5d680b"
}

rule MalwareBazaar_Mirai_091_8971bc38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8971bc38f11bb873115e0839508cdff8452dc34d993ebaac332e84dad96a45bf"
    family = "Mirai"
    file_name = "zero.mipsrouter"
    file_type = "elf"
    first_seen = "2026-07-31 20:01:49"
  condition:
    hash.sha256(0, filesize) == "8971bc38f11bb873115e0839508cdff8452dc34d993ebaac332e84dad96a45bf"
}

rule MalwareBazaar_Mirai_092_b8bc0ed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8bc0ed87ec3183f801031a5fe354758ba943f06918146b9a92d9bb8a5eec5d3"
    family = "Mirai"
    file_name = "zero.sh4"
    file_type = "elf"
    first_seen = "2026-07-31 19:58:39"
  condition:
    hash.sha256(0, filesize) == "b8bc0ed87ec3183f801031a5fe354758ba943f06918146b9a92d9bb8a5eec5d3"
}

rule MalwareBazaar_unknown_093_28657f65
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "28657f6526fa6385d7a3f8ca32c83d4e8bb8be69c34239f081daa3c448c5413c"
    family = "unknown"
    file_name = "milan.sh"
    file_type = "sh"
    first_seen = "2026-07-31 19:52:43"
  condition:
    hash.sha256(0, filesize) == "28657f6526fa6385d7a3f8ca32c83d4e8bb8be69c34239f081daa3c448c5413c"
}

rule MalwareBazaar_unknown_094_c28a7bf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c28a7bf288adab51e1371dddf98d10cd81c6099cd346e6093f50b367c2cd0b46"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-31 19:52:27"
  condition:
    hash.sha256(0, filesize) == "c28a7bf288adab51e1371dddf98d10cd81c6099cd346e6093f50b367c2cd0b46"
}

rule MalwareBazaar_Mirai_095_15ee716a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15ee716af9c7add145999df4ad744e8c58246a74ec7fd194a5dc6378f1b0483e"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 19:47:25"
  condition:
    hash.sha256(0, filesize) == "15ee716af9c7add145999df4ad744e8c58246a74ec7fd194a5dc6378f1b0483e"
}

rule MalwareBazaar_Mirai_096_357559d9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "357559d98829cb62fc5cad7b9fe9d7919cfb7ece64a3c890485dfa1c42d4a0ce"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-31 19:47:23"
  condition:
    hash.sha256(0, filesize) == "357559d98829cb62fc5cad7b9fe9d7919cfb7ece64a3c890485dfa1c42d4a0ce"
}

rule MalwareBazaar_Mirai_097_a1d30118
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1d301181d0270ad6559cf22daa9e7ee50506fdb116eea167b6dd274f259e26e"
    family = "Mirai"
    file_name = "nz.arm7"
    file_type = "elf"
    first_seen = "2026-07-31 19:46:46"
  condition:
    hash.sha256(0, filesize) == "a1d301181d0270ad6559cf22daa9e7ee50506fdb116eea167b6dd274f259e26e"
}

rule MalwareBazaar_Mirai_098_39757f55
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "39757f55c492188c04e133bd916b10769a1edc89b9c5067cc57038cdf7cc5048"
    family = "Mirai"
    file_name = "nz.mips"
    file_type = "elf"
    first_seen = "2026-07-31 19:46:45"
  condition:
    hash.sha256(0, filesize) == "39757f55c492188c04e133bd916b10769a1edc89b9c5067cc57038cdf7cc5048"
}

rule MalwareBazaar_Mirai_099_0020d6a6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0020d6a69202ba61f8a7ff6cc2c332ac297b8761e1a1fde9d658c88085791a62"
    family = "Mirai"
    file_name = "BlahajNet.armv5l"
    file_type = "elf"
    first_seen = "2026-07-31 19:43:44"
  condition:
    hash.sha256(0, filesize) == "0020d6a69202ba61f8a7ff6cc2c332ac297b8761e1a1fde9d658c88085791a62"
}

rule MalwareBazaar_Mirai_100_7fec435c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fec435c8069f75ee7661ace5d8ece030c51d25e24426e017df358c8b1cc0207"
    family = "Mirai"
    file_name = "nz.arm6"
    file_type = "elf"
    first_seen = "2026-07-31 19:38:30"
  condition:
    hash.sha256(0, filesize) == "7fec435c8069f75ee7661ace5d8ece030c51d25e24426e017df358c8b1cc0207"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

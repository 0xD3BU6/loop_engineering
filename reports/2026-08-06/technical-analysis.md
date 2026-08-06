# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-08-06

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 641 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 641 |
| Unique family labels | 6 |
| Unique file types | 4 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 74 |
| unknown | 20 |
| ValleyRAT | 2 |
| CoinMiner | 2 |
| GuLoader | 1 |
| RustyStealer | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 77 |
| exe | 17 |
| sh | 5 |
| js | 1 |

## Per-Sample Analysis

### Sample 1: `c70bd410fd31eb06`

| Field | Value |
|---|---|
| SHA-256 | `c70bd410fd31eb06bac8978b0b2ee3bf9132cce5db023a64f3bbcfb96a291680` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-06 03:03:44` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `438bb45167330b05530353161fc1a565` |
| SHA-1 | `511a1a50c0e07b6d190c21d6f5b57ac694e3dfc2` |
| SHA-256 | `c70bd410fd31eb06bac8978b0b2ee3bf9132cce5db023a64f3bbcfb96a291680` |
| SHA3-384 | `d44c4b2582841f3776ccb2791aa0808c686ae7fc520443cd1fb3ada6ecf7671d306399a0792efd743162118656676f2a` |
| TLSH | `T15E04094F7720CF61C729C53049B3CB4656E926522AE18849F32CDE08BE6534DA96FFD8` |
| TELFHASH | `t10d31d3b08b7b55119ac5c7ec88ec7756491e8515470adf33fd3180bc50260ece229d4f` |
| SSDEEP | `3072:4tY3f9iESxHwXMNcaiOSJxSznNP3TkkfRGzRAc05Wn1DzjD:YTixEPvyyX5W1TD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_c70bd410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c70bd410fd31eb06bac8978b0b2ee3bf9132cce5db023a64f3bbcfb96a291680"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 03:03:44"
  condition:
    hash.sha256(0, filesize) == "c70bd410fd31eb06bac8978b0b2ee3bf9132cce5db023a64f3bbcfb96a291680"
}
```

### Sample 2: `d1ffb7ec3dcaec34`

| Field | Value |
|---|---|
| SHA-256 | `d1ffb7ec3dcaec3400d22859583a961ba661a78089a561b9092b455e017788f7` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-06 03:02:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `76bc76350ed078d4de82972a9b01f79c` |
| SHA-1 | `b243fd604f24249d0061756f4ba5e9122b15120d` |
| SHA-256 | `d1ffb7ec3dcaec3400d22859583a961ba661a78089a561b9092b455e017788f7` |
| SHA3-384 | `7ed563b2b990f0fc04b17e2e07399fe786790410b6e76fffc49057abefb1783fc274e1c13d82252a375e601b03efdc50` |
| TLSH | `T1898312674C4E8685FB876434A489A3143651371D5DAEBB36E3CCF07EA8BC4E9E090C87` |
| SSDEEP | `1536:/jN48MgA98131Jfrkqj6ggF0njQhDuZ5UNXXkRIlDUK+KM9t2r4whZ6iRHMgBq5M:/jNZM18B1JTkCgFgEusXXWSO9it5q5M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_d1ffb7ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ffb7ec3dcaec3400d22859583a961ba661a78089a561b9092b455e017788f7"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 03:02:55"
  condition:
    hash.sha256(0, filesize) == "d1ffb7ec3dcaec3400d22859583a961ba661a78089a561b9092b455e017788f7"
}
```

### Sample 3: `79a184c05789e447`

| Field | Value |
|---|---|
| SHA-256 | `79a184c05789e4479d16d15a22206de124b2102b861dc4ba050c2aacb3ef834e` |
| Family label | `GuLoader` |
| File name | `rDetalle_Visita_I_137894350961234.exe` |
| File type | `exe` |
| First seen | `2026-08-06 03:01:13` |
| Reporter | `fabiodemartin` |
| Tags | `exe, GuLoader, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fec9198dac87022d7c6fc56e1e18ed62` |
| SHA-1 | `4beb0a2628da83bb6b0bf15ba48f36343db3666c` |
| SHA-256 | `79a184c05789e4479d16d15a22206de124b2102b861dc4ba050c2aacb3ef834e` |
| SHA3-384 | `6b575ac3efb98f48ba908caf771b8383e9e11825ede9b493fa57c9acedd4a71c4e323f1880f5255c0a2cce29c0607f9e` |
| IMPHASH | `671f2a1f8aee14d336bab98fea93d734` |
| TLSH | `T1F264C091724494A3C97007B049BAD53652A15E2DB9B1D20F33E1BE6FBBFE3C31A16607` |
| SSDEEP | `6144:ncBvWHOjyRV4zuAtanxSce0eutJ+p3Yw2Iva1NlTA:cSRWzuA25e0fJMZ2IC1XA` |
| ICON-DHASH | `22e0d0deda5c8cc0` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_003_79a184c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79a184c05789e4479d16d15a22206de124b2102b861dc4ba050c2aacb3ef834e"
    family = "GuLoader"
    file_name = "rDetalle_Visita_I_137894350961234.exe"
    file_type = "exe"
    first_seen = "2026-08-06 03:01:13"
  condition:
    hash.sha256(0, filesize) == "79a184c05789e4479d16d15a22206de124b2102b861dc4ba050c2aacb3ef834e"
}
```

### Sample 4: `6fcc636637d758b1`

| Field | Value |
|---|---|
| SHA-256 | `6fcc636637d758b1068ebcff7363ab4aefa39b93e278dbea825eebeb8a9357e2` |
| Family label | `ValleyRAT` |
| File name | `setup_r8013.exe` |
| File type | `exe` |
| First seen | `2026-08-06 02:57:51` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5e9f2eeb4f5a44fe672d74c53959577` |
| SHA-1 | `f094702af184cb7df67f3885451e212a954a88d7` |
| SHA-256 | `6fcc636637d758b1068ebcff7363ab4aefa39b93e278dbea825eebeb8a9357e2` |
| SHA3-384 | `0143bc0b8863282a340e83aa29230d74aef4aba4337e4ab8cd764e5fd5d360d036aa138b6b25d5555c4bbeea398caf1c` |
| IMPHASH | `380560563ebacca1589d8d38ac610187` |
| TLSH | `T161E78216B74289CEE076A238944B8F51E336E9704A71933723B5735D1FFE38C8EA6149` |
| SSDEEP | `98304:duj9nmW2eUAAq4gm4mNSh6q+luaePvl8/bbJtF0gofLzXQQ7QfM3rr:MRnmW2s/m3xq9a2l8/QX9EfM3rr` |
| ICON-DHASH | `c4e0b0a4cc74626a` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_004_6fcc6366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fcc636637d758b1068ebcff7363ab4aefa39b93e278dbea825eebeb8a9357e2"
    family = "ValleyRAT"
    file_name = "setup_r8013.exe"
    file_type = "exe"
    first_seen = "2026-08-06 02:57:51"
  condition:
    hash.sha256(0, filesize) == "6fcc636637d758b1068ebcff7363ab4aefa39b93e278dbea825eebeb8a9357e2"
}
```

### Sample 5: `f6be87cd9afeab65`

| Field | Value |
|---|---|
| SHA-256 | `f6be87cd9afeab65ef6ce2652f506ecaf228a705d3a22843e4eca96997f1dcf3` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-06 02:53:39` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8b3bac5ba9bd44c818160be7ddcd86b` |
| SHA-1 | `0d5d711f86def1f2ccaaf6d1b2891d4490ae727a` |
| SHA-256 | `f6be87cd9afeab65ef6ce2652f506ecaf228a705d3a22843e4eca96997f1dcf3` |
| SHA3-384 | `0ea87654b9ab3f4ca0f08bcb607c1cd833db7043d5043fce56f73427e1b854d8333c5dcdf38f4c7a17f97d6d1a8b07dd` |
| TLSH | `T11C235C2516857C24AE98C4361C7E2F0CB9AD43E6325452EEBFCB3CF68C4A6ADD10971D` |
| SSDEEP | `768:bJ+5S9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:bJ+53cr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_005_f6be87cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6be87cd9afeab65ef6ce2652f506ecaf228a705d3a22843e4eca96997f1dcf3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:53:39"
  condition:
    hash.sha256(0, filesize) == "f6be87cd9afeab65ef6ce2652f506ecaf228a705d3a22843e4eca96997f1dcf3"
}
```

### Sample 6: `62885ef62f5ce8db`

| Field | Value |
|---|---|
| SHA-256 | `62885ef62f5ce8dbb0df9f8a8a9955f6badc1ff303d5b9c5b1338082f1c5b5f5` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-08-06 02:50:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `714f66cf57a6859cea8b7e5ae350ceae` |
| SHA-1 | `a51e6e8b872c93d33db2d07a04776d65237ada53` |
| SHA-256 | `62885ef62f5ce8dbb0df9f8a8a9955f6badc1ff303d5b9c5b1338082f1c5b5f5` |
| SHA3-384 | `79adaa9c181a93316378353ed095f5843d2c44ff08733b3c0bdc5bf3676289f474238d8a46dee7983ef5a2febbfbd138` |
| TLSH | `T122B30855F880CA52CAD52679FF4E428D336317B8D3D93102CE24AE3577FA99A4B3B901` |
| SSDEEP | `3072:k4h68rMJxEB6b1nhalD/ljR8kI/iKbU4:k4hlMJxEQzalD/ljR8F1U4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_62885ef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62885ef62f5ce8dbb0df9f8a8a9955f6badc1ff303d5b9c5b1338082f1c5b5f5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:50:45"
  condition:
    hash.sha256(0, filesize) == "62885ef62f5ce8dbb0df9f8a8a9955f6badc1ff303d5b9c5b1338082f1c5b5f5"
}
```

### Sample 7: `791be1e6f2839b92`

| Field | Value |
|---|---|
| SHA-256 | `791be1e6f2839b929c5c6e65cfed9f27d16789e36443dfdc852051ceb53b5745` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-06 02:50:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d1b2045be2a57ae338568e26503284c` |
| SHA-1 | `e9af8c608a09363932cc6b74a992e052d7da6a28` |
| SHA-256 | `791be1e6f2839b929c5c6e65cfed9f27d16789e36443dfdc852051ceb53b5745` |
| SHA3-384 | `d14b73c6d510d7861f4a1f3a3bf2c95376df5fcebe0b0aa2e80475e268c79866b06fe0e6b382263580c556c2f2b6dc2a` |
| TLSH | `T160D312D54F48188EE537E234A6876324BCFC6BF2855BFA0057C85A691F5BB13F886390` |
| SSDEEP | `3072:6DNAIQLFGBMkW3TE2ESzXVGQFM6dCbyrQLRJVcs6jAmjpUVH:eAIQLFXZ3TE2ESLVG5hYQlycGKH` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_791be1e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "791be1e6f2839b929c5c6e65cfed9f27d16789e36443dfdc852051ceb53b5745"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-06 02:50:42"
  condition:
    hash.sha256(0, filesize) == "791be1e6f2839b929c5c6e65cfed9f27d16789e36443dfdc852051ceb53b5745"
}
```

### Sample 8: `3f515f90d48f8900`

| Field | Value |
|---|---|
| SHA-256 | `3f515f90d48f8900a449406a4bd176eac3731e9a203334af516b9add6a9ca7cc` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-08-06 02:48:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e6b9bd2021041fd5851db30891c47215` |
| SHA-1 | `6023d2873728698c4df36f737a51fb936d09a208` |
| SHA-256 | `3f515f90d48f8900a449406a4bd176eac3731e9a203334af516b9add6a9ca7cc` |
| SHA3-384 | `c41300508f5b0836a0b31c4d077ea845c05d7396ad62bc78c2728fa5d7f751d5f649b0c35b40a079463e344e75c84b02` |
| TLSH | `T111F32B56EA418A13C1D217BAFBDF825533239764D3DB33069928BFB43F8269E0E27505` |
| TELFHASH | `t1fa31ef72dba092271992d8009eff6f70612ee2032155fe27ef155c6c51e140f6817c5f` |
| SSDEEP | `3072:iVEQPusaqsoEbUIqXipNiR1dibf6IHSBbW22PLiM/9tsWhcmRwaWQx+i/:6EQP7aqDEbUIqXipQ1Ubf6IHSBy22PWQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_3f515f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f515f90d48f8900a449406a4bd176eac3731e9a203334af516b9add6a9ca7cc"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:48:38"
  condition:
    hash.sha256(0, filesize) == "3f515f90d48f8900a449406a4bd176eac3731e9a203334af516b9add6a9ca7cc"
}
```

### Sample 9: `520e8e29ace68efc`

| Field | Value |
|---|---|
| SHA-256 | `520e8e29ace68efc7f636e4b9722c663e4c81a152db1f3370eb13f889636f5a6` |
| Family label | `unknown` |
| File name | `MT_LADY_YASSO_VSL_BRIEF_DETAILSpdf.js` |
| File type | `js` |
| First seen | `2026-08-06 02:48:36` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f32649c7517a120e01f03d2ff7338ea1` |
| SHA-1 | `9633a041770c8755cd753dec7804e650285231bb` |
| SHA-256 | `520e8e29ace68efc7f636e4b9722c663e4c81a152db1f3370eb13f889636f5a6` |
| SHA3-384 | `9e5d363312bc584aad37d404da725adf67e62bc8589b28375aaa1aa2382c5c57bce41603c2c5d09cf62f2e7344bb4d0b` |
| TLSH | `T1CAE5F8F136DD7A059E1AB76C980E6A189B09D1710E83E1C4F0EF1FD1AA0F81762D4D9B` |
| SSDEEP | `49152:tuuX1LudDML/wlTSfbILkejdXK0OJIZtcdgiXuN:C` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_520e8e29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "520e8e29ace68efc7f636e4b9722c663e4c81a152db1f3370eb13f889636f5a6"
    family = "unknown"
    file_name = "MT_LADY_YASSO_VSL_BRIEF_DETAILSpdf.js"
    file_type = "js"
    first_seen = "2026-08-06 02:48:36"
  condition:
    hash.sha256(0, filesize) == "520e8e29ace68efc7f636e4b9722c663e4c81a152db1f3370eb13f889636f5a6"
}
```

### Sample 10: `00b0dee9cc3cb281`

| Field | Value |
|---|---|
| SHA-256 | `00b0dee9cc3cb281e4a53c33fa91b41d86004fb486b6af52ab809adcc74505d8` |
| Family label | `Mirai` |
| File name | `boatnet.arm7` |
| File type | `elf` |
| First seen | `2026-08-06 02:47:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e139d42932ebbc5c05930158692d970c` |
| SHA-1 | `0daefbf2bef680d2027d65ccfae78b805edcb537` |
| SHA-256 | `00b0dee9cc3cb281e4a53c33fa91b41d86004fb486b6af52ab809adcc74505d8` |
| SHA3-384 | `646148835043a2f0ad00e1924842f34462b757c20e307e6d4a80ea203d0ea467344cc08e1a501fe8ae83460b75baa77c` |
| TLSH | `T1B153F21B0DB419FAE7D026FAAD7ADDDA2942B7F49CB8A65133116F2C60C418347F44E2` |
| SSDEEP | `1536:t40V6Uke19LNL+n5tlGUShWkgshrx7muLjUEb9pzL+tk:tzR1dknZGzhosv7jLjUKLzLkk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_00b0dee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00b0dee9cc3cb281e4a53c33fa91b41d86004fb486b6af52ab809adcc74505d8"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:47:49"
  condition:
    hash.sha256(0, filesize) == "00b0dee9cc3cb281e4a53c33fa91b41d86004fb486b6af52ab809adcc74505d8"
}
```

### Sample 11: `189af4f4616bc74e`

| Field | Value |
|---|---|
| SHA-256 | `189af4f4616bc74e5aa2e39dcd8d33c668cd792ff84bbe63adaa57fbfc448294` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-08-06 02:44:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `efb3aa9cc287d928def315c48f599d96` |
| SHA-1 | `05907891bb00e27669d25e9da23212f04fdc6535` |
| SHA-256 | `189af4f4616bc74e5aa2e39dcd8d33c668cd792ff84bbe63adaa57fbfc448294` |
| SHA3-384 | `21fbd64f2d90d809646ae241446be1e54834d86833ccb99590ee5ae8144c0ff9392e1a009e600dd1d2a6b47fbde50aa0` |
| TLSH | `T149236D6516857C24AA98D4371D7E2F0CBDAD43E6320492DE7FCA3CF28C5AA9D910871D` |
| SSDEEP | `768:pXRWNGxVa9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnS:jlxBcr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_189af4f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189af4f4616bc74e5aa2e39dcd8d33c668cd792ff84bbe63adaa57fbfc448294"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:44:40"
  condition:
    hash.sha256(0, filesize) == "189af4f4616bc74e5aa2e39dcd8d33c668cd792ff84bbe63adaa57fbfc448294"
}
```

### Sample 12: `ffb0668a571ad16e`

| Field | Value |
|---|---|
| SHA-256 | `ffb0668a571ad16e671d71ee480fa292e94357c6cfc794dfa38be1a37779e431` |
| Family label | `Mirai` |
| File name | `killbotx.arm7` |
| File type | `elf` |
| First seen | `2026-08-06 02:44:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4bb19cb9e89759128972dd8d803ab4c2` |
| SHA-1 | `59ad2caea7b2d07d5101d4a72e3d198001f4be49` |
| SHA-256 | `ffb0668a571ad16e671d71ee480fa292e94357c6cfc794dfa38be1a37779e431` |
| SHA3-384 | `84ad79facd7a4b42b5a499f00e156b8a1d769cf3b4b7773e2e48921cbc116a8315c2a031abecc6539c9f24b7ca2f86b3` |
| TLSH | `T1EBB3F959F880CA52C6D5267AFB4E428D33231B78D3D97102CE24AE3577FE95A4B3B901` |
| SSDEEP | `3072:n4hqvUA4hakSXEd504awTVix8ezDvKeBEPg:n4h8UAcakQ4awTVix8yDBEP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_ffb0668a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb0668a571ad16e671d71ee480fa292e94357c6cfc794dfa38be1a37779e431"
    family = "Mirai"
    file_name = "killbotx.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:44:38"
  condition:
    hash.sha256(0, filesize) == "ffb0668a571ad16e671d71ee480fa292e94357c6cfc794dfa38be1a37779e431"
}
```

### Sample 13: `1c246410593a1d5b`

| Field | Value |
|---|---|
| SHA-256 | `1c246410593a1d5bc31cf4d58c6905df5e30fa7948c23e82ed424d6c9e2198ec` |
| Family label | `Mirai` |
| File name | `killbotx.mipsel` |
| File type | `elf` |
| First seen | `2026-08-06 02:39:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b539134199dfe15bb52c8dcfd47df01e` |
| SHA-1 | `7e59d22ff7754f05f155d0eefe19cfc4d3aa9d67` |
| SHA-256 | `1c246410593a1d5bc31cf4d58c6905df5e30fa7948c23e82ed424d6c9e2198ec` |
| SHA3-384 | `3698834449d689fba13dc2e7e862719df26df3abeca66508105e1cd77b790ee9dbf6478e8a9038b62316203900ed0e5a` |
| TLSH | `T1A3F32989EFA60FDFD46FCE30021E131719DD589B92F16336867CDD48769E6088AE3858` |
| TELFHASH | `t1fa317208c83acb3e58e243e8dfec0e61d685c56a9a521e228f36c35c4575009912befe` |
| SSDEEP | `3072:JgK/zPOoLvWIav3+RRMgtOzfd7V2eFBl8f5omb2kYubOQ8Magf8VX4bgy11lS6mF:qK/zPOoLvW1v3+RRMgtOzfd7A5omb2kq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_1c246410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c246410593a1d5bc31cf4d58c6905df5e30fa7948c23e82ed424d6c9e2198ec"
    family = "Mirai"
    file_name = "killbotx.mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 02:39:40"
  condition:
    hash.sha256(0, filesize) == "1c246410593a1d5bc31cf4d58c6905df5e30fa7948c23e82ed424d6c9e2198ec"
}
```

### Sample 14: `07310b71a33cb767`

| Field | Value |
|---|---|
| SHA-256 | `07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b` |
| Family label | `Mirai` |
| File name | `killbotx.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 02:39:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `295f892ac5feb6333dc52ae20eae8a85` |
| SHA-1 | `7b34ace5b1a37aef96f8cc99570051af7bfc4f96` |
| SHA-256 | `07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b` |
| SHA3-384 | `6f8a5df45fe6a3ee6c45f780184d8568ef0bef4824ef1d2b339e51977ab18c139f656ba13a0ae9806db66b71e779c247` |
| TLSH | `T1FAA34D02B49180FED49AD174879FD137EB32F98512347B5F2B847E312E36F222B5A691` |
| SSDEEP | `1536:CxAXe0QXW3LFgkogUKqfVKl1KkzS916LKtZWw+6ppxd9iZrQbInyNLor:y0SW3WFs3wkmOhC98Ubmf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_07310b71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b"
    family = "Mirai"
    file_name = "killbotx.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 02:39:37"
  condition:
    hash.sha256(0, filesize) == "07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b"
}
```

### Sample 15: `5dc7cef8a389cbd4`

| Field | Value |
|---|---|
| SHA-256 | `5dc7cef8a389cbd45cef863b10f2657e471101c1b4db34acba289b33066886ed` |
| Family label | `Mirai` |
| File name | `killbotx.mipsel` |
| File type | `elf` |
| First seen | `2026-08-06 02:38:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6554d2f05a8201b908211b1c43b0a94` |
| SHA-1 | `2aeea2d93d31481edf1ae55552f8c9206909c17f` |
| SHA-256 | `5dc7cef8a389cbd45cef863b10f2657e471101c1b4db34acba289b33066886ed` |
| SHA3-384 | `bed64bd0836df62441a18416f64f1e473d79671d562b3795a0205da2dd36d9910d24dc90c8fd44d83cb951270c4c59ee` |
| TLSH | `T16163033AB3E54B9BCBCA5D7FB45B1723E50852F310D897AB49028D4C4A9453B783E81B` |
| SSDEEP | `1536:S5nG3+T8Pq0FoEoXRzIIKNSNrK+ej/UJAzYPD8CfZoT/692Naq:S54hPqZzV/rGdknu/tV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_5dc7cef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dc7cef8a389cbd45cef863b10f2657e471101c1b4db34acba289b33066886ed"
    family = "Mirai"
    file_name = "killbotx.mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 02:38:37"
  condition:
    hash.sha256(0, filesize) == "5dc7cef8a389cbd45cef863b10f2657e471101c1b4db34acba289b33066886ed"
}
```

### Sample 16: `ea7244d77c736277`

| Field | Value |
|---|---|
| SHA-256 | `ea7244d77c73627733522c2658ccd158cd91d6505aaefbd83ed12259811324c0` |
| Family label | `Mirai` |
| File name | `killbotx.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 02:38:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f81faaead39c1398e084a44b27e269e` |
| SHA-1 | `e98e418386f0906ad128a1ca4126437b48fbf20f` |
| SHA-256 | `ea7244d77c73627733522c2658ccd158cd91d6505aaefbd83ed12259811324c0` |
| SHA3-384 | `084d2b4e4b34de25c2e3bf45f84d5afc03c0057adaa03c68666f238ccd25fe6ad079655f34c815a73e1ab77256061fac` |
| TLSH | `T15933F162574BDABCC47C957A0C9D0A8DFC638A25752BEE2BDC1027E20C674170FB2B85` |
| SSDEEP | `1536:VCFEnQDpN2OiBLgVn3bkrqCrfTpbOCx5Dl:VCFEQ1PiyVnLkmCzTVOCnDl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_ea7244d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea7244d77c73627733522c2658ccd158cd91d6505aaefbd83ed12259811324c0"
    family = "Mirai"
    file_name = "killbotx.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 02:38:36"
  condition:
    hash.sha256(0, filesize) == "ea7244d77c73627733522c2658ccd158cd91d6505aaefbd83ed12259811324c0"
}
```

### Sample 17: `716119c3bdd05a5a`

| Field | Value |
|---|---|
| SHA-256 | `716119c3bdd05a5a7d6d1033418919561030038081dc5f79ffc8bda6ca002923` |
| Family label | `Mirai` |
| File name | `boatnet.i486` |
| File type | `elf` |
| First seen | `2026-08-06 02:36:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `834069b0eb309178129491f3c7c013f8` |
| SHA-1 | `b283122bffab256d9ec24aeafde45cfd5b555c2c` |
| SHA-256 | `716119c3bdd05a5a7d6d1033418919561030038081dc5f79ffc8bda6ca002923` |
| SHA3-384 | `a436f0abb073d5e8c23281bae855cc8bf915b69dc44d3b53565306caa1a9bd9d03299ae162e8fd1afac1bc3ed5367500` |
| TLSH | `T123732B86F343E4F0ED4A46B1009FB37EE6348E525024DA6AEF91FDA19D23A12601F75D` |
| TELFHASH | `t16d3128bb5eb11de877d06805c35f63e22a39d537195035ba06b2696033e2a92d06ec38` |
| SSDEEP | `1536:xW1K5YnYMnC3tx5CeG4qpsQp+li7gdkBUx31cJIxcMMr:xWfYtx5CpMiWNip` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_716119c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716119c3bdd05a5a7d6d1033418919561030038081dc5f79ffc8bda6ca002923"
    family = "Mirai"
    file_name = "boatnet.i486"
    file_type = "elf"
    first_seen = "2026-08-06 02:36:38"
  condition:
    hash.sha256(0, filesize) == "716119c3bdd05a5a7d6d1033418919561030038081dc5f79ffc8bda6ca002923"
}
```

### Sample 18: `27f06e0d5c08b66a`

| Field | Value |
|---|---|
| SHA-256 | `27f06e0d5c08b66a9c3ae1ca7c0629d8e20f9489bf4e1463481b6c9d5fdb27ee` |
| Family label | `Mirai` |
| File name | `boatnet.i486` |
| File type | `elf` |
| First seen | `2026-08-06 02:35:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71210752f2cb45c2790dc7ba905e6ba9` |
| SHA-1 | `5237be1bc647f056c9219bb7a6259b99b9eb6285` |
| SHA-256 | `27f06e0d5c08b66a9c3ae1ca7c0629d8e20f9489bf4e1463481b6c9d5fdb27ee` |
| SHA3-384 | `1de477a15eb9fa104848bb14e900ece09e5905b17f135a72af7bbe29c3614304a77e0f8ebfc758e280f6011fc5dfbaa8` |
| TLSH | `T1C4F2E162EA541835C3A76739D07D8CEC95A86C9B392C861E73D28F97075E02752BAE00` |
| SSDEEP | `768:rFd1biqKf8IJMBjThF/JgA2riyuF8i4w1HeHOACTvMI6XNTT0IRjVFam/BS:rJdKfdiJF/JgAa+F8PqmxL/f04RAmg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_27f06e0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27f06e0d5c08b66a9c3ae1ca7c0629d8e20f9489bf4e1463481b6c9d5fdb27ee"
    family = "Mirai"
    file_name = "boatnet.i486"
    file_type = "elf"
    first_seen = "2026-08-06 02:35:40"
  condition:
    hash.sha256(0, filesize) == "27f06e0d5c08b66a9c3ae1ca7c0629d8e20f9489bf4e1463481b6c9d5fdb27ee"
}
```

### Sample 19: `2ed02943cd801954`

| Field | Value |
|---|---|
| SHA-256 | `2ed02943cd801954de9d92a66eab12cb718ffe57a3e0f3df95103a72d181f879` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 02:33:36` |
| Reporter | `Bitsight` |
| Tags | `81a64890ca97bd87f0c9d35bc6501f4d, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8fe3f9d368c0f417944d46048083f878` |
| SHA-1 | `0650505c58c16706a01566ea45d4ee362dfbdda6` |
| SHA-256 | `2ed02943cd801954de9d92a66eab12cb718ffe57a3e0f3df95103a72d181f879` |
| SHA3-384 | `a90c4a02bd7d573a0c63541cbc9b890262b490fa25e99f6e065c3eaf4c6698e5e37660b593b1c5e305576efd47deee16` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T13536339659C62976C0E5C3F8D21E243DB1777B640AB17D0B7BCC7208CE5AA1129BC3DA` |
| SSDEEP | `98304:nhxpRNrQ/RnVF4OflR1zlZJffeB6vFGQOTsqj80Q1Wdk4cIVKPVWj1ECPcI0vYy:ndHrG5f7zZJfWeGtTsqjrQkG45ctAiCQ` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_019_2ed02943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed02943cd801954de9d92a66eab12cb718ffe57a3e0f3df95103a72d181f879"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:36"
  condition:
    hash.sha256(0, filesize) == "2ed02943cd801954de9d92a66eab12cb718ffe57a3e0f3df95103a72d181f879"
}
```

### Sample 20: `2e747f610c929513`

| Field | Value |
|---|---|
| SHA-256 | `2e747f610c9295132aa6e2827b4dca7656869eea15b6cad5b0a4aa61c37413a2` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 02:33:24` |
| Reporter | `Bitsight` |
| Tags | `81a64890ca97bd87f0c9d35bc6501f4d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `afac731c2877a0db53b783d6a05ea86f` |
| SHA-1 | `aa5ebfaa709abce178170a9d43916d6882303f59` |
| SHA-256 | `2e747f610c9295132aa6e2827b4dca7656869eea15b6cad5b0a4aa61c37413a2` |
| SHA3-384 | `7db40eebbb6dca5935cfb31a6fbafaf06393693c95c7ec5f16f11cfe7f806c48ba0b28847f9e2972c471d1aa456b069c` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1FCD5238A7AB11DB0C43BC3B65F52E07EB0297B868B354D5BB6CC5A108E235586C3B735` |
| SSDEEP | `49152:7XMKPZC37lZp3K25H0BVjFk/S+TV/9hzbtd2Pq3Yc6Vt/4cTr1RFJVsoj58cwkMP:AWC7lZ1K25H0TF23Txtd69VX/X1RRtCL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_020_2e747f61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e747f610c9295132aa6e2827b4dca7656869eea15b6cad5b0a4aa61c37413a2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:24"
  condition:
    hash.sha256(0, filesize) == "2e747f610c9295132aa6e2827b4dca7656869eea15b6cad5b0a4aa61c37413a2"
}
```

### Sample 21: `d6d7444a1d99ffa5`

| Field | Value |
|---|---|
| SHA-256 | `d6d7444a1d99ffa5f99e0ad5d41c69916e67b57fa005a785b338160b15eb90bf` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 02:33:17` |
| Reporter | `Bitsight` |
| Tags | `81a64890ca97bd87f0c9d35bc6501f4d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `03319ce88bb10dc9b695ae57a619463a` |
| SHA-1 | `47412e5a95ec3d9324c0e3c87662790a7ef79b9f` |
| SHA-256 | `d6d7444a1d99ffa5f99e0ad5d41c69916e67b57fa005a785b338160b15eb90bf` |
| SHA3-384 | `6fca0ae5a2b49b5826dc7c252a2625f4f50e69628e5c875b14fbda23d691cb403753ca890dc3b55672d0c7608a6fe261` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T12CD5239EFDB31531E036C3F3819720AEF21A7B8087658D5676C92B206D539286C7737A` |
| SSDEEP | `49152:VejFwDKGX1i5SWchAujnXonPqauRxB536uxVvTzpL885CS0lsj43BVJWgbS0gr+x:VejFsX2SwcmPqauRJxVrrHcjbSLHG` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_d6d7444a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6d7444a1d99ffa5f99e0ad5d41c69916e67b57fa005a785b338160b15eb90bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:17"
  condition:
    hash.sha256(0, filesize) == "d6d7444a1d99ffa5f99e0ad5d41c69916e67b57fa005a785b338160b15eb90bf"
}
```

### Sample 22: `b133af2fc6335073`

| Field | Value |
|---|---|
| SHA-256 | `b133af2fc6335073a8742691d536e97409b04c59c23b2440b26b23da66c76b81` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 02:33:10` |
| Reporter | `Bitsight` |
| Tags | `81a64890ca97bd87f0c9d35bc6501f4d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd4187782911531014435e70be06f6be` |
| SHA-1 | `36936a1f13fb3721ab84c5b74875e6eb9e221f33` |
| SHA-256 | `b133af2fc6335073a8742691d536e97409b04c59c23b2440b26b23da66c76b81` |
| SHA3-384 | `a8417544934f2f1c4a54ce54cf4e40e84abdbba8832f6cb65acb68a893984c4fcb8197110fcec79a9b66806c0a554d69` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T198D523D678F214B5D833C7B6CFD2F45EB22A77C50B664D8676CD29108E826825C3A738` |
| SSDEEP | `49152:YnncZwHu1r8bkjkp6OrqaxBr7bdHSilmnTDea5L5rGypEYIsQLz9UTas4:YncZ5r8bkjktTbdHPl2TD7LEyeiyo` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_b133af2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b133af2fc6335073a8742691d536e97409b04c59c23b2440b26b23da66c76b81"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:10"
  condition:
    hash.sha256(0, filesize) == "b133af2fc6335073a8742691d536e97409b04c59c23b2440b26b23da66c76b81"
}
```

### Sample 23: `5015daf6cd5f8b73`

| Field | Value |
|---|---|
| SHA-256 | `5015daf6cd5f8b73685b91536a69ed646a510ed97bd70d9bf2c661f501bdc42f` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-06 02:26:42` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `147924e0968285d0ac603a7c1df339d9` |
| SHA-1 | `d15bd76f6182777dc433cd0f428567fdb51662cf` |
| SHA-256 | `5015daf6cd5f8b73685b91536a69ed646a510ed97bd70d9bf2c661f501bdc42f` |
| SHA3-384 | `d95d0466299898ecd695088b9d80e49ea794281e6dd36d46cbfba6c547eb33b9da361f87a90c1fc7bf6f9f3f662c7a5a` |
| TLSH | `T174C27D956A867C44BDC98A3E4CBD2B1D6DF5C3D1224942AC3D8B3C71DC11FACD618B1A` |
| SSDEEP | `768:I8vCB+25j6es8RI9FYpMSUpi+20qUpi+20YQX:I8l25Jed2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_5015daf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5015daf6cd5f8b73685b91536a69ed646a510ed97bd70d9bf2c661f501bdc42f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:26:42"
  condition:
    hash.sha256(0, filesize) == "5015daf6cd5f8b73685b91536a69ed646a510ed97bd70d9bf2c661f501bdc42f"
}
```

### Sample 24: `c208a7a095ef6247`

| Field | Value |
|---|---|
| SHA-256 | `c208a7a095ef6247c309165af0230c0ef8ab9709bd362b29258cff68f58f839d` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-08-06 02:21:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c96dea4d6e78c458589c4ce72beab084` |
| SHA-1 | `a03aa93e7976eaa64f766ba901ef8edf0458b8d8` |
| SHA-256 | `c208a7a095ef6247c309165af0230c0ef8ab9709bd362b29258cff68f58f839d` |
| SHA3-384 | `6f87230bccdb6b48af99022e93c94e95635b26396ea0fc935aac34a23de11522772688f03e38fb8bfb24bd14cb46c5c7` |
| TLSH | `T1D8932996F8818B12C5D512BAFA1E118D332717F8E3DE72229E206F247BC692B0D77D45` |
| TELFHASH | `t1f0b01221df720f79f3828318108841280facf2fdd6c29c3deaf017b6894e1813200d00` |
| SSDEEP | `1536:74nP611KQoKr8gM1rrZl/ge7V8wSygWapTPkUInPOMRivdg8vQ58YQ6x:Tvr8Brll1WygWap+qdgOQeWx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_c208a7a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c208a7a095ef6247c309165af0230c0ef8ab9709bd362b29258cff68f58f839d"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 02:21:38"
  condition:
    hash.sha256(0, filesize) == "c208a7a095ef6247c309165af0230c0ef8ab9709bd362b29258cff68f58f839d"
}
```

### Sample 25: `3d647fcb1c48da7a`

| Field | Value |
|---|---|
| SHA-256 | `3d647fcb1c48da7a95c0bc500da45c150f00ddd7871e90297d2f79f38286ada3` |
| Family label | `Mirai` |
| File name | `killbotx.mips` |
| File type | `elf` |
| First seen | `2026-08-06 02:20:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6e5be017144ea23f2277d4b02d8d82f` |
| SHA-1 | `951abb177f965016ec53b47713b0353a3696f430` |
| SHA-256 | `3d647fcb1c48da7a95c0bc500da45c150f00ddd7871e90297d2f79f38286ada3` |
| SHA3-384 | `7c3ef189f4d8bbbbbcc0ba9b7ad872461c3b03ef6b2351ba179ca09ab3f9f3854aecac05a10e6d81362afbab278691e6` |
| TLSH | `T132F3194B77118FA1D33AD63006F34BA7ABA9268517D2A585E36DDD007F6034C682FFA4` |
| TELFHASH | `t1fa317208c83acb3e58e243e8dfec0e61d685c56a9a521e228f36c35c4575009912befe` |
| SSDEEP | `3072:rYM/RSXUitDSbR6CdSbGjAHHfnH6AKjDPW1LGjNxmZoHZjby:J5SkIDSkCd4Gk/gwLGjzUolW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_3d647fcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d647fcb1c48da7a95c0bc500da45c150f00ddd7871e90297d2f79f38286ada3"
    family = "Mirai"
    file_name = "killbotx.mips"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:52"
  condition:
    hash.sha256(0, filesize) == "3d647fcb1c48da7a95c0bc500da45c150f00ddd7871e90297d2f79f38286ada3"
}
```

### Sample 26: `b26ce9d2b84da259`

| Field | Value |
|---|---|
| SHA-256 | `b26ce9d2b84da259a16cff2788c9d36011f60f4fcfaf08a2a736490db92e4949` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-08-06 02:20:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf5df11f2527f30d2836723a1ec94ebc` |
| SHA-1 | `3f8d93239910f688e14a3690e145c2bc599fed7d` |
| SHA-256 | `b26ce9d2b84da259a16cff2788c9d36011f60f4fcfaf08a2a736490db92e4949` |
| SHA3-384 | `6ff6b1b0ffe7e0d6b92bc4480ba5c8086274a98221ed34d6a782d6d1f658604a3655485454020b6376842c9cee03159c` |
| TLSH | `T18813F15AE32E4652CDB35E71DAE82C0732AFC26890ED30B207AD5A9065C270D5DF97C7` |
| SSDEEP | `768:ga6sPPGAgp62bwuFr54xdJk3jVR9FRC0LNZSU81uS9q3UELrw:ga6sPfgp62bbIdO3jRLLNZS51uHLc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_b26ce9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b26ce9d2b84da259a16cff2788c9d36011f60f4fcfaf08a2a736490db92e4949"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:41"
  condition:
    hash.sha256(0, filesize) == "b26ce9d2b84da259a16cff2788c9d36011f60f4fcfaf08a2a736490db92e4949"
}
```

### Sample 27: `23cb10bd16bcc36e`

| Field | Value |
|---|---|
| SHA-256 | `23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25` |
| Family label | `unknown` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-08-06 02:20:39` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e3991bfeb38bc3ec59c1d2ed26439406` |
| SHA-1 | `9ac2d1d689c1f25fc7aec50919baf88f73d3d917` |
| SHA-256 | `23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25` |
| SHA3-384 | `c08d4a6cdbd6fd7f9bb78eb9b9e04e4fcc4c893d11b6a6d88d3248f1754ecd14857fbae454963ab7fb5fefb738a1b309` |
| TLSH | `T149B3122471AFE57D1B072CB0EE781FC20F68AD2A569F2591602937E187924FB31354EB` |
| SSDEEP | `3072:RM0Fk5sjvQXtte6Pgb/cxVDm2sysv/y0q+emJN:e0Fk5sUtte6POAVJsvq07JN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_027_23cb10bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:39"
  condition:
    hash.sha256(0, filesize) == "23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25"
}
```

### Sample 28: `024ee12e5b892c7b`

| Field | Value |
|---|---|
| SHA-256 | `024ee12e5b892c7bbb2baa1376f8b85c7c382e0c513071d0ed54b1187da73584` |
| Family label | `Mirai` |
| File name | `killbotx.mips` |
| File type | `elf` |
| First seen | `2026-08-06 02:20:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb67e34f3ab7458e5ed30bb6bfa9fb69` |
| SHA-1 | `ac391f683252698a00d5c6ae31961a7bc5367f7e` |
| SHA-256 | `024ee12e5b892c7bbb2baa1376f8b85c7c382e0c513071d0ed54b1187da73584` |
| SHA3-384 | `cbe7bb7ad30f4d6e3e76356c42b5469d001965f0043b50e34d1e6f5398fb1d54e2a517511533851b38a644d53ed2861f` |
| TLSH | `T1216301AC2178052BEBC630B5319743992E330BD2B83ACC9EFDA5E28705F645EA4D75C0` |
| SSDEEP | `1536:x/0wEgHjcX4IdsAcgoih/J4NE/ixFgp4gpXLrscvVEWOF:WwEgDgdZkGeE/iQOgBNvVE9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_024ee12e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "024ee12e5b892c7bbb2baa1376f8b85c7c382e0c513071d0ed54b1187da73584"
    family = "Mirai"
    file_name = "killbotx.mips"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:37"
  condition:
    hash.sha256(0, filesize) == "024ee12e5b892c7bbb2baa1376f8b85c7c382e0c513071d0ed54b1187da73584"
}
```

### Sample 29: `b913aed0a412dc14`

| Field | Value |
|---|---|
| SHA-256 | `b913aed0a412dc14e3bd5570f8aa0bc2c04fdba0ab04a885e2b24638d25f2553` |
| Family label | `Mirai` |
| File name | `killbotx.arm4` |
| File type | `elf` |
| First seen | `2026-08-06 02:11:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c86cfcd5053349b4863b081ebceb57ce` |
| SHA-1 | `95cec8d57a00eeae42fe7bbed02a85ef5e3ee28a` |
| SHA-256 | `b913aed0a412dc14e3bd5570f8aa0bc2c04fdba0ab04a885e2b24638d25f2553` |
| SHA3-384 | `5316f2e9771eab274ca92a9f81464bd1ac74d7aab74c33721eb27f254f1de67d84371f14a34f35bbb3567cf32c1d0573` |
| TLSH | `T1E7B3F855F880CB62C6D4267AFB4E428D33231B79D3ED3106CE14AF3567FA95A4B3A901` |
| SSDEEP | `3072:/4hJ7xmHgbjdIqU3wWqIOItn/S1z1bqhrJS8aLEP:/4hpxmudIqU33q4tn/S1z1uf0EP` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_b913aed0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b913aed0a412dc14e3bd5570f8aa0bc2c04fdba0ab04a885e2b24638d25f2553"
    family = "Mirai"
    file_name = "killbotx.arm4"
    file_type = "elf"
    first_seen = "2026-08-06 02:11:40"
  condition:
    hash.sha256(0, filesize) == "b913aed0a412dc14e3bd5570f8aa0bc2c04fdba0ab04a885e2b24638d25f2553"
}
```

### Sample 30: `dd60f1a53de66a16`

| Field | Value |
|---|---|
| SHA-256 | `dd60f1a53de66a16846e426f6972a17ce668eb7b6586c846dccdfa04e01e313e` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-08-06 02:09:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97878209df43fa41623069d297468192` |
| SHA-1 | `e4e191c74a17a8c00f42290af868cab630524faf` |
| SHA-256 | `dd60f1a53de66a16846e426f6972a17ce668eb7b6586c846dccdfa04e01e313e` |
| SHA3-384 | `7bab826866b2c002abe6361cd876a1ee49fcf690e2ddd70e0877bd798a6d77d0640a9cd033d17250fbe20632753573a8` |
| TLSH | `T1EF732C02B70C0E47D3A71EF03A3F27E6939ED58122E4AE88394EAE459171D3255C6ED9` |
| SSDEEP | `1536:HNZWZCQwQwQwf+6246yktuGRNtopGVaaPRyIi4Xh/XYrBycqvNX:H/Or9VaaliHKB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_dd60f1a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd60f1a53de66a16846e426f6972a17ce668eb7b6586c846dccdfa04e01e313e"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 02:09:25"
  condition:
    hash.sha256(0, filesize) == "dd60f1a53de66a16846e426f6972a17ce668eb7b6586c846dccdfa04e01e313e"
}
```

### Sample 31: `71b77cc8813142f0`

| Field | Value |
|---|---|
| SHA-256 | `71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c` |
| Family label | `unknown` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-06 02:08:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1bf84d7c62c30854a25359eaf4021a29` |
| SHA-1 | `ed1ff12097a5990b0eeeb00444e2a62b206782fd` |
| SHA-256 | `71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c` |
| SHA3-384 | `970284c5789527443227e6960f3e863e5d4a4674090c756833fb515128f44d0ed810d22956b707f1c8316f9bfb829490` |
| TLSH | `T1EAC312823AA847FEC82D547310DB75F78A04864CF0957A529F4F2997EB287106FF6A13` |
| SSDEEP | `3072:i+Qasc1vsCLcBaDYWAUDtj122Q6g/v9nIovjmloutF:nsc5LYBaqwtp5/49nRvYoSF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_71b77cc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-06 02:08:42"
  condition:
    hash.sha256(0, filesize) == "71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c"
}
```

### Sample 32: `f819a2a054b85e6d`

| Field | Value |
|---|---|
| SHA-256 | `f819a2a054b85e6d4d85cd5df2fa6682630f6afd4b7abeac159980b0e98452d4` |
| Family label | `Mirai` |
| File name | `boatnet.ppc` |
| File type | `elf` |
| First seen | `2026-08-06 02:08:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6060fd2f074c04524acc6aad594bb8b6` |
| SHA-1 | `6f3f5e82e0453b707a8ce397893c0df6b2b14c19` |
| SHA-256 | `f819a2a054b85e6d4d85cd5df2fa6682630f6afd4b7abeac159980b0e98452d4` |
| SHA3-384 | `7afd0261e7ba2b47e5849fff7a6f2f1ea1fc1d1eca6d14edf4a5c7bbb0e6fb49d5d6d4abd33fa17d4c133ea88e73f2e7` |
| TLSH | `T1C7F2E071E1E9AA23CFDEBDF15CCA9B963BF63E6836720D5140895B50129E0F947008F8` |
| SSDEEP | `768:HdPkw4kSeNkHjEYdsY23VF9OpGmC6nWn1elkIVgxFrAn74uVcqgw098:9B4k/Nk7SPX9OpGKWn1euQgbAn74u+qV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_f819a2a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f819a2a054b85e6d4d85cd5df2fa6682630f6afd4b7abeac159980b0e98452d4"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 02:08:40"
  condition:
    hash.sha256(0, filesize) == "f819a2a054b85e6d4d85cd5df2fa6682630f6afd4b7abeac159980b0e98452d4"
}
```

### Sample 33: `3f856bcfb0f007e9`

| Field | Value |
|---|---|
| SHA-256 | `3f856bcfb0f007e94896433d134d16b22b653745d26a5c7d14bd9e9d9b1eb068` |
| Family label | `Mirai` |
| File name | `boatnet.mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 02:06:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2aaccdb3c409455c24fee846df6f3031` |
| SHA-1 | `13363de0b541ceed4d3ece85627eb643b0adaf1c` |
| SHA-256 | `3f856bcfb0f007e94896433d134d16b22b653745d26a5c7d14bd9e9d9b1eb068` |
| SHA3-384 | `5fcb17d49bb7af9af47e7ecfabeca3ff53585ba802c512bf39aec335b71a4dc06798480ac5ff4eb9ca41bb4680b25550` |
| TLSH | `T1BFA3E716EF100EFBD86FDE3705A90B41358C594722A93B3A7674CA28FA5A94F09D3C74` |
| SSDEEP | `1536:mFdM87/jzucl7gcQG0zuZ5HYOpacoeQjc6bVyebrru6n4s7ncqC+:m7/X576GZLv6Nl4+K+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_3f856bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f856bcfb0f007e94896433d134d16b22b653745d26a5c7d14bd9e9d9b1eb068"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 02:06:32"
  condition:
    hash.sha256(0, filesize) == "3f856bcfb0f007e94896433d134d16b22b653745d26a5c7d14bd9e9d9b1eb068"
}
```

### Sample 34: `4b53589aa2d15bbd`

| Field | Value |
|---|---|
| SHA-256 | `4b53589aa2d15bbd5e723d2ec61a9453edcd3dfd5d82cee356c5388f7d37aadd` |
| Family label | `Mirai` |
| File name | `boatnet.mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 02:05:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1cce40b2e456629e680d17f1e76ad14` |
| SHA-1 | `ddfe715e619e7e45e4ca42b72956c7f35ac34813` |
| SHA-256 | `4b53589aa2d15bbd5e723d2ec61a9453edcd3dfd5d82cee356c5388f7d37aadd` |
| SHA3-384 | `6e0690e4c634fee18b433b186bdd907cd483fc7eb2ef847a22df3eb467497fbf277d24949630a48406a1ea86f1c2b17c` |
| TLSH | `T1DE03F1EE91616B05C58F9D3A81DB23712E84B0E0304E6F35B21564DD737EE67E82C4B8` |
| SSDEEP | `768:tgZQtrQ3/OMRTK64Yg6AjZlD0hs3svdxsn0GqOWW+:t0Qtri7RCZN0xLsRqOC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_4b53589a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b53589aa2d15bbd5e723d2ec61a9453edcd3dfd5d82cee356c5388f7d37aadd"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 02:05:45"
  condition:
    hash.sha256(0, filesize) == "4b53589aa2d15bbd5e723d2ec61a9453edcd3dfd5d82cee356c5388f7d37aadd"
}
```

### Sample 35: `707e752878d6f836`

| Field | Value |
|---|---|
| SHA-256 | `707e752878d6f836c80cee34643e99a676c1c6885d9b7443709528d9633c0f23` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-08-06 02:02:44` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5149aee7429a4e87eaf73c615208c72b` |
| SHA-1 | `4a0467fea75f0d55d2b3350d2ca3bd1285034e93` |
| SHA-256 | `707e752878d6f836c80cee34643e99a676c1c6885d9b7443709528d9633c0f23` |
| SHA3-384 | `6c56f1f80d53b94dde449c22dadd44883e41440fbd75ccd2af59893655c40df35e6c50d3057760cf8ef3dd0177712975` |
| TLSH | `T10EC27D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8A3C719C11FACD618B1A` |
| SSDEEP | `768:H8vCB+25j6es8Rs9FYpMSUpi+20qUpi+20YQX:H8l25J6d2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_035_707e7528
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "707e752878d6f836c80cee34643e99a676c1c6885d9b7443709528d9633c0f23"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:02:44"
  condition:
    hash.sha256(0, filesize) == "707e752878d6f836c80cee34643e99a676c1c6885d9b7443709528d9633c0f23"
}
```

### Sample 36: `00c19ed8f175ed2d`

| Field | Value |
|---|---|
| SHA-256 | `00c19ed8f175ed2d4ac9381b892bd96a403e9d823a6f7d89a312c678b54a4b13` |
| Family label | `Mirai` |
| File name | `boatnet.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 02:01:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29e9fd70333a3096cfee71550538978e` |
| SHA-1 | `c540db47b0cb5711ca3f7d7e119c40d6851dffc3` |
| SHA-256 | `00c19ed8f175ed2d4ac9381b892bd96a403e9d823a6f7d89a312c678b54a4b13` |
| SHA3-384 | `e9b250353038470ff561c22f960f146378db2084910c515b23a08d273cea0774de7d00e549c38977f69beeaffc6a07b0` |
| TLSH | `T10D637C07B68180BEC4D9C2B557AFD235E433B4AB6238B36927C4EE113E1ED116E9DB50` |
| TELFHASH | `t1243129b23aa508e0f2e7f2a36749f5a54c341e7110d132d2e67258f3eb06b811d75837` |
| SSDEEP | `1536:TLQ6PXdgByEhzgpYnGPxKDGzp4Q2NGmjw3dQsKRu:46PXdsyKWK20GzmNGmjkEE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_00c19ed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00c19ed8f175ed2d4ac9381b892bd96a403e9d823a6f7d89a312c678b54a4b13"
    family = "Mirai"
    file_name = "boatnet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 02:01:12"
  condition:
    hash.sha256(0, filesize) == "00c19ed8f175ed2d4ac9381b892bd96a403e9d823a6f7d89a312c678b54a4b13"
}
```

### Sample 37: `aa313a14c9387d8d`

| Field | Value |
|---|---|
| SHA-256 | `aa313a14c9387d8dbcb098ae6c056f2fa58e6cefda798a0abef2742471f1ccf8` |
| Family label | `Mirai` |
| File name | `boatnet.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 01:59:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d9a0a9910bacc0322590a2fbf74b4ef1` |
| SHA-1 | `26830a1e430bd6d45d15a79ac043428c60ddea80` |
| SHA-256 | `aa313a14c9387d8dbcb098ae6c056f2fa58e6cefda798a0abef2742471f1ccf8` |
| SHA3-384 | `35e1d9572e874ed8a1853e6db9cd83b34fd654144d2e9779972102695e2c2220845d2008e26e8a2e0e2cc35f6d86c7b3` |
| TLSH | `T1DCF2E0E1F33EE475D06562F65A9E0344BE6A381BC40F196E18D973A98EBB5082B05230` |
| SSDEEP | `768:I/RFmm2gNI4m2a20SuVKlN1xVc1N7FAGpkUaXhHSPQIa3cLujK/x0rwB:mOjgG6aBAgAXhyPJa3cLujgjB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_aa313a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa313a14c9387d8dbcb098ae6c056f2fa58e6cefda798a0abef2742471f1ccf8"
    family = "Mirai"
    file_name = "boatnet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 01:59:33"
  condition:
    hash.sha256(0, filesize) == "aa313a14c9387d8dbcb098ae6c056f2fa58e6cefda798a0abef2742471f1ccf8"
}
```

### Sample 38: `901ac5e8541d5f7e`

| Field | Value |
|---|---|
| SHA-256 | `901ac5e8541d5f7e2ea51a635bcb33d7c12ae809c2f75edb63622d9004dbbde0` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-06 01:54:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c2a2bb23ca8110153334430f40f5294` |
| SHA-1 | `0db7d9c98591506e1c4d47cdcc4334a3913064d6` |
| SHA-256 | `901ac5e8541d5f7e2ea51a635bcb33d7c12ae809c2f75edb63622d9004dbbde0` |
| SHA3-384 | `e884b84f38408bf818b7f6b6df101d7ced20ff9aef0252d3e84ebce817ec94c7587b3a4838af952c6fcdf569eca19696` |
| TLSH | `T16EF3284A77108FA1D336A63046F387A7ABB9228217D2D585E36DDE107F2135C681FFA4` |
| TELFHASH | `t17d318208c83acb3e48e243e8cfec0e61d684c66a9a511e228f36c35c4575009901befe` |
| SSDEEP | `3072:GT6WkkNUjyvuasdTgWnQUf1F0b79GpDP1CyJ7uwkjbl:xWNoyvFsJBQCYSDP1hluVB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_901ac5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "901ac5e8541d5f7e2ea51a635bcb33d7c12ae809c2f75edb63622d9004dbbde0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:54:38"
  condition:
    hash.sha256(0, filesize) == "901ac5e8541d5f7e2ea51a635bcb33d7c12ae809c2f75edb63622d9004dbbde0"
}
```

### Sample 39: `6fe059ee63705b74`

| Field | Value |
|---|---|
| SHA-256 | `6fe059ee63705b742a2a3b3db9e81e6158c84d66dfe3f01dcd5ead853ed1c180` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-08-06 01:53:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ba806962eb865ca08edb60d15e9c37fe` |
| SHA-1 | `8a6e473e3d15a9eb21ff0698cf2d59da8fb2edab` |
| SHA-256 | `6fe059ee63705b742a2a3b3db9e81e6158c84d66dfe3f01dcd5ead853ed1c180` |
| SHA3-384 | `fc308e1662fc563459cb4fb757c78d326484ba7d04b54ebd27caf5d9ce2a3f7897dab84f5d648b11bd845b6d43a41781` |
| TLSH | `T10863028CA145BCEADD614DBC03290333E2A19B7AB2620C0E3537DB46CF3555D79EBA85` |
| SSDEEP | `1536:O6lq0XXFNVfxUtdBk5WQV2NkDwgKZpHdpf5wnbF3E8EKtm2McTNTVEWS:OERXFNVfKdBVGEnZ9Rq5RE52ZTJVEl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_039_6fe059ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe059ee63705b742a2a3b3db9e81e6158c84d66dfe3f01dcd5ead853ed1c180"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:53:35"
  condition:
    hash.sha256(0, filesize) == "6fe059ee63705b742a2a3b3db9e81e6158c84d66dfe3f01dcd5ead853ed1c180"
}
```

### Sample 40: `306a43e268d005d7`

| Field | Value |
|---|---|
| SHA-256 | `306a43e268d005d7491b1c472d3f13e66ca5551cb5714b5a48f54830f15ad0d9` |
| Family label | `Mirai` |
| File name | `boatnet.m68k` |
| File type | `elf` |
| First seen | `2026-08-06 01:53:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4690bfecb470957b7086f32470fb4fda` |
| SHA-1 | `c7bc51a765212d1f55f3baa580c339c64e8d4f5a` |
| SHA-256 | `306a43e268d005d7491b1c472d3f13e66ca5551cb5714b5a48f54830f15ad0d9` |
| SHA3-384 | `d59b97aca2945de0d2bd7f06aaf246e7e0b05bbbdd89c1c03a7c48b737497d2ed7233b3f656a437a7ee1c1a933e6a053` |
| TLSH | `T13D8309C7FC10E97AF409D73B04970A0AB230E3A14A831A76B7473567EE7A1951537F86` |
| SSDEEP | `1536:mO82Gi6I8A45G8kvPU37UyAo6zHELyR3w/sznBheZfrWc8B0HohLZZSigIShgn:K2GX5gPUrUyAo6ztRgk6frWcZHaLYOn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_306a43e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "306a43e268d005d7491b1c472d3f13e66ca5551cb5714b5a48f54830f15ad0d9"
    family = "Mirai"
    file_name = "boatnet.m68k"
    file_type = "elf"
    first_seen = "2026-08-06 01:53:32"
  condition:
    hash.sha256(0, filesize) == "306a43e268d005d7491b1c472d3f13e66ca5551cb5714b5a48f54830f15ad0d9"
}
```

### Sample 41: `e47771be0dfb7637`

| Field | Value |
|---|---|
| SHA-256 | `e47771be0dfb7637a11ab8fdce4bb71593ac3fe4e753e14522450c9cf52839b1` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-06 01:50:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8f31f4c472ebf5156fc9274f328f64e2` |
| SHA-1 | `53c30d553634b470d2c8d4db67a2e5e24c9ef547` |
| SHA-256 | `e47771be0dfb7637a11ab8fdce4bb71593ac3fe4e753e14522450c9cf52839b1` |
| SHA3-384 | `0df42523a0438bdd706380bc8fd74048cefbe381bcb286b9c6841a0ea8c810a102dcd67b7a5fb20c0f74c272a59e32b3` |
| TLSH | `T13AB34A40FA83D1F1E9530670002BA75A9B34ED358064DB4AEB983E75EC71B428D6F7AC` |
| SSDEEP | `3072:gzTwAkI/25sjj5WaZmRzypFga6EUT3uHq:gHwE/2tRzw6EwuK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_e47771be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e47771be0dfb7637a11ab8fdce4bb71593ac3fe4e753e14522450c9cf52839b1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:50:34"
  condition:
    hash.sha256(0, filesize) == "e47771be0dfb7637a11ab8fdce4bb71593ac3fe4e753e14522450c9cf52839b1"
}
```

### Sample 42: `957e67f204d9e925`

| Field | Value |
|---|---|
| SHA-256 | `957e67f204d9e9254e4750bf73cc7bc1ec551f1a0536d586df76902b5dab0726` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-06 01:45:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `639c97940c3642268d8e51acdbca079f` |
| SHA-1 | `c75cdc2f285b8254195b5f221dcd76894ee55f48` |
| SHA-256 | `957e67f204d9e9254e4750bf73cc7bc1ec551f1a0536d586df76902b5dab0726` |
| SHA3-384 | `918425241974c21666d3a25c0b89d07e4b753330799f9626b3b75f090683d0e9e6cbbc0e4f48168a441017a4123b5c7f` |
| TLSH | `T1DBF31889EFA50FDFD46FCE30062E132719ED589E92F16336457CCC58B69E2484AE3858` |
| TELFHASH | `t17d318208c83acb3e48e243e8cfec0e61d684c66a9a511e228f36c35c4575009901befe` |
| SSDEEP | `3072:8DNtskU5LcNcLcl1UDUVlEz6FV4EfFOBeiInJO7PYzcE84PPCmI8/j6CcW6UP5w:qXskU5LcNcAl1UDUVlEz6FV8eiInJOys` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_957e67f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "957e67f204d9e9254e4750bf73cc7bc1ec551f1a0536d586df76902b5dab0726"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 01:45:32"
  condition:
    hash.sha256(0, filesize) == "957e67f204d9e9254e4750bf73cc7bc1ec551f1a0536d586df76902b5dab0726"
}
```

### Sample 43: `418239951e671967`

| Field | Value |
|---|---|
| SHA-256 | `418239951e671967784688d121cd66a63a1c9896633038453be3afff2393ecd0` |
| Family label | `Mirai` |
| File name | `boatnet.x86` |
| File type | `elf` |
| First seen | `2026-08-06 01:44:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0939be97e36f2be2a40df101e1d291fc` |
| SHA-1 | `ed0a1a6f09875b32b81ba91973fb91976d6edb3e` |
| SHA-256 | `418239951e671967784688d121cd66a63a1c9896633038453be3afff2393ecd0` |
| SHA3-384 | `17f292a077fffeeb8120f8c726b7eb67a017359b3266eb6a73aac9bf024a6a94ec4008ac6e074ddfce96f3beba2948c6` |
| TLSH | `T1BBE2F186D0C4AEA4C003C6FD47DDDCBAA1E1EDC09684514A365E6FDF9E32170C292D87` |
| SSDEEP | `768:D1XTVwwC7yCFpxtk/NNugn7gIwsATuJQMfvj637Xk9Bx5rZvV:FBCh9kR0TMQM39D5dt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_41823995
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "418239951e671967784688d121cd66a63a1c9896633038453be3afff2393ecd0"
    family = "Mirai"
    file_name = "boatnet.x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:44:34"
  condition:
    hash.sha256(0, filesize) == "418239951e671967784688d121cd66a63a1c9896633038453be3afff2393ecd0"
}
```

### Sample 44: `70beea3dbd4deaa7`

| Field | Value |
|---|---|
| SHA-256 | `70beea3dbd4deaa71bff2d2da10b30f1617abb1167922aa88ae96da064027de8` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-08-06 01:44:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6793a370caa387d45e2425c005c9e6b7` |
| SHA-1 | `797e5d7aab3303f4d359ef328773c575d71aeee7` |
| SHA-256 | `70beea3dbd4deaa71bff2d2da10b30f1617abb1167922aa88ae96da064027de8` |
| SHA3-384 | `52d8c22c3f3344ba50d9d7fcc060579f7a5ac82664b4f05e7f158f41ac325862c742b00e078b30a4abbc70b283622e50` |
| TLSH | `T1DA73028E69566DC7C90DAE38C94C2206663340A5B3478B7C9601EE5DA7F1D2E709ECFC` |
| SSDEEP | `1536:CkuWUz6q4PVGmbhoU8r19A8OEjzATaln+LqhGIBxf7oE4yNxKl:Izj4Ps9fOEjzATaUwGqyCc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_70beea3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70beea3dbd4deaa71bff2d2da10b30f1617abb1167922aa88ae96da064027de8"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 01:44:32"
  condition:
    hash.sha256(0, filesize) == "70beea3dbd4deaa71bff2d2da10b30f1617abb1167922aa88ae96da064027de8"
}
```

### Sample 45: `db444503cda9f673`

| Field | Value |
|---|---|
| SHA-256 | `db444503cda9f6734797db51f8b159802634cdace744431867741475203c8755` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 01:36:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66ad681cfea3a4adc9824ebd1e237cb9` |
| SHA-1 | `907b5ba7c639099a3b45bacd738879a3a8ad6370` |
| SHA-256 | `db444503cda9f6734797db51f8b159802634cdace744431867741475203c8755` |
| SHA3-384 | `338bf03d99d4fc7c694839d5de9556a56fb9b7844a034a20b6a9be42cefb241feaec411d922412679ceb9d28fd4f476a` |
| TLSH | `T10CD31205BD30E5F1EDBD38EECA662D288C60E0D5B6B20FD857E07D1996A3E18378546C` |
| SSDEEP | `3072:HGIwE0mwxqRnx/0KNxq7YWNf6s4x2fNmWQdyWgX+PF+BH3v:mfE0mwERnBhm7J8shNtwra` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_db444503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db444503cda9f6734797db51f8b159802634cdace744431867741475203c8755"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 01:36:33"
  condition:
    hash.sha256(0, filesize) == "db444503cda9f6734797db51f8b159802634cdace744431867741475203c8755"
}
```

### Sample 46: `a56ec538bb6c72b7`

| Field | Value |
|---|---|
| SHA-256 | `a56ec538bb6c72b724cce88be69161b418fdc0f6ee41413400a388568daf154f` |
| Family label | `Mirai` |
| File name | `putita.m68k` |
| File type | `elf` |
| First seen | `2026-08-06 01:30:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `46cce029960fb7272176960e3d560e6b` |
| SHA-1 | `8d9a2f0cbac4cb47c80e1e47cc0d540cfa145ac5` |
| SHA-256 | `a56ec538bb6c72b724cce88be69161b418fdc0f6ee41413400a388568daf154f` |
| SHA3-384 | `792d25944b21ee5708604ef601631eda9c06b93a7acdcb894b130d7ebf855ac407693cfdd9172868be6eb4ae5298225a` |
| TLSH | `T165C36CC1B10C7E9DE5932E7CC20A17176E1C9A559C83520190B5FE47E9BB2E32E36AC7` |
| TELFHASH | `t1c7d0c9f1878fa206468ccbcd83c9779c0a0de145004bff13fd22993c80a091cb92998f` |
| SSDEEP | `3072:J2NK4Vl0SLPfdtcfafKlPtuLi0kvnOX+QLLjcow:UNKkjfoEKlPyyvng+QXFw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_a56ec538
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56ec538bb6c72b724cce88be69161b418fdc0f6ee41413400a388568daf154f"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-06 01:30:34"
  condition:
    hash.sha256(0, filesize) == "a56ec538bb6c72b724cce88be69161b418fdc0f6ee41413400a388568daf154f"
}
```

### Sample 47: `b52b605b22e497ca`

| Field | Value |
|---|---|
| SHA-256 | `b52b605b22e497caa6930b9cc46dff2be18eaf63dcf7c2226906dfc5114f2b49` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-06 01:28:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a3f9ecfddcc355d142f6a7335b853504` |
| SHA-1 | `e05025adaf8d204a7369b699eafac52205414031` |
| SHA-256 | `b52b605b22e497caa6930b9cc46dff2be18eaf63dcf7c2226906dfc5114f2b49` |
| SHA3-384 | `62bf19e5ca3dba1380dc0ffb4a490251b79f347390577923b74dc553f403856189b7ac2bc989f7251ccd088db30d39e9` |
| TLSH | `T180C329A9F890DE52C6C52676FB5E028C33231778D3DE7105CE109E34F7EB95A0A3A942` |
| SSDEEP | `3072:GMS8HWIzZvDVsINudJj+3scYEEU3cRE4fOAvLSKykdGER6U1yGk1lf1Dl:GLMnlUQscYEEU3cRE4GsLLVdGM1l4l95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_b52b605b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b52b605b22e497caa6930b9cc46dff2be18eaf63dcf7c2226906dfc5114f2b49"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:28:42"
  condition:
    hash.sha256(0, filesize) == "b52b605b22e497caa6930b9cc46dff2be18eaf63dcf7c2226906dfc5114f2b49"
}
```

### Sample 48: `97a04076d3b1d884`

| Field | Value |
|---|---|
| SHA-256 | `97a04076d3b1d8845c64d8087f6b879def4560566e2376372d728529dc837cfd` |
| Family label | `Mirai` |
| File name | `putita.arm5` |
| File type | `elf` |
| First seen | `2026-08-06 01:27:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d65b60667dcdbfc734995aae0c25ef93` |
| SHA-1 | `a0465bf8d72f4de589adc86ca7cd9589e64e4930` |
| SHA-256 | `97a04076d3b1d8845c64d8087f6b879def4560566e2376372d728529dc837cfd` |
| SHA3-384 | `71aa7ac9e151c7dbd1abe3266541b51cf7df3a87b68f018e5815a88968c4c4982951dc88764e06161d7c2e60c92d9663` |
| TLSH | `T17443F1D34685AEB6C1E9143AE52CF3B674240AB8DDFB3555C52208ED76F92038B72C47` |
| SSDEEP | `768:U6h6u1yyGeIYG6mbYyVpR/tG+0zpiPGHF2TT9m1Ok7FyL6qZBtuXNiRuTM0IdZAL:56u1yyGOzYpRlJEHsTxGy5nQXQQT18fa` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_97a04076
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a04076d3b1d8845c64d8087f6b879def4560566e2376372d728529dc837cfd"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:27:47"
  condition:
    hash.sha256(0, filesize) == "97a04076d3b1d8845c64d8087f6b879def4560566e2376372d728529dc837cfd"
}
```

### Sample 49: `a79c069996a02e25`

| Field | Value |
|---|---|
| SHA-256 | `a79c069996a02e251222db1ca25b83a07741436a98809b0315341271403ab0b9` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-06 01:27:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `08d053f8dfe1e66c54bfcaf71783cd6e` |
| SHA-1 | `0fcee9c4e754b41117ae4b772a8a283425d418ca` |
| SHA-256 | `a79c069996a02e251222db1ca25b83a07741436a98809b0315341271403ab0b9` |
| SHA3-384 | `17aa3ab6c8d484290aa2f0b1398c169f380df7c52fc23f8caf728f4a3382c06714e87f8cb26f6f883c48f00e50baf3fe` |
| TLSH | `T19304290E7720CF21C76DC53105B3CB8656F926522BE28849F36CDE18BE64349A95FED8` |
| TELFHASH | `t14431beb08b7b65119ac5c7ec88ecb75a491e8515470adf33fd3281ac50260ede22ad5f` |
| SSDEEP | `3072:tyJBGWHHw18/ZaNm3NYFblp3N3vlZy1DTjzc:E/xHlBazb3d/lZobg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_a79c0699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79c069996a02e251222db1ca25b83a07741436a98809b0315341271403ab0b9"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:27:02"
  condition:
    hash.sha256(0, filesize) == "a79c069996a02e251222db1ca25b83a07741436a98809b0315341271403ab0b9"
}
```

### Sample 50: `424b4e38d6f73cc6`

| Field | Value |
|---|---|
| SHA-256 | `424b4e38d6f73cc6f7c45b03d604e0d921ac815dfb88e0e492a15a4fe535d9f3` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-08-06 01:26:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c7915c5481e6e8a699d09ce5debc26f` |
| SHA-1 | `b572807cadf0b7e51a1a1641fe4ef3c63e18dc60` |
| SHA-256 | `424b4e38d6f73cc6f7c45b03d604e0d921ac815dfb88e0e492a15a4fe535d9f3` |
| SHA3-384 | `700745f63ef3cc702b177846fbf1564373f24f1852715cc43820e2d32693969ed9824fe87ec1ffe50e439e386ea53b4e` |
| TLSH | `T1D6E35B49FA4BC0F0D6C344F1052BABAA9A77D9212273F1A1FF563776F8B1302258526C` |
| SSDEEP | `3072:LuTrgfFTj555orwyFEjHBaUzU9LWIESXUHw:grgtTL51bTzmLeSE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_424b4e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "424b4e38d6f73cc6f7c45b03d604e0d921ac815dfb88e0e492a15a4fe535d9f3"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:26:56"
  condition:
    hash.sha256(0, filesize) == "424b4e38d6f73cc6f7c45b03d604e0d921ac815dfb88e0e492a15a4fe535d9f3"
}
```

### Sample 51: `7bbd6d4cf4bb82ee`

| Field | Value |
|---|---|
| SHA-256 | `7bbd6d4cf4bb82ee90515cc745379bfb2d73ba8d9d92c839896023b6386f9c04` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-06 01:26:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71d0a0a009f9260d7d3b7eb19c2b612d` |
| SHA-1 | `d5ea7c5bdf4211be32c1e99bbb94e4a7ea2e0a50` |
| SHA-256 | `7bbd6d4cf4bb82ee90515cc745379bfb2d73ba8d9d92c839896023b6386f9c04` |
| SHA3-384 | `cccafa9ed152f8884dd7c520e97a2a3b138adf1912a3ff2fc6410ea154da20e99c972cfaa042ef58208e2dcb9556f9a1` |
| TLSH | `T13F148E00FB185953D1931DB45B3B0776E37D9C8318B8E019190E7B568733EFA9A87B8A` |
| SSDEEP | `6144:PN3KQIlteuY0SMAQWhWICAIQiwGSOvqHzD4:luJApLiK4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_7bbd6d4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bbd6d4cf4bb82ee90515cc745379bfb2d73ba8d9d92c839896023b6386f9c04"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 01:26:51"
  condition:
    hash.sha256(0, filesize) == "7bbd6d4cf4bb82ee90515cc745379bfb2d73ba8d9d92c839896023b6386f9c04"
}
```

### Sample 52: `3233d5128b3453c6`

| Field | Value |
|---|---|
| SHA-256 | `3233d5128b3453c621d31df5c3d1ce4525318068224c0ab37c609a72884c3f15` |
| Family label | `Mirai` |
| File name | `putita.mips` |
| File type | `elf` |
| First seen | `2026-08-06 01:24:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3e649e99a379ed479fb9d6511bad3b0` |
| SHA-1 | `21fdc522cfb226cea56b1fe7fef3c97b207fbf66` |
| SHA-256 | `3233d5128b3453c621d31df5c3d1ce4525318068224c0ab37c609a72884c3f15` |
| SHA3-384 | `f8ec212560113908ee1fffd9a0f8522e6ee70e95e339506f144067e1170dcbe40b89cb9c7bac14db7368d2c8ed0d9194` |
| TLSH | `T19D830262C3B44A6AE48F82B7551904FB7AB1B70D6C1D07EAE5FBE2071A350DF8409F25` |
| SSDEEP | `1536:Yd2A4JLL921sR/ITcPry9sDBdjY6Jp3KbqzqWY97PTE3TPKFhqgcJ0KRlaeQueo:Y8Ao52mR/ITq6+2WY9EjPKJcJ0KbTeo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_3233d512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3233d5128b3453c621d31df5c3d1ce4525318068224c0ab37c609a72884c3f15"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:45"
  condition:
    hash.sha256(0, filesize) == "3233d5128b3453c621d31df5c3d1ce4525318068224c0ab37c609a72884c3f15"
}
```

### Sample 53: `863709a3b2ad698a`

| Field | Value |
|---|---|
| SHA-256 | `863709a3b2ad698aee58280f46803d17f4d2850536e860eece547eb874103325` |
| Family label | `Mirai` |
| File name | `arm4` |
| File type | `elf` |
| First seen | `2026-08-06 01:24:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66628633e1aa6d73ec4047ea88ff2048` |
| SHA-1 | `df6bcfe7d56f7a8afcbb1bc508908d8d3af4fa67` |
| SHA-256 | `863709a3b2ad698aee58280f46803d17f4d2850536e860eece547eb874103325` |
| SHA3-384 | `f04b28da4167b72a6f895ffb3f8f93e6ea29524ab2949177353e2f87df42a2bc79481b7499a00a9c67105b087dc3e020` |
| TLSH | `T17DB3F755F880DB62C6D4267AFB4E428D33231B78D3ED3106DD10AF35B7EA95A4A3B502` |
| SSDEEP | `3072:ulM20bU97F37uDtD1Hbs3HLIPlY1O+aX7AMaS4:ulV97F37QD1HYHLIPlY1O1R4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_053_863709a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863709a3b2ad698aee58280f46803d17f4d2850536e860eece547eb874103325"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:43"
  condition:
    hash.sha256(0, filesize) == "863709a3b2ad698aee58280f46803d17f4d2850536e860eece547eb874103325"
}
```

### Sample 54: `57255dd221323eff`

| Field | Value |
|---|---|
| SHA-256 | `57255dd221323efff68cb3f00710edc4a6b404eb0561e49fa03d2b2b1dc1639e` |
| Family label | `Mirai` |
| File name | `putita.x86` |
| File type | `elf` |
| First seen | `2026-08-06 01:24:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd6f57843dc972cde2020742d28fe910` |
| SHA-1 | `ea1a158d836937efbdd93de14deb474724e94a02` |
| SHA-256 | `57255dd221323efff68cb3f00710edc4a6b404eb0561e49fa03d2b2b1dc1639e` |
| SHA3-384 | `af4a3b3e7acfa38754800f25505f9744c7519d0c3f6c87982669928fc93a3d0c360ea9901b22891da68c1a502d677b8d` |
| TLSH | `T1535302DEB7CD9BFCD6BF047491AAF82F2428E67A12045CD5F7AC50FDB480E68101424A` |
| SSDEEP | `768:lN+L/obPEAHI4Xm6JEDt6JCKClfzfLLRcTeexQ44nM3+xFmfX+v6QVuB/GwrcEgF:l2335cofjROe9vMvPlNqA+Inouy8DMl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_57255dd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57255dd221323efff68cb3f00710edc4a6b404eb0561e49fa03d2b2b1dc1639e"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:41"
  condition:
    hash.sha256(0, filesize) == "57255dd221323efff68cb3f00710edc4a6b404eb0561e49fa03d2b2b1dc1639e"
}
```

### Sample 55: `3091e5d6c4d7b71b`

| Field | Value |
|---|---|
| SHA-256 | `3091e5d6c4d7b71b15bc46b3a7ee6327e9cc1c8b554aedb10bcf0f7986eef4be` |
| Family label | `Mirai` |
| File name | `putita.ppc` |
| File type | `elf` |
| First seen | `2026-08-06 01:24:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85a9392a8369c0b688e16bc481f8d362` |
| SHA-1 | `8d538b27369e3942791665ae1338be655c871c14` |
| SHA-256 | `3091e5d6c4d7b71b15bc46b3a7ee6327e9cc1c8b554aedb10bcf0f7986eef4be` |
| SHA3-384 | `7ce30683a9cd97bdfc6e35c61cf87ee7e10d6057b246610cfd0a281525e0c99f334d72e16928c9182b6b07c5a4926d42` |
| TLSH | `T110530174E34397A8EEDB99F0441ECB191748EBF45DB1CB8002666B61A1423B2770EBF5` |
| SSDEEP | `1536:8kBUZjbiy+qNgUQaXEN8W2I/G05MwwX7uuPNtqQtQP4u+qgw0r+:8kGZay+faEEIZ/e75iQtQP4u+qgw5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_3091e5d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3091e5d6c4d7b71b15bc46b3a7ee6327e9cc1c8b554aedb10bcf0f7986eef4be"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:39"
  condition:
    hash.sha256(0, filesize) == "3091e5d6c4d7b71b15bc46b3a7ee6327e9cc1c8b554aedb10bcf0f7986eef4be"
}
```

### Sample 56: `bb0cf0b3a99ce733`

| Field | Value |
|---|---|
| SHA-256 | `bb0cf0b3a99ce7331be0143e7a535bdcc5e881e6e64c39d256cf1f02fb620158` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-08-06 01:22:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ed84bd0ab44e13e943404cb57a085330` |
| SHA-1 | `d1ff4649d89bfd795ea0c854da577d67fbf0b47d` |
| SHA-256 | `bb0cf0b3a99ce7331be0143e7a535bdcc5e881e6e64c39d256cf1f02fb620158` |
| SHA3-384 | `054ee374d87ae9fa0578a183518d5ef529ec02897d4bdeaf36709f0c6b77b1799da52e7f2d4fbb696e9c503112eaec82` |
| TLSH | `T183830A9AFD829B11D6C115FAFE1E928D7313077CE2DF72266E14AE20678746B0E3B405` |
| TELFHASH | `t1dcd02b108d886cd9afb440a152c8a026762e69f07a002a918e3db98e4026dd82a3055e` |
| SSDEEP | `1536:GMn8H3TAYwaKnSAelVFDIziukioeowTlSOgx7QU5x5/YzcqoZ:eHDAYwaOX8ioeowTlSOgxv5xhj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_bb0cf0b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0cf0b3a99ce7331be0143e7a535bdcc5e881e6e64c39d256cf1f02fb620158"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:22:43"
  condition:
    hash.sha256(0, filesize) == "bb0cf0b3a99ce7331be0143e7a535bdcc5e881e6e64c39d256cf1f02fb620158"
}
```

### Sample 57: `a962a71c3da3b8d6`

| Field | Value |
|---|---|
| SHA-256 | `a962a71c3da3b8d67c97d0d3db1ef7548998640eb55564830986398376f31e40` |
| Family label | `Mirai` |
| File name | `boatnet.arm6` |
| File type | `elf` |
| First seen | `2026-08-06 01:21:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad2e9b110527e59e2867b791f1659369` |
| SHA-1 | `de578f46e973f0bd122b5116f0be81fd10110536` |
| SHA-256 | `a962a71c3da3b8d67c97d0d3db1ef7548998640eb55564830986398376f31e40` |
| SHA3-384 | `6a1c8de86010caa162199ecfc843d023bae229c257ec7713a48740074c921107abe4e93b1ffbf97821db3b217656154c` |
| TLSH | `T1DC03F1F1CEA29C70CBBC28365CF606DB85510BA8D87F61A70E44D3AC6BE454A15D76C2` |
| SSDEEP | `768:X2zVupXAei/cvWhjExFigdrCGxzt3SUY2pWJy9q3UELb:7X9WY6w7j5xzoiKnLb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_a962a71c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a962a71c3da3b8d67c97d0d3db1ef7548998640eb55564830986398376f31e40"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:21:34"
  condition:
    hash.sha256(0, filesize) == "a962a71c3da3b8d67c97d0d3db1ef7548998640eb55564830986398376f31e40"
}
```

### Sample 58: `d44a14c3cf5307a0`

| Field | Value |
|---|---|
| SHA-256 | `d44a14c3cf5307a005c7831bee40fdbdffdb78dd9196d3265e032c4f433d3069` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-06 01:16:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56b90a061f0553534f4861de3e6f864e` |
| SHA-1 | `c805772f02d7d7b194ab0a313cf0953ef2875fda` |
| SHA-256 | `d44a14c3cf5307a005c7831bee40fdbdffdb78dd9196d3265e032c4f433d3069` |
| SHA3-384 | `4f266c2353155d5f3af82c52530105e3d310d358a4507634defd9641e276278c23165826c62dac19383ae380b259505b` |
| TLSH | `T1C0C36E989A1F9D81E2C3D6BDED694FB331363CB40664C3B24E10526DD8E9DD68CA2533` |
| SSDEEP | `1536:iwEAu5FBEJyXGtUU4Z1VNWVMmqw0LRQ/SysCrbZ3e5vYK/J2C+QPeoVuBKau5Ir:hEAuegXWN4Z7NNmqwnSV45Q22uBKy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_d44a14c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d44a14c3cf5307a005c7831bee40fdbdffdb78dd9196d3265e032c4f433d3069"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-06 01:16:01"
  condition:
    hash.sha256(0, filesize) == "d44a14c3cf5307a005c7831bee40fdbdffdb78dd9196d3265e032c4f433d3069"
}
```

### Sample 59: `049768ce81f1310f`

| Field | Value |
|---|---|
| SHA-256 | `049768ce81f1310f8bab20dc015e9dc515c390e53ad3479858292c4f68fdc3f6` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-06 01:15:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9e12b3a8affedf5d9e92b40ca3f1e39` |
| SHA-1 | `7f4a938db3abbb33d3958759fa3dc2b87787e49f` |
| SHA-256 | `049768ce81f1310f8bab20dc015e9dc515c390e53ad3479858292c4f68fdc3f6` |
| SHA3-384 | `cda8d80e387a5162ea7e7fb09b7e94c2db7846c8f74fcc84d4bfb9a9f1fcc6d237732c1e1c53887c17c2e486a680f482` |
| TLSH | `T19743F29003C2BD92D4C5B27E8B62D151BE85FCBB34E0E1BD2825DB8CB59C974B13E819` |
| SSDEEP | `1536:BbqIvgFeFmU0CrjGQULacdEZ2OVw4mNDLYNDrTSOQ6y:B2IYFiIKjnAatZe16NDrC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_049768ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049768ce81f1310f8bab20dc015e9dc515c390e53ad3479858292c4f68fdc3f6"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-06 01:15:31"
  condition:
    hash.sha256(0, filesize) == "049768ce81f1310f8bab20dc015e9dc515c390e53ad3479858292c4f68fdc3f6"
}
```

### Sample 60: `8c03d205d6000645`

| Field | Value |
|---|---|
| SHA-256 | `8c03d205d6000645c309fe41b7d7e4d4a91b3570d98a22036f60a47993a2c6b7` |
| Family label | `Mirai` |
| File name | `boatnet.arm5` |
| File type | `elf` |
| First seen | `2026-08-06 01:13:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `951871ee98b906705a81713cfb586931` |
| SHA-1 | `c1eb51761a6985cca593a242da1e5acf3c9fe865` |
| SHA-256 | `8c03d205d6000645c309fe41b7d7e4d4a91b3570d98a22036f60a47993a2c6b7` |
| SHA3-384 | `64b68d6b81307ec120de8d57cd4d79a1f5cc16220c92486ee7cf38d0b36c82110eac49b7154e87d27cb5f5f8c4e4b557` |
| TLSH | `T113A294D2ED42009EC7C057FFAF5ED7C8739393B1C5EDB21AEA088614649A94E5F1AE40` |
| TELFHASH | `t106c08c00a1a4580e0ef30470dcae0fa231a1026619669a958a08af90d13b5809245d0f` |
| SSDEEP | `384:Xq2lYgow4AIQYgow4A5BJRZhpx5BJRZhpx5KpRT7TKALTtTTs7sjeeKyzgwWiTWp:XqeYgow4AIQYgow4A5BJRZhpx5BJRZhl` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_8c03d205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c03d205d6000645c309fe41b7d7e4d4a91b3570d98a22036f60a47993a2c6b7"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:13:45"
  condition:
    hash.sha256(0, filesize) == "8c03d205d6000645c309fe41b7d7e4d4a91b3570d98a22036f60a47993a2c6b7"
}
```

### Sample 61: `e312d125a54f6b14`

| Field | Value |
|---|---|
| SHA-256 | `e312d125a54f6b144a024d7440d5f403cf75209a730de2646513e888dc713abf` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-06 01:13:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `279048c84aefc51f41e13685aa89eba9` |
| SHA-1 | `fd61ba14ab4dc013bc65ffd267ffa035eef60d75` |
| SHA-256 | `e312d125a54f6b144a024d7440d5f403cf75209a730de2646513e888dc713abf` |
| SHA3-384 | `037784c3012efdfc174a4b66c374746299d40d8299c4051c75c5eacbc2c780ed134b73be1f97f83616789b1f0bb8ee7f` |
| TLSH | `T16404294F7720CF61C759C93005B3C79666E926626BD38849F36CDE08BE64349A82FED4` |
| TELFHASH | `t17821feb08b7765019a85c7ec85ecb70a491e82010746df33fe3180bc80260ece229d4f` |
| SSDEEP | `3072:386gjmardOSEmvYPKiIpoqY9+5/ljfVhVXw1Dej+m:MNjma5OSE+YPKrp/v/1dHXWA+m` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_e312d125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e312d125a54f6b144a024d7440d5f403cf75209a730de2646513e888dc713abf"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-06 01:13:42"
  condition:
    hash.sha256(0, filesize) == "e312d125a54f6b144a024d7440d5f403cf75209a730de2646513e888dc713abf"
}
```

### Sample 62: `3d3cdd80cc4ef5e2`

| Field | Value |
|---|---|
| SHA-256 | `3d3cdd80cc4ef5e23c5ad9c86732ab8861ab2a4d931239040e54c3d410ff7c6d` |
| Family label | `Mirai` |
| File name | `boatnet.i686` |
| File type | `elf` |
| First seen | `2026-08-06 01:13:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30a9e53c466039b91c8ac5373fdec16c` |
| SHA-1 | `52482cc65f451c82561abcc97999741430cb6edb` |
| SHA-256 | `3d3cdd80cc4ef5e23c5ad9c86732ab8861ab2a4d931239040e54c3d410ff7c6d` |
| SHA3-384 | `6e55fbead16c283ed0a8b004449913866d44e244a9e3b1e3ade2da4ebbb647ed557cb3f7152a898900ef9c509391feef` |
| TLSH | `T119534A82FA83D0FAE8130571442EF37FE631D61AD121D365EF695E32D923902462B7AC` |
| TELFHASH | `t11e3178f31dae09e9f3c06848c31e6fc16b3ad577146132a504b2995432e7ee291f9c39` |
| SSDEEP | `1536:ZsS/1WjA5svTWm8KnAKMSzjQl61rG4Zp1LbnbcMYRg:6SdL5JnfKM+jQlA7pJq+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_3d3cdd80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d3cdd80cc4ef5e23c5ad9c86732ab8861ab2a4d931239040e54c3d410ff7c6d"
    family = "Mirai"
    file_name = "boatnet.i686"
    file_type = "elf"
    first_seen = "2026-08-06 01:13:38"
  condition:
    hash.sha256(0, filesize) == "3d3cdd80cc4ef5e23c5ad9c86732ab8861ab2a4d931239040e54c3d410ff7c6d"
}
```

### Sample 63: `d83ef44a44e68fd1`

| Field | Value |
|---|---|
| SHA-256 | `d83ef44a44e68fd1bed4e81209c4f62913bca52f60c245f127527ff6757cdffe` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-06 01:13:02` |
| Reporter | `Bitsight` |
| Tags | `C, dropped-by-GCleaner, exe, MIX5.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d2ef3e4a44441fe4284ba28f7c9f203c` |
| SHA-1 | `837db5b38ad691a6c6a6b813bc7cb63a4ea6d378` |
| SHA-256 | `d83ef44a44e68fd1bed4e81209c4f62913bca52f60c245f127527ff6757cdffe` |
| SHA3-384 | `a0925f7b57430f61689c622587b2be1a5f14c43b4518e492a106ea6f771a97f8616b67882e980fd75e370ff0ff0b1da9` |
| IMPHASH | `f67e7371d5a4cc2cec9f3d61b9959c69` |
| TLSH | `T17AB66802ABC1E9D6E3141933C4750D733EE54A986D216A3E1B14E1EEBFFE342BA511D2` |
| SSDEEP | `98304:WdtvSFRs4ejJZ0xUhRGjPV0IQ35qNMgk6D4v7UB+B0nB7RL:WXqA45iGjPrQJYpkEmUBC0B7F` |
| ICON-DHASH | `5277371e0f1f2b2b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_d83ef44a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d83ef44a44e68fd1bed4e81209c4f62913bca52f60c245f127527ff6757cdffe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 01:13:02"
  condition:
    hash.sha256(0, filesize) == "d83ef44a44e68fd1bed4e81209c4f62913bca52f60c245f127527ff6757cdffe"
}
```

### Sample 64: `4e70361a2c27d7da`

| Field | Value |
|---|---|
| SHA-256 | `4e70361a2c27d7da8185766187b3757e1fa966f4e0b1e370886d66481121e5e8` |
| Family label | `Mirai` |
| File name | `boatnet.arm5` |
| File type | `elf` |
| First seen | `2026-08-06 01:12:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1da83ef242705b19c9a8c0d64b773cd1` |
| SHA-1 | `08c8f0b41796672c1952808be9564d6a1b09717f` |
| SHA-256 | `4e70361a2c27d7da8185766187b3757e1fa966f4e0b1e370886d66481121e5e8` |
| SHA3-384 | `7d7db4586037402339d0a48e2df11b7787637f07001fa6d7a3f28cb7488745f6491a25edd46c5e6e57616c54d48736c5` |
| TLSH | `T1F532CF07B7186EE1FA920F77137F11E1EAA76A2A10D4E37F7049520A142B485E31D459` |
| SSDEEP | `192:L1Ace22dcx7BO3IXQjLo+bOFBQC6qraoBGbKogNOU2fikhTpWOltZZEaBHKEY1i:1e2h7BmRLAdvrgU8hTp/ftB1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_4e70361a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e70361a2c27d7da8185766187b3757e1fa966f4e0b1e370886d66481121e5e8"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:12:36"
  condition:
    hash.sha256(0, filesize) == "4e70361a2c27d7da8185766187b3757e1fa966f4e0b1e370886d66481121e5e8"
}
```

### Sample 65: `6abb06e956ce2bfa`

| Field | Value |
|---|---|
| SHA-256 | `6abb06e956ce2bfa05920c0c13857ec6aa11ef2810e017d5d44f51b018170d10` |
| Family label | `Mirai` |
| File name | `putita.mipsrouter` |
| File type | `elf` |
| First seen | `2026-08-06 01:12:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac72919d425cf574c6c6ae1abcce2b1f` |
| SHA-1 | `95d55a8899c48664ac2514c9728ccfbdd2366d15` |
| SHA-256 | `6abb06e956ce2bfa05920c0c13857ec6aa11ef2810e017d5d44f51b018170d10` |
| SHA3-384 | `4776f34b56b3c452a8f29e9423511b5d709feaab5a69b72d642132eaf4a759fc14d9634597fd3a13e36cd066a635e7ba` |
| TLSH | `T17C63F14D6A070386C17A997C81439F37EE007E55D81698CBBFA0C24B6DA38E971E77C9` |
| SSDEEP | `1536:EJve2CUQK68FWgghtR4z9GnCM8FFioLz0ySru5cieKV1clS:N98FMht+zlXiOz4ieKV1cS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_6abb06e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6abb06e956ce2bfa05920c0c13857ec6aa11ef2810e017d5d44f51b018170d10"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-06 01:12:34"
  condition:
    hash.sha256(0, filesize) == "6abb06e956ce2bfa05920c0c13857ec6aa11ef2810e017d5d44f51b018170d10"
}
```

### Sample 66: `d2ee4c98c10d1d6b`

| Field | Value |
|---|---|
| SHA-256 | `d2ee4c98c10d1d6b51792f0cd7afb69de916dd33db6c635e61e4cdff715aabe5` |
| Family label | `Mirai` |
| File name | `boatnet.i686` |
| File type | `elf` |
| First seen | `2026-08-06 01:12:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6719c0006c9386625606121267c9643` |
| SHA-1 | `8d2c7e4bf60b9ecceeac659d40c18d88cbddd2d5` |
| SHA-256 | `d2ee4c98c10d1d6b51792f0cd7afb69de916dd33db6c635e61e4cdff715aabe5` |
| SHA3-384 | `1d755859a5d4d99bb002f7627b043018a20c71fcd301b96839a650bc57d4c3f2cd1178188c8d338f2115e4e3acf42a8d` |
| TLSH | `T11DF2F2FF63E4053FDD231232D31FB1D4A87EADA8CB4A45B366C44186E9E5065263483D` |
| SSDEEP | `768:AEu0ps+ere5PWBEVOUp2BX1X/6vtgPkt6TEzhG:AElPYEDmZ/KtgcoEhG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_d2ee4c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ee4c98c10d1d6b51792f0cd7afb69de916dd33db6c635e61e4cdff715aabe5"
    family = "Mirai"
    file_name = "boatnet.i686"
    file_type = "elf"
    first_seen = "2026-08-06 01:12:32"
  condition:
    hash.sha256(0, filesize) == "d2ee4c98c10d1d6b51792f0cd7afb69de916dd33db6c635e61e4cdff715aabe5"
}
```

### Sample 67: `9f53c9c4daf662ac`

| Field | Value |
|---|---|
| SHA-256 | `9f53c9c4daf662aca794c22b08cedfed2634acc40f5d6b9c89728462c63be3af` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-06 01:11:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ab30d127b5e17f257b9035e87d6124c` |
| SHA-1 | `86b83a419ae8e5d82d146a140a2752e1f7c1ff28` |
| SHA-256 | `9f53c9c4daf662aca794c22b08cedfed2634acc40f5d6b9c89728462c63be3af` |
| SHA3-384 | `3cddd58e406924c6be9502adddefb2d2828c0bdfaadf9e7c347482a4e72ee21a316c038b88f12e73b7afeb8acf3cdf6d` |
| TLSH | `T12AC329A9F890DE52C6C52676FB5E028C33231778D3DE7105CE109E34F7EB95A0A3A942` |
| SSDEEP | `3072:GMS8HWIzZvDVsINudJj+3scYEEU3cRE4fOAvLSKykdGER6U1yGk1Af1Dl:GLMnlUQscYEEU3cRE4GsLLVdGM1l4A95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_9f53c9c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f53c9c4daf662aca794c22b08cedfed2634acc40f5d6b9c89728462c63be3af"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:11:01"
  condition:
    hash.sha256(0, filesize) == "9f53c9c4daf662aca794c22b08cedfed2634acc40f5d6b9c89728462c63be3af"
}
```

### Sample 68: `2910c598d1658ee0`

| Field | Value |
|---|---|
| SHA-256 | `2910c598d1658ee0193b3001fe15137ca62be3a312efd76c134904c5c6abb345` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-06 01:10:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `81cd35bf389a55b94dfa2c639a3b2571` |
| SHA-1 | `9e7e878c2ec4113601ac1796003e1b4517bb68fa` |
| SHA-256 | `2910c598d1658ee0193b3001fe15137ca62be3a312efd76c134904c5c6abb345` |
| SHA3-384 | `f03e050d010e07a234d90ad80d9c3f17925e02ce3ca1a90901bc67198ed73bb61c3300450700b029778cedb22d016f26` |
| TLSH | `T1B7C31A99F890DE52C6D52675FA5E028C332357B8C3DA7205CD209F34F7EB95A0E3A942` |
| SSDEEP | `3072:8N9P0r4MP9Zkocit2uEbUQ4g8O8C17MC+0OhBAmPj7ClTf1Dl4:8N9P00M1guqUQ4g8Oh17MCFmPjMT95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_2910c598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2910c598d1658ee0193b3001fe15137ca62be3a312efd76c134904c5c6abb345"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 01:10:57"
  condition:
    hash.sha256(0, filesize) == "2910c598d1658ee0193b3001fe15137ca62be3a312efd76c134904c5c6abb345"
}
```

### Sample 69: `6be33d68a77ca518`

| Field | Value |
|---|---|
| SHA-256 | `6be33d68a77ca5185614457fbbc16fb0e877b8e17760be7277c8327cc4e23bb6` |
| Family label | `Mirai` |
| File name | `putita.arm6` |
| File type | `elf` |
| First seen | `2026-08-06 01:09:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29d2f48a6f63824578c7471363551bd6` |
| SHA-1 | `ca8502ff22ed31ffd6254966daa44ce5115de673` |
| SHA-256 | `6be33d68a77ca5185614457fbbc16fb0e877b8e17760be7277c8327cc4e23bb6` |
| SHA3-384 | `fe1b04eb99425fa02c20b105c8789f8b83b6f26b882b0c3843b905bdc822947ee23f5c17207026ac47df888d18224137` |
| TLSH | `T11943F1D35105EEF6C1EA1036E62CE3EA341946B8EDF63896C52108ED66FA2078B75D07` |
| SSDEEP | `768:9v6h6u1yyGeIYG6mbYyVpR/tG+0zpiPGHF2TT9m1Ok7FyL6qZBtu64MDGRIw2Zg1:9w6u1yyGOzYpRlJEHsTxGy5nQynfk` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_6be33d68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6be33d68a77ca5185614457fbbc16fb0e877b8e17760be7277c8327cc4e23bb6"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:09:39"
  condition:
    hash.sha256(0, filesize) == "6be33d68a77ca5185614457fbbc16fb0e877b8e17760be7277c8327cc4e23bb6"
}
```

### Sample 70: `a916b91671fbecdd`

| Field | Value |
|---|---|
| SHA-256 | `a916b91671fbecdd5d92285b3911228d49785bfc9c740305f8bb040e3b1a3ddb` |
| Family label | `Mirai` |
| File name | `putita.arm7` |
| File type | `elf` |
| First seen | `2026-08-06 01:09:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `453453deadf1f003189ea5d7ee8fc19d` |
| SHA-1 | `ee61d564c99154ffeaf235740e13c3bd9a7a98ce` |
| SHA-256 | `a916b91671fbecdd5d92285b3911228d49785bfc9c740305f8bb040e3b1a3ddb` |
| SHA3-384 | `c66d9832e4214c4f25c49777cdf97ac1480ff7d9c60ad0c61baa55b5fa6117d8b9a8123292df31560fbad52410097e39` |
| TLSH | `T1CF330260406A66F3DB481C39FB7B800B579617E83AB3231523047F6CB7E7059317AA8E` |
| SSDEEP | `1536:+8LB5BPyiL/8yviYQG+L6gnOcEKl69H/0tobKMBQfI:tB1Rv/+1OfKSH/0KKBQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_a916b916
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a916b91671fbecdd5d92285b3911228d49785bfc9c740305f8bb040e3b1a3ddb"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 01:09:36"
  condition:
    hash.sha256(0, filesize) == "a916b91671fbecdd5d92285b3911228d49785bfc9c740305f8bb040e3b1a3ddb"
}
```

### Sample 71: `e2aef39546ce2732`

| Field | Value |
|---|---|
| SHA-256 | `e2aef39546ce27325e44a7e386a875133484251a8b115074038103ac6235e2e7` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 01:07:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12d46d381a697241ff6f5937b268b9e2` |
| SHA-1 | `df933f77857b7fab248075fcbb74c28bb1d08838` |
| SHA-256 | `e2aef39546ce27325e44a7e386a875133484251a8b115074038103ac6235e2e7` |
| SHA3-384 | `5caec9409025782d6ddea4f459ba0c7131a6af958d10c7d63e49d03267e7bf561fe1589c76d6e33846bf61d3379ce146` |
| TLSH | `T188A34C02A49180FEC49BD174879FD137EB72F94912307B1F3B907E712E36E626B1A691` |
| SSDEEP | `3072:RwRZog981c2H+ZpIrF3oo6STqB2wqbhR:aPokbCrpoo70ybhR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_e2aef395
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2aef39546ce27325e44a7e386a875133484251a8b115074038103ac6235e2e7"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 01:07:41"
  condition:
    hash.sha256(0, filesize) == "e2aef39546ce27325e44a7e386a875133484251a8b115074038103ac6235e2e7"
}
```

### Sample 72: `90635095f7edc189`

| Field | Value |
|---|---|
| SHA-256 | `90635095f7edc189533d696d5af6edd85024dd2438bd7741fada4e7ee94a7e2b` |
| Family label | `Mirai` |
| File name | `boatnet.mips` |
| File type | `elf` |
| First seen | `2026-08-06 01:07:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a98d67e67fc04b4451850c70952d9b3f` |
| SHA-1 | `1fe6d3d412ea89ec4e4a284792c429a7558c9ae0` |
| SHA-256 | `90635095f7edc189533d696d5af6edd85024dd2438bd7741fada4e7ee94a7e2b` |
| SHA3-384 | `f915390f0a4c8efe5869207d16bce4c24eb076f1e85db94da57593836aab7ebbbe7a9cb9ac14212ba926954aab9ad396` |
| TLSH | `T114A3CA5B6E318FADF27887304BB74B30A79963D623F1C685E29DC5011E6434E681FB98` |
| TELFHASH | `t159217c18483823f4d7624cdc6bdcff72e46170df5a266e378d10e9ae9a2a9429e00c1c` |
| SSDEEP | `1536:UfM9z2Ptbv86hzsv8c374hzrXmPrh2cbGlHerWNwbZDNCHgLcqCw3:UfHtbhiD3GrXYYc6vwbZhCHT2` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_90635095
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90635095f7edc189533d696d5af6edd85024dd2438bd7741fada4e7ee94a7e2b"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:07:38"
  condition:
    hash.sha256(0, filesize) == "90635095f7edc189533d696d5af6edd85024dd2438bd7741fada4e7ee94a7e2b"
}
```

### Sample 73: `c092a870c7d18ace`

| Field | Value |
|---|---|
| SHA-256 | `c092a870c7d18acedda48fdc36c4169770f0aea76be5f20d3d8ce5f3c2de2af2` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 01:06:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9299214a9917ae17cb98ad84af534d0` |
| SHA-1 | `8dfaa6537250a3e07fbc795f33aec9031c19500e` |
| SHA-256 | `c092a870c7d18acedda48fdc36c4169770f0aea76be5f20d3d8ce5f3c2de2af2` |
| SHA3-384 | `c0f1bda58010852faad3e489427d1695ec58fa5ea5e61f1ad52d39742270f42f607ed5ac3909463aa9618b7662ba279e` |
| TLSH | `T1A633F12F21ABABB0CD33A677A5178510C61470C27364C72344A896B50CF36E19BF6BE7` |
| SSDEEP | `1536:0ekzrn/SHxscEGWSko20OJKxnQ/oxicE9rH+:0FzrQaHGVc0ZBNxicUH+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_c092a870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c092a870c7d18acedda48fdc36c4169770f0aea76be5f20d3d8ce5f3c2de2af2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 01:06:42"
  condition:
    hash.sha256(0, filesize) == "c092a870c7d18acedda48fdc36c4169770f0aea76be5f20d3d8ce5f3c2de2af2"
}
```

### Sample 74: `96f7c5a4774691e2`

| Field | Value |
|---|---|
| SHA-256 | `96f7c5a4774691e2397617d90eeb27eddb0dd5b2b5b5ab44167ac948d135bbc9` |
| Family label | `Mirai` |
| File name | `boatnet.mips` |
| File type | `elf` |
| First seen | `2026-08-06 01:06:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a96bfd3680f088b24881cc643be76fc2` |
| SHA-1 | `87eddc2e6b623952cb793023526da4287cc6227c` |
| SHA-256 | `96f7c5a4774691e2397617d90eeb27eddb0dd5b2b5b5ab44167ac948d135bbc9` |
| SHA3-384 | `3aeb212ae6ea7cebb5ed4063b410d9631ad11c546fb534e14ba8f942987053e93da8fb9450e217cdbf0c9b5ddfc8cec8` |
| TLSH | `T17D03F1DD470392EDDA62A0FC1EE50BB46E1897D2A5429F2B7299C74A8D800F13D83DF1` |
| SSDEEP | `768:m0Sq4hADe1a+a7bNQyFmAUBXYgPN7qPWJgGlzDpbuR1JR:ZSqm8eC7bZFxIBPVwCVJu3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_96f7c5a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96f7c5a4774691e2397617d90eeb27eddb0dd5b2b5b5ab44167ac948d135bbc9"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:06:41"
  condition:
    hash.sha256(0, filesize) == "96f7c5a4774691e2397617d90eeb27eddb0dd5b2b5b5ab44167ac948d135bbc9"
}
```

### Sample 75: `db0b035705417896`

| Field | Value |
|---|---|
| SHA-256 | `db0b0357054178961f2f9fbf1bec670cb1f84aae49537ed401bea4910c60b7db` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-08-06 01:04:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d9ea1dd79b437600ca53caf184a186b` |
| SHA-1 | `b502c07510ba5c84d42b17594d0af48b9c7ccef7` |
| SHA-256 | `db0b0357054178961f2f9fbf1bec670cb1f84aae49537ed401bea4910c60b7db` |
| SHA3-384 | `874c21cd39638780947f1c1e2106dfff91e5caac404c03b268616a71e2f8bb8f507094274a003d9a98a2a392737423e2` |
| TLSH | `T188731995FD429A12C6C115BBFF5E828C771B43A8D2EE3207AF159F20368B95B0E3B541` |
| TELFHASH | `t1dee0264c8d0c2eecbbc0448a02ed78123b28f4302902049408eeccd959a2de8380418d` |
| SSDEEP | `1536:iSnVZE+XyaLKNwWaWQTHbCFOxtCJAopKfx9Jaju7EpvScqR8:5nVZEfaLkfaWebPVoENES` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_db0b0357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db0b0357054178961f2f9fbf1bec670cb1f84aae49537ed401bea4910c60b7db"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-06 01:04:36"
  condition:
    hash.sha256(0, filesize) == "db0b0357054178961f2f9fbf1bec670cb1f84aae49537ed401bea4910c60b7db"
}
```

### Sample 76: `566e7e389cfed8ae`

| Field | Value |
|---|---|
| SHA-256 | `566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f` |
| Family label | `unknown` |
| File name | `k.sh` |
| File type | `sh` |
| First seen | `2026-08-06 01:03:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13cd6fa2231bf79ae7dfc802baccebb3` |
| SHA-1 | `2ca195624b63c1819618561a25eeb7284ef80011` |
| SHA-256 | `566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f` |
| SHA3-384 | `6356d8de8efc7e8bbcd7c94003f3bdadabb9f4355a698bbed16b57a26080910713da600b79e90e20eaad6a5f0aec71af` |
| TLSH | `T11521834A50106FA2C629DF157132467C4103E2C9D2FB2EC4AA876A74ECDDBC5F485F5A` |
| SSDEEP | `12:fHGIC9+k9W8X2XzSlmSF/afzB8NLhfUZKJIKKZMMGlOaaR7VRIJ:Y5Tr/AWNVlN` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_076_566e7e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f"
    family = "unknown"
    file_name = "k.sh"
    file_type = "sh"
    first_seen = "2026-08-06 01:03:45"
  condition:
    hash.sha256(0, filesize) == "566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f"
}
```

### Sample 77: `9e7ca69553ed9649`

| Field | Value |
|---|---|
| SHA-256 | `9e7ca69553ed9649a52a8a4e35e6df16b37a17b32d9fcc96c9b22473b37ca48c` |
| Family label | `Mirai` |
| File name | `boatnet.arm` |
| File type | `elf` |
| First seen | `2026-08-06 01:03:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1db82515c31b29890a53c9bb67cf92eb` |
| SHA-1 | `73083b451f41de9b11bf7cb1c90c94f1f9574e00` |
| SHA-256 | `9e7ca69553ed9649a52a8a4e35e6df16b37a17b32d9fcc96c9b22473b37ca48c` |
| SHA3-384 | `99a82bfb230e4101fe57c99d75aaa2a24929502bb2f01fcf533195aed168b112f3c118b43fe39be4dbac5fe4c9c1115e` |
| TLSH | `T1E0F2E161DA8DE52086735C3D6DAE00C1AD3BAA3EB9E070F2B044D664B7001479AB4BCB` |
| SSDEEP | `768:SEUMB4BGxOrwZ+VD//EWxbObFbbb30nbq13drVBosidFy/3Gs3Uozw:SEUMB4M0cZvQSd0bq133ayfrzw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_9e7ca695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e7ca69553ed9649a52a8a4e35e6df16b37a17b32d9fcc96c9b22473b37ca48c"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-06 01:03:41"
  condition:
    hash.sha256(0, filesize) == "9e7ca69553ed9649a52a8a4e35e6df16b37a17b32d9fcc96c9b22473b37ca48c"
}
```

### Sample 78: `29248b98fe7b3e59`

| Field | Value |
|---|---|
| SHA-256 | `29248b98fe7b3e59919395e2f044d9c40a9a1eedf226f7bd2eb9d9067f4163e9` |
| Family label | `Mirai` |
| File name | `boatnet.spc` |
| File type | `elf` |
| First seen | `2026-08-06 01:00:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e02aa151386792f5a3a34eba21d9be07` |
| SHA-1 | `faf51e0aa172fa76b987e703c3765c2036c8a518` |
| SHA-256 | `29248b98fe7b3e59919395e2f044d9c40a9a1eedf226f7bd2eb9d9067f4163e9` |
| SHA3-384 | `8680682fa7f002610273ef9be7eadee621a1a3943b44c73b0503dd89b71cb88141ffa9756ce21e9c32c1fc541108106d` |
| TLSH | `T1F4733B22BA72192BC5D0E57A61F30235F2F343CA14AC8A1B3D714DCDBF65A4026677E9` |
| SSDEEP | `1536:ATBMTVz4pNZlEtztNk5Nw/o3/WWtx2t7QmyL2:+eVz4pNZCtztNUwNzuC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_29248b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29248b98fe7b3e59919395e2f044d9c40a9a1eedf226f7bd2eb9d9067f4163e9"
    family = "Mirai"
    file_name = "boatnet.spc"
    file_type = "elf"
    first_seen = "2026-08-06 01:00:56"
  condition:
    hash.sha256(0, filesize) == "29248b98fe7b3e59919395e2f044d9c40a9a1eedf226f7bd2eb9d9067f4163e9"
}
```

### Sample 79: `c842cdf88aa56522`

| Field | Value |
|---|---|
| SHA-256 | `c842cdf88aa56522af9a7f74736445af07e8b6b1f4b43e9fd8063c8146655fb4` |
| Family label | `Mirai` |
| File name | `boatnet.mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 00:58:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f5c5070c5e14a6debb086f9936e4b9a1` |
| SHA-1 | `3f612b1ad030104b0486f6409ce1946ab08735ea` |
| SHA-256 | `c842cdf88aa56522af9a7f74736445af07e8b6b1f4b43e9fd8063c8146655fb4` |
| SHA3-384 | `56ed99e1806212df43dccbdede9e67d39e7ecf9289e38b7bac966b5ae10617ef41c1c365043606f334bd07d32bc3d90b` |
| TLSH | `T1F1A30906FB010FF7D8ABCD3745B91B0128DC555A22A66B37B634C918B54B64B1BE3CA4` |
| SSDEEP | `1536:HmNe95/JcP7pARt7xkQWoBIw4UZljONCNZGIBQOjVm7u0vmbvc:Hc8M7pAR8QWF8ljfNRkvgc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_c842cdf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c842cdf88aa56522af9a7f74736445af07e8b6b1f4b43e9fd8063c8146655fb4"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:58:42"
  condition:
    hash.sha256(0, filesize) == "c842cdf88aa56522af9a7f74736445af07e8b6b1f4b43e9fd8063c8146655fb4"
}
```

### Sample 80: `84f81d78f84f045a`

| Field | Value |
|---|---|
| SHA-256 | `84f81d78f84f045a4a26d5a2aa98a0a47442334f22903a43e2cf72528e064863` |
| Family label | `Mirai` |
| File name | `boatnet.mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 00:58:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ec85b6b1f2ffb0eea2403d36c6a803f` |
| SHA-1 | `e09c4ece2b490ac6399a37a22550e15c5662232b` |
| SHA-256 | `84f81d78f84f045a4a26d5a2aa98a0a47442334f22903a43e2cf72528e064863` |
| SHA3-384 | `fab168bb91ba4074a7905a03a6acba35032957868a41fe027ed801e9e43cec4fa32b1efb4c10e528b1dab59afb9bc084` |
| TLSH | `T1B113E16C65646E8B98BF2C3EB49E37F44A14F1D077DE2BCDA652440CB91D24BE81C4B8` |
| SSDEEP | `768:/O7iEvAbuR8n7EnNG+7FKEylgUc+Y6i0kry9yvGck6orGLPqT6EMWZ0vWb:/O7iEvSuGgNBF+cRH+UoyPw6EZJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_84f81d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84f81d78f84f045a4a26d5a2aa98a0a47442334f22903a43e2cf72528e064863"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:58:24"
  condition:
    hash.sha256(0, filesize) == "84f81d78f84f045a4a26d5a2aa98a0a47442334f22903a43e2cf72528e064863"
}
```

### Sample 81: `ec4ae4bf894da852`

| Field | Value |
|---|---|
| SHA-256 | `ec4ae4bf894da8529697d86f2956d49116192c7ab2eef8035c5196999d21cd71` |
| Family label | `unknown` |
| File name | `composer.dat` |
| File type | `exe` |
| First seen | `2026-08-06 00:52:33` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a2e59336a50e3192dafe4773e7008f0` |
| SHA-1 | `a4782f3a8417674f28ef9c3dbc4a1e48c4ccdbdf` |
| SHA-256 | `ec4ae4bf894da8529697d86f2956d49116192c7ab2eef8035c5196999d21cd71` |
| SHA3-384 | `91f159ff872bad9873d5335f47de7c749141a7a42230afae02147321387e123ab0d555f85b625cd180d6160c43949751` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T17FE6330C27D123FEF533917D9AD20669F979B8352BB0C68F1B6C89645D231E04E3A366` |
| SSDEEP | `393216:QSGmmbiEtomUzVvCl23MXMCHWUjhYcuI3/PGTAI:QSGRCeXMb8htH/O7` |
| ICON-DHASH | `e86864e1d8e8ec58` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_ec4ae4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec4ae4bf894da8529697d86f2956d49116192c7ab2eef8035c5196999d21cd71"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-06 00:52:33"
  condition:
    hash.sha256(0, filesize) == "ec4ae4bf894da8529697d86f2956d49116192c7ab2eef8035c5196999d21cd71"
}
```

### Sample 82: `a524ccbc295bf3ac`

| Field | Value |
|---|---|
| SHA-256 | `a524ccbc295bf3ac6c30a10b75007e8799487a5367e6a6542037c2e6dc1bd749` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 00:48:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41d64fe83d22e3fc6499130384964b12` |
| SHA-1 | `9899ed6986f534df56134067c253839261eff3b8` |
| SHA-256 | `a524ccbc295bf3ac6c30a10b75007e8799487a5367e6a6542037c2e6dc1bd749` |
| SHA3-384 | `e55409477aeda476a694ed664ee44d409a6a23ed21f982e4b151f1d1678dbe0b24405b150179d4c61ba49caac66ffe54` |
| TLSH | `T1AEC34A0675A144FCC156C074C73FE937EA31B85D12353ABF6B84BA31AE22E355B0AB52` |
| SSDEEP | `1536:jkajesnuoaftVIkeDsGPb9a4xDrMd7yzi/eSqCucY/pfmqbzr6QG4Hor4TRm:XjWtVIkLGjtli3eFnfm4r6QG4w4Vm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_a524ccbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a524ccbc295bf3ac6c30a10b75007e8799487a5367e6a6542037c2e6dc1bd749"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 00:48:45"
  condition:
    hash.sha256(0, filesize) == "a524ccbc295bf3ac6c30a10b75007e8799487a5367e6a6542037c2e6dc1bd749"
}
```

### Sample 83: `17cfbd25034b2924`

| Field | Value |
|---|---|
| SHA-256 | `17cfbd25034b29242d00aa52257b7edccae959cfc3cc8534d0515e5d4fadf165` |
| Family label | `Mirai` |
| File name | `putita.x86_64` |
| File type | `elf` |
| First seen | `2026-08-06 00:47:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16d86d1b5b2c6a06cc21d942faacece3` |
| SHA-1 | `3db4c949578b5ee2fba3ba653373116cc64fcf0a` |
| SHA-256 | `17cfbd25034b29242d00aa52257b7edccae959cfc3cc8534d0515e5d4fadf165` |
| SHA3-384 | `a42778df37249c381aace967fb1cc3ec43e5947c0d0d559601c2ef468397036583c1b1f2bad22c75bdf650d5ef5b3b90` |
| TLSH | `T10C43F2AB9284BB38C2263B771C35434FF72264BE99751F5317EBF299C899B542C30821` |
| SSDEEP | `1536:07hPV608wtwklGUaDeRPSvULZNMALmVuTIq:0JV6itwk4rDTINMAzF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_17cfbd25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17cfbd25034b29242d00aa52257b7edccae959cfc3cc8534d0515e5d4fadf165"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 00:47:40"
  condition:
    hash.sha256(0, filesize) == "17cfbd25034b29242d00aa52257b7edccae959cfc3cc8534d0515e5d4fadf165"
}
```

### Sample 84: `3a81c926fdeb699c`

| Field | Value |
|---|---|
| SHA-256 | `3a81c926fdeb699cf8a4de9e037d6ffbe9041d22d7c9b0fa1ed36e6966dc4211` |
| Family label | `ValleyRAT` |
| File name | `setup_r8010.exe` |
| File type | `exe` |
| First seen | `2026-08-06 00:45:18` |
| Reporter | `CNGaoLing` |
| Tags | `exe, SilverFox, Trojan/SilverFox.bm[lddel], ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7457acf4ae83faae52db909d15eab181` |
| SHA-1 | `3300b405cd6e322c09a4a063255328dccfcbe531` |
| SHA-256 | `3a81c926fdeb699cf8a4de9e037d6ffbe9041d22d7c9b0fa1ed36e6966dc4211` |
| SHA3-384 | `79f5f95600f2164c4b49a4cbcc0f34ff55231c65d0934d3ac2bac3d2e76d2c55fe8398ec219d5a611b9e3d601933094b` |
| IMPHASH | `380560563ebacca1589d8d38ac610187` |
| TLSH | `T130E78216B74289CEE076A238944B8F51E336E9704A71933723B5735D1FFE38C8EA6149` |
| SSDEEP | `98304:cuj9nmW2eUAAq4gm4mNSh6q+luaePvl8/bbJtF0gofLzXQQ7QfM3rR:dRnmW2s/m3xq9a2l8/QX9EfM3rR` |
| ICON-DHASH | `c4e0b0a4cc74626a` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_084_3a81c926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a81c926fdeb699cf8a4de9e037d6ffbe9041d22d7c9b0fa1ed36e6966dc4211"
    family = "ValleyRAT"
    file_name = "setup_r8010.exe"
    file_type = "exe"
    first_seen = "2026-08-06 00:45:18"
  condition:
    hash.sha256(0, filesize) == "3a81c926fdeb699cf8a4de9e037d6ffbe9041d22d7c9b0fa1ed36e6966dc4211"
}
```

### Sample 85: `1af0e29181b7839d`

| Field | Value |
|---|---|
| SHA-256 | `1af0e29181b7839de6d941ce7751a93832b5b07f891157972d8369888f8931bb` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 00:38:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e400dab0d2d5f341cb0ed60e4d388501` |
| SHA-1 | `83c96128d0a00c628ca6df6ad4b3c242aa3e8d80` |
| SHA-256 | `1af0e29181b7839de6d941ce7751a93832b5b07f891157972d8369888f8931bb` |
| SHA3-384 | `37ea8c41cca768e2b5f7cee65baa7939c48eef3b9e81ab68942082a879e189eb7a4b5bb790bcce4c44cb7f932c75d2b1` |
| TLSH | `T102043B49BE642BFBC06FCE70052D834621DDA44BA2F5A73D6278DD4CB9AA2485CF3C54` |
| TELFHASH | `t14431beb08b7b65119ac5c7ec88ecb75a491e8515470adf33fd3281ac50260ede22ad5f` |
| SSDEEP | `3072:VyZHgiHkvSyKkUXY7cgkESG5CwKo6Z06bHr17P/JZfrE13lF1DA4:8ZHjHkqyKkUX+cgkESG5CwKo6Z06bHr4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_1af0e291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1af0e29181b7839de6d941ce7751a93832b5b07f891157972d8369888f8931bb"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:38:31"
  condition:
    hash.sha256(0, filesize) == "1af0e29181b7839de6d941ce7751a93832b5b07f891157972d8369888f8931bb"
}
```

### Sample 86: `30753a7b23ebe62c`

| Field | Value |
|---|---|
| SHA-256 | `30753a7b23ebe62c5daa7ba3930c2aba7859b90070718eb82edada1ef01b4f8b` |
| Family label | `Mirai` |
| File name | `putita.mpsl` |
| File type | `elf` |
| First seen | `2026-08-06 00:37:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80d1a207a1cd95be5c77658529c9f87e` |
| SHA-1 | `2c010487642ea85ce691bd77c9dd70063e8b1bb5` |
| SHA-256 | `30753a7b23ebe62c5daa7ba3930c2aba7859b90070718eb82edada1ef01b4f8b` |
| SHA3-384 | `94704f8bfe59e585b97bb00cbc91c3b6aa6521698fc4e0ff21cf21b15b17007e869615cf26802a72b95f0f31224e23cc` |
| TLSH | `T1308302FFECA4578FE301CDF467B3D5A29B160368D940028534EA575876C0FDC62686A9` |
| SSDEEP | `1536:s1BcY50K+FyH3EASExZZX5GKCvE0on4zPP/Wz3J5Eul0w:a0ZFyUApZDC8d2PP63J5Eul0w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_30753a7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30753a7b23ebe62c5daa7ba3930c2aba7859b90070718eb82edada1ef01b4f8b"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:37:29"
  condition:
    hash.sha256(0, filesize) == "30753a7b23ebe62c5daa7ba3930c2aba7859b90070718eb82edada1ef01b4f8b"
}
```

### Sample 87: `53fe10c912647359`

| Field | Value |
|---|---|
| SHA-256 | `53fe10c9126473590e35a1fac360f48e815cd39ec48e3bf73baf350300dba3a4` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 23:54:40` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, E, exe, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5d688ba843a446a819c3825c1cd5f34` |
| SHA-1 | `22acdae08e83a6b557479cdc2d656c9c587fdbe6` |
| SHA-256 | `53fe10c9126473590e35a1fac360f48e815cd39ec48e3bf73baf350300dba3a4` |
| SHA3-384 | `cb5c3a1fcd20d6b283910bf169fd4997140e363da0998a8f07874f998e03f25e7d961333772c65d3ba0c09e1bba14b53` |
| IMPHASH | `de85a398477c39117ee5fd3f2278b959` |
| TLSH | `T10AA5E1D3EBA645F4C5F21838623EA613E234350D87185A7BB3DD0AA03F2674D94B971E` |
| SSDEEP | `49152:Gd1/CqfWT+jF7jiViWSdL434iQUQC/4dW/vYm3CD4rtT:+xFJFMQU5/pbCDWT` |
| ICON-DHASH | `000002c0c0c00000` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_53fe10c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53fe10c9126473590e35a1fac360f48e815cd39ec48e3bf73baf350300dba3a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 23:54:40"
  condition:
    hash.sha256(0, filesize) == "53fe10c9126473590e35a1fac360f48e815cd39ec48e3bf73baf350300dba3a4"
}
```

### Sample 88: `7f2f9568ed5c3a32`

| Field | Value |
|---|---|
| SHA-256 | `7f2f9568ed5c3a32cea5cfb11b09ebc1e3b011c5aec406ea77e268060ec8f318` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-05 23:40:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aa1963e9ed98a574507be71f97b58292` |
| SHA-1 | `d84c297c5c22a07aa74775294f854b66d9f126f4` |
| SHA-256 | `7f2f9568ed5c3a32cea5cfb11b09ebc1e3b011c5aec406ea77e268060ec8f318` |
| SHA3-384 | `5b3f7971f168e68ecb9e0ccb3d64027861506066b5d2e669e0d273c93fc22c7e7314b4688e5eec1e01ab13409fe32d2a` |
| TLSH | `T1D4C329A9F890DE52C6C52676FB5E028C33231778D3DE7105CE109E34F7EB95A0A3A942` |
| SSDEEP | `3072:GMS8HWIzZvDVsINudJj+3scYEEU3cRE4fOAvLSKykdGER6U1yGk1qf1Dl:GLMnlUQscYEEU3cRE4GsLLVdGM1l4q95` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_7f2f9568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f2f9568ed5c3a32cea5cfb11b09ebc1e3b011c5aec406ea77e268060ec8f318"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-05 23:40:36"
  condition:
    hash.sha256(0, filesize) == "7f2f9568ed5c3a32cea5cfb11b09ebc1e3b011c5aec406ea77e268060ec8f318"
}
```

### Sample 89: `e248d956f20e2877`

| Field | Value |
|---|---|
| SHA-256 | `e248d956f20e28773321e81afbe9ee0f53dd5882dc9dd738fb5a7c38e5105aa7` |
| Family label | `Mirai` |
| File name | `putita.arm` |
| File type | `elf` |
| First seen | `2026-08-05 23:39:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9f549be718492984c76db4f36e50381` |
| SHA-1 | `9bc38ae8d96a0612537784be388f54a282921330` |
| SHA-256 | `e248d956f20e28773321e81afbe9ee0f53dd5882dc9dd738fb5a7c38e5105aa7` |
| SHA3-384 | `158c1354fbedbf2483d692c7de03427816032297d95b58492c13e520d210e26d8bb0854a1ec9705341f119043b07fdcd` |
| TLSH | `T14D43F1D392869EF5C0E6103AE52CF2EA34694AB8DDF73092C5211CED65FA6034B32D46` |
| SSDEEP | `1536:56u1yyGOzYpRlJEHsTxGy5nQ6itnItffl:5/za4sTm6qKN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_e248d956
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e248d956f20e28773321e81afbe9ee0f53dd5882dc9dd738fb5a7c38e5105aa7"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-05 23:39:30"
  condition:
    hash.sha256(0, filesize) == "e248d956f20e28773321e81afbe9ee0f53dd5882dc9dd738fb5a7c38e5105aa7"
}
```

### Sample 90: `5e468b536228953b`

| Field | Value |
|---|---|
| SHA-256 | `5e468b536228953bcace7b3793da62f6ea5e7d57026812c2654d1f78e8a5e1f9` |
| Family label | `Mirai` |
| File name | `boatnet.sh4` |
| File type | `elf` |
| First seen | `2026-08-05 22:21:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f39684b9ec67d552d3dbc47ae111322b` |
| SHA-1 | `cbfa4e0608ae4bbd72c146a85dc10e480b2db9bf` |
| SHA-256 | `5e468b536228953bcace7b3793da62f6ea5e7d57026812c2654d1f78e8a5e1f9` |
| SHA3-384 | `bf212ac28a31558ed0cc8947fc958e2d6ebe76d5ff8a4ff61f59520f56197dc20816c81d7a4c4b53ef6bb96e007b84fe` |
| TLSH | `T1CF536C67CA663E5CC2254BF470B1DF706763646040671EB929AAC6B8D0C3DCCF9863B9` |
| SSDEEP | `1536:QII2IKjH3qKcz3JPVDiZqyqe87HSC5Qms1:WoXtclVDWqjjS/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_5e468b53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e468b536228953bcace7b3793da62f6ea5e7d57026812c2654d1f78e8a5e1f9"
    family = "Mirai"
    file_name = "boatnet.sh4"
    file_type = "elf"
    first_seen = "2026-08-05 22:21:39"
  condition:
    hash.sha256(0, filesize) == "5e468b536228953bcace7b3793da62f6ea5e7d57026812c2654d1f78e8a5e1f9"
}
```

### Sample 91: `b72342c9ae243231`

| Field | Value |
|---|---|
| SHA-256 | `b72342c9ae243231eecefda808f66e0177637b120cb8d45e3bc9681c84d0a9a0` |
| Family label | `RustyStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 21:56:20` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe, RustyStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e518f1ad663f9150e8cf17ce7daa2a50` |
| SHA-1 | `7ad89bf65b82c2f1205532f5e193d1a9246497f7` |
| SHA-256 | `b72342c9ae243231eecefda808f66e0177637b120cb8d45e3bc9681c84d0a9a0` |
| SHA3-384 | `20ee232c1a3d0d36e20de6abef65a0abc0e41a28e74e5e8be5161d4ca0cc87fbf9e28c888502857775abc373e99acbf3` |
| IMPHASH | `809293624745fa482c080f26d20f3a8b` |
| TLSH | `T1E1161257B291923EE15BC1749386D972F236B4CA0631ACFF11E8E7342E59EA50F0CB18` |
| SSDEEP | `98304:sJBET2r0jV2AFwBiN5YcR/zuETZeWKatBEzVOx1ReBdSaFO:LCIVXFsiN5YcuETcWKatB4ETRaJO` |

#### Technical Assessment

- The sample is tracked as `RustyStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RustyStealer_091_b72342c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b72342c9ae243231eecefda808f66e0177637b120cb8d45e3bc9681c84d0a9a0"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 21:56:20"
  condition:
    hash.sha256(0, filesize) == "b72342c9ae243231eecefda808f66e0177637b120cb8d45e3bc9681c84d0a9a0"
}
```

### Sample 92: `5ef6019fb6ee1db1`

| Field | Value |
|---|---|
| SHA-256 | `5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f` |
| Family label | `unknown` |
| File name | `notification_helper.exe` |
| File type | `exe` |
| First seen | `2026-08-05 21:54:02` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a266dbe358d13f9416ca8c11ca94853b` |
| SHA-1 | `a108b96794a46ea5eb604044f7447d70957a03e6` |
| SHA-256 | `5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f` |
| SHA3-384 | `8fc325596e6369133aa7a9999795aa038817eaecf17dc740d233e3cf36f85fb007d3421f35f5c0789340c9fd3250269c` |
| IMPHASH | `a015389f60165399e844c3b119b7e185` |
| TLSH | `T14E847D11B780D171E4F302B59ABCEB14593DBE310B6690CBF3C84A5E1A34AD0BB75B66` |
| SSDEEP | `6144:s4WATf7l+psNkdSMLLSAT3NxFx3T6RNLL:sITfgpsidSsLT3NxqzLL` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_5ef6019f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f"
    family = "unknown"
    file_name = "notification_helper.exe"
    file_type = "exe"
    first_seen = "2026-08-05 21:54:02"
  condition:
    hash.sha256(0, filesize) == "5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f"
}
```

### Sample 93: `ce37bbeaa6551bab`

| Field | Value |
|---|---|
| SHA-256 | `ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5` |
| Family label | `unknown` |
| File name | `ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5` |
| File type | `elf` |
| First seen | `2026-08-05 21:30:17` |
| Reporter | `EnthecSolutions` |
| Tags | `elf, enthec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6041ec612ed7ca1d3a31e6ac0d4535b5` |
| SHA-1 | `e453d1973774406fc45e573f20c1321de848c416` |
| SHA-256 | `ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5` |
| SHA3-384 | `6b0a8fd332e2b83f4adc7074fd2ee42273fa4c7abda127379ebee555a9489f60b82742b33e2611fa3e6164c86023f8fb` |
| TLSH | `T12B261973A49154E4C2EED574C6256213BEE0389B273423DB7BD066E11B7AFE49A78330` |
| SSDEEP | `49152:c8nxDgC7g9rb/TBvO90dL3BmAFd4A64nsfJ7QQzjFHWkMNRCdQqzB0dSyG2VjMQX:cqYUQuVDt0TZEE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_ce37bbea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5"
    family = "unknown"
    file_name = "ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5"
    file_type = "elf"
    first_seen = "2026-08-05 21:30:17"
  condition:
    hash.sha256(0, filesize) == "ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5"
}
```

### Sample 94: `5bab10c1591c7266`

| Field | Value |
|---|---|
| SHA-256 | `5bab10c1591c7266cbfc42b0e40ee060ba34ad4cf5cfd0d7a1913516c836953c` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 20:42:59` |
| Reporter | `Bitsight` |
| Tags | `2f719eee4e212aa5bc8ebe9ac849895d, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c336f724d3da4b821c3fa6a69f92746` |
| SHA-1 | `0e137764acb0ad25066d4222b37a45eca5b66515` |
| SHA-256 | `5bab10c1591c7266cbfc42b0e40ee060ba34ad4cf5cfd0d7a1913516c836953c` |
| SHA3-384 | `a103ede9962c8e1113f62b6faec97d8646eded9f8eb8326f2befa6b99fcad840add1e9352f42dc91794584b63596f18c` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T19D3633A6ADC295B1C047C3F8442354AEB33A7B91CAA07D56779E79888E37F06603D7D0` |
| SSDEEP | `98304:GAJdY+0Ll6TK09RUIFr3psguiYdHIC2vPF2C8enAkbBI+G+vmhCU:drY+0LEe0//Fr3psgWiF58enLw+v` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_094_5bab10c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bab10c1591c7266cbfc42b0e40ee060ba34ad4cf5cfd0d7a1913516c836953c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:59"
  condition:
    hash.sha256(0, filesize) == "5bab10c1591c7266cbfc42b0e40ee060ba34ad4cf5cfd0d7a1913516c836953c"
}
```

### Sample 95: `b8c1c8f9c34a33e8`

| Field | Value |
|---|---|
| SHA-256 | `b8c1c8f9c34a33e84930fbaf8a3d52954420bc000f01ea45d48ffdfe108b0c60` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 20:42:30` |
| Reporter | `Bitsight` |
| Tags | `2f719eee4e212aa5bc8ebe9ac849895d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a567eff6cb3448293a25eaf0970a44e3` |
| SHA-1 | `8ce1e4e500f7fa25ec48332023b2aa0ff789327f` |
| SHA-256 | `b8c1c8f9c34a33e84930fbaf8a3d52954420bc000f01ea45d48ffdfe108b0c60` |
| SHA3-384 | `9b1505147236d3fcea016706cc15f54eb972d6531e858ab3bccde580e41d19520b2de48c4dd177c8bc5b123d336e9b67` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1B8D52285B8F61EB5D836C3B29D83E0BDB129775496658D1B37CD66008CA38987C393BC` |
| SSDEEP | `49152:Qf7mZlyW3Yy5/pU+G2mDQUjiL/jq1JBHKz8ce2T4CvuD18NoCkN+3iN:QTmZr5/pU72mDLGO1JtWs8oGoVw3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_b8c1c8f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8c1c8f9c34a33e84930fbaf8a3d52954420bc000f01ea45d48ffdfe108b0c60"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:30"
  condition:
    hash.sha256(0, filesize) == "b8c1c8f9c34a33e84930fbaf8a3d52954420bc000f01ea45d48ffdfe108b0c60"
}
```

### Sample 96: `75ae5ef8c6db196c`

| Field | Value |
|---|---|
| SHA-256 | `75ae5ef8c6db196c5545ceaa4dc1ac3f916d50b18d5ff73f16a5e3e3cd500a44` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 20:42:20` |
| Reporter | `Bitsight` |
| Tags | `2f719eee4e212aa5bc8ebe9ac849895d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21fe9cbf8be67ea36a21466534446006` |
| SHA-1 | `a678c2c06d2182650d86ec45941a1733e060404e` |
| SHA-256 | `75ae5ef8c6db196c5545ceaa4dc1ac3f916d50b18d5ff73f16a5e3e3cd500a44` |
| SHA3-384 | `2e6ea808fdc9a7787b29521da7c687f512dbb76b61db5a69dfce98a0bd7a30faf09bb1aa5f57fd37fac33ffc85b055eb` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T1CBD5238D7C967276E033C3B392A324ED712E379A8B71AE8E32C85B505D125186C7735E` |
| SSDEEP | `49152:4JQ8eh3uXGoU9FmH3GnUankQxieuLsUzbRShR0DKhXre1ysB/VsGoanVB:Aeh3uXGoUu2n/BuJzbRm0WdsLvn` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_75ae5ef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75ae5ef8c6db196c5545ceaa4dc1ac3f916d50b18d5ff73f16a5e3e3cd500a44"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:20"
  condition:
    hash.sha256(0, filesize) == "75ae5ef8c6db196c5545ceaa4dc1ac3f916d50b18d5ff73f16a5e3e3cd500a44"
}
```

### Sample 97: `05f9271f2618d599`

| Field | Value |
|---|---|
| SHA-256 | `05f9271f2618d599d2e263d8f4aa761a77ed1178369ba59403a72b412ceb10bc` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 20:42:11` |
| Reporter | `Bitsight` |
| Tags | `2f719eee4e212aa5bc8ebe9ac849895d, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `be9bc966e9e7feb9a2d56869683cd71c` |
| SHA-1 | `ea3902ee3b17552b713b95f4d7450ccaf338849f` |
| SHA-256 | `05f9271f2618d599d2e263d8f4aa761a77ed1178369ba59403a72b412ceb10bc` |
| SHA3-384 | `3f3d0b81402a151d31c975f30c04f44de95e872c757288813d2e4ff92dac8d0372af577b1c34ca9092ca1f7d884e1436` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T11BD52395B9F21AB4D837C7B68F93F02CB02A3B5597B18D5BF68CA8500E53104993737A` |
| SSDEEP | `49152:Vbz6aLOg/gk/oLWlHhBr4y/NZiKYKrvh62KUAVh9PxuL99npM0W:VWfg/f0cB1XbvVKzVNurnR` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_097_05f9271f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05f9271f2618d599d2e263d8f4aa761a77ed1178369ba59403a72b412ceb10bc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:11"
  condition:
    hash.sha256(0, filesize) == "05f9271f2618d599d2e263d8f4aa761a77ed1178369ba59403a72b412ceb10bc"
}
```

### Sample 98: `4135a4f52eb88adb`

| Field | Value |
|---|---|
| SHA-256 | `4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-08-05 20:40:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `22bee70986e4966a5e009facebcccf71` |
| SHA-1 | `cf9ead45a7574faaf6aa9c4e19872b955c3f3dba` |
| SHA-256 | `4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5` |
| SHA3-384 | `9b4d73b871f18d8441c9a387fde0483a8b85e2dad44f7717bf942ee098fd95d89e61e8f6b212d6c9e30397698b4fdaa4` |
| TLSH | `T18CA36C40FA83D1F1F85705700167E75A8B34ED398024DB4AEB593E35ECB5B068A6B7AC` |
| SSDEEP | `3072:IZFJEggNaoTcad8yzmzhEL9Z9Wa1YTDGNg:IZ/gNavEL5/oGm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_4135a4f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-05 20:40:47"
  condition:
    hash.sha256(0, filesize) == "4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5"
}
```

### Sample 99: `ed23e0d5d55c1299`

| Field | Value |
|---|---|
| SHA-256 | `ed23e0d5d55c12998aea2e4d065726301cb02257f4c9435758368fb94c7881c9` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-08-05 20:35:15` |
| Reporter | `Bitsight` |
| Tags | `54e64e, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce643c8ff7f688a91f69f150ff8a8c9f` |
| SHA-1 | `ec3f15706a546a1431fd2dde042f9cc562722382` |
| SHA-256 | `ed23e0d5d55c12998aea2e4d065726301cb02257f4c9435758368fb94c7881c9` |
| SHA3-384 | `37768ef94a8fbbaa5f79285c101789d538e7aa343b9667b9b4f964eb65a116a6981fb281b06fb7f495e41c1ab1b14f15` |
| IMPHASH | `d1c35276ff2b8e9d448afb940bccb1f0` |
| TLSH | `T111144B5BD4D540EDEC1AC638899AE237A4B2FC5A1936BA4F2BA0DF151B50B30B71DF04` |
| SSDEEP | `3072:GcktfAkaT19iAPkAMf89JFqTvurOX/yrfjqbplmYhle5x73k7g9/c:lD5M09JFqTma/y7ub3e5Nkg9/` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_ed23e0d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed23e0d5d55c12998aea2e4d065726301cb02257f4c9435758368fb94c7881c9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:35:15"
  condition:
    hash.sha256(0, filesize) == "ed23e0d5d55c12998aea2e4d065726301cb02257f4c9435758368fb94c7881c9"
}
```

### Sample 100: `73954ad21e67eef9`

| Field | Value |
|---|---|
| SHA-256 | `73954ad21e67eef91256bc65f3b2b88ca6d20ca45cf0918247ade9a4d7bab694` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-08-05 20:25:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `269d6af241149e64faa5ad184fac16bf` |
| SHA-1 | `07fa63293460724bc38a3075ce88bbfa9212d93d` |
| SHA-256 | `73954ad21e67eef91256bc65f3b2b88ca6d20ca45cf0918247ade9a4d7bab694` |
| SHA3-384 | `00fc93705f43fdfea114606ec1491a2fee06dd47b3846ae38d80c2fd45210efdec2663f08ed86f4220b3536f0c87a399` |
| TLSH | `T1C6C37E98D60F9D81D2C3E6BDAD190EB371363CB84664C3B25A00536DE8EDED68C62573` |
| SSDEEP | `1536:weeedOxJ94TWQwnX7DXOqrVbXAVPk7Coh4DPCw4SdJ5p+aIoo8L1KauVIr:1eyaQTWvH3rV0T91oaDDL1Km` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_73954ad2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73954ad21e67eef91256bc65f3b2b88ca6d20ca45cf0918247ade9a4d7bab694"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-05 20:25:37"
  condition:
    hash.sha256(0, filesize) == "73954ad21e67eef91256bc65f3b2b88ca6d20ca45cf0918247ade9a4d7bab694"
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
 * Generated: 2026-08-06T03:44:45.796106+00:00
 */

rule MalwareBazaar_Mirai_001_c70bd410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c70bd410fd31eb06bac8978b0b2ee3bf9132cce5db023a64f3bbcfb96a291680"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 03:03:44"
  condition:
    hash.sha256(0, filesize) == "c70bd410fd31eb06bac8978b0b2ee3bf9132cce5db023a64f3bbcfb96a291680"
}

rule MalwareBazaar_Mirai_002_d1ffb7ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1ffb7ec3dcaec3400d22859583a961ba661a78089a561b9092b455e017788f7"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 03:02:55"
  condition:
    hash.sha256(0, filesize) == "d1ffb7ec3dcaec3400d22859583a961ba661a78089a561b9092b455e017788f7"
}

rule MalwareBazaar_GuLoader_003_79a184c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "79a184c05789e4479d16d15a22206de124b2102b861dc4ba050c2aacb3ef834e"
    family = "GuLoader"
    file_name = "rDetalle_Visita_I_137894350961234.exe"
    file_type = "exe"
    first_seen = "2026-08-06 03:01:13"
  condition:
    hash.sha256(0, filesize) == "79a184c05789e4479d16d15a22206de124b2102b861dc4ba050c2aacb3ef834e"
}

rule MalwareBazaar_ValleyRAT_004_6fcc6366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fcc636637d758b1068ebcff7363ab4aefa39b93e278dbea825eebeb8a9357e2"
    family = "ValleyRAT"
    file_name = "setup_r8013.exe"
    file_type = "exe"
    first_seen = "2026-08-06 02:57:51"
  condition:
    hash.sha256(0, filesize) == "6fcc636637d758b1068ebcff7363ab4aefa39b93e278dbea825eebeb8a9357e2"
}

rule MalwareBazaar_unknown_005_f6be87cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6be87cd9afeab65ef6ce2652f506ecaf228a705d3a22843e4eca96997f1dcf3"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:53:39"
  condition:
    hash.sha256(0, filesize) == "f6be87cd9afeab65ef6ce2652f506ecaf228a705d3a22843e4eca96997f1dcf3"
}

rule MalwareBazaar_Mirai_006_62885ef6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62885ef62f5ce8dbb0df9f8a8a9955f6badc1ff303d5b9c5b1338082f1c5b5f5"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:50:45"
  condition:
    hash.sha256(0, filesize) == "62885ef62f5ce8dbb0df9f8a8a9955f6badc1ff303d5b9c5b1338082f1c5b5f5"
}

rule MalwareBazaar_Mirai_007_791be1e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "791be1e6f2839b929c5c6e65cfed9f27d16789e36443dfdc852051ceb53b5745"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-06 02:50:42"
  condition:
    hash.sha256(0, filesize) == "791be1e6f2839b929c5c6e65cfed9f27d16789e36443dfdc852051ceb53b5745"
}

rule MalwareBazaar_Mirai_008_3f515f90
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f515f90d48f8900a449406a4bd176eac3731e9a203334af516b9add6a9ca7cc"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:48:38"
  condition:
    hash.sha256(0, filesize) == "3f515f90d48f8900a449406a4bd176eac3731e9a203334af516b9add6a9ca7cc"
}

rule MalwareBazaar_unknown_009_520e8e29
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "520e8e29ace68efc7f636e4b9722c663e4c81a152db1f3370eb13f889636f5a6"
    family = "unknown"
    file_name = "MT_LADY_YASSO_VSL_BRIEF_DETAILSpdf.js"
    file_type = "js"
    first_seen = "2026-08-06 02:48:36"
  condition:
    hash.sha256(0, filesize) == "520e8e29ace68efc7f636e4b9722c663e4c81a152db1f3370eb13f889636f5a6"
}

rule MalwareBazaar_Mirai_010_00b0dee9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00b0dee9cc3cb281e4a53c33fa91b41d86004fb486b6af52ab809adcc74505d8"
    family = "Mirai"
    file_name = "boatnet.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:47:49"
  condition:
    hash.sha256(0, filesize) == "00b0dee9cc3cb281e4a53c33fa91b41d86004fb486b6af52ab809adcc74505d8"
}

rule MalwareBazaar_unknown_011_189af4f4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "189af4f4616bc74e5aa2e39dcd8d33c668cd792ff84bbe63adaa57fbfc448294"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:44:40"
  condition:
    hash.sha256(0, filesize) == "189af4f4616bc74e5aa2e39dcd8d33c668cd792ff84bbe63adaa57fbfc448294"
}

rule MalwareBazaar_Mirai_012_ffb0668a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ffb0668a571ad16e671d71ee480fa292e94357c6cfc794dfa38be1a37779e431"
    family = "Mirai"
    file_name = "killbotx.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 02:44:38"
  condition:
    hash.sha256(0, filesize) == "ffb0668a571ad16e671d71ee480fa292e94357c6cfc794dfa38be1a37779e431"
}

rule MalwareBazaar_Mirai_013_1c246410
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c246410593a1d5bc31cf4d58c6905df5e30fa7948c23e82ed424d6c9e2198ec"
    family = "Mirai"
    file_name = "killbotx.mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 02:39:40"
  condition:
    hash.sha256(0, filesize) == "1c246410593a1d5bc31cf4d58c6905df5e30fa7948c23e82ed424d6c9e2198ec"
}

rule MalwareBazaar_Mirai_014_07310b71
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b"
    family = "Mirai"
    file_name = "killbotx.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 02:39:37"
  condition:
    hash.sha256(0, filesize) == "07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b"
}

rule MalwareBazaar_Mirai_015_5dc7cef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5dc7cef8a389cbd45cef863b10f2657e471101c1b4db34acba289b33066886ed"
    family = "Mirai"
    file_name = "killbotx.mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 02:38:37"
  condition:
    hash.sha256(0, filesize) == "5dc7cef8a389cbd45cef863b10f2657e471101c1b4db34acba289b33066886ed"
}

rule MalwareBazaar_Mirai_016_ea7244d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ea7244d77c73627733522c2658ccd158cd91d6505aaefbd83ed12259811324c0"
    family = "Mirai"
    file_name = "killbotx.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 02:38:36"
  condition:
    hash.sha256(0, filesize) == "ea7244d77c73627733522c2658ccd158cd91d6505aaefbd83ed12259811324c0"
}

rule MalwareBazaar_Mirai_017_716119c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "716119c3bdd05a5a7d6d1033418919561030038081dc5f79ffc8bda6ca002923"
    family = "Mirai"
    file_name = "boatnet.i486"
    file_type = "elf"
    first_seen = "2026-08-06 02:36:38"
  condition:
    hash.sha256(0, filesize) == "716119c3bdd05a5a7d6d1033418919561030038081dc5f79ffc8bda6ca002923"
}

rule MalwareBazaar_Mirai_018_27f06e0d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "27f06e0d5c08b66a9c3ae1ca7c0629d8e20f9489bf4e1463481b6c9d5fdb27ee"
    family = "Mirai"
    file_name = "boatnet.i486"
    file_type = "elf"
    first_seen = "2026-08-06 02:35:40"
  condition:
    hash.sha256(0, filesize) == "27f06e0d5c08b66a9c3ae1ca7c0629d8e20f9489bf4e1463481b6c9d5fdb27ee"
}

rule MalwareBazaar_CoinMiner_019_2ed02943
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ed02943cd801954de9d92a66eab12cb718ffe57a3e0f3df95103a72d181f879"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:36"
  condition:
    hash.sha256(0, filesize) == "2ed02943cd801954de9d92a66eab12cb718ffe57a3e0f3df95103a72d181f879"
}

rule MalwareBazaar_unknown_020_2e747f61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e747f610c9295132aa6e2827b4dca7656869eea15b6cad5b0a4aa61c37413a2"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:24"
  condition:
    hash.sha256(0, filesize) == "2e747f610c9295132aa6e2827b4dca7656869eea15b6cad5b0a4aa61c37413a2"
}

rule MalwareBazaar_unknown_021_d6d7444a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d6d7444a1d99ffa5f99e0ad5d41c69916e67b57fa005a785b338160b15eb90bf"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:17"
  condition:
    hash.sha256(0, filesize) == "d6d7444a1d99ffa5f99e0ad5d41c69916e67b57fa005a785b338160b15eb90bf"
}

rule MalwareBazaar_unknown_022_b133af2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b133af2fc6335073a8742691d536e97409b04c59c23b2440b26b23da66c76b81"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 02:33:10"
  condition:
    hash.sha256(0, filesize) == "b133af2fc6335073a8742691d536e97409b04c59c23b2440b26b23da66c76b81"
}

rule MalwareBazaar_unknown_023_5015daf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5015daf6cd5f8b73685b91536a69ed646a510ed97bd70d9bf2c661f501bdc42f"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:26:42"
  condition:
    hash.sha256(0, filesize) == "5015daf6cd5f8b73685b91536a69ed646a510ed97bd70d9bf2c661f501bdc42f"
}

rule MalwareBazaar_Mirai_024_c208a7a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c208a7a095ef6247c309165af0230c0ef8ab9709bd362b29258cff68f58f839d"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 02:21:38"
  condition:
    hash.sha256(0, filesize) == "c208a7a095ef6247c309165af0230c0ef8ab9709bd362b29258cff68f58f839d"
}

rule MalwareBazaar_Mirai_025_3d647fcb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d647fcb1c48da7a95c0bc500da45c150f00ddd7871e90297d2f79f38286ada3"
    family = "Mirai"
    file_name = "killbotx.mips"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:52"
  condition:
    hash.sha256(0, filesize) == "3d647fcb1c48da7a95c0bc500da45c150f00ddd7871e90297d2f79f38286ada3"
}

rule MalwareBazaar_Mirai_026_b26ce9d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b26ce9d2b84da259a16cff2788c9d36011f60f4fcfaf08a2a736490db92e4949"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:41"
  condition:
    hash.sha256(0, filesize) == "b26ce9d2b84da259a16cff2788c9d36011f60f4fcfaf08a2a736490db92e4949"
}

rule MalwareBazaar_unknown_027_23cb10bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25"
    family = "unknown"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:39"
  condition:
    hash.sha256(0, filesize) == "23cb10bd16bcc36e97e538e6d6d7271cbed14e49f535dc535c2c4859dbd56c25"
}

rule MalwareBazaar_Mirai_028_024ee12e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "024ee12e5b892c7bbb2baa1376f8b85c7c382e0c513071d0ed54b1187da73584"
    family = "Mirai"
    file_name = "killbotx.mips"
    file_type = "elf"
    first_seen = "2026-08-06 02:20:37"
  condition:
    hash.sha256(0, filesize) == "024ee12e5b892c7bbb2baa1376f8b85c7c382e0c513071d0ed54b1187da73584"
}

rule MalwareBazaar_Mirai_029_b913aed0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b913aed0a412dc14e3bd5570f8aa0bc2c04fdba0ab04a885e2b24638d25f2553"
    family = "Mirai"
    file_name = "killbotx.arm4"
    file_type = "elf"
    first_seen = "2026-08-06 02:11:40"
  condition:
    hash.sha256(0, filesize) == "b913aed0a412dc14e3bd5570f8aa0bc2c04fdba0ab04a885e2b24638d25f2553"
}

rule MalwareBazaar_Mirai_030_dd60f1a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd60f1a53de66a16846e426f6972a17ce668eb7b6586c846dccdfa04e01e313e"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 02:09:25"
  condition:
    hash.sha256(0, filesize) == "dd60f1a53de66a16846e426f6972a17ce668eb7b6586c846dccdfa04e01e313e"
}

rule MalwareBazaar_unknown_031_71b77cc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c"
    family = "unknown"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-06 02:08:42"
  condition:
    hash.sha256(0, filesize) == "71b77cc8813142f076b260e70f5ac5979f6ddd620f9705eb0f3b8db5012dbb8c"
}

rule MalwareBazaar_Mirai_032_f819a2a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f819a2a054b85e6d4d85cd5df2fa6682630f6afd4b7abeac159980b0e98452d4"
    family = "Mirai"
    file_name = "boatnet.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 02:08:40"
  condition:
    hash.sha256(0, filesize) == "f819a2a054b85e6d4d85cd5df2fa6682630f6afd4b7abeac159980b0e98452d4"
}

rule MalwareBazaar_Mirai_033_3f856bcf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3f856bcfb0f007e94896433d134d16b22b653745d26a5c7d14bd9e9d9b1eb068"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 02:06:32"
  condition:
    hash.sha256(0, filesize) == "3f856bcfb0f007e94896433d134d16b22b653745d26a5c7d14bd9e9d9b1eb068"
}

rule MalwareBazaar_Mirai_034_4b53589a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b53589aa2d15bbd5e723d2ec61a9453edcd3dfd5d82cee356c5388f7d37aadd"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 02:05:45"
  condition:
    hash.sha256(0, filesize) == "4b53589aa2d15bbd5e723d2ec61a9453edcd3dfd5d82cee356c5388f7d37aadd"
}

rule MalwareBazaar_unknown_035_707e7528
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "707e752878d6f836c80cee34643e99a676c1c6885d9b7443709528d9633c0f23"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-08-06 02:02:44"
  condition:
    hash.sha256(0, filesize) == "707e752878d6f836c80cee34643e99a676c1c6885d9b7443709528d9633c0f23"
}

rule MalwareBazaar_Mirai_036_00c19ed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00c19ed8f175ed2d4ac9381b892bd96a403e9d823a6f7d89a312c678b54a4b13"
    family = "Mirai"
    file_name = "boatnet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 02:01:12"
  condition:
    hash.sha256(0, filesize) == "00c19ed8f175ed2d4ac9381b892bd96a403e9d823a6f7d89a312c678b54a4b13"
}

rule MalwareBazaar_Mirai_037_aa313a14
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa313a14c9387d8dbcb098ae6c056f2fa58e6cefda798a0abef2742471f1ccf8"
    family = "Mirai"
    file_name = "boatnet.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 01:59:33"
  condition:
    hash.sha256(0, filesize) == "aa313a14c9387d8dbcb098ae6c056f2fa58e6cefda798a0abef2742471f1ccf8"
}

rule MalwareBazaar_Mirai_038_901ac5e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "901ac5e8541d5f7e2ea51a635bcb33d7c12ae809c2f75edb63622d9004dbbde0"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:54:38"
  condition:
    hash.sha256(0, filesize) == "901ac5e8541d5f7e2ea51a635bcb33d7c12ae809c2f75edb63622d9004dbbde0"
}

rule MalwareBazaar_Mirai_039_6fe059ee
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6fe059ee63705b742a2a3b3db9e81e6158c84d66dfe3f01dcd5ead853ed1c180"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:53:35"
  condition:
    hash.sha256(0, filesize) == "6fe059ee63705b742a2a3b3db9e81e6158c84d66dfe3f01dcd5ead853ed1c180"
}

rule MalwareBazaar_Mirai_040_306a43e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "306a43e268d005d7491b1c472d3f13e66ca5551cb5714b5a48f54830f15ad0d9"
    family = "Mirai"
    file_name = "boatnet.m68k"
    file_type = "elf"
    first_seen = "2026-08-06 01:53:32"
  condition:
    hash.sha256(0, filesize) == "306a43e268d005d7491b1c472d3f13e66ca5551cb5714b5a48f54830f15ad0d9"
}

rule MalwareBazaar_Mirai_041_e47771be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e47771be0dfb7637a11ab8fdce4bb71593ac3fe4e753e14522450c9cf52839b1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:50:34"
  condition:
    hash.sha256(0, filesize) == "e47771be0dfb7637a11ab8fdce4bb71593ac3fe4e753e14522450c9cf52839b1"
}

rule MalwareBazaar_Mirai_042_957e67f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "957e67f204d9e9254e4750bf73cc7bc1ec551f1a0536d586df76902b5dab0726"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 01:45:32"
  condition:
    hash.sha256(0, filesize) == "957e67f204d9e9254e4750bf73cc7bc1ec551f1a0536d586df76902b5dab0726"
}

rule MalwareBazaar_Mirai_043_41823995
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "418239951e671967784688d121cd66a63a1c9896633038453be3afff2393ecd0"
    family = "Mirai"
    file_name = "boatnet.x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:44:34"
  condition:
    hash.sha256(0, filesize) == "418239951e671967784688d121cd66a63a1c9896633038453be3afff2393ecd0"
}

rule MalwareBazaar_Mirai_044_70beea3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70beea3dbd4deaa71bff2d2da10b30f1617abb1167922aa88ae96da064027de8"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-08-06 01:44:32"
  condition:
    hash.sha256(0, filesize) == "70beea3dbd4deaa71bff2d2da10b30f1617abb1167922aa88ae96da064027de8"
}

rule MalwareBazaar_Mirai_045_db444503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db444503cda9f6734797db51f8b159802634cdace744431867741475203c8755"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 01:36:33"
  condition:
    hash.sha256(0, filesize) == "db444503cda9f6734797db51f8b159802634cdace744431867741475203c8755"
}

rule MalwareBazaar_Mirai_046_a56ec538
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a56ec538bb6c72b724cce88be69161b418fdc0f6ee41413400a388568daf154f"
    family = "Mirai"
    file_name = "putita.m68k"
    file_type = "elf"
    first_seen = "2026-08-06 01:30:34"
  condition:
    hash.sha256(0, filesize) == "a56ec538bb6c72b724cce88be69161b418fdc0f6ee41413400a388568daf154f"
}

rule MalwareBazaar_Mirai_047_b52b605b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b52b605b22e497caa6930b9cc46dff2be18eaf63dcf7c2226906dfc5114f2b49"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:28:42"
  condition:
    hash.sha256(0, filesize) == "b52b605b22e497caa6930b9cc46dff2be18eaf63dcf7c2226906dfc5114f2b49"
}

rule MalwareBazaar_Mirai_048_97a04076
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97a04076d3b1d8845c64d8087f6b879def4560566e2376372d728529dc837cfd"
    family = "Mirai"
    file_name = "putita.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:27:47"
  condition:
    hash.sha256(0, filesize) == "97a04076d3b1d8845c64d8087f6b879def4560566e2376372d728529dc837cfd"
}

rule MalwareBazaar_Mirai_049_a79c0699
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a79c069996a02e251222db1ca25b83a07741436a98809b0315341271403ab0b9"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:27:02"
  condition:
    hash.sha256(0, filesize) == "a79c069996a02e251222db1ca25b83a07741436a98809b0315341271403ab0b9"
}

rule MalwareBazaar_Mirai_050_424b4e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "424b4e38d6f73cc6f7c45b03d604e0d921ac815dfb88e0e492a15a4fe535d9f3"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:26:56"
  condition:
    hash.sha256(0, filesize) == "424b4e38d6f73cc6f7c45b03d604e0d921ac815dfb88e0e492a15a4fe535d9f3"
}

rule MalwareBazaar_Mirai_051_7bbd6d4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7bbd6d4cf4bb82ee90515cc745379bfb2d73ba8d9d92c839896023b6386f9c04"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 01:26:51"
  condition:
    hash.sha256(0, filesize) == "7bbd6d4cf4bb82ee90515cc745379bfb2d73ba8d9d92c839896023b6386f9c04"
}

rule MalwareBazaar_Mirai_052_3233d512
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3233d5128b3453c621d31df5c3d1ce4525318068224c0ab37c609a72884c3f15"
    family = "Mirai"
    file_name = "putita.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:45"
  condition:
    hash.sha256(0, filesize) == "3233d5128b3453c621d31df5c3d1ce4525318068224c0ab37c609a72884c3f15"
}

rule MalwareBazaar_Mirai_053_863709a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863709a3b2ad698aee58280f46803d17f4d2850536e860eece547eb874103325"
    family = "Mirai"
    file_name = "arm4"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:43"
  condition:
    hash.sha256(0, filesize) == "863709a3b2ad698aee58280f46803d17f4d2850536e860eece547eb874103325"
}

rule MalwareBazaar_Mirai_054_57255dd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57255dd221323efff68cb3f00710edc4a6b404eb0561e49fa03d2b2b1dc1639e"
    family = "Mirai"
    file_name = "putita.x86"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:41"
  condition:
    hash.sha256(0, filesize) == "57255dd221323efff68cb3f00710edc4a6b404eb0561e49fa03d2b2b1dc1639e"
}

rule MalwareBazaar_Mirai_055_3091e5d6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3091e5d6c4d7b71b15bc46b3a7ee6327e9cc1c8b554aedb10bcf0f7986eef4be"
    family = "Mirai"
    file_name = "putita.ppc"
    file_type = "elf"
    first_seen = "2026-08-06 01:24:39"
  condition:
    hash.sha256(0, filesize) == "3091e5d6c4d7b71b15bc46b3a7ee6327e9cc1c8b554aedb10bcf0f7986eef4be"
}

rule MalwareBazaar_Mirai_056_bb0cf0b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bb0cf0b3a99ce7331be0143e7a535bdcc5e881e6e64c39d256cf1f02fb620158"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:22:43"
  condition:
    hash.sha256(0, filesize) == "bb0cf0b3a99ce7331be0143e7a535bdcc5e881e6e64c39d256cf1f02fb620158"
}

rule MalwareBazaar_Mirai_057_a962a71c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a962a71c3da3b8d67c97d0d3db1ef7548998640eb55564830986398376f31e40"
    family = "Mirai"
    file_name = "boatnet.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:21:34"
  condition:
    hash.sha256(0, filesize) == "a962a71c3da3b8d67c97d0d3db1ef7548998640eb55564830986398376f31e40"
}

rule MalwareBazaar_Mirai_058_d44a14c3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d44a14c3cf5307a005c7831bee40fdbdffdb78dd9196d3265e032c4f433d3069"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-06 01:16:01"
  condition:
    hash.sha256(0, filesize) == "d44a14c3cf5307a005c7831bee40fdbdffdb78dd9196d3265e032c4f433d3069"
}

rule MalwareBazaar_Mirai_059_049768ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "049768ce81f1310f8bab20dc015e9dc515c390e53ad3479858292c4f68fdc3f6"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-06 01:15:31"
  condition:
    hash.sha256(0, filesize) == "049768ce81f1310f8bab20dc015e9dc515c390e53ad3479858292c4f68fdc3f6"
}

rule MalwareBazaar_Mirai_060_8c03d205
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8c03d205d6000645c309fe41b7d7e4d4a91b3570d98a22036f60a47993a2c6b7"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:13:45"
  condition:
    hash.sha256(0, filesize) == "8c03d205d6000645c309fe41b7d7e4d4a91b3570d98a22036f60a47993a2c6b7"
}

rule MalwareBazaar_Mirai_061_e312d125
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e312d125a54f6b144a024d7440d5f403cf75209a730de2646513e888dc713abf"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-06 01:13:42"
  condition:
    hash.sha256(0, filesize) == "e312d125a54f6b144a024d7440d5f403cf75209a730de2646513e888dc713abf"
}

rule MalwareBazaar_Mirai_062_3d3cdd80
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3d3cdd80cc4ef5e23c5ad9c86732ab8861ab2a4d931239040e54c3d410ff7c6d"
    family = "Mirai"
    file_name = "boatnet.i686"
    file_type = "elf"
    first_seen = "2026-08-06 01:13:38"
  condition:
    hash.sha256(0, filesize) == "3d3cdd80cc4ef5e23c5ad9c86732ab8861ab2a4d931239040e54c3d410ff7c6d"
}

rule MalwareBazaar_unknown_063_d83ef44a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d83ef44a44e68fd1bed4e81209c4f62913bca52f60c245f127527ff6757cdffe"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-06 01:13:02"
  condition:
    hash.sha256(0, filesize) == "d83ef44a44e68fd1bed4e81209c4f62913bca52f60c245f127527ff6757cdffe"
}

rule MalwareBazaar_Mirai_064_4e70361a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e70361a2c27d7da8185766187b3757e1fa966f4e0b1e370886d66481121e5e8"
    family = "Mirai"
    file_name = "boatnet.arm5"
    file_type = "elf"
    first_seen = "2026-08-06 01:12:36"
  condition:
    hash.sha256(0, filesize) == "4e70361a2c27d7da8185766187b3757e1fa966f4e0b1e370886d66481121e5e8"
}

rule MalwareBazaar_Mirai_065_6abb06e9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6abb06e956ce2bfa05920c0c13857ec6aa11ef2810e017d5d44f51b018170d10"
    family = "Mirai"
    file_name = "putita.mipsrouter"
    file_type = "elf"
    first_seen = "2026-08-06 01:12:34"
  condition:
    hash.sha256(0, filesize) == "6abb06e956ce2bfa05920c0c13857ec6aa11ef2810e017d5d44f51b018170d10"
}

rule MalwareBazaar_Mirai_066_d2ee4c98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2ee4c98c10d1d6b51792f0cd7afb69de916dd33db6c635e61e4cdff715aabe5"
    family = "Mirai"
    file_name = "boatnet.i686"
    file_type = "elf"
    first_seen = "2026-08-06 01:12:32"
  condition:
    hash.sha256(0, filesize) == "d2ee4c98c10d1d6b51792f0cd7afb69de916dd33db6c635e61e4cdff715aabe5"
}

rule MalwareBazaar_Mirai_067_9f53c9c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f53c9c4daf662aca794c22b08cedfed2634acc40f5d6b9c89728462c63be3af"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:11:01"
  condition:
    hash.sha256(0, filesize) == "9f53c9c4daf662aca794c22b08cedfed2634acc40f5d6b9c89728462c63be3af"
}

rule MalwareBazaar_Mirai_068_2910c598
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2910c598d1658ee0193b3001fe15137ca62be3a312efd76c134904c5c6abb345"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 01:10:57"
  condition:
    hash.sha256(0, filesize) == "2910c598d1658ee0193b3001fe15137ca62be3a312efd76c134904c5c6abb345"
}

rule MalwareBazaar_Mirai_069_6be33d68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6be33d68a77ca5185614457fbbc16fb0e877b8e17760be7277c8327cc4e23bb6"
    family = "Mirai"
    file_name = "putita.arm6"
    file_type = "elf"
    first_seen = "2026-08-06 01:09:39"
  condition:
    hash.sha256(0, filesize) == "6be33d68a77ca5185614457fbbc16fb0e877b8e17760be7277c8327cc4e23bb6"
}

rule MalwareBazaar_Mirai_070_a916b916
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a916b91671fbecdd5d92285b3911228d49785bfc9c740305f8bb040e3b1a3ddb"
    family = "Mirai"
    file_name = "putita.arm7"
    file_type = "elf"
    first_seen = "2026-08-06 01:09:36"
  condition:
    hash.sha256(0, filesize) == "a916b91671fbecdd5d92285b3911228d49785bfc9c740305f8bb040e3b1a3ddb"
}

rule MalwareBazaar_Mirai_071_e2aef395
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2aef39546ce27325e44a7e386a875133484251a8b115074038103ac6235e2e7"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 01:07:41"
  condition:
    hash.sha256(0, filesize) == "e2aef39546ce27325e44a7e386a875133484251a8b115074038103ac6235e2e7"
}

rule MalwareBazaar_Mirai_072_90635095
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "90635095f7edc189533d696d5af6edd85024dd2438bd7741fada4e7ee94a7e2b"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:07:38"
  condition:
    hash.sha256(0, filesize) == "90635095f7edc189533d696d5af6edd85024dd2438bd7741fada4e7ee94a7e2b"
}

rule MalwareBazaar_Mirai_073_c092a870
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c092a870c7d18acedda48fdc36c4169770f0aea76be5f20d3d8ce5f3c2de2af2"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 01:06:42"
  condition:
    hash.sha256(0, filesize) == "c092a870c7d18acedda48fdc36c4169770f0aea76be5f20d3d8ce5f3c2de2af2"
}

rule MalwareBazaar_Mirai_074_96f7c5a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "96f7c5a4774691e2397617d90eeb27eddb0dd5b2b5b5ab44167ac948d135bbc9"
    family = "Mirai"
    file_name = "boatnet.mips"
    file_type = "elf"
    first_seen = "2026-08-06 01:06:41"
  condition:
    hash.sha256(0, filesize) == "96f7c5a4774691e2397617d90eeb27eddb0dd5b2b5b5ab44167ac948d135bbc9"
}

rule MalwareBazaar_Mirai_075_db0b0357
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db0b0357054178961f2f9fbf1bec670cb1f84aae49537ed401bea4910c60b7db"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-06 01:04:36"
  condition:
    hash.sha256(0, filesize) == "db0b0357054178961f2f9fbf1bec670cb1f84aae49537ed401bea4910c60b7db"
}

rule MalwareBazaar_unknown_076_566e7e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f"
    family = "unknown"
    file_name = "k.sh"
    file_type = "sh"
    first_seen = "2026-08-06 01:03:45"
  condition:
    hash.sha256(0, filesize) == "566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f"
}

rule MalwareBazaar_Mirai_077_9e7ca695
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e7ca69553ed9649a52a8a4e35e6df16b37a17b32d9fcc96c9b22473b37ca48c"
    family = "Mirai"
    file_name = "boatnet.arm"
    file_type = "elf"
    first_seen = "2026-08-06 01:03:41"
  condition:
    hash.sha256(0, filesize) == "9e7ca69553ed9649a52a8a4e35e6df16b37a17b32d9fcc96c9b22473b37ca48c"
}

rule MalwareBazaar_Mirai_078_29248b98
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29248b98fe7b3e59919395e2f044d9c40a9a1eedf226f7bd2eb9d9067f4163e9"
    family = "Mirai"
    file_name = "boatnet.spc"
    file_type = "elf"
    first_seen = "2026-08-06 01:00:56"
  condition:
    hash.sha256(0, filesize) == "29248b98fe7b3e59919395e2f044d9c40a9a1eedf226f7bd2eb9d9067f4163e9"
}

rule MalwareBazaar_Mirai_079_c842cdf8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c842cdf88aa56522af9a7f74736445af07e8b6b1f4b43e9fd8063c8146655fb4"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:58:42"
  condition:
    hash.sha256(0, filesize) == "c842cdf88aa56522af9a7f74736445af07e8b6b1f4b43e9fd8063c8146655fb4"
}

rule MalwareBazaar_Mirai_080_84f81d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "84f81d78f84f045a4a26d5a2aa98a0a47442334f22903a43e2cf72528e064863"
    family = "Mirai"
    file_name = "boatnet.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:58:24"
  condition:
    hash.sha256(0, filesize) == "84f81d78f84f045a4a26d5a2aa98a0a47442334f22903a43e2cf72528e064863"
}

rule MalwareBazaar_unknown_081_ec4ae4bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec4ae4bf894da8529697d86f2956d49116192c7ab2eef8035c5196999d21cd71"
    family = "unknown"
    file_name = "composer.dat"
    file_type = "exe"
    first_seen = "2026-08-06 00:52:33"
  condition:
    hash.sha256(0, filesize) == "ec4ae4bf894da8529697d86f2956d49116192c7ab2eef8035c5196999d21cd71"
}

rule MalwareBazaar_Mirai_082_a524ccbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a524ccbc295bf3ac6c30a10b75007e8799487a5367e6a6542037c2e6dc1bd749"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 00:48:45"
  condition:
    hash.sha256(0, filesize) == "a524ccbc295bf3ac6c30a10b75007e8799487a5367e6a6542037c2e6dc1bd749"
}

rule MalwareBazaar_Mirai_083_17cfbd25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "17cfbd25034b29242d00aa52257b7edccae959cfc3cc8534d0515e5d4fadf165"
    family = "Mirai"
    file_name = "putita.x86_64"
    file_type = "elf"
    first_seen = "2026-08-06 00:47:40"
  condition:
    hash.sha256(0, filesize) == "17cfbd25034b29242d00aa52257b7edccae959cfc3cc8534d0515e5d4fadf165"
}

rule MalwareBazaar_ValleyRAT_084_3a81c926
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a81c926fdeb699cf8a4de9e037d6ffbe9041d22d7c9b0fa1ed36e6966dc4211"
    family = "ValleyRAT"
    file_name = "setup_r8010.exe"
    file_type = "exe"
    first_seen = "2026-08-06 00:45:18"
  condition:
    hash.sha256(0, filesize) == "3a81c926fdeb699cf8a4de9e037d6ffbe9041d22d7c9b0fa1ed36e6966dc4211"
}

rule MalwareBazaar_Mirai_085_1af0e291
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1af0e29181b7839de6d941ce7751a93832b5b07f891157972d8369888f8931bb"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:38:31"
  condition:
    hash.sha256(0, filesize) == "1af0e29181b7839de6d941ce7751a93832b5b07f891157972d8369888f8931bb"
}

rule MalwareBazaar_Mirai_086_30753a7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30753a7b23ebe62c5daa7ba3930c2aba7859b90070718eb82edada1ef01b4f8b"
    family = "Mirai"
    file_name = "putita.mpsl"
    file_type = "elf"
    first_seen = "2026-08-06 00:37:29"
  condition:
    hash.sha256(0, filesize) == "30753a7b23ebe62c5daa7ba3930c2aba7859b90070718eb82edada1ef01b4f8b"
}

rule MalwareBazaar_unknown_087_53fe10c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53fe10c9126473590e35a1fac360f48e815cd39ec48e3bf73baf350300dba3a4"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 23:54:40"
  condition:
    hash.sha256(0, filesize) == "53fe10c9126473590e35a1fac360f48e815cd39ec48e3bf73baf350300dba3a4"
}

rule MalwareBazaar_Mirai_088_7f2f9568
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f2f9568ed5c3a32cea5cfb11b09ebc1e3b011c5aec406ea77e268060ec8f318"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-05 23:40:36"
  condition:
    hash.sha256(0, filesize) == "7f2f9568ed5c3a32cea5cfb11b09ebc1e3b011c5aec406ea77e268060ec8f318"
}

rule MalwareBazaar_Mirai_089_e248d956
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e248d956f20e28773321e81afbe9ee0f53dd5882dc9dd738fb5a7c38e5105aa7"
    family = "Mirai"
    file_name = "putita.arm"
    file_type = "elf"
    first_seen = "2026-08-05 23:39:30"
  condition:
    hash.sha256(0, filesize) == "e248d956f20e28773321e81afbe9ee0f53dd5882dc9dd738fb5a7c38e5105aa7"
}

rule MalwareBazaar_Mirai_090_5e468b53
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e468b536228953bcace7b3793da62f6ea5e7d57026812c2654d1f78e8a5e1f9"
    family = "Mirai"
    file_name = "boatnet.sh4"
    file_type = "elf"
    first_seen = "2026-08-05 22:21:39"
  condition:
    hash.sha256(0, filesize) == "5e468b536228953bcace7b3793da62f6ea5e7d57026812c2654d1f78e8a5e1f9"
}

rule MalwareBazaar_RustyStealer_091_b72342c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b72342c9ae243231eecefda808f66e0177637b120cb8d45e3bc9681c84d0a9a0"
    family = "RustyStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 21:56:20"
  condition:
    hash.sha256(0, filesize) == "b72342c9ae243231eecefda808f66e0177637b120cb8d45e3bc9681c84d0a9a0"
}

rule MalwareBazaar_unknown_092_5ef6019f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f"
    family = "unknown"
    file_name = "notification_helper.exe"
    file_type = "exe"
    first_seen = "2026-08-05 21:54:02"
  condition:
    hash.sha256(0, filesize) == "5ef6019fb6ee1db1201ee479a68669b47eb0d5d82770dbd30b05f46ccbc68f4f"
}

rule MalwareBazaar_unknown_093_ce37bbea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5"
    family = "unknown"
    file_name = "ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5"
    file_type = "elf"
    first_seen = "2026-08-05 21:30:17"
  condition:
    hash.sha256(0, filesize) == "ce37bbeaa6551bab9cdd06a7c05217ce3ca049473d721833a2137ca7d68370e5"
}

rule MalwareBazaar_CoinMiner_094_5bab10c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bab10c1591c7266cbfc42b0e40ee060ba34ad4cf5cfd0d7a1913516c836953c"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:59"
  condition:
    hash.sha256(0, filesize) == "5bab10c1591c7266cbfc42b0e40ee060ba34ad4cf5cfd0d7a1913516c836953c"
}

rule MalwareBazaar_unknown_095_b8c1c8f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8c1c8f9c34a33e84930fbaf8a3d52954420bc000f01ea45d48ffdfe108b0c60"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:30"
  condition:
    hash.sha256(0, filesize) == "b8c1c8f9c34a33e84930fbaf8a3d52954420bc000f01ea45d48ffdfe108b0c60"
}

rule MalwareBazaar_unknown_096_75ae5ef8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "75ae5ef8c6db196c5545ceaa4dc1ac3f916d50b18d5ff73f16a5e3e3cd500a44"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:20"
  condition:
    hash.sha256(0, filesize) == "75ae5ef8c6db196c5545ceaa4dc1ac3f916d50b18d5ff73f16a5e3e3cd500a44"
}

rule MalwareBazaar_unknown_097_05f9271f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05f9271f2618d599d2e263d8f4aa761a77ed1178369ba59403a72b412ceb10bc"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:42:11"
  condition:
    hash.sha256(0, filesize) == "05f9271f2618d599d2e263d8f4aa761a77ed1178369ba59403a72b412ceb10bc"
}

rule MalwareBazaar_Mirai_098_4135a4f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-08-05 20:40:47"
  condition:
    hash.sha256(0, filesize) == "4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5"
}

rule MalwareBazaar_unknown_099_ed23e0d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ed23e0d5d55c12998aea2e4d065726301cb02257f4c9435758368fb94c7881c9"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-08-05 20:35:15"
  condition:
    hash.sha256(0, filesize) == "ed23e0d5d55c12998aea2e4d065726301cb02257f4c9435758368fb94c7881c9"
}

rule MalwareBazaar_Mirai_100_73954ad2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "73954ad21e67eef91256bc65f3b2b88ca6d20ca45cf0918247ade9a4d7bab694"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-08-05 20:25:37"
  condition:
    hash.sha256(0, filesize) == "73954ad21e67eef91256bc65f3b2b88ca6d20ca45cf0918247ade9a4d7bab694"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

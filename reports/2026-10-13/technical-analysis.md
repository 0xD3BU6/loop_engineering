# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-13

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 690 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 690 |
| Unique family labels | 19 |
| Unique file types | 8 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 34 |
| Vidar | 22 |
| unknown | 16 |
| Formbook | 4 |
| RemcosRAT | 3 |
| AgentTesla | 3 |
| Gafgyt | 3 |
| ValleyRAT | 2 |
| DCRat | 2 |
| NanoCore | 2 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 46 |
| elf | 39 |
| js | 5 |
| ps1 | 3 |
| sh | 3 |
| macho | 2 |
| hta | 1 |
| wsf | 1 |

## Per-Sample Analysis

### Sample 1: `16602885d0f879e4`

| Field | Value |
|---|---|
| SHA-256 | `16602885d0f879e4477ad54079a8b04f5c163c539ca9c4c26cc33df98925472b` |
| Family label | `unknown` |
| File name | `adissarm5` |
| File type | `elf` |
| First seen | `2026-10-13 06:51:49` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3470b3325425585c27c2d34dc45379bf` |
| SHA-1 | `dc02aae48baa805527b286fa7934c7b216079382` |
| SHA-256 | `16602885d0f879e4477ad54079a8b04f5c163c539ca9c4c26cc33df98925472b` |
| SHA3-384 | `67dbddfdae5ecc5e01aa2ce7a9a048d2be67fb2c6fce2b2ba5ba668802cbe0a82332b4cc616e15cd463f8b5be65e5b37` |
| TLSH | `T1F3142A95FC509A23C6C1167BFB5E428C372B13B8D2EE31039D156F24379B86B0E7A652` |
| TELFHASH | `t1063133209e8405ec73d4c995909d123ea61139f66e313950ceb7aa8d4e82cd17136836` |
| SSDEEP | `6144:FKRy/b4D1vE65p87DEb/ibRE94iTsg/MlZHE1sv9h:FKkb4RvETYf94iTJ/+Hmsv9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_16602885
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16602885d0f879e4477ad54079a8b04f5c163c539ca9c4c26cc33df98925472b"
    family = "unknown"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-13 06:51:49"
  condition:
    hash.sha256(0, filesize) == "16602885d0f879e4477ad54079a8b04f5c163c539ca9c4c26cc33df98925472b"
}
```

### Sample 2: `8d87e9e7076ec05e`

| Field | Value |
|---|---|
| SHA-256 | `8d87e9e7076ec05efe85a83510bfbc87bc680216f4c4a6f9f871990eaa7906b7` |
| Family label | `Mirai` |
| File name | `disspoor` |
| File type | `elf` |
| First seen | `2026-10-13 06:46:23` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b87e3965dda4529b0138d092688393e2` |
| SHA-1 | `7bb525ea91f7c47cf1c36c950813158cd6b8c62f` |
| SHA-256 | `8d87e9e7076ec05efe85a83510bfbc87bc680216f4c4a6f9f871990eaa7906b7` |
| SHA3-384 | `03a53348de7220c798f452f383cd3d29b5e6c743d908eefd4dff87f358876723a84b9d5f2eb22fbcbcbf46c6a0932577` |
| TLSH | `T1D0246E05B71C0943E2632EF03B3F27D193EF99D221F5EA446A0EBA499271D322589DDD` |
| SSDEEP | `6144:GkebfwwSn7BN7elarLl5u/exOjqoziNYvalBlm1tt:Gw7rylavl0qOalBQt` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_8d87e9e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d87e9e7076ec05efe85a83510bfbc87bc680216f4c4a6f9f871990eaa7906b7"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-13 06:46:23"
  condition:
    hash.sha256(0, filesize) == "8d87e9e7076ec05efe85a83510bfbc87bc680216f4c4a6f9f871990eaa7906b7"
}
```

### Sample 3: `4f3c9112b612349c`

| Field | Value |
|---|---|
| SHA-256 | `4f3c9112b612349ca18cd3bd4ab6905afff34e4d806f9d38ac4c5e41194712aa` |
| Family label | `Mirai` |
| File name | `dissarm6` |
| File type | `elf` |
| First seen | `2026-10-13 06:41:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d90efbceef2a6ce3b52bb02d4bbd62d0` |
| SHA-1 | `25ff152c3db2e9b749a19dd1959e73e55e6f6e04` |
| SHA-256 | `4f3c9112b612349ca18cd3bd4ab6905afff34e4d806f9d38ac4c5e41194712aa` |
| SHA3-384 | `16de538a47396d1d9838ddd18ddb75ffc766adf0838f62f9a9cd6f0bf06eaa2d60a99456c75a8c907b65f404d88b499c` |
| TLSH | `T126242956F8819F11D5C016BAFE1E528D33231B78E2EE32169E246F20778B87F0E7A515` |
| TELFHASH | `t150c08c20458001e4f02088c3419a232046e6c02b8e423499aa903a8ec691ea9f06a22b` |
| SSDEEP | `6144:NKdaL2PbOqP0clX/RjUahcymuu+TGj8P68:NKdo2PqqM4XVUaho9wGj8PF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_4f3c9112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f3c9112b612349ca18cd3bd4ab6905afff34e4d806f9d38ac4c5e41194712aa"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-13 06:41:14"
  condition:
    hash.sha256(0, filesize) == "4f3c9112b612349ca18cd3bd4ab6905afff34e4d806f9d38ac4c5e41194712aa"
}
```

### Sample 4: `d1c4adea218def89`

| Field | Value |
|---|---|
| SHA-256 | `d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97` |
| Family label | `Mirai` |
| File name | `d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97.elf` |
| File type | `elf` |
| First seen | `2026-10-13 06:40:36` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `348067ceee64ada537521a93027f5961` |
| SHA-1 | `162487fc4629e99099026f3636eb7ff28299e5cd` |
| SHA-256 | `d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97` |
| SHA3-384 | `250cd026c9833664a462bf2337d13867bdea4e69731352d43c519271dea7bc658cb5dccd7f08472717d9ba8b2cb1c42d` |
| TLSH | `T13A841A8862F5FBCEE196EE3983017C076C298B3274837586719EF96313B71850AF9D61` |
| SSDEEP | `6144:DK+zl6+t5J13Qz55RWy+QyGzUVWFc/bljkvBW/gi2a:D96+t5P055cypMbQZih` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_d1c4adea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97"
    family = "Mirai"
    file_name = "d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97.elf"
    file_type = "elf"
    first_seen = "2026-10-13 06:40:36"
  condition:
    hash.sha256(0, filesize) == "d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97"
}
```

### Sample 5: `ef9131af106c6d7c`

| Field | Value |
|---|---|
| SHA-256 | `ef9131af106c6d7cf77c8d4856c93e18c2c6c038e3584319498f1acc98703c93` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-13 06:37:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b240bef82225805cfb5832bbdb6fd219` |
| SHA-1 | `d108e969b9493eef3e4a1d43e93fbaf294e4d027` |
| SHA-256 | `ef9131af106c6d7cf77c8d4856c93e18c2c6c038e3584319498f1acc98703c93` |
| SHA3-384 | `8d52aa7d22462cad138f5cf4cf10a1af8cc1da54247ead1e73dc98f8b22782a93782e23979c153d221fc4647b2bb88a9` |
| TLSH | `T1A2840A8953F1DFDDE258EA7013736D179D76063735D36286E16EF92223A128808EFE60` |
| TELFHASH | `t104e01a2c983823f0d1c89c2d81dcff11d8b1c5db58b50e1bc508d8b46671e429e00c34` |
| SSDEEP | `6144:IbQR8GMBUIP8sGVLnzNGDrdIwIed/d8JK7jcVHBi4C2I:B8GMKIXlrAAGHA4C2I` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_ef9131af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef9131af106c6d7cf77c8d4856c93e18c2c6c038e3584319498f1acc98703c93"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-13 06:37:28"
  condition:
    hash.sha256(0, filesize) == "ef9131af106c6d7cf77c8d4856c93e18c2c6c038e3584319498f1acc98703c93"
}
```

### Sample 6: `4f5d0e91305ebeae`

| Field | Value |
|---|---|
| SHA-256 | `4f5d0e91305ebeae3ef3a16d32103961c401c9061f67076fdc3722693adc74d6` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-13 06:36:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2252a8755fab46b1fc44999f9abe4a0f` |
| SHA-1 | `70da39d6d6a5fc6162c5ecb2e40af217930c4871` |
| SHA-256 | `4f5d0e91305ebeae3ef3a16d32103961c401c9061f67076fdc3722693adc74d6` |
| SHA3-384 | `6d36a412912ba0f1570f4d5ed2565def181a34f4627338773415677d6d25b64d524e0ea6f82b43001a30dd7dd25870ad` |
| TLSH | `T1D0556D59A2F3F2FCD146D1305397EA625931743621327DBF22C8DA322EB6DD01369B62` |
| TELFHASH | `t160f1dc700ef539b1b6dbe611b312f4789d7314a625f936f11a22ac98ef41f810cab427` |
| SSDEEP | `24576:aNJQKso8M1ZP7B8mNgnXDMOTS9yWwAQxe+90MkwC:TK15lJNgnXDMxVHLw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_4f5d0e91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f5d0e91305ebeae3ef3a16d32103961c401c9061f67076fdc3722693adc74d6"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-13 06:36:15"
  condition:
    hash.sha256(0, filesize) == "4f5d0e91305ebeae3ef3a16d32103961c401c9061f67076fdc3722693adc74d6"
}
```

### Sample 7: `cd823efda222cf6a`

| Field | Value |
|---|---|
| SHA-256 | `cd823efda222cf6a0885d46759e80932f555bf26b0e0c6ee7caf8bbe415bfd3b` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-13 06:36:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e970823e94839b60048299b8e31eeb3` |
| SHA-1 | `f58d859e13eb9d9621bb7217a645db411c298b31` |
| SHA-256 | `cd823efda222cf6a0885d46759e80932f555bf26b0e0c6ee7caf8bbe415bfd3b` |
| SHA3-384 | `31cc712845471cf4f1dce14f5a77830aaec24f86d7a0ae00655e6a6bbc49b0cc1737365d965dfc489b0a018553824b23` |
| TLSH | `T135C31259AC64BEC1E9A0407C0DF24BECBE3D06E299B7D50AB516DC6963036C13874ECE` |
| SSDEEP | `3072:ldJL/sP3z6daFWalptmKhIeVo/G4kEfo8NwoldsoDV7:ldJLEP3CaFWCttP7Ofoqr7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_cd823efd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd823efda222cf6a0885d46759e80932f555bf26b0e0c6ee7caf8bbe415bfd3b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-13 06:36:13"
  condition:
    hash.sha256(0, filesize) == "cd823efda222cf6a0885d46759e80932f555bf26b0e0c6ee7caf8bbe415bfd3b"
}
```

### Sample 8: `e96178beb8202507`

| Field | Value |
|---|---|
| SHA-256 | `e96178beb8202507f8a9dfc51fc6db12bd1848cf158992d6188b0693681dc424` |
| Family label | `Mirai` |
| File name | `dbg` |
| File type | `elf` |
| First seen | `2026-10-13 06:36:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4eadc82cb52b06f007fdf40c63978e62` |
| SHA-1 | `a9bd2b9c7f69aa7203bb5b0037fae200e8bcbdab` |
| SHA-256 | `e96178beb8202507f8a9dfc51fc6db12bd1848cf158992d6188b0693681dc424` |
| SHA3-384 | `d3ef562a0adc6abb1880f94fedf668a376984f828bdb1b8d968a1289d2655015ca32c8bc8cd225a64e2c63c32e584ad8` |
| TLSH | `T107255A2BB2B3F0BCE107C03457DBCAE1A525B07922312DBF66C5DA312D66DD11369B62` |
| TELFHASH | `t1d9b1c27048fe75a4a2dadd117323f4b95c33489766e93ab01a22bd84dfc5e800c7782b` |
| SSDEEP | `24576:AqImB5ICF9lbybNW9iU9xw6RWRHJmJvp:jplbybNWc6w6KJmJR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_e96178be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96178beb8202507f8a9dfc51fc6db12bd1848cf158992d6188b0693681dc424"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-10-13 06:36:11"
  condition:
    hash.sha256(0, filesize) == "e96178beb8202507f8a9dfc51fc6db12bd1848cf158992d6188b0693681dc424"
}
```

### Sample 9: `89ade231d9eea230`

| Field | Value |
|---|---|
| SHA-256 | `89ade231d9eea23055ab72eddc0b81d80c8d886534ce76821647cbf974410d4d` |
| Family label | `Mirai` |
| File name | `dissarm7` |
| File type | `elf` |
| First seen | `2026-10-13 06:31:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `15c36b3d764ae95fdf0dcc0916da0360` |
| SHA-1 | `bff70fa0c2537239e4117e788437b7ee3ad6961e` |
| SHA-256 | `89ade231d9eea23055ab72eddc0b81d80c8d886534ce76821647cbf974410d4d` |
| SHA3-384 | `aa0f2bd1af726c3c2759375b3ccdb0bc9016aeadaced723b41500ee4171fb65c822efc5bd6bf47ee34794390fb9cfae8` |
| TLSH | `T135142949FD81AF11D5D536BAFA1E4189336317BCD3FA7112AE245F2023CA91B0F7A611` |
| TELFHASH | `t108c02b11000496e43b5cce4bc0eb3386e3d0c37e008074691444342104e02f2d090013` |
| SSDEEP | `3072:RvPoHTLKalGD9PUkvF3aWxsqVv+y73yadSRTpxX+ucYOfmlnd/r3ZWmzQZIw:RvUTfE9s817sqVWu3yadSBpxX+ucfmnu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_89ade231
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ade231d9eea23055ab72eddc0b81d80c8d886534ce76821647cbf974410d4d"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-13 06:31:05"
  condition:
    hash.sha256(0, filesize) == "89ade231d9eea23055ab72eddc0b81d80c8d886534ce76821647cbf974410d4d"
}
```

### Sample 10: `2c1f19a9ed33cfca`

| Field | Value |
|---|---|
| SHA-256 | `2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d` |
| Family label | `Vidar` |
| File name | `2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:42` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `505a135a49d214154a1863956fa161da` |
| SHA-1 | `7b51a2073b0e38b70282e8c5b4e00782a4ed3083` |
| SHA-256 | `2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d` |
| SHA3-384 | `7ba6e767e2bc6dc3ae5e5f254f4a1174b3559886db60296a71aa1661067a0ee161c3b24ae9ef3155db91fae4b3d67440` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T16FE629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:qUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoFB:qORDNEqm0496sBSoFB` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_010_2c1f19a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d"
    family = "Vidar"
    file_name = "2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:42"
  condition:
    hash.sha256(0, filesize) == "2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d"
}
```

### Sample 11: `f761f56f9f7f65c5`

| Field | Value |
|---|---|
| SHA-256 | `f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432` |
| Family label | `Vidar` |
| File name | `f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:38` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `31f29c789e6cab8b96ccd162cf2c330a` |
| SHA-1 | `f1e264b75dcde588dd5f567376bd5d2a4bae40ed` |
| SHA-256 | `f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432` |
| SHA3-384 | `11ceab2ad4925f28ca1eb0c1c605c66baf28d20586675580de73ff95463edd4cf69d43e27dcf435ebb35d0238c51ad8e` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T169E629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:fUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoFM:fORDNEqm0496sBSoFM` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_011_f761f56f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432"
    family = "Vidar"
    file_name = "f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:38"
  condition:
    hash.sha256(0, filesize) == "f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432"
}
```

### Sample 12: `2684dd7946751a6b`

| Field | Value |
|---|---|
| SHA-256 | `2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149` |
| Family label | `Vidar` |
| File name | `2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:34` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce8144286e438036dceb5a5593b8d420` |
| SHA-1 | `6b62457abedb635ae8c1846b353564bb5cfdd0ea` |
| SHA-256 | `2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149` |
| SHA3-384 | `6138730a49e1e67473e6465e8c49922cc5bf8917e2292f8cca7193191f6008d2fb87752fd04b284edbaa5db232e6933f` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T175E629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:lUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoFD:lORDNEqm0496sBSoFD` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_012_2684dd79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149"
    family = "Vidar"
    file_name = "2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:34"
  condition:
    hash.sha256(0, filesize) == "2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149"
}
```

### Sample 13: `b31a87efe83fe2d6`

| Field | Value |
|---|---|
| SHA-256 | `b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee` |
| Family label | `ArkeiStealer` |
| File name | `b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:30` |
| Reporter | `anonymous` |
| Tags | `ArkeiStealer, exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a9c83c2558490dd0b9b769273c34d1c` |
| SHA-1 | `8770203705ce05ccc340bd7cdb1d1ac8e687bb61` |
| SHA-256 | `b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee` |
| SHA3-384 | `999837a57fe1d1f415778adde8a3f2ea586534f9c315f5af907964ccbfbaee9ee476aa25a19b57108e00b4fc2b972de6` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T1AAE629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:sUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoFS:sORDNEqm0496sBSoFS` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `ArkeiStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ArkeiStealer_013_b31a87ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee"
    family = "ArkeiStealer"
    file_name = "b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:30"
  condition:
    hash.sha256(0, filesize) == "b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee"
}
```

### Sample 14: `3c7e4f7adfcc9373`

| Field | Value |
|---|---|
| SHA-256 | `3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e` |
| Family label | `unknown` |
| File name | `3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:26` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd2989f5e07a4d4b9cede02773f90d9f` |
| SHA-1 | `efcc91d0b14e7abbcd9f8d938819072098f42e84` |
| SHA-256 | `3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e` |
| SHA3-384 | `cf47463aa48dd4321cda977ebe5f629744b6aba5cf82ad3c5378667e72b404c6cfb3e29ac1b8eaeba3ff9b546474b628` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T157E629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:VUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoFW:VORDNEqm0496sBSoFW` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_3c7e4f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e"
    family = "unknown"
    file_name = "3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:26"
  condition:
    hash.sha256(0, filesize) == "3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e"
}
```

### Sample 15: `a37845bf7a3b2d27`

| Field | Value |
|---|---|
| SHA-256 | `a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074` |
| Family label | `Vidar` |
| File name | `a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:23` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `129961880548c4eb4245de812aa6d45f` |
| SHA-1 | `b1300420b14000fcd5ee785634fa44b5a4cb8175` |
| SHA-256 | `a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074` |
| SHA3-384 | `03aef32d7695fa55317e14dbdfc121bd3c2eef01310401840a6c3598abfb334441bfda7478c68338d9abec0124fc7de4` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T138B59C077CC824BAD5EA923299B512A0B731F8990B3127C72F55A3B92F777D40E39394` |
| SSDEEP | `49152:zqveuaVJQWaaxlq41/e1fzJ+OSgk0p4D1a:Aa8WaaS8EVv` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_015_a37845bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074"
    family = "Vidar"
    file_name = "a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:23"
  condition:
    hash.sha256(0, filesize) == "a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074"
}
```

### Sample 16: `adcddb34f3f1257f`

| Field | Value |
|---|---|
| SHA-256 | `adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77` |
| Family label | `Vidar` |
| File name | `adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:20` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `87bdb9dfe9bca574aeb3d6aa6113a7a3` |
| SHA-1 | `171528b9893a1a3c0670d5ef39e8fcbcf23bc1b6` |
| SHA-256 | `adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77` |
| SHA3-384 | `40048d965b351d8999a605bedaf3020839169e783ff521e8870ca07c2b086b80cb1a2fcc931a12f114d591fdbf9b787d` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T133B59C477C8414B6D9EA923298B41290B731F8590B2167C73F51B3B92FB7BE40E793A4` |
| SSDEEP | `49152:cDu0wuePuOsLrEHUOsaQMyq0lvOSgk0KsD1v:9uLOGE0Osaxyq0lA` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_016_adcddb34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77"
    family = "Vidar"
    file_name = "adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:20"
  condition:
    hash.sha256(0, filesize) == "adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77"
}
```

### Sample 17: `65d76e7d64607076`

| Field | Value |
|---|---|
| SHA-256 | `65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db` |
| Family label | `Vidar` |
| File name | `65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:17` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5e131f8aec1c61ad0c2644385c542eb6` |
| SHA-1 | `e65fe89e33ed2dcc4f236c3e3d9a625f3417d5c8` |
| SHA-256 | `65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db` |
| SHA3-384 | `f10bb0249cec9d128341f7a4debb19cf69e8ed3067a6fd9c672c3ba7f5ae7d3635387c622374b5e86ae10e3096486941` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T10CB5AD867CD425B6D9EA923299B14290B731F88A1B2163C73B54A3FD2F377D40E39394` |
| SSDEEP | `24576:eARPx5UI4VYHmzl3TU9uVwfC2ExiSNJhQqutdJheSgk0HD2yD1J:eARx5UIU/lDU9u3AOSgk0yyD1J` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_017_65d76e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db"
    family = "Vidar"
    file_name = "65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:17"
  condition:
    hash.sha256(0, filesize) == "65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db"
}
```

### Sample 18: `e748d92f5d8f584b`

| Field | Value |
|---|---|
| SHA-256 | `e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9` |
| Family label | `Vidar` |
| File name | `e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:14` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a1b07aa5c91c6ed229ccbdbb530a012` |
| SHA-1 | `6044d6f328ca7b900a72076f789a43765a7c428d` |
| SHA-256 | `e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9` |
| SHA3-384 | `fa435befe32660dfcee5f329880d4a045c17f210789ff6606d6b5116380dc627716e36b93c8525e45c89946a6b30da97` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T1B4B58C067CC420B6D9FA923289B55291BB31F8990B3127C72F55A2F82F77BD40E79394` |
| SSDEEP | `49152:nOKVfrLJdIT7vIiCsi/q8Cyg72KsCaEc+OOSgk0E8D1R:vpdVpsmqpygQE5` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_018_e748d92f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9"
    family = "Vidar"
    file_name = "e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:14"
  condition:
    hash.sha256(0, filesize) == "e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9"
}
```

### Sample 19: `7ab8d9e65597bf7a`

| Field | Value |
|---|---|
| SHA-256 | `7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0` |
| Family label | `Vidar` |
| File name | `7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:11` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b6bab0d7dcbe0e4eee0569e25f6f70ab` |
| SHA-1 | `66525b132efd4e6e7de6b00771d4faa14f9c9ae1` |
| SHA-256 | `7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0` |
| SHA3-384 | `3644fc4e7a3b07a155aed7585f2a2f21618d3b6ccc4407148fddba464b1d9609eeb7461bca8da779fe4ae76d13aa92d1` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T115B59D467CD420B6D5EA923289B512917B31F8890B31A7C32F56A3F92F773D41E39398` |
| SSDEEP | `49152:dAAxpc481HMjc7Te1bs4/YzJT+i9QWx1sDfOrOSgk0dSD1NRx:3E1HMjQ2bn/Yzh+iXx1szOH` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_019_7ab8d9e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0"
    family = "Vidar"
    file_name = "7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:11"
  condition:
    hash.sha256(0, filesize) == "7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0"
}
```

### Sample 20: `618bc21cf7dc193f`

| Field | Value |
|---|---|
| SHA-256 | `618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51` |
| Family label | `Vidar` |
| File name | `618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:08` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d4980af9fe62f9de336a25529afe927e` |
| SHA-1 | `492322a4fb7f20a9fb7112c2de5da1a2f6689206` |
| SHA-256 | `618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51` |
| SHA3-384 | `533bec79c4686e34b14935e8b43e3185c822a854a6a489e5b6585d9000280556c3fefebddd80c8514995d846aae2ea50` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T101B59D06BCC425BAD9AAA33289B15291B731F8590B3127C33F55A7B92F737D40E39394` |
| SSDEEP | `49152:Dn7URjeQNDePtErhMOAl54+4n2JuvYEOSgk0XAD11v:s1NDGtEsIY0v` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_020_618bc21c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51"
    family = "Vidar"
    file_name = "618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:08"
  condition:
    hash.sha256(0, filesize) == "618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51"
}
```

### Sample 21: `4c160e5bebe1495c`

| Field | Value |
|---|---|
| SHA-256 | `4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9` |
| Family label | `Vidar` |
| File name | `4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:04` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ede42b43f2b6faa9f912376003fe3790` |
| SHA-1 | `43e971a331093ebdab4d9e59784134bb0ffcdbd8` |
| SHA-256 | `4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9` |
| SHA3-384 | `5db6eb61f58ffeaf7ff9df392c7d498cfe01bc96a21dd14867464f1c9e0472cdcb01ab139a2d82c09ab4f09c09d7ce4d` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T19FB58C067CC424B6D5A9A2328DB15291B731F8890B3167C73F56A7B92F773D80E3A394` |
| SSDEEP | `49152:xrM5t1aUryTID2RVXYV3CpAOSgk0+5D1Y:MTrAoWW4` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_021_4c160e5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9"
    family = "Vidar"
    file_name = "4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:04"
  condition:
    hash.sha256(0, filesize) == "4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9"
}
```

### Sample 22: `1a301fde61e3214c`

| Field | Value |
|---|---|
| SHA-256 | `1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6` |
| Family label | `Vidar` |
| File name | `1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:27:01` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bf3813e144e2187eab50f917ee7df1fb` |
| SHA-1 | `6223822bd564422be212a54e66c3d8ea1852d0ee` |
| SHA-256 | `1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6` |
| SHA3-384 | `2dcc3de6f83c11fc4e64b47bdc305e406f59c16320efa61c9944ec27301ac330c34c58e39c2cc796a446246d669a166a` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T11BB58B577CC425B6D6BA923288BA11917B31F8890B3127C72F59A2F92F773D40E39394` |
| SSDEEP | `24576:drUhEO26IV2NNzf8t/JpKjgRUdlAqVb+62N4H3sdD3p8pvGcJheSgk0HxxpD1a:drcEO26cQf8hJpGLDsdD3+OSgk0PpD1a` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_022_1a301fde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6"
    family = "Vidar"
    file_name = "1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:01"
  condition:
    hash.sha256(0, filesize) == "1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6"
}
```

### Sample 23: `50424bc060c6593c`

| Field | Value |
|---|---|
| SHA-256 | `50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14` |
| Family label | `Vidar` |
| File name | `50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:58` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b4cadafa067002787b646fcab7e4e19` |
| SHA-1 | `af4fafbbed3e3801dd511fd32e786e067e5d66a7` |
| SHA-256 | `50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14` |
| SHA3-384 | `3512526046c8735cca9baf523882438522d53f7de989f13b0638dd9a09051543dd8a543c347d5ac6bdcc1cf297cedbc1` |
| IMPHASH | `f0ea7b7844bbc5bfa9bb32efdcea957c` |
| TLSH | `T118B59D077CC011B6D5FAA2328DB512A1B732F8891B2167C72F55B2B92E7B7D80E35394` |
| SSDEEP | `49152:JZIX/0kZlC8AAnITxNU4fy2Q8dO8Xm3QOSgk0/oD1J:J4C8nnp4vHmY` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_023_50424bc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14"
    family = "Vidar"
    file_name = "50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:58"
  condition:
    hash.sha256(0, filesize) == "50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14"
}
```

### Sample 24: `63b838a03da7178e`

| Field | Value |
|---|---|
| SHA-256 | `63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc` |
| Family label | `Vidar` |
| File name | `63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:55` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a2d3e3f8be31938e4c80795e398a3a32` |
| SHA-1 | `32e1eacc52bbc3a914ee0ad4cf762932c24cbf22` |
| SHA-256 | `63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc` |
| SHA3-384 | `37f03d4c39a7b900a21e47a4d7b29aeb7968d017bc6a6496109144eaddbfec7dc7ca406851e6f1122d6e79df84c61126` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T118C59D1ABD9108F6D06A63368DB352827B71BC490F3263C72E90BA782FB72D45D79714` |
| SSDEEP | `49152:fwznG5KIWjqeHva2Jtt706efgUgnHNTOtI2fdaZrL5:fwK5ToqcMzgnH1IdI7` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_024_63b838a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc"
    family = "Vidar"
    file_name = "63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:55"
  condition:
    hash.sha256(0, filesize) == "63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc"
}
```

### Sample 25: `b941316399a25269`

| Field | Value |
|---|---|
| SHA-256 | `b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37` |
| Family label | `Vidar` |
| File name | `b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:31` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `743152ce5d3d5b3bffbdcc32b09e979c` |
| SHA-1 | `b99b62935e59f480163d9dbbdfb0f3db7faf469b` |
| SHA-256 | `b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37` |
| SHA3-384 | `4883da5d93494122ecc72dc83cd2d23a14ff919591af184584cf83a8811a055946f1e84bf99353759f7db81fc9e82f49` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T1D9C58D0ABCE084F6D059A3324CA769617BB2BC588F3153D32E94F5B82E73AD49E74750` |
| SSDEEP | `49152:nk+MGqfXtfNRHhgan2FIhExrVp5tXqJTKr3OnI:nkEqPJF2qhE9htXgpI` |
| ICON-DHASH | `10808a8c8c8a8010` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_025_b9413163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37"
    family = "Vidar"
    file_name = "b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:31"
  condition:
    hash.sha256(0, filesize) == "b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37"
}
```

### Sample 26: `266411bef009df38`

| Field | Value |
|---|---|
| SHA-256 | `266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468` |
| Family label | `Vidar` |
| File name | `266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:27` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `40f69f875f03bb0f42201d29e0e61fda` |
| SHA-1 | `84c6409d2f3e56a620d17773761ee227f5b4cc5c` |
| SHA-256 | `266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468` |
| SHA3-384 | `b22765fb9c00bf4279cb60e1efc235e1cd3e37f763ee126b5e41bbcd1f20babe42eda3c0205b93aaa22260cd497d1811` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T14AE629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:BUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoFm:BORDNEqm0496sBSoFm` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_026_266411be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468"
    family = "Vidar"
    file_name = "266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:27"
  condition:
    hash.sha256(0, filesize) == "266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468"
}
```

### Sample 27: `754705b56629e4ce`

| Field | Value |
|---|---|
| SHA-256 | `754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661` |
| Family label | `Vidar` |
| File name | `754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:24` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f57f20b963978d298a7173c756153105` |
| SHA-1 | `a0af69e07b70fb5739829401321bd19d7e79ef4d` |
| SHA-256 | `754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661` |
| SHA3-384 | `30d7e8617e71e7f62debfb0dc0ce3fd57998d250b6f47a1b56b6cced94b7090d879df2aba595b99e89cb84c87c0bf106` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17FC5B236EC9236A5C0DD52B2C8A2114166EDA8473BED12C33950FE2B2EF26DC59357C7` |
| SSDEEP | `49152:vVzCtSXEdkeiHkNsOYpmjGD4xL5UXGSFa:voJIk8mjGD4xuWWa` |
| ICON-DHASH | `e8c4989d86b6c0e8` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_027_754705b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661"
    family = "Vidar"
    file_name = "754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:24"
  condition:
    hash.sha256(0, filesize) == "754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661"
}
```

### Sample 28: `b0f970472a9e2c88`

| Field | Value |
|---|---|
| SHA-256 | `b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7` |
| Family label | `Vidar` |
| File name | `b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:20` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c0ba39732f699262da38725e78d82cf` |
| SHA-1 | `4f5f5c8871b36baac9c1a778425e83f4aa382ffd` |
| SHA-256 | `b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7` |
| SHA3-384 | `1d352631f810e8ee3cf56ee1d58e7b22712420e1e033dd19c041d3550693a57a1f5a5b0b2ce1d6bf9e5ba89eacca45ba` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14F160622ECA226D9C0DD52B0C462550236EC7C463BAD53D73A10FE7A2EB26DC5D793C6` |
| SSDEEP | `49152:WcRd80KuZfAljNw/NzK2HFrjvMKBeMvAc+8pYvsdv41:WogaG2lrzMKBePc+8Wvse` |
| ICON-DHASH | `e8c4989d86b6c0e8` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_028_b0f97047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7"
    family = "Vidar"
    file_name = "b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:20"
  condition:
    hash.sha256(0, filesize) == "b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7"
}
```

### Sample 29: `e41e5fd90907e2f5`

| Field | Value |
|---|---|
| SHA-256 | `e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663` |
| Family label | `Vidar` |
| File name | `e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:17` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c68f21e42213ff358666c54ea35cbe15` |
| SHA-1 | `cc92e3e6eb66757a3073bb78cf3b6955afdeb360` |
| SHA-256 | `e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663` |
| SHA3-384 | `b8a3868d94af404afd954ed9cab70a1360e83c2be8d969886a679be3290d8d63b6fa3dbeea73b75e6e249093649e360d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T168079D0A6CD009EAC06A63328DB762917B76FC491F3227D72E60B2782FB67D49D75314` |
| SSDEEP | `49152:5opNl4JDhvs6qVGUOj8ZaJ90tm0DjCkyIAi:5m4lmGUOQaJ901D+vG` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_029_e41e5fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663"
    family = "Vidar"
    file_name = "e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:17"
  condition:
    hash.sha256(0, filesize) == "e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663"
}
```

### Sample 30: `f046d52fafa99ed0`

| Field | Value |
|---|---|
| SHA-256 | `f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3` |
| Family label | `Vidar` |
| File name | `f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:14` |
| Reporter | `anonymous` |
| Tags | `exe, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f53308c3508b2346f6e39e1d5bc04947` |
| SHA-1 | `7299ce8d52380b76e0d056debb425b86f361d586` |
| SHA-256 | `f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3` |
| SHA3-384 | `56d20614bfcd547dc1b69537dccb913edb0edf922a683571c23f09988a7fb0c051af5d5434e57468f7a03eb3a223512b` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T1F5E629257B9A99ACD05BC47482474A625E7170CB0B39B9FF449492383F7ABF42F38319` |
| SSDEEP | `196608:fUgIRP7e9wRKzrhYEqjaY/4AQB7Osu/G+XoF5:fORDNEqm0496sBSoF5` |
| ICON-DHASH | `62d8ada4da4ae439` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_030_f046d52f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3"
    family = "Vidar"
    file_name = "f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:14"
  condition:
    hash.sha256(0, filesize) == "f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3"
}
```

### Sample 31: `9569def1fc3d84e6`

| Field | Value |
|---|---|
| SHA-256 | `9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2` |
| Family label | `Vidar` |
| File name | `9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2.bin` |
| File type | `exe` |
| First seen | `2026-10-13 06:26:10` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b7fcb924f08373a86d93a72c128a971` |
| SHA-1 | `829836a5af591f1a628ce7196fb37013a7eef48a` |
| SHA-256 | `9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2` |
| SHA3-384 | `43ac49db4556f4b82714dd4ae5022b1e53139d19a293926671e3962f64d36745bf1c820b8cee16e9f748a6272b9b9179` |
| IMPHASH | `ebc247a77b4d4a804b261f97a1fd075c` |
| TLSH | `T19CC58C1ABDD508F6C06A63368CB722927B75BC080F3223D72A90BA782F776D45CB5754` |
| SSDEEP | `49152:6wznG5KIWjqeHva2phrn6EYJT6cAiy6sG+BdF2rs25Q:6wK5ToqKdYJSuQ` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_031_9569def1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2"
    family = "Vidar"
    file_name = "9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:10"
  condition:
    hash.sha256(0, filesize) == "9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2"
}
```

### Sample 32: `5cb39a8d4e7f3f45`

| Field | Value |
|---|---|
| SHA-256 | `5cb39a8d4e7f3f452a8ff91c83c866dbe7a0c10fd95ccacc772e13329350d993` |
| Family label | `Mirai` |
| File name | `android-arm64` |
| File type | `elf` |
| First seen | `2026-10-13 06:26:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db2ca3545c8269b075a441ad3cc74355` |
| SHA-1 | `5171c1b7b16722417126e5f9ff2e037f2d53cc8e` |
| SHA-256 | `5cb39a8d4e7f3f452a8ff91c83c866dbe7a0c10fd95ccacc772e13329350d993` |
| SHA3-384 | `cade7a33b6f151e9400fe4882c45b2f35ea363ca4dc5b0b2c91498023d610ee8973a377352c33e4266f9def4aea668ed` |
| TLSH | `T12E944C4C91F5E7DEE28CF57892067C569C72253630A3B286710FE5BB53AB28409EDE31` |
| TELFHASH | `t12811c946e9bd97a99ea24920aca927b18053da2261b1c320ef11ded4583f501f119e8f` |
| SSDEEP | `3072:jUvQkUjlrsZ1POfyvgw0+aRqHtxVKmaWNgiQV+kAXA5bt5Gt1Ps8CVnJjaa90DAO:jPqa9P2Wy92bIzOE/alxUxZKdx+tudo` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_5cb39a8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cb39a8d4e7f3f452a8ff91c83c866dbe7a0c10fd95ccacc772e13329350d993"
    family = "Mirai"
    file_name = "android-arm64"
    file_type = "elf"
    first_seen = "2026-10-13 06:26:03"
  condition:
    hash.sha256(0, filesize) == "5cb39a8d4e7f3f452a8ff91c83c866dbe7a0c10fd95ccacc772e13329350d993"
}
```

### Sample 33: `7a66c00dd4680237`

| Field | Value |
|---|---|
| SHA-256 | `7a66c00dd4680237bb341163ca6f250c6222c181dd44c42a556b620de8859000` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-10-13 06:26:01` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9a98ed897c3650551beed19683ed7cb` |
| SHA-1 | `356f96c2d85926dfdb9c6b6f18e9a63bfd76ee82` |
| SHA-256 | `7a66c00dd4680237bb341163ca6f250c6222c181dd44c42a556b620de8859000` |
| SHA3-384 | `1ee1da70026596ea93a7ef7439ae95778b6b9f13674f41e25f81d7a485b229b6218df14bf6e05ac1b906b7e424fb8b29` |
| TLSH | `T110843C8453E2D7CEE214EA7053A27C1AACB6063774D3A187E26FB97303B719458EDD60` |
| SSDEEP | `6144:2wzSpAIqzTVZ15VkFQAUNiWKEk1vmwGjrb:JzSpAIq9Qsbk1vmwQrb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_7a66c00d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a66c00dd4680237bb341163ca6f250c6222c181dd44c42a556b620de8859000"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-10-13 06:26:01"
  condition:
    hash.sha256(0, filesize) == "7a66c00dd4680237bb341163ca6f250c6222c181dd44c42a556b620de8859000"
}
```

### Sample 34: `4614bb60faf9c9ed`

| Field | Value |
|---|---|
| SHA-256 | `4614bb60faf9c9edfac1fa8c90d0c9f939a495cd47bea531142221f6919cabb1` |
| Family label | `unknown` |
| File name | `macho_4614bb60faf9.bin` |
| File type | `macho` |
| First seen | `2026-10-13 06:22:47` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5ad0f7ed6093649b0e682c56a6e1e754` |
| SHA-1 | `d7639bb48fc66cf06c7a43a51ed54b5375947ff9` |
| SHA-256 | `4614bb60faf9c9edfac1fa8c90d0c9f939a495cd47bea531142221f6919cabb1` |
| SHA3-384 | `d1f5884b194201fe2d96d649205f0c3fc0caeb4cad09d0b1a2f6192d2e13505c3a25e4fadc3b161f3da5564cf3d3b567` |
| TLSH | `T19255F100CF6680A5F4CCEF303B269E779F712A60490517EA63925F989D363E3F16725A` |
| SSDEEP | `24576:e+3tMYTDWIqZFrSvqMiV85QstJXzYvqQ43cna:R3tMaqbSlrQstRYRLa` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_4614bb60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4614bb60faf9c9edfac1fa8c90d0c9f939a495cd47bea531142221f6919cabb1"
    family = "unknown"
    file_name = "macho_4614bb60faf9.bin"
    file_type = "macho"
    first_seen = "2026-10-13 06:22:47"
  condition:
    hash.sha256(0, filesize) == "4614bb60faf9c9edfac1fa8c90d0c9f939a495cd47bea531142221f6919cabb1"
}
```

### Sample 35: `3e83eb0906d4c8e8`

| Field | Value |
|---|---|
| SHA-256 | `3e83eb0906d4c8e8f94263d3fb5127146238255e627482de75ff3d3a8ae6ae34` |
| Family label | `GCleaner` |
| File name | `file.exe` |
| File type | `exe` |
| First seen | `2026-10-13 06:21:58` |
| Reporter | `abuse_ch` |
| Tags | `exe, GCleaner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bfb8db9df49d8719b744321349af97b8` |
| SHA-1 | `800c890a3a8396c10ef8098886c6d8c46e594911` |
| SHA-256 | `3e83eb0906d4c8e8f94263d3fb5127146238255e627482de75ff3d3a8ae6ae34` |
| SHA3-384 | `2e339adc17bf560c9bcd5f42883299a8a53e7bc0c6d29815e63c88f46897b4431c634f0e1b9d20cdf1c21f30d18c8a47` |
| IMPHASH | `c4e958372c5ed19e596806cf28b926e1` |
| TLSH | `T1BCE48E26B2E0E532D1631E388D5BE2799C3A7E413928986E2EE85D4C7F3464134673F7` |
| SSDEEP | `12288:S+DkHFnLCA5mXX0tEo8mB1tqGQ6vVIX1Ndkp2SgdMQ0NxL53284:JgZnU0tmEnvVIneB+M1w` |
| ICON-DHASH | `399998ecd4d46c0e` |

#### Technical Assessment

- The sample is tracked as `GCleaner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GCleaner_035_3e83eb09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e83eb0906d4c8e8f94263d3fb5127146238255e627482de75ff3d3a8ae6ae34"
    family = "GCleaner"
    file_name = "file.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:21:58"
  condition:
    hash.sha256(0, filesize) == "3e83eb0906d4c8e8f94263d3fb5127146238255e627482de75ff3d3a8ae6ae34"
}
```

### Sample 36: `342c8cbca7f6c97a`

| Field | Value |
|---|---|
| SHA-256 | `342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1` |
| Family label | `RemcosRAT` |
| File name | `1791829747116b783c49b924ce6d049b5f5c00346c8d4b7fe679e0452e1d24c0b33c31cf43258.dat-decoded` |
| File type | `exe` |
| First seen | `2026-10-13 06:21:54` |
| Reporter | `abuse_ch` |
| Tags | `dat-decoded, exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68f0b67fc3dee548bbfd5ef3bea3bd01` |
| SHA-1 | `6ab570b2077012fb6f2dd7ccfd184907a8afdeae` |
| SHA-256 | `342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1` |
| SHA3-384 | `1bc513d47e7217f8ef35c20aff44eda82f1f7d81d12b52a0d7e61e4b295b98ce7a993ced5627861d3e06e52cd0201362` |
| TLSH | `T153E49E69539140BCD0B6C2B0C2C7823BDAB27C5665B5423F03D76B6B4E23791ED2EB19` |
| SSDEEP | `12288:lIfkJ8RbLnOqwllUi4Ti3ymNX1MKBwFd1QWpq3Vols5T+:688R3nnwllUBTi3ypKBwFdKWpq3Vols5` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_036_342c8cbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1"
    family = "RemcosRAT"
    file_name = "1791829747116b783c49b924ce6d049b5f5c00346c8d4b7fe679e0452e1d24c0b33c31cf43258.dat-decoded"
    file_type = "exe"
    first_seen = "2026-10-13 06:21:54"
  condition:
    hash.sha256(0, filesize) == "342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1"
}
```

### Sample 37: `c66116cfe82dc563`

| Field | Value |
|---|---|
| SHA-256 | `c66116cfe82dc563239bfbd7ac4f91e1e9af966f7729212a3c9f32d197bf0985` |
| Family label | `unknown` |
| File name | `besofluck.htA` |
| File type | `hta` |
| First seen | `2026-10-13 06:21:31` |
| Reporter | `abuse_ch` |
| Tags | `hta` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `20bb03f4cf7b23c98008f60b193b4fa4` |
| SHA-1 | `ed579de7e27adfc05ef25ed0c01d25c65ca38bf6` |
| SHA-256 | `c66116cfe82dc563239bfbd7ac4f91e1e9af966f7729212a3c9f32d197bf0985` |
| SHA3-384 | `5e939b66f79c51fb9627d3751ecabfc098be40c6d56e801bed966ab249f556e17101e2b37a1660900c73f0cf14a360d2` |
| TLSH | `T104E23D374CFA78E7537D0C31E1439F2158B19F2B0B253A081FAB6CE5AAFA1AD6543590` |
| SSDEEP | `384:SXcT+ywAHm2y7eqoLd8HunKKHUGYSDf+4:xHmVeqo6HunlBYSr+4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_c66116cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c66116cfe82dc563239bfbd7ac4f91e1e9af966f7729212a3c9f32d197bf0985"
    family = "unknown"
    file_name = "besofluck.htA"
    file_type = "hta"
    first_seen = "2026-10-13 06:21:31"
  condition:
    hash.sha256(0, filesize) == "c66116cfe82dc563239bfbd7ac4f91e1e9af966f7729212a3c9f32d197bf0985"
}
```

### Sample 38: `1fb0b0a0efd6dac9`

| Field | Value |
|---|---|
| SHA-256 | `1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5` |
| Family label | `AgentTesla` |
| File name | `geen.ps1` |
| File type | `ps1` |
| First seen | `2026-10-13 06:21:06` |
| Reporter | `abuse_ch` |
| Tags | `AgentTesla, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `067b0a291d897c3dd8133d04c1ee2b7f` |
| SHA-1 | `a2909f0e4ff9a4dffa43e14d89b33109d930bde9` |
| SHA-256 | `1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5` |
| SHA3-384 | `8cbafd7e80d169fddc003a3b82fbb4fc951c07215a27d88eb9d739dee42865652ce11a7204fe736314c9d8f413526e34` |
| TLSH | `T105252379CD8DE3D84F40B1FBB9609889B39C51821897971382ECC26272E587DA773CB5` |
| SSDEEP | `24576:GfDu4iKanCsxPGYfeFLpyuPS+fVeChw9zgeKrnsH7DCs:Gf67C++FNGJZfH7T` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_038_1fb0b0a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5"
    family = "AgentTesla"
    file_name = "geen.ps1"
    file_type = "ps1"
    first_seen = "2026-10-13 06:21:06"
  condition:
    hash.sha256(0, filesize) == "1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5"
}
```

### Sample 39: `30f1a88560497fdf`

| Field | Value |
|---|---|
| SHA-256 | `30f1a88560497fdfe4058b60f4c1109f3f470c76b774a718c34e6c1a080219fd` |
| Family label | `RevStealer` |
| File name | `6eq5gvOfRvNmCi54.exe` |
| File type | `exe` |
| First seen | `2026-10-13 06:20:35` |
| Reporter | `abuse_ch` |
| Tags | `exe, RevStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b574cbf2d6cc830c45dca6607cf7df8a` |
| SHA-1 | `686d3d47fb565d68eff30ecb113b7a50c572e0f8` |
| SHA-256 | `30f1a88560497fdfe4058b60f4c1109f3f470c76b774a718c34e6c1a080219fd` |
| SHA3-384 | `c7d70da4fe1cc4a331fc9ec6ace68b94fbb4b778049d2e021db748509ce0f5b8c68cc55e8a2d250db7830fe364d66667` |
| IMPHASH | `f6ce08c0cf7798e8b58a99c4c1552f29` |
| TLSH | `T1FAD523A9BAF249B8C837C7B29F97F22DB01E37648BB08E57768919005D539885C37731` |
| SSDEEP | `49152:ZW6/dT0HDj/1EsR2UXox7nKRuKfwoFCxe+nn+yCZPXAJVZ2u6EP1ZN8U1KnbIWbc:ZW4YT1E+Yx7KTwoFCxb+yW/ATZzWU2Ym` |

#### Technical Assessment

- The sample is tracked as `RevStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RevStealer_039_30f1a885
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f1a88560497fdfe4058b60f4c1109f3f470c76b774a718c34e6c1a080219fd"
    family = "RevStealer"
    file_name = "6eq5gvOfRvNmCi54.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:20:35"
  condition:
    hash.sha256(0, filesize) == "30f1a88560497fdfe4058b60f4c1109f3f470c76b774a718c34e6c1a080219fd"
}
```

### Sample 40: `392bede600c5f320`

| Field | Value |
|---|---|
| SHA-256 | `392bede600c5f3202b72e34b0c84d9aad85bf9e8bfed7811e7043410c09b03eb` |
| Family label | `unknown` |
| File name | `24453f26fd490c42009a19e91881e1a1.exe` |
| File type | `exe` |
| First seen | `2026-10-13 06:17:31` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24453f26fd490c42009a19e91881e1a1` |
| SHA-1 | `df5cd4004ff8e80b5c55e96024d183e54f9f02f5` |
| SHA-256 | `392bede600c5f3202b72e34b0c84d9aad85bf9e8bfed7811e7043410c09b03eb` |
| SHA3-384 | `be8b22e231082f4c5237e780c8d66fe71cef68d24731e8566d6532682014fb36e15cfc0c00e37e36d7a7c908f67e5855` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T191C47D2736924F21C29D1733D1D79400C3EA964336ABEB2B3585239A1D463FFDA0A797` |
| SSDEEP | `12288:WC4WemA5XyLR2u6BxGaRANkYE62wzkYV957YeBpYFJ:R4WmsR2u6BxNC9+wNTBpYF` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_392bede6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392bede600c5f3202b72e34b0c84d9aad85bf9e8bfed7811e7043410c09b03eb"
    family = "unknown"
    file_name = "24453f26fd490c42009a19e91881e1a1.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:17:31"
  condition:
    hash.sha256(0, filesize) == "392bede600c5f3202b72e34b0c84d9aad85bf9e8bfed7811e7043410c09b03eb"
}
```

### Sample 41: `971a006d7ad0618b`

| Field | Value |
|---|---|
| SHA-256 | `971a006d7ad0618bf25aad494adda105c4e0544ae62081577f5be26eb6ba73de` |
| Family label | `unknown` |
| File name | `LX_Cyglye5QY5.js` |
| File type | `js` |
| First seen | `2026-10-13 06:17:19` |
| Reporter | `abuse_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eb131d9ff33a76c90b7bd4e3b637e88b` |
| SHA-1 | `33601cde4a8ac1667f686335150fc2188d72f1b4` |
| SHA-256 | `971a006d7ad0618bf25aad494adda105c4e0544ae62081577f5be26eb6ba73de` |
| SHA3-384 | `75054785439856371c851d1a7914aa61240e0d83d32433b0486a800592deeff12da41aa2619fbc2bf7ee0ad657f7fc9f` |
| TLSH | `T1ECD50414DE6714BCBC2FA4034BAE5E5509BB5A131520C882756EB4CFCF1A85B6C3A8FD` |
| SSDEEP | `24576:r92pDipkMp0AumuGEMe0PJvD5bWVky2rziW4VtEWAHYd0jR3IEOIV3DJga1EAwzH:r91peCJVlrzWzE6iWIVA1zeq5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_971a006d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "971a006d7ad0618bf25aad494adda105c4e0544ae62081577f5be26eb6ba73de"
    family = "unknown"
    file_name = "LX_Cyglye5QY5.js"
    file_type = "js"
    first_seen = "2026-10-13 06:17:19"
  condition:
    hash.sha256(0, filesize) == "971a006d7ad0618bf25aad494adda105c4e0544ae62081577f5be26eb6ba73de"
}
```

### Sample 42: `b22a88e0510e60d9`

| Field | Value |
|---|---|
| SHA-256 | `b22a88e0510e60d9b4c447794c67da462d73ac4e774bdff1977f8cef1b38e7b3` |
| Family label | `unknown` |
| File name | `fade9fc65c0c51f683156c8296cf55a4.exe` |
| File type | `exe` |
| First seen | `2026-10-13 06:16:19` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fade9fc65c0c51f683156c8296cf55a4` |
| SHA-1 | `4a1b639a215c8761ccb0f19a0bb3e66cb2d29592` |
| SHA-256 | `b22a88e0510e60d9b4c447794c67da462d73ac4e774bdff1977f8cef1b38e7b3` |
| SHA3-384 | `c1813025aac9f11bc7e5439b157081d77e0abbeae7c41e4179d0132738849b66923bd7b1eb7160ea00bae62187e7c856` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1D406F107BB998299FE2B4F385A76470AD371F8614B66D3CF51841AE9ED537C00E29383` |
| SSDEEP | `49152:JS0WffMmhJWvk0L56JsVfYqAQV9jW3wQkRibLQf28Kadqn4mN8/Ei8xXErMLFvA7:k0WffRsk0Lw6KeVqpK6ld0Rit2` |
| ICON-DHASH | `e0f0e4c8e2f0d888` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_b22a88e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b22a88e0510e60d9b4c447794c67da462d73ac4e774bdff1977f8cef1b38e7b3"
    family = "unknown"
    file_name = "fade9fc65c0c51f683156c8296cf55a4.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:16:19"
  condition:
    hash.sha256(0, filesize) == "b22a88e0510e60d9b4c447794c67da462d73ac4e774bdff1977f8cef1b38e7b3"
}
```

### Sample 43: `425fddfc0b8f3b30`

| Field | Value |
|---|---|
| SHA-256 | `425fddfc0b8f3b3044dcc4c75dac56bee233784bf3977d620f49f4d280f26fe9` |
| Family label | `Mirai` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-13 06:15:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1dc992fce4d02539dad327c362e62cc5` |
| SHA-1 | `d153818c7711ffe644dd5db243098b9be1dc8f38` |
| SHA-256 | `425fddfc0b8f3b3044dcc4c75dac56bee233784bf3977d620f49f4d280f26fe9` |
| SHA3-384 | `46ca31c2a9c786e7f14a2e9124e377a1f302c8aa001a5e5b698a63610190aa60e4ce276b0813a6e79672ade3d91bb31e` |
| TLSH | `T1D8142B85F8519E23C7C1567BFB1E428C372B1778D2EE31029E156F20379B86B0E7A652` |
| TELFHASH | `t1693125348b881dfc27d0908f40aeb33be3b235b53b151815bf5bae86aa53de17911436` |
| SSDEEP | `6144:Ju9ZLEa7o2ldcN6SlrdLFYVG4t/+qF2J8l6Ub:UZd02ld8CG4t/+e2IBb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_425fddfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "425fddfc0b8f3b3044dcc4c75dac56bee233784bf3977d620f49f4d280f26fe9"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-13 06:15:57"
  condition:
    hash.sha256(0, filesize) == "425fddfc0b8f3b3044dcc4c75dac56bee233784bf3977d620f49f4d280f26fe9"
}
```

### Sample 44: `86c5d22a1b6525bb`

| Field | Value |
|---|---|
| SHA-256 | `86c5d22a1b6525bb6083aa538b2956ec45d4886deddff1db180166a8202e6369` |
| Family label | `unknown` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-10-13 06:10:42` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1f911823ae989bd92de4381f6adfcbd1` |
| SHA-1 | `fde175facb09a3f96368a0ef177eaefbce4b3e9e` |
| SHA-256 | `86c5d22a1b6525bb6083aa538b2956ec45d4886deddff1db180166a8202e6369` |
| SHA3-384 | `421928950f2667fd3e58b8efb7ee91f800ca1551d676215d36cbe8d1cc21558862f3e9e599aaa056cf619875cc930a95` |
| TLSH | `T192666B49BC1E6462D5C979B52F6302957A38BC889FC2C7236614BB3CBAF17A4CF13161` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:kGfgTahtUjjHZ8U6qOsWXLlQNSkpYL+38HyOnMREHsY5fJj+5EZ:kGfg2htUjl/HWXxmb6yVRAsY5JUEZ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_86c5d22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c5d22a1b6525bb6083aa538b2956ec45d4886deddff1db180166a8202e6369"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-13 06:10:42"
  condition:
    hash.sha256(0, filesize) == "86c5d22a1b6525bb6083aa538b2956ec45d4886deddff1db180166a8202e6369"
}
```

### Sample 45: `e70ffd7f676b97c9`

| Field | Value |
|---|---|
| SHA-256 | `e70ffd7f676b97c9884d248b00d4bd264b488bea0cfb940fcd1cd2c16931d10f` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-13 06:10:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `409a73de7448c09314a232cb37964e63` |
| SHA-1 | `b293814cdb8df82dd4a45cca8189b81db78cd5d5` |
| SHA-256 | `e70ffd7f676b97c9884d248b00d4bd264b488bea0cfb940fcd1cd2c16931d10f` |
| SHA3-384 | `7526e0354ef2c366c2b46b181b43adf0ede1d837a6b34b704fc0a7f8f95f0037e2ee03551f596436672b78b88e44dde7` |
| TLSH | `T179E49D98BB8D7C43D387F33DDE8ACA71322BB5E59352D2A23901425DD4C6EA9CBB0541` |
| SSDEEP | `12288:wAFdB/rzHyUnRcr5z08SlvLDN2U2GoB4hJxZEp2pmAERAQs5y0Wc:wABZnRcr5zmxN2U2GoBGV+2sYv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_e70ffd7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e70ffd7f676b97c9884d248b00d4bd264b488bea0cfb940fcd1cd2c16931d10f"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-13 06:10:39"
  condition:
    hash.sha256(0, filesize) == "e70ffd7f676b97c9884d248b00d4bd264b488bea0cfb940fcd1cd2c16931d10f"
}
```

### Sample 46: `7394aecaeda4d0c2`

| Field | Value |
|---|---|
| SHA-256 | `7394aecaeda4d0c2fb3fdd5e2acd8fca82be731991130463bdf3344401f75f97` |
| Family label | `unknown` |
| File name | `start.exe` |
| File type | `exe` |
| First seen | `2026-10-13 06:09:44` |
| Reporter | `ghozt` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6c15f86fd05c4a84e392b183208708b1` |
| SHA-1 | `e6d73384c453305a8dc6c7a6af42353f58afb3fa` |
| SHA-256 | `7394aecaeda4d0c2fb3fdd5e2acd8fca82be731991130463bdf3344401f75f97` |
| SHA3-384 | `8c138f39cdc14966ee158e06ba271c0d1792b6f2ae7331d3e0e0e1a904d7bd9305b14020c96525c8598a33abddd4ee2e` |
| IMPHASH | `88016fcdef7f227c62171d0afad9aae4` |
| TLSH | `T15BB6233BF24B653EE06A56367EB29210453BBA6164134C5296FCF88CCF255B01E3E787` |
| SSDEEP | `196608:crY6MtBF1BXdl1bsSJL9IFS1t5Iv0cvo/x50umvovQNTD+gHCzMzEIBSQy:crYTRtldVn4Xv0t/fL8oIXzEIny` |
| ICON-DHASH | `5050d270cccc82ae` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_7394aeca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7394aecaeda4d0c2fb3fdd5e2acd8fca82be731991130463bdf3344401f75f97"
    family = "unknown"
    file_name = "start.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:09:44"
  condition:
    hash.sha256(0, filesize) == "7394aecaeda4d0c2fb3fdd5e2acd8fca82be731991130463bdf3344401f75f97"
}
```

### Sample 47: `3e38de4089d16371`

| Field | Value |
|---|---|
| SHA-256 | `3e38de4089d16371f2c6f2a49cd34da0877ff90392f430c8c88772927cd14a40` |
| Family label | `AgentTesla` |
| File name | `SOLICITUD DE COTIZACIÓN.JS` |
| File type | `js` |
| First seen | `2026-10-13 06:06:54` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d93b816f9a6727ee75e77929747f2c59` |
| SHA-1 | `19e7ddc9bd0033f63be90ed76b498abe464aa05d` |
| SHA-256 | `3e38de4089d16371f2c6f2a49cd34da0877ff90392f430c8c88772927cd14a40` |
| SHA3-384 | `22fffb592e5cc148f64662f96d3ed1fc61bb7cacf89d0111c1433efa60585fe21036030a81e16f1a632e7337e714b347` |
| TLSH | `T169F5935AF7289774653C2F0FC03AB6B45E29921732D5BFBD32E82114329171A275F8E2` |
| SSDEEP | `98304:bOJFAKgh+QxgKr+KvWLsFAQDVXqkzkXDStGrG/l+ZkfCumbqAwrtrOYa:bOJ7gqKr7vjANvStGrUEkqumGAE+` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_047_3e38de40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e38de4089d16371f2c6f2a49cd34da0877ff90392f430c8c88772927cd14a40"
    family = "AgentTesla"
    file_name = "SOLICITUD DE COTIZACIÓN.JS"
    file_type = "js"
    first_seen = "2026-10-13 06:06:54"
  condition:
    hash.sha256(0, filesize) == "3e38de4089d16371f2c6f2a49cd34da0877ff90392f430c8c88772927cd14a40"
}
```

### Sample 48: `21f53d2b3cf28862`

| Field | Value |
|---|---|
| SHA-256 | `21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92` |
| Family label | `AgentTesla` |
| File name | `New order PO-22609 Kawasan Perindustrian Bukit Raja.js` |
| File type | `js` |
| First seen | `2026-10-13 06:05:21` |
| Reporter | `lowmal3` |
| Tags | `AgentTesla, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5be4152aaeac8e446c823c0be1e9dbca` |
| SHA-1 | `4ef7570c3b894d64cc066d0d53cfcbc0601a32d1` |
| SHA-256 | `21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92` |
| SHA3-384 | `93f1e75561179b4fca8fb41c78c78a90d4167ba6a19a0aa2476ab8b346610758fcf1af10abf2e5534029889cef6a548c` |
| TLSH | `T1C1C48B5603550BBDF78D4EC5886F201B24F2E9667D241298EFB36AE7BC3FD849430629` |
| SSDEEP | `1536:Fg7Fl01OjpENLmv44bIaH77RFdnao9w+UUAPeVVDxAukBjy/rl6iNsyLqfMOa5ux:EjpEkDN/kvJwg5ID/m` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_048_21f53d2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
    family = "AgentTesla"
    file_name = "New order PO-22609 Kawasan Perindustrian Bukit Raja.js"
    file_type = "js"
    first_seen = "2026-10-13 06:05:21"
  condition:
    hash.sha256(0, filesize) == "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
}
```

### Sample 49: `20ef2e404fab9b92`

| Field | Value |
|---|---|
| SHA-256 | `20ef2e404fab9b92936af4ee20cddf5513cfb909fa5a8fb3a0f9c6b32ee2a17d` |
| Family label | `Formbook` |
| File name | `RFQ – Supply of Carbon Steel Pipes, Fittings, Flanges & Related Piping Materials (SHESB)_xlsx.wsf` |
| File type | `wsf` |
| First seen | `2026-10-13 06:01:45` |
| Reporter | `lowmal3` |
| Tags | `Formbook, wsf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b52fa366cd4751b66d48a1ba735b579` |
| SHA-1 | `ab1e506182487b823e6e9c0b8632e62bfe1e96da` |
| SHA-256 | `20ef2e404fab9b92936af4ee20cddf5513cfb909fa5a8fb3a0f9c6b32ee2a17d` |
| SHA3-384 | `b87225c674c203402f88e74eb90edd1ffd11753a8c74c3a6b9e6e9a3171af737aa247535f4936fd5a08185f6f38918e0` |
| TLSH | `T19FD2DC045986B49063726B7BA72AA8E5F7370A6701848907B87C7884EFF1D09DEF4DB1` |
| SSDEEP | `768:vHfrI66g60sBmvn+UkpT1bJDlgvc1VkUGFoze1Mj8520+P8g2r7xfFvlocCs96xY:PfrtsBmv4OVxfFFt` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `wsf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_049_20ef2e40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20ef2e404fab9b92936af4ee20cddf5513cfb909fa5a8fb3a0f9c6b32ee2a17d"
    family = "Formbook"
    file_name = "RFQ – Supply of Carbon Steel Pipes, Fittings, Flanges & Related Piping Materials (SHESB)_xlsx.wsf"
    file_type = "wsf"
    first_seen = "2026-10-13 06:01:45"
  condition:
    hash.sha256(0, filesize) == "20ef2e404fab9b92936af4ee20cddf5513cfb909fa5a8fb3a0f9c6b32ee2a17d"
}
```

### Sample 50: `125625a137697c38`

| Field | Value |
|---|---|
| SHA-256 | `125625a137697c38b44d050d3a0f96d9ce885bfe7410cf3b82affdd9de36e77c` |
| Family label | `unknown` |
| File name | `bot_linux_x86_32` |
| File type | `elf` |
| First seen | `2026-10-13 06:01:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `badafd3bc00ef0776ebd27a02c363137` |
| SHA-1 | `63f159c794e456a8a08d284467cfd867e1245d21` |
| SHA-256 | `125625a137697c38b44d050d3a0f96d9ce885bfe7410cf3b82affdd9de36e77c` |
| SHA3-384 | `64e95c3ebfbc64ad7941c2945e338f2c7ae4e267e26e56e79fc30f2e33614b56f6a5a078e36481e0a3c9168154283eb4` |
| TLSH | `T16DD64951FACB50F6EA031D7094AFA22F23315D058B24DBC7D7947F19F937AA2193A218` |
| TELFHASH | `t16533c273059da4e867f04407826f7124cff6e0b766e478f118e67cc1da72c83a626979` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `393216:f5eaiW5hhvu++91c4q+RV/q+2W3z+SG648p9E8sk:S` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_125625a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "125625a137697c38b44d050d3a0f96d9ce885bfe7410cf3b82affdd9de36e77c"
    family = "unknown"
    file_name = "bot_linux_x86_32"
    file_type = "elf"
    first_seen = "2026-10-13 06:01:39"
  condition:
    hash.sha256(0, filesize) == "125625a137697c38b44d050d3a0f96d9ce885bfe7410cf3b82affdd9de36e77c"
}
```

### Sample 51: `06690169576f8b79`

| Field | Value |
|---|---|
| SHA-256 | `06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5` |
| Family label | `unknown` |
| File name | `bot_linux_x86_32` |
| File type | `elf` |
| First seen | `2026-10-13 06:00:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3e43554db87cc8f25cab37cac13aa35` |
| SHA-1 | `d303a481b006324be86503a30b834e833d24c86a` |
| SHA-256 | `06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5` |
| SHA3-384 | `916182146bb6e9f4ebb61b6a3ec41b9d00aeb41384a975a30ee1e1db271634278c0f697902c8607a9022c8699141bd5a` |
| TLSH | `T11EF533CC80F0CF0134F6D817BEE3A9D0C7B53AADC4DAA4626E99379C9578893456F462` |
| TELFHASH | `t16fb0110c2cfc382800e2f0828a8ab200000a20bcb00a088c2302c2022ac82c2efa0c0a` |
| SSDEEP | `98304:eZxikIfEyRtZNnAZnHZHMgKWpCODuZbQICGI3k9n:ITIv/n4PCOCZ0IE36n` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_06690169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5"
    family = "unknown"
    file_name = "bot_linux_x86_32"
    file_type = "elf"
    first_seen = "2026-10-13 06:00:34"
  condition:
    hash.sha256(0, filesize) == "06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5"
}
```

### Sample 52: `6662803a648165e0`

| Field | Value |
|---|---|
| SHA-256 | `6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19` |
| Family label | `unknown` |
| File name | `game_library.dll` |
| File type | `exe` |
| First seen | `2026-10-13 05:58:23` |
| Reporter | `Kejult` |
| Tags | `agent, dll, exe, fakeVAC, injector, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ade148d2cf09f4fa3005bd7ad8a45f2d` |
| SHA-1 | `8be4fe080f3f3e76a1e30436eff555b2822c5af5` |
| SHA-256 | `6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19` |
| SHA3-384 | `4b3b3938640e257286a89cde65f664aefcde8d04734ea85efcbc96bc6c30016726b2524eeed46a0960de88f44e84d145` |
| IMPHASH | `27f2ebf515707ac20c1dff0115b66291` |
| TLSH | `T1ADD35B5BB3A500BFE137C67C99A34605D772B80957619BEF23A0422A1F27BD49D3DB20` |
| SSDEEP | `3072:Pnsn5g1DulhnedZXdICPZkortDDG8IS4OPkzU+R9Yo3K:PsflheHdD1hDSVj3` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_6662803a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19"
    family = "unknown"
    file_name = "game_library.dll"
    file_type = "exe"
    first_seen = "2026-10-13 05:58:23"
  condition:
    hash.sha256(0, filesize) == "6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19"
}
```

### Sample 53: `4eab4e848a9e9802`

| Field | Value |
|---|---|
| SHA-256 | `4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad` |
| Family label | `unknown` |
| File name | `dsound.dll` |
| File type | `exe` |
| First seen | `2026-10-13 05:57:43` |
| Reporter | `Kejult` |
| Tags | `dll, exe, stealer, steamstealer, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60afa57a267f7cf330a6b11eb1b299f5` |
| SHA-1 | `e5f69feb9810bd40435adb662edd0e2e41bafd84` |
| SHA-256 | `4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad` |
| SHA3-384 | `a401612e542134abd0877b697d537752dc3d325ea051fdf0c004adc05f7ca5d81fca85c6c6af1862a1e13830ed511233` |
| IMPHASH | `a5f69b72a4835304c2c1d3683b17d41b` |
| TLSH | `T1C186BF6AF2B80059E866C5BDC2976327E772B82413B057CF1A6496F51F73BD01ABB700` |
| SSDEEP | `98304:GGnnnnnP7xww5ayuVtQB46vG6Qgbh0+rBoK8dkBXqm+g0NxcCZw:JxLayuVtQa6vG6Qg10oQdkBNCO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_4eab4e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad"
    family = "unknown"
    file_name = "dsound.dll"
    file_type = "exe"
    first_seen = "2026-10-13 05:57:43"
  condition:
    hash.sha256(0, filesize) == "4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad"
}
```

### Sample 54: `313fb55ebf313280`

| Field | Value |
|---|---|
| SHA-256 | `313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9` |
| Family label | `Vidar` |
| File name | `313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9.bin` |
| File type | `exe` |
| First seen | `2026-10-13 05:55:33` |
| Reporter | `anonymous` |
| Tags | `exe, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd6d9e700b7ad9cf0b75a73fb2a4c3a3` |
| SHA-1 | `bd826bb01253546288fea61c5b88e3979bacd93a` |
| SHA-256 | `313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9` |
| SHA3-384 | `cfe1db79d84fce66d6ddf7ca25e3c40d92beb21f44f71ed796547401d469c0a49530ed00e579fa18a3bbc816bb6cde60` |
| IMPHASH | `7ecc3b9e18c31c23f5275a91f6c533d1` |
| TLSH | `T16AC59D46BD9009B6D1AA933189F65251773CF8980B2323C72F60B2BA2F777E45E78354` |
| SSDEEP | `49152:hI1HRxTsZEfPovFjMD1AabgxBBq1TfTwpgva29oKOSgkwuUC5:GwHvFbaMoHVKiUe` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_054_313fb55e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9"
    family = "Vidar"
    file_name = "313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9.bin"
    file_type = "exe"
    first_seen = "2026-10-13 05:55:33"
  condition:
    hash.sha256(0, filesize) == "313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9"
}
```

### Sample 55: `0ffa713642813fd0`

| Field | Value |
|---|---|
| SHA-256 | `0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd` |
| Family label | `Mirai` |
| File name | `pid.ppc` |
| File type | `elf` |
| First seen | `2026-10-13 05:54:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fa9bc6549b05b68d659386568d9ffad` |
| SHA-1 | `37e162f52e1714eb428f279e7436efedd56d163c` |
| SHA-256 | `0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd` |
| SHA3-384 | `667eb4f914ac376e818c80646579584977f98f0a4e4769881e286a1e899d6c57510180c40f7591ce70a5e83d141bbb93` |
| TLSH | `T16E942A44B3B1D3CBD294DE7053362E2B9B6A463238E7B189610FBA73137317545DABA0` |
| SSDEEP | `6144:2r1SFIPuLrbhx1TszNEp3/P465LiDOqiGlJWzKihD6GJ1HsJZLlcT8uAzqza1:41mHP54O/K7UMNqza1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_0ffa7136
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd"
    family = "Mirai"
    file_name = "pid.ppc"
    file_type = "elf"
    first_seen = "2026-10-13 05:54:45"
  condition:
    hash.sha256(0, filesize) == "0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd"
}
```

### Sample 56: `f2a74507f0c0660e`

| Field | Value |
|---|---|
| SHA-256 | `f2a74507f0c0660e1a22e7d2d011529a44347289ff2f1b122ed3e901470aac5f` |
| Family label | `Mirai` |
| File name | `pid.arm6` |
| File type | `elf` |
| First seen | `2026-10-13 05:54:42` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47d120e52097a13a0f089757d962379d` |
| SHA-1 | `d700e1dbfb9aa12bcd5b092d98e658a1eb9ad151` |
| SHA-256 | `f2a74507f0c0660e1a22e7d2d011529a44347289ff2f1b122ed3e901470aac5f` |
| SHA3-384 | `4a0b64521f6274f7d35e25e843d6786c18694813f09fcfc06d749f9466d6f63480262478643cf37b45cae950f47635fd` |
| TLSH | `T159840988E1F0E7DAD2D4AA75B319790E3B230735B1D73146A51DFE3223EB1490ABD921` |
| TELFHASH | `t183f02b85d88c66b0f2336bf04abda100a3be1a02ce630ca38001b23f9243dc360c2807` |
| SSDEEP | `6144:pu11vskNKBAvM08vu3qBbSJ7MvgXmBkbVXwaPwFn02ahipxjYFMa9w:Q8hTvYqhG602Eria9w` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_056_f2a74507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2a74507f0c0660e1a22e7d2d011529a44347289ff2f1b122ed3e901470aac5f"
    family = "Mirai"
    file_name = "pid.arm6"
    file_type = "elf"
    first_seen = "2026-10-13 05:54:42"
  condition:
    hash.sha256(0, filesize) == "f2a74507f0c0660e1a22e7d2d011529a44347289ff2f1b122ed3e901470aac5f"
}
```

### Sample 57: `38f02f4a4eb8d829`

| Field | Value |
|---|---|
| SHA-256 | `38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d` |
| Family label | `Mirai` |
| File name | `38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d.sh` |
| File type | `sh` |
| First seen | `2026-10-13 05:48:43` |
| Reporter | `abuse_ch` |
| Tags | `Mirai, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a454b8a2eff7165bff3a07cc5033e1c9` |
| SHA-1 | `50543b19b6c32a74ff840df180f66225b5cd9256` |
| SHA-256 | `38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d` |
| SHA3-384 | `7e2c301758360280b74f44e3ada41e40cfc6d971519a8ae61df2fd33148fe8899bc2a4166adde86d095777909231d1c2` |
| TLSH | `T16552463720F08B3297D011C9A2771B614F729B0B456614B9F4FE2725AF2DA0371EBB61` |
| SSDEEP | `384:T0p4hvZ5m5FGGoKNphvY8MNbVIiE3A6NL:QpUiVN7V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_38f02f4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d"
    family = "Mirai"
    file_name = "38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d.sh"
    file_type = "sh"
    first_seen = "2026-10-13 05:48:43"
  condition:
    hash.sha256(0, filesize) == "38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d"
}
```

### Sample 58: `4777c49910b352e3`

| Field | Value |
|---|---|
| SHA-256 | `4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79` |
| Family label | `SloppyRAT` |
| File name | `4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79.bin` |
| File type | `ps1` |
| First seen | `2026-10-13 05:45:35` |
| Reporter | `Tuxxin` |
| Tags | `ps1, SloppyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b45477d1c39b4b5b54ffcb00de143cee` |
| SHA-1 | `e5ce303b956aab46db234afcdfbfb837e23531a4` |
| SHA-256 | `4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79` |
| SHA3-384 | `377ce7260c08c6ce72106c9a3fa3e7f3afb0ab02f86a9c25f92b29fc3c8e2d7482d0b6ae7b656cca0563908b2ebe410a` |
| TLSH | `T13911637109EAB5B0250089C2D77A77888B6100CBF65A389A53CEA190A2244C94B423F4` |
| SSDEEP | `24:FQUGjhtHokrmGSHrPhxfjrBlr62XyCYza:FQhhtIk6JHfDr6OpJ` |

#### Technical Assessment

- The sample is tracked as `SloppyRAT` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SloppyRAT_058_4777c499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79"
    family = "SloppyRAT"
    file_name = "4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79.bin"
    file_type = "ps1"
    first_seen = "2026-10-13 05:45:35"
  condition:
    hash.sha256(0, filesize) == "4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79"
}
```

### Sample 59: `b2a327241ee8fdf5`

| Field | Value |
|---|---|
| SHA-256 | `b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6` |
| Family label | `Formbook` |
| File name | `b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6.exe` |
| File type | `exe` |
| First seen | `2026-10-13 05:41:02` |
| Reporter | `Tuxxin` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a5bf0a3dfaa2def2eef649c06f50764` |
| SHA-1 | `4818c02fef49bc411e54a74247543d940de655a9` |
| SHA-256 | `b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6` |
| SHA3-384 | `a599def9fc7dea78b632a3a14673921211d5975627fec1c74e3c75e9fa4b50b0883b3d333c4d4d6aad2c877107f58537` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1CCF41219669CC127D96B0F7A19A2D230177B6DDEAA30C716AFE11DCF3A37B400624B53` |
| SSDEEP | `12288:obT8E1uK4b7bANf5afgy6DKiisbQ+/eBIbkSiM3h0PkXPP2yDGW8cvNtqHu0t:obTHuJryogy6+KbQ+GBEzD/3rqO` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_059_b2a32724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6"
    family = "Formbook"
    file_name = "b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6.exe"
    file_type = "exe"
    first_seen = "2026-10-13 05:41:02"
  condition:
    hash.sha256(0, filesize) == "b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6"
}
```

### Sample 60: `68ce321d9ca45f9f`

| Field | Value |
|---|---|
| SHA-256 | `68ce321d9ca45f9f206b03be37395880a124cf7616f65523725e9a6863275505` |
| Family label | `Mirai` |
| File name | `arm8` |
| File type | `elf` |
| First seen | `2026-10-13 05:37:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1598933464525c3c53664a021ed26986` |
| SHA-1 | `bd53f28a2b52b0c63ba9702ee008b3107de2b536` |
| SHA-256 | `68ce321d9ca45f9f206b03be37395880a124cf7616f65523725e9a6863275505` |
| SHA3-384 | `f96e197440deb366447437e8f317379a2a380ccaf05e195973ec2f9ce776b524326f360c0c9d597aa402df0dd224d462` |
| TLSH | `T1EA843B8CD2FAE7CEE298FA7952257D17683225793093B1D6210EF56B53EB1C448F9830` |
| SSDEEP | `6144:jP45eHDiOSpMbVUlmPej2AAnu79futYKZa9Wg:U5eH29EPej5Agqa9W` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_68ce321d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68ce321d9ca45f9f206b03be37395880a124cf7616f65523725e9a6863275505"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-13 05:37:20"
  condition:
    hash.sha256(0, filesize) == "68ce321d9ca45f9f206b03be37395880a124cf7616f65523725e9a6863275505"
}
```

### Sample 61: `bd809b2f625d640a`

| Field | Value |
|---|---|
| SHA-256 | `bd809b2f625d640a21fc9418538b686639b719f09e6c2efacffa49a7be3f613a` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-13 05:37:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Ngioweb` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58f446cdc4d0f1abb6158f5df4b9c636` |
| SHA-1 | `7fb7b76f50d9fce2ed6cf1ecc8ec2b452b435988` |
| SHA-256 | `bd809b2f625d640a21fc9418538b686639b719f09e6c2efacffa49a7be3f613a` |
| SHA3-384 | `1e8e828c24ff982508185b72bd49769259990e967febef2d932c6d409e9950e03f75e02b00b5687cb00414d7e19ba864` |
| TLSH | `T173840A88E1E0E7DAD2D4AA75B319790D3B630735B0D73146A51AFE3223EB1490AFDD21` |
| TELFHASH | `t1b3f02710c04c80f9a27b99840ebd22e2d534526d9b0bbae30602f6be9da68c16153c16` |
| SSDEEP | `6144:1zwxZgGrsKRaAEImnAJ2I/xAKsUXaLiQaU+HIYoT8wqcOjae6rN9Lk7ma9Q:+ZrspAHZJnMiPUqgOjn2ja9Q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_bd809b2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd809b2f625d640a21fc9418538b686639b719f09e6c2efacffa49a7be3f613a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-13 05:37:18"
  condition:
    hash.sha256(0, filesize) == "bd809b2f625d640a21fc9418538b686639b719f09e6c2efacffa49a7be3f613a"
}
```

### Sample 62: `b19f095b2d90e780`

| Field | Value |
|---|---|
| SHA-256 | `b19f095b2d90e78011178060d8d63aff1c285c5be25f2df949dd8ada442889ff` |
| Family label | `Mirai` |
| File name | `ppc64` |
| File type | `elf` |
| First seen | `2026-10-13 05:37:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6164c5426639fa21d594c9deabe2297e` |
| SHA-1 | `9d5575647460671190640ff98862d207c4e34e39` |
| SHA-256 | `b19f095b2d90e78011178060d8d63aff1c285c5be25f2df949dd8ada442889ff` |
| SHA3-384 | `419d5a3298e8b2059f9b44e497848f60583b095a4c6854c1eee77891f3034b594a29025f5c6b64c6a7dbb4ef1eac3cd9` |
| TLSH | `T1AC941A44A3F1D2DAD244AEB493227F169B72053634F7B286324EBB7313F327545DAA60` |
| SSDEEP | `6144:8WjbVXi9S61iyu7Bq82T70aWcjwG03h9LoEfW4MBXji9liZbv:xbUMtzaBwG6LofXGnsv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_b19f095b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19f095b2d90e78011178060d8d63aff1c285c5be25f2df949dd8ada442889ff"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-13 05:37:16"
  condition:
    hash.sha256(0, filesize) == "b19f095b2d90e78011178060d8d63aff1c285c5be25f2df949dd8ada442889ff"
}
```

### Sample 63: `e4023b4b7a693fb1`

| Field | Value |
|---|---|
| SHA-256 | `e4023b4b7a693fb18338f8a1c9c3c2998c6d3150dcf2528dec5025840e44036f` |
| Family label | `Mirai` |
| File name | `EkSgbins.sh` |
| File type | `sh` |
| First seen | `2026-10-13 05:31:56` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `37554937e4a70b3792db7ff666639a8a` |
| SHA-1 | `330e4cf7c6cafb262d209d89cb84365ef326ccca` |
| SHA-256 | `e4023b4b7a693fb18338f8a1c9c3c2998c6d3150dcf2528dec5025840e44036f` |
| SHA3-384 | `b01f301760432369037e92cbe8851f6ca2455373efbd77f672445bb91ee587e064202b60cdfa9cf5035c3d8d1b0fbf11` |
| TLSH | `T15C319BCB22A24B706CE1EA27327D840475D5EAC736C65FADBCDC38E541CDE09B010693` |
| SSDEEP | `12:q0Ft9V0FtL0Fdc43fX0FeeekX0Fkk0FhX0F71FZ0FoEX0Ft0F9V8po0FsO0FN:vD+mdc4keasOhs7+oEsG4JuN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_e4023b4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4023b4b7a693fb18338f8a1c9c3c2998c6d3150dcf2528dec5025840e44036f"
    family = "Mirai"
    file_name = "EkSgbins.sh"
    file_type = "sh"
    first_seen = "2026-10-13 05:31:56"
  condition:
    hash.sha256(0, filesize) == "e4023b4b7a693fb18338f8a1c9c3c2998c6d3150dcf2528dec5025840e44036f"
}
```

### Sample 64: `ad0d27bee2efabe5`

| Field | Value |
|---|---|
| SHA-256 | `ad0d27bee2efabe56d584238d605fafd6ad6edbfae29b8a86f6b0c1bce4e1a2a` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da6a9e1589bb919f83977b477a4c83a9` |
| SHA-1 | `4055631504519f90220a859ed6d5c5ba7fc34160` |
| SHA-256 | `ad0d27bee2efabe56d584238d605fafd6ad6edbfae29b8a86f6b0c1bce4e1a2a` |
| SHA3-384 | `3cd708f8f0a3a1628ec0f06d9d23813281d74293e0502539d0f315cb9472afd75461a55d268ca0d2a0efbc284b0d6ddf` |
| TLSH | `T1C0842888E2F3E2FEE159E9701326B91B5D3146377093F685E39E693352B724041EEA34` |
| TELFHASH | `t12c71c500ae1ad878fb760ec5c6fa40aa4add465fd32b0a108797b93b1e4fcd31055d63` |
| SSDEEP | `6144:QlEFPbud6K+gAFziayYMSCcmnWaP4nO/cghQ87HcPa90:QmFDOXfAFuayY3CcmF/HQ878Pa90` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_ad0d27be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad0d27bee2efabe56d584238d605fafd6ad6edbfae29b8a86f6b0c1bce4e1a2a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:51"
  condition:
    hash.sha256(0, filesize) == "ad0d27bee2efabe56d584238d605fafd6ad6edbfae29b8a86f6b0c1bce4e1a2a"
}
```

### Sample 65: `34c3c6f2d3920e86`

| Field | Value |
|---|---|
| SHA-256 | `34c3c6f2d3920e8643cdbd0bd7e66bba8d2a066ddd9e3eacd8c19b1c7694bce7` |
| Family label | `Mirai` |
| File name | `bot.ppc440` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8c4d1b5d320b0da4ece3353fea686201` |
| SHA-1 | `9bb8244bba4d57e4d76afe5a67778093ef7f081f` |
| SHA-256 | `34c3c6f2d3920e8643cdbd0bd7e66bba8d2a066ddd9e3eacd8c19b1c7694bce7` |
| SHA3-384 | `be222c07feffbfa51a54facef32af2a9b078163a81f83dba7512902dc8ea6890e0be3a1a114da8a16a3e0561c29aa68b` |
| TLSH | `T151530842BB0E8F03C1532DF026B717E18396BD6629B6D184B51AFDC98371DF1A506EE8` |
| SSDEEP | `1536:dhWqqUGy0giWdM7wTJW3nlI0NGxrpRpKb:mqq3Dz7ZnlIzxrdKb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_34c3c6f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34c3c6f2d3920e8643cdbd0bd7e66bba8d2a066ddd9e3eacd8c19b1c7694bce7"
    family = "Mirai"
    file_name = "bot.ppc440"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:48"
  condition:
    hash.sha256(0, filesize) == "34c3c6f2d3920e8643cdbd0bd7e66bba8d2a066ddd9e3eacd8c19b1c7694bce7"
}
```

### Sample 66: `3cc6e26d1ac6aa7e`

| Field | Value |
|---|---|
| SHA-256 | `3cc6e26d1ac6aa7e804a51dbebb7edd134e3e48097b0bce49a85d1e1b0671e3a` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da76930e792a0e803c37181168ddda86` |
| SHA-1 | `2e6341bfc470467707abdd3355c6f5f630971c49` |
| SHA-256 | `3cc6e26d1ac6aa7e804a51dbebb7edd134e3e48097b0bce49a85d1e1b0671e3a` |
| SHA3-384 | `0389f7c553541845d8db6b5b3deac758615cba018afcd11b0a30b031c61abb97eaccc979139a9d5fedd09e96eab37d36` |
| TLSH | `T12CE31930D4504B17C2D213FAA69E825E3F221FA793D733115B38BAB41FE279A1D69924` |
| TELFHASH | `t187313122943546142fb39928acbd56b315222f2363993e716f26c5cc492b0e2e93ad5f` |
| SSDEEP | `3072:Z41HOuaGVV3NfHUOjqylGqCw3jkmhxQwoVZUNu:Ze3aGVVdqylGq1jkmhxQwoVZUNu` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_3cc6e26d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cc6e26d1ac6aa7e804a51dbebb7edd134e3e48097b0bce49a85d1e1b0671e3a"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:46"
  condition:
    hash.sha256(0, filesize) == "3cc6e26d1ac6aa7e804a51dbebb7edd134e3e48097b0bce49a85d1e1b0671e3a"
}
```

### Sample 67: `7322610f54ac4135`

| Field | Value |
|---|---|
| SHA-256 | `7322610f54ac41353161f90b35f975125eb65dedb5933c280ed197c8f6638749` |
| Family label | `Mirai` |
| File name | `powerpc` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e28a62dcf04b24368f24cdf2919ef1b3` |
| SHA-1 | `760228453f1a33fb9b523faf1887bc2028239d04` |
| SHA-256 | `7322610f54ac41353161f90b35f975125eb65dedb5933c280ed197c8f6638749` |
| SHA3-384 | `0b9ea2bc056506246ee72c2eafe17c7aa6b6cf2a848e43547e22ff7bccb4e230f9c23906c4c3cd3343ec764324ed4482` |
| TLSH | `T1C4B32B37A61C0B43C49B55F02CB77BF24F69AEA312A611C4A309FED04B73AB12551F99` |
| TELFHASH | `t154219622503542182fb3d928acbc567311222b2363987f716f26c0cc08370e2e93ad4f` |
| SSDEEP | `3072:Uvc29uyIcxE/sZxw+Oq6KZmm/QcuLmH26PNb:Uvl9jIg4sZxjOj4mm/QcuLmH26PNb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_7322610f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7322610f54ac41353161f90b35f975125eb65dedb5933c280ed197c8f6638749"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:43"
  condition:
    hash.sha256(0, filesize) == "7322610f54ac41353161f90b35f975125eb65dedb5933c280ed197c8f6638749"
}
```

### Sample 68: `dc2adaa551af3e6f`

| Field | Value |
|---|---|
| SHA-256 | `dc2adaa551af3e6fa6a76ec4f9c9599e39da33705dc22fe186d52f4b3c57a074` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef23775acf1177b44e7eaf6fa4a5b8c0` |
| SHA-1 | `3f261d6fdc734c416211e9604ae3a462d51818b6` |
| SHA-256 | `dc2adaa551af3e6fa6a76ec4f9c9599e39da33705dc22fe186d52f4b3c57a074` |
| SHA3-384 | `c7cd000526e0cea5a704d0b8a24e993b316b8fdf60b417450fd038afd98e11f460b06c0effec28a49b7c3c661e883741` |
| TLSH | `T1D3A3F972E642CA72C44306F102A79A6B0D21BE7B0A3A5E86F31C3DB49F334C97555F59` |
| TELFHASH | `t195317722553546142fb3d928acfd56b315222b2363587f716f26c48c49370e2e93dd4f` |
| SSDEEP | `3072:SOGAEtZoGZKWl6u4YTnbHnbimmFVcqq0G27ZT:SqEtZ755nbHnbimmFVcqq0G27ZT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_dc2adaa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc2adaa551af3e6fa6a76ec4f9c9599e39da33705dc22fe186d52f4b3c57a074"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:40"
  condition:
    hash.sha256(0, filesize) == "dc2adaa551af3e6fa6a76ec4f9c9599e39da33705dc22fe186d52f4b3c57a074"
}
```

### Sample 69: `8323cf5a01e889ab`

| Field | Value |
|---|---|
| SHA-256 | `8323cf5a01e889abcb3bae7a498f4750fd4ad44f44495ca72fd42319cdd5560a` |
| Family label | `Gafgyt` |
| File name | `armv4l` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b13df36374726cbdab26b1e7f9c0f995` |
| SHA-1 | `0205f3f49228b9fd3986f06c4bba57594b17f92a` |
| SHA-256 | `8323cf5a01e889abcb3bae7a498f4750fd4ad44f44495ca72fd42319cdd5560a` |
| SHA3-384 | `f5aa3a651d9019d49277e80fb35dca480496d0604e91fa46fd2d043181ad7292380bda15a1e1b2b4b45476e5d3cd84af` |
| TLSH | `T1B5D3F730E8044B1BC2D227F6A79E469E3F351EA7979733115A387DB02FF27992E25520` |
| TELFHASH | `t171217622513542182fb3d928acbd567315222b2363597f716f26c4cc49370e2e93ad4f` |
| SSDEEP | `3072:+DShVLkDZ6waCAdclbbYJOmP46aQyfPluesNb:VhVeZ6zclbboOmP46aQyfPluesNb` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_069_8323cf5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8323cf5a01e889abcb3bae7a498f4750fd4ad44f44495ca72fd42319cdd5560a"
    family = "Gafgyt"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:37"
  condition:
    hash.sha256(0, filesize) == "8323cf5a01e889abcb3bae7a498f4750fd4ad44f44495ca72fd42319cdd5560a"
}
```

### Sample 70: `3e95e873dedae3cb`

| Field | Value |
|---|---|
| SHA-256 | `3e95e873dedae3cbe5458444b3cca9270a7d8dfcc998eb79adc651a04c518413` |
| Family label | `Mirai` |
| File name | `i586` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d604a79500f555e8071f496a6f975b7d` |
| SHA-1 | `c5f07ff67eec7b6fb98257543e87e2f1e3090d63` |
| SHA-256 | `3e95e873dedae3cbe5458444b3cca9270a7d8dfcc998eb79adc651a04c518413` |
| SHA3-384 | `e4041ed6a2532111f1061e27ce6346104292933d1309827ab05c076179d2838dacf9c7ac5eedb82252c314a3b8b42982` |
| TLSH | `T188A30731A641C973D14305F211A7DB620D32FEBB1A6AAA96E36D3CB0DE360C1B561E5C` |
| TELFHASH | `t195317722553546142fb3d928acfd56b315222b2363587f716f26c48c49370e2e93dd4f` |
| SSDEEP | `3072:gjtwgA6UlYzZveohR9kIEofdGZmmFVcqq0G27ZT:gjhzt3mIEofAmmFVcqq0G27ZT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_3e95e873
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e95e873dedae3cbe5458444b3cca9270a7d8dfcc998eb79adc651a04c518413"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:34"
  condition:
    hash.sha256(0, filesize) == "3e95e873dedae3cbe5458444b3cca9270a7d8dfcc998eb79adc651a04c518413"
}
```

### Sample 71: `56c3e4dd1d1a7e32`

| Field | Value |
|---|---|
| SHA-256 | `56c3e4dd1d1a7e32c9fb9f43bf14d23bb4d5ece5aff9adf933c3bfde15cd26d5` |
| Family label | `Mirai` |
| File name | `sparc` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f76df268ff67f3bc24c93f89c6b2530a` |
| SHA-1 | `933e5aaf2998cfc8276d6ea4c55758db044cf21f` |
| SHA-256 | `56c3e4dd1d1a7e32c9fb9f43bf14d23bb4d5ece5aff9adf933c3bfde15cd26d5` |
| SHA3-384 | `6f9ce14c9fcee23147a291a45523dca74143d90e971fe1b7b2aa58f300698054b2ca79368c08e54c10fd7201cf6d254d` |
| TLSH | `T19AD3C73B27170E23C0C950B101E74332AE75DE9B34B952D7AAA07D686F37A843856BDD` |
| TELFHASH | `t13e215462513552182fb3d928acbd5a7316222a2363597e716f26c5cc48370e2e93ee4f` |
| SSDEEP | `3072:3v8G4ZNBQTZiNPR6Iwd9g+plAOhmm/QMurB12CGNb:RrUlklXmm/QMurB12CGNb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_56c3e4dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c3e4dd1d1a7e32c9fb9f43bf14d23bb4d5ece5aff9adf933c3bfde15cd26d5"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:32"
  condition:
    hash.sha256(0, filesize) == "56c3e4dd1d1a7e32c9fb9f43bf14d23bb4d5ece5aff9adf933c3bfde15cd26d5"
}
```

### Sample 72: `8141fb252441eb74`

| Field | Value |
|---|---|
| SHA-256 | `8141fb252441eb74264b6adf1d3e2c887620f3e1afcd0506186b936439ccd665` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f2401058ece3f010b5754c29f62e652` |
| SHA-1 | `097a4157d389688eca5a8819eb73399919a00e84` |
| SHA-256 | `8141fb252441eb74264b6adf1d3e2c887620f3e1afcd0506186b936439ccd665` |
| SHA3-384 | `53488372b1ac4c80a39ef2932e15e26ea2d30fd3cb2278c1d015e4b2b0101e0604f5134bcbbb1995e1d7a0be312b6149` |
| TLSH | `T1D5C3F772B804DF66F40AD6B604D38B227E30BFA70E631662B31739669D331D52867F49` |
| TELFHASH | `t171217622513542182fb3d928acbd567315222b2363597f716f26c4cc49370e2e93ad4f` |
| SSDEEP | `3072:L+YUpmc5hIof5UM7XgYjykKdnmm/QcuLB126DNb:LwU1of5UMPyk2nmm/QcuLB126DNb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_8141fb25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8141fb252441eb74264b6adf1d3e2c887620f3e1afcd0506186b936439ccd665"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:28"
  condition:
    hash.sha256(0, filesize) == "8141fb252441eb74264b6adf1d3e2c887620f3e1afcd0506186b936439ccd665"
}
```

### Sample 73: `03d477d4a5e14e77`

| Field | Value |
|---|---|
| SHA-256 | `03d477d4a5e14e77a482ef3b2a4f755ae73c02f167af38471e4f247639554ccf` |
| Family label | `Gafgyt` |
| File name | `armv5l` |
| File type | `elf` |
| First seen | `2026-10-13 05:31:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d650729943eb3c29eb7b78da22635117` |
| SHA-1 | `9ceb36dfc184d5056280a0776c67a7ee0835c9be` |
| SHA-256 | `03d477d4a5e14e77a482ef3b2a4f755ae73c02f167af38471e4f247639554ccf` |
| SHA3-384 | `78f0c429455bb45159442225c0ce2682ce11cddc260919a5748c632f53c552516bf677f98a722a16c521001ef7b8ac0e` |
| TLSH | `T142C3E731E8044B2BC2D223F6E79A829E3F351E9797973311573879B02FF27991E29524` |
| TELFHASH | `t171217622513542182fb3d928acbd567315222b2363597f716f26c4cc49370e2e93ad4f` |
| SSDEEP | `3072:FDcYVLWKlAQTv+mYzbpl2m7/L7QsvmGugiNb:WYVxlAk9YzbH2m7/L7QsvmGugiNb` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_073_03d477d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03d477d4a5e14e77a482ef3b2a4f755ae73c02f167af38471e4f247639554ccf"
    family = "Gafgyt"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:25"
  condition:
    hash.sha256(0, filesize) == "03d477d4a5e14e77a482ef3b2a4f755ae73c02f167af38471e4f247639554ccf"
}
```

### Sample 74: `3e68de6f60c7fb59`

| Field | Value |
|---|---|
| SHA-256 | `3e68de6f60c7fb5911837df0a5ce6a9aafd4e54a53af4c21bd8472fe16df4c67` |
| Family label | `Mirai` |
| File name | `main_ppc` |
| File type | `elf` |
| First seen | `2026-10-13 05:11:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dbe0007e4beafd466d52d3166e4079cc` |
| SHA-1 | `16899364cb155fddaacb6e1f1fb1b778a80b9ff8` |
| SHA-256 | `3e68de6f60c7fb5911837df0a5ce6a9aafd4e54a53af4c21bd8472fe16df4c67` |
| SHA3-384 | `0792a194d83cb7c8d5c093af21a1ffe71657f535fe01b9c2cf9fa570e8ad4c8a76347d75382cc27b57b876f47225d416` |
| TLSH | `T133C32906B30C0947D1A32EF43A3F27E197AFDA8121E4F640355F9B8A91B1D365585ECE` |
| SSDEEP | `1536:QSczyk0vL8gbjG8xFiZ4PA1Zi4J9qU+MbvAOhb15DZqL0sqFW5qiwGcz:QGk0X3G8xTex9F+FOEvcz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_3e68de6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e68de6f60c7fb5911837df0a5ce6a9aafd4e54a53af4c21bd8472fe16df4c67"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:13"
  condition:
    hash.sha256(0, filesize) == "3e68de6f60c7fb5911837df0a5ce6a9aafd4e54a53af4c21bd8472fe16df4c67"
}
```

### Sample 75: `498ac2d84c8ea573`

| Field | Value |
|---|---|
| SHA-256 | `498ac2d84c8ea5730bcb960556734a0e7407faeb33fb859f01602b93aed5d786` |
| Family label | `Mirai` |
| File name | `main_mpsl` |
| File type | `elf` |
| First seen | `2026-10-13 05:11:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `358dcde4b9943090dab8fc5eb81e2d8e` |
| SHA-1 | `09a50bba2396b1ccb8a074c07fa45ed9da78d888` |
| SHA-256 | `498ac2d84c8ea5730bcb960556734a0e7407faeb33fb859f01602b93aed5d786` |
| SHA3-384 | `4169d168fa04fe9ae9f5cd31ca52c8f95046e5e5c0a4ed24f61c76a91c58e8002a35d661d004520e35df979c8c3c730c` |
| TLSH | `T13E04D816AF510FBBDCAFCD3706A9070139CCA55B22A43B363674D528F54B64B4AE3C68` |
| SSDEEP | `1536:Z8h1yd05/4hJzC8sqFPNcN2QCg+Rqnhype2Zwenqc0tlmp/chvHYDbSwoS:Ayq+hNCxOuwpe2DIlmpkh6SZS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_498ac2d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "498ac2d84c8ea5730bcb960556734a0e7407faeb33fb859f01602b93aed5d786"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:11"
  condition:
    hash.sha256(0, filesize) == "498ac2d84c8ea5730bcb960556734a0e7407faeb33fb859f01602b93aed5d786"
}
```

### Sample 76: `d462900f4ea70ad6`

| Field | Value |
|---|---|
| SHA-256 | `d462900f4ea70ad634803710b3360bddabb6f74244e38c6c9854f6deb3cf4c6c` |
| Family label | `Mirai` |
| File name | `main_sh4` |
| File type | `elf` |
| First seen | `2026-10-13 05:11:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3faca5d80d270ab797a3794982b3b813` |
| SHA-1 | `d59e470e41c5e0ee9777e7912cd8d30dd5b05bac` |
| SHA-256 | `d462900f4ea70ad634803710b3360bddabb6f74244e38c6c9854f6deb3cf4c6c` |
| SHA3-384 | `34942ea8866d5ce34ddddf2dc59f1f5e4ca829f6ad497938c5f55b06e2124f4e82cd3308c3fe92aa63e6668f0c143823` |
| TLSH | `T14AB36A73D8266F98C655D070B0B48FB92B53A59082871FFF59B2C2B06083D9DF945BB8` |
| SSDEEP | `1536:wdQ/+osbi5iTMZo1lcr+KwClrIKWvlQp9a5+/PfbWDzlBuKCSuw1:wyfsb9fQ+KworvWKy5+/bWDJBu4uw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_d462900f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d462900f4ea70ad634803710b3360bddabb6f74244e38c6c9854f6deb3cf4c6c"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:08"
  condition:
    hash.sha256(0, filesize) == "d462900f4ea70ad634803710b3360bddabb6f74244e38c6c9854f6deb3cf4c6c"
}
```

### Sample 77: `fef4ca17e2e6bf13`

| Field | Value |
|---|---|
| SHA-256 | `fef4ca17e2e6bf135e017fadbfab10bf89086b878139d6d0ac0d1443f97220d8` |
| Family label | `Mirai` |
| File name | `main_arm5` |
| File type | `elf` |
| First seen | `2026-10-13 05:11:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f7bfa6518be2c21c084a8cef6b0384f8` |
| SHA-1 | `a5fc3ff8692540c2165fef7e738d05b9c73b9d4a` |
| SHA-256 | `fef4ca17e2e6bf135e017fadbfab10bf89086b878139d6d0ac0d1443f97220d8` |
| SHA3-384 | `b413c179d183f99bd687e0610a9a0dbaa96c9c2b7b7af4a397a2c34da0560a2665c1a93fd98b6578def6fd4c0f67c9db` |
| TLSH | `T183C30945FC405B23C6D612BBFB9E428D3B2A57E9D3EE720399216F20378695B0D37642` |
| SSDEEP | `1536:JJLMoPG5iB2sLMecHf7xtqWGAeSd4VYdrTBmPVG1j07YpQSlC7wyw0Rq2+dO/wBc:JJXoiM3/7DqWG240rAPVGC78JVvy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_fef4ca17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fef4ca17e2e6bf135e017fadbfab10bf89086b878139d6d0ac0d1443f97220d8"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:06"
  condition:
    hash.sha256(0, filesize) == "fef4ca17e2e6bf135e017fadbfab10bf89086b878139d6d0ac0d1443f97220d8"
}
```

### Sample 78: `d5872fe90fe7b763`

| Field | Value |
|---|---|
| SHA-256 | `d5872fe90fe7b76308f57b1d1ab7ebeb8eab06e55a67105774e2aa2a4b746720` |
| Family label | `Mirai` |
| File name | `main_m68k` |
| File type | `elf` |
| First seen | `2026-10-13 05:11:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `576a6712526b0b2586e052644b1b0851` |
| SHA-1 | `07e06d102f7a67bb557711bc648a429294194614` |
| SHA-256 | `d5872fe90fe7b76308f57b1d1ab7ebeb8eab06e55a67105774e2aa2a4b746720` |
| SHA3-384 | `8de8014c9062bd99655245bd1930fa5b97659edf605e6a7b4a7ab4a17ebf3aa7e138f64b1eefa63b529577c368689af2` |
| TLSH | `T139E32AD7F800DEFEF80AE73A48170805B530B7E105925B372267797BED7A1991923E86` |
| SSDEEP | `3072:QefJMkeCNOxSoQch1ybmF4jV3jbi8L1JayY12qQoQlm:QeyZ0oQchwqF4JLCyYkqQw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_d5872fe9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5872fe90fe7b76308f57b1d1ab7ebeb8eab06e55a67105774e2aa2a4b746720"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:04"
  condition:
    hash.sha256(0, filesize) == "d5872fe90fe7b76308f57b1d1ab7ebeb8eab06e55a67105774e2aa2a4b746720"
}
```

### Sample 79: `05bdc12486c7b3f6`

| Field | Value |
|---|---|
| SHA-256 | `05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31` |
| Family label | `NetSupport` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-13 05:04:00` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-GCleaner, exe, G, NetSupport, US0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4741ac868f7540a07138020c7d956699` |
| SHA-1 | `bbb5924dd9db5b685a1fda5485c00f0fb98b84e5` |
| SHA-256 | `05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31` |
| SHA3-384 | `30382af66ed852a75de575e7c70045300624aa5db3074947f8d11195c1aa264955c050ba029e3a7fec4b09ca426b3760` |
| IMPHASH | `61fa20e04a6d92b332b9552404fa2577` |
| TLSH | `T1E3461752A866FDABD3935436FC1C802097A1B97EE7FB6476B49570327CCC1423CA990B` |
| SSDEEP | `98304:6mIsmj9vJG0htiduqVCSC0sVK8RqwyPGt7TN7kDEv3CSvhBoGCxQ/iDPA6MZsoWT:6mIsmj9BG0zxTK8RqwyPGt7TN7kDEv3B` |
| ICON-DHASH | `b0b4b636fe9a80e0` |

#### Technical Assessment

- The sample is tracked as `NetSupport` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NetSupport_079_05bdc124
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31"
    family = "NetSupport"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-13 05:04:00"
  condition:
    hash.sha256(0, filesize) == "05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31"
}
```

### Sample 80: `a91330492f053103`

| Field | Value |
|---|---|
| SHA-256 | `a91330492f0531032816fe6033b0dd3a579b285dff39559a392be153f8dc6d37` |
| Family label | `Mirai` |
| File name | `aisu.i486` |
| File type | `elf` |
| First seen | `2026-10-13 05:02:20` |
| Reporter | `ksi_digital` |
| Tags | `cowrie, elf, honeypot, Mirai, x86` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f90159f88af43e3192c9c7f83420405` |
| SHA-1 | `a34facd6b60955301328a23eb032f9e8043e797c` |
| SHA-256 | `a91330492f0531032816fe6033b0dd3a579b285dff39559a392be153f8dc6d37` |
| SHA3-384 | `24a436c4742716f3a9230add2a85be0b67330e78c9a592e3ca16f8ab812d5ed0dc9f74f59deee92b8d4ac413a9daa82c` |
| TLSH | `T1B2A31843E357D0F1D88315B611F7FB3A5A30AD260260DD5FE7A4FEB669322D26426328` |
| TELFHASH | `t1e631f3762aa10ce5b7e00803b5cfa3318e2da67f35207aa246f9295533f76019377c39` |
| SSDEEP | `3072:Ocm+nKMYyd2iwmNcJZJYCbaNkAzMcVYkGypCC:bmET63JP6kmM6p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_a9133049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a91330492f0531032816fe6033b0dd3a579b285dff39559a392be153f8dc6d37"
    family = "Mirai"
    file_name = "aisu.i486"
    file_type = "elf"
    first_seen = "2026-10-13 05:02:20"
  condition:
    hash.sha256(0, filesize) == "a91330492f0531032816fe6033b0dd3a579b285dff39559a392be153f8dc6d37"
}
```

### Sample 81: `a666c1bded48fe95`

| Field | Value |
|---|---|
| SHA-256 | `a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5` |
| Family label | `Formbook` |
| File name | `SOA #Q4-2026.exe` |
| File type | `exe` |
| First seen | `2026-10-13 05:01:11` |
| Reporter | `threatcat_ch` |
| Tags | `exe, Formbook` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e993cb5fb05722c0b0c69982253ea68c` |
| SHA-1 | `8c86bfb0d673bc5c90c55aa77aa826bf9970f233` |
| SHA-256 | `a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5` |
| SHA3-384 | `5c89f2195c1634ae97afc0fcfe0bc9751e4131d88d38aac77d6ece5a1dcb49b7ba01d410bd972e6a8c76779a17f3ff3f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11AE40195321D8817D83A53F804A2E2B553F0AC9D77A2D3C9ADCA3DEB39D5B941A00F47` |
| SSDEEP | `12288:/IJyxg8gTPjxAMGzh1hRIIgsKKztwWAuo093ayZ1FSFm10bQ91lr1txXx:/IJyxg8g3xAMGzbhRijWAuQyQmibQRrX` |
| ICON-DHASH | `8e4d8ecccc8e4d8e` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_081_a666c1bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5"
    family = "Formbook"
    file_name = "SOA #Q4-2026.exe"
    file_type = "exe"
    first_seen = "2026-10-13 05:01:11"
  condition:
    hash.sha256(0, filesize) == "a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5"
}
```

### Sample 82: `e07c5e686877ffef`

| Field | Value |
|---|---|
| SHA-256 | `e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b` |
| Family label | `Vidar` |
| File name | `e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:49:24` |
| Reporter | `Kejult` |
| Tags | `exe, signed, stealer, vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7caa3b84685b1709ecdd7bc363bbbb45` |
| SHA-1 | `f704d266aec87000ada46cb39ed833a381a48cb0` |
| SHA-256 | `e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b` |
| SHA3-384 | `912cc2e0af549645087ba420bd312f4d1c938c8e1201b8e9a2b845ed702367a6f44e37e73fc4975a27caf1edf2738131` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1E376E96971C410E9CA8E837644F45DBE23B23DBF5613A28A0759BBA13F13BE55F24D08` |
| SSDEEP | `24576:WKAZGPqH6Frt29W5z9OXJSob806Dfy2YqQ7lV+Nh5/rN7O:W1GPqan2Q5aHqQrgRr8` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_082_e07c5e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b"
    family = "Vidar"
    file_name = "e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:49:24"
  condition:
    hash.sha256(0, filesize) == "e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b"
}
```

### Sample 83: `5cde94846e1e9c2e`

| Field | Value |
|---|---|
| SHA-256 | `5cde94846e1e9c2e97d7c6e0b2ce506341f47ad411f305d6de5c4dbf21ccd3e8` |
| Family label | `unknown` |
| File name | `anticheat_update.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:33:46` |
| Reporter | `Kejult` |
| Tags | `dropper, exe, FaceIt, fakeinstaller, trojan` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `75350c9aa5a2102f915c4477e3835896` |
| SHA-1 | `758a4eaeba937eff1b3e413610480244328751a1` |
| SHA-256 | `5cde94846e1e9c2e97d7c6e0b2ce506341f47ad411f305d6de5c4dbf21ccd3e8` |
| SHA3-384 | `659192ed3131fc92d79088d90ff9190cf1f13b2fcc2a7636d40b8f59d49ed1e0c0b08ef12b7c9e1ba0129d347bd446dc` |
| IMPHASH | `dab18f1145d8ff77a683784279450a7c` |
| TLSH | `T102462340F1C581BCC157D275885A8F2FE632F848270561DB33E0DB242FE2AD59FBA669` |
| SSDEEP | `98304:0cawbhJExk8JsmUm3TAIaqvo6hY8CwQphmulimFQAT3aTOR8z+X70wyav5iRWDkp:T3ExBtUKayU8CwQfmul5QAT3ewmPw3eq` |
| ICON-DHASH | `30f08ea2b2cc68b2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_5cde9484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cde94846e1e9c2e97d7c6e0b2ce506341f47ad411f305d6de5c4dbf21ccd3e8"
    family = "unknown"
    file_name = "anticheat_update.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:33:46"
  condition:
    hash.sha256(0, filesize) == "5cde94846e1e9c2e97d7c6e0b2ce506341f47ad411f305d6de5c4dbf21ccd3e8"
}
```

### Sample 84: `1c8db058dd109899`

| Field | Value |
|---|---|
| SHA-256 | `1c8db058dd109899cc1fb6ef362fa7b6b7871b3248e510531ed875dcccc1e7f8` |
| Family label | `unknown` |
| File name | `faceit.ps1` |
| File type | `ps1` |
| First seen | `2026-10-13 04:29:49` |
| Reporter | `Kejult` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b22856a501e86e2c435b6d16adb7e475` |
| SHA-1 | `96c28f6b3911ee19426522956117dacef5c52a4d` |
| SHA-256 | `1c8db058dd109899cc1fb6ef362fa7b6b7871b3248e510531ed875dcccc1e7f8` |
| SHA3-384 | `8f9fb8ccdbc659e90612be48015ba600cc5e4c2fc52a3067cd5649c4a333c4073fcddd8fa0c8fa540d999f8c723725d1` |
| TLSH | `T143A16506A560199DE2D2432796C767CF6F4190BF031B0D84B46CC2953F62B7F4F2996A` |
| SSDEEP | `48:izGdT3dgGdbd8dMdLOd2RKDX73kUFEyMRGlKNF1OQ4fIkXb1aWgYKFCNBi5arXiX:HyDXR2GlYFFEMomsrMuhAjx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_1c8db058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c8db058dd109899cc1fb6ef362fa7b6b7871b3248e510531ed875dcccc1e7f8"
    family = "unknown"
    file_name = "faceit.ps1"
    file_type = "ps1"
    first_seen = "2026-10-13 04:29:49"
  condition:
    hash.sha256(0, filesize) == "1c8db058dd109899cc1fb6ef362fa7b6b7871b3248e510531ed875dcccc1e7f8"
}
```

### Sample 85: `9ddd60703a3f6ac1`

| Field | Value |
|---|---|
| SHA-256 | `9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee` |
| Family label | `Formbook` |
| File name | `QUOTATION_FORMS.js` |
| File type | `js` |
| First seen | `2026-10-13 04:28:49` |
| Reporter | `threatcat_ch` |
| Tags | `Formbook, js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ebdbca261609f02af342db33fb5f2c02` |
| SHA-1 | `9ba27523f9d84edb7c0b37a2705e4471cc3a5ee1` |
| SHA-256 | `9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee` |
| SHA3-384 | `7a89cd4e87c5a3d37ec1b311f34cf0a11b6bd2ffab61f59c49083888193ed199e2dbb2ce7bdb06eaac3e06761ee77029` |
| TLSH | `T17CC51247ED8B8F9F401891AA56648A0A6837395B117473D134CFEEADB31CE3063BE647` |
| SSDEEP | `24576:0PnwLlpjElXbCf48VAoLWdu2F2CdbL899Ac/s3M191R13zlbZdPAlbXQuEYJwlhu:TjEhV9tsJdbSs84Aw4D` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_085_9ddd6070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee"
    family = "Formbook"
    file_name = "QUOTATION_FORMS.js"
    file_type = "js"
    first_seen = "2026-10-13 04:28:49"
  condition:
    hash.sha256(0, filesize) == "9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee"
}
```

### Sample 86: `c741e6782fb3cf5e`

| Field | Value |
|---|---|
| SHA-256 | `c741e6782fb3cf5e1c0e220781de618eae7317b3120bce9c642d7e8d71970957` |
| Family label | `ValleyRAT` |
| File name | `1921841f7abdd3dcd00ba9316aef101f.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:47` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1921841f7abdd3dcd00ba9316aef101f` |
| SHA-1 | `c2f7d541d889a74b360cfcc7e15dc5797252b446` |
| SHA-256 | `c741e6782fb3cf5e1c0e220781de618eae7317b3120bce9c642d7e8d71970957` |
| SHA3-384 | `057f7ac58156a11e6ce581b0308dc42f150add610c46496fb4d0cb71e843251da74950be78bdfc5d08c6b9d24c475732` |
| IMPHASH | `f0619aa204ece9a2499f1e067fc596c4` |
| TLSH | `T1CBA54BEE21731B8EF0B9C17899B4054BDDBB9D72E740D52312F316B26A033A06E5ED64` |
| SSDEEP | `24576:OALLYFAWUv0c9dJe7KIFV/RvCzNpNEWC1mYs287yCgFXpe8It1J:OHUv0cUOIbUNEWWDKgFXpe8K` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_086_c741e678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c741e6782fb3cf5e1c0e220781de618eae7317b3120bce9c642d7e8d71970957"
    family = "ValleyRAT"
    file_name = "1921841f7abdd3dcd00ba9316aef101f.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:47"
  condition:
    hash.sha256(0, filesize) == "c741e6782fb3cf5e1c0e220781de618eae7317b3120bce9c642d7e8d71970957"
}
```

### Sample 87: `fd6513495a7b6356`

| Field | Value |
|---|---|
| SHA-256 | `fd6513495a7b63565afe836b6e7b3581ed767d66f5b2e31fc642766671d06858` |
| Family label | `ValleyRAT` |
| File name | `0d74b16d2022d70ffd074ecf48579a99.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:43` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, ValleyRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0d74b16d2022d70ffd074ecf48579a99` |
| SHA-1 | `d2c5998ebfc07253eabb6b2f87045190bc6ac062` |
| SHA-256 | `fd6513495a7b63565afe836b6e7b3581ed767d66f5b2e31fc642766671d06858` |
| SHA3-384 | `7d035647532b5bac57faf7cd48d3f70254b47fabcfc5e773efed42d4c19ad1f3e406f0ddd097aeaa108758e258473ab7` |
| IMPHASH | `5df5eac7d1a8cb68f8fe700b326611bf` |
| TLSH | `T19875077FF195C17AC1EED13AD1A38F05E433B1720B33C2EB52940A669E0A9D55E3E660` |
| SSDEEP | `12288:2Iq7m1Vp38AWqu2DdjEnyRo+iD37IzGnxD3Twdk0KYM8YnNlajr88+JrFz+2Im9e:217m1PJgSdjEnyS+igfdkHRVe` |

#### Technical Assessment

- The sample is tracked as `ValleyRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ValleyRAT_087_fd651349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6513495a7b63565afe836b6e7b3581ed767d66f5b2e31fc642766671d06858"
    family = "ValleyRAT"
    file_name = "0d74b16d2022d70ffd074ecf48579a99.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:43"
  condition:
    hash.sha256(0, filesize) == "fd6513495a7b63565afe836b6e7b3581ed767d66f5b2e31fc642766671d06858"
}
```

### Sample 88: `b028b2b4a6a39c51`

| Field | Value |
|---|---|
| SHA-256 | `b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9` |
| Family label | `DCRat` |
| File name | `A0FFB31D84C2F5FFACD879F4F12C1CE6.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:38` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a0ffb31d84c2f5ffacd879f4f12c1ce6` |
| SHA-1 | `2280ee7e5d7dbf727306dd6b47025bd547172a57` |
| SHA-256 | `b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9` |
| SHA3-384 | `e3d147e6264f64ffc99575bae7bfb9194508e23a772d701b5a5940bfa7e7e1330595b897ea6e1f6994c95740c997bd0b` |
| IMPHASH | `fcf1390e9ce472c7270447fc5c61a0c1` |
| TLSH | `T11F657B017E44CE11F0191633C2EF4A0447B4AC51AAA6E72B7EFA376E55223937D1DACB` |
| SSDEEP | `24576:U2G/nvxW3Ww0toautb3DPlC9XxQpH9hl9AwLcIlDQ20NBtCxC:UbA30o7t/9rhcwHp6Rr` |
| ICON-DHASH | `9494b494d4aeaeac` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_088_b028b2b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9"
    family = "DCRat"
    file_name = "A0FFB31D84C2F5FFACD879F4F12C1CE6.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:38"
  condition:
    hash.sha256(0, filesize) == "b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9"
}
```

### Sample 89: `c6ed1c7e207d9a18`

| Field | Value |
|---|---|
| SHA-256 | `c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c` |
| Family label | `DCRat` |
| File name | `7B7E613EBF31774A1883442FA1728A9B.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:33` |
| Reporter | `abuse_ch` |
| Tags | `DCRat, exe, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7b7e613ebf31774a1883442fa1728a9b` |
| SHA-1 | `061d5068fd55b56e72c6c47d4bafdc7001d1fefd` |
| SHA-256 | `c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c` |
| SHA3-384 | `06d277d567613becdc106b46252754b91a3723bfa62429f96d18b0f266467ad9971478e2bf8d4fe4a918a9502454eaef` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1853549057E44CE11F0191633C2EF4A4887B49D51A6A6E32B7DFA37AE15123A77C0DACB` |
| SSDEEP | `24576:mautb3DPlC9XxQpH9hl9AwLcIlDQ20NBtCx:m7t/9rhcwHp6R` |

#### Technical Assessment

- The sample is tracked as `DCRat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_DCRat_089_c6ed1c7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c"
    family = "DCRat"
    file_name = "7B7E613EBF31774A1883442FA1728A9B.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:33"
  condition:
    hash.sha256(0, filesize) == "c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c"
}
```

### Sample 90: `e0e218a1ce45c5a7`

| Field | Value |
|---|---|
| SHA-256 | `e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2` |
| Family label | `RemcosRAT` |
| File name | `00e1caf43096125ae92ab913d6ee905e.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:28` |
| Reporter | `abuse_ch` |
| Tags | `exe, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00e1caf43096125ae92ab913d6ee905e` |
| SHA-1 | `18ea5297b184cfc4269239a7f66cc9c27a401caa` |
| SHA-256 | `e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2` |
| SHA3-384 | `3e10185c56d688bae57fcca21da2527b56d1b0bc318a9c26a022d5d82122cd9f64bb1098e2c76626a2ae995b527c5afa` |
| IMPHASH | `e77512f955eaf60ccff45e02d69234de` |
| TLSH | `T116A4BF01BAD2C072D57654300C3AE775DEBDBD212839897BB3D61D97FD30190A63AAB2` |
| SSDEEP | `12288:T13ak/mBXTG4/1v08KI7ZnMEF76JqmsvZQeS:Zak/mBXTV/R0nEF76gFZ1` |
| ICON-DHASH | `c4d48eaa8ad4d4f8` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_090_e0e218a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2"
    family = "RemcosRAT"
    file_name = "00e1caf43096125ae92ab913d6ee905e.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:28"
  condition:
    hash.sha256(0, filesize) == "e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2"
}
```

### Sample 91: `bbb93295a53d2215`

| Field | Value |
|---|---|
| SHA-256 | `bbb93295a53d22150eef772cc4ab5436e769f97041e741d6377c9373468c03ad` |
| Family label | `RemcosRAT` |
| File name | `SwiftMtc.JS.js` |
| File type | `js` |
| First seen | `2026-10-13 04:15:24` |
| Reporter | `abuse_ch` |
| Tags | `js, RAT, RemcosRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c35ce46522df3da30a07169ffb3d3c09` |
| SHA-1 | `82c67a9e2be5c1f8310ae4fed296381ca3277037` |
| SHA-256 | `bbb93295a53d22150eef772cc4ab5436e769f97041e741d6377c9373468c03ad` |
| SHA3-384 | `015bd2436419836d08670870f4b0b9c187b2c81f6dfce27bc4f80f65fedc0cbfc894808f1d1f39166c6ac0e8ea263ed4` |
| TLSH | `T1FB26095E13089DF5761D5B1ED13AF9A04D0B620375C6EFAC32ECE2047798A0B5B4E9E2` |
| SSDEEP | `98304:Exv/1st49LY+ZvgT5leRQbWS10DN9NhJH3A+dJCykf3cs8cj8kIhzKM7uAchTG/e:Ed1R9WGQ10JH3A+dJCFMs8cjzIBKY5qf` |

#### Technical Assessment

- The sample is tracked as `RemcosRAT` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemcosRAT_091_bbb93295
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbb93295a53d22150eef772cc4ab5436e769f97041e741d6377c9373468c03ad"
    family = "RemcosRAT"
    file_name = "SwiftMtc.JS.js"
    file_type = "js"
    first_seen = "2026-10-13 04:15:24"
  condition:
    hash.sha256(0, filesize) == "bbb93295a53d22150eef772cc4ab5436e769f97041e741d6377c9373468c03ad"
}
```

### Sample 92: `136bfdf68486a6b8`

| Field | Value |
|---|---|
| SHA-256 | `136bfdf68486a6b8d9acaaf957c4936f4364953c148a7de195b791c875b83452` |
| Family label | `njrat` |
| File name | `8A727EB3C78BA186DFEF3C0EDB90D3BD.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, njrat, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a727eb3c78ba186dfef3c0edb90d3bd` |
| SHA-1 | `a956b239d8d64e09797cb0075a85c964e2b5db04` |
| SHA-256 | `136bfdf68486a6b8d9acaaf957c4936f4364953c148a7de195b791c875b83452` |
| SHA3-384 | `64aead441c4d6ea916c32fa5730074b0fbd8e15b475e8676d39387b6649b4d2adcd70cd9f5f257effe6e1e3384ef1ac8` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C747331CEE64FB01DF6F16B36BDA7EB82687906FB61627E1489428D257D20D700F6E40` |
| SSDEEP | `393216:XqqXnFU9cn6IfTwTy8EZ29f6FmEPeNt69MIyZ+HnZ5IUl14D2hg2U0HDSV:XqqXFU9K7fTwTyhurAIe4Z+HZ5IUlmD8` |
| ICON-DHASH | `038625a396ccccd0` |

#### Technical Assessment

- The sample is tracked as `njrat` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_njrat_092_136bfdf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "136bfdf68486a6b8d9acaaf957c4936f4364953c148a7de195b791c875b83452"
    family = "njrat"
    file_name = "8A727EB3C78BA186DFEF3C0EDB90D3BD.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:16"
  condition:
    hash.sha256(0, filesize) == "136bfdf68486a6b8d9acaaf957c4936f4364953c148a7de195b791c875b83452"
}
```

### Sample 93: `41bf4c830222866a`

| Field | Value |
|---|---|
| SHA-256 | `41bf4c830222866a7f4d795937574fb21a4e1a03fc5cb7a80c5399946b01f0eb` |
| Family label | `NanoCore` |
| File name | `24d7969a26c4e42778d6d1cfab4ced2d.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:10` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `24d7969a26c4e42778d6d1cfab4ced2d` |
| SHA-1 | `4c0059296e058bfdeccd718d40aab3e50abab1c8` |
| SHA-256 | `41bf4c830222866a7f4d795937574fb21a4e1a03fc5cb7a80c5399946b01f0eb` |
| SHA3-384 | `8550adb3d975223f1e07eaaf027bb6e218432982160091f8d9fff44d87263a1386e0ddece387842ebf09f3d19cccbcd3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16814CF5677A94A3FD2DE82BD612211439378C2E399C3F7EE28D464B74B263E50A071D3` |
| SSDEEP | `6144:sLV6Bta6dtJmakIM5jMBrwBJnaMC8xFev7y4QT1t6:sLV6Btpmk2MFIPHPe2Dt6` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_093_41bf4c83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41bf4c830222866a7f4d795937574fb21a4e1a03fc5cb7a80c5399946b01f0eb"
    family = "NanoCore"
    file_name = "24d7969a26c4e42778d6d1cfab4ced2d.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:10"
  condition:
    hash.sha256(0, filesize) == "41bf4c830222866a7f4d795937574fb21a4e1a03fc5cb7a80c5399946b01f0eb"
}
```

### Sample 94: `063a716290fe030a`

| Field | Value |
|---|---|
| SHA-256 | `063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a` |
| Family label | `NanoCore` |
| File name | `223d1c4d8ffbb76a5638290572fefec9.exe` |
| File type | `exe` |
| First seen | `2026-10-13 04:15:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, NanoCore, RAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `223d1c4d8ffbb76a5638290572fefec9` |
| SHA-1 | `ef15e9af8dbe1be1bb7fb33ef3e900740f02a5db` |
| SHA-256 | `063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a` |
| SHA3-384 | `08ec8eca5c144895ff78c2942f45064afbb7d5f0504b9fe635d6d50ad4c520554e8a60fa35ea1de35f05723229f094c2` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13214CF2677A84A2FE2DE86BD702251168379C2E398C3F3DE68D451B78F167E10A471D3` |
| SSDEEP | `6144:sLV6Bta6dtJmakIM5os7UBmOKqVotp/wK32Q:sLV6BtpmkYQmGuAK32Q` |

#### Technical Assessment

- The sample is tracked as `NanoCore` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_NanoCore_094_063a7162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a"
    family = "NanoCore"
    file_name = "223d1c4d8ffbb76a5638290572fefec9.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:06"
  condition:
    hash.sha256(0, filesize) == "063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a"
}
```

### Sample 95: `c50aaeeb818ba3fd`

| Field | Value |
|---|---|
| SHA-256 | `c50aaeeb818ba3fd2ff56ff05702286ee3700461f84d2b499a0de2a4c99f5cdc` |
| Family label | `AsyncRAT` |
| File name | `c50aaeeb818ba3fd.bin` |
| File type | `exe` |
| First seen | `2026-10-13 03:24:31` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `910177419aed4b21f118570eff5aad7b` |
| SHA-1 | `510ab5bb200382c18cd35af659f5317ac7c6b62f` |
| SHA-256 | `c50aaeeb818ba3fd2ff56ff05702286ee3700461f84d2b499a0de2a4c99f5cdc` |
| SHA3-384 | `68b438ce3985a90629a39916e987bd87f5e18c6311d92a8a7898af619dbdf1e9e0272fa835027628db9367018110603f` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BB233B002BE8C127F2BE4F7499F221558577F2633603DA4D1CC8469A5B13FC696926FE` |
| SSDEEP | `768:YuYHKTsufqG9vSLjWUvlPRmo2qbMEht18wmoFcPIrUOJtaO0bsc2vkfnNwdFGVk5:YuYHKTsjMvSX2/EhFmoFhrjJ8bsXgnNO` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_095_c50aaeeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50aaeeb818ba3fd2ff56ff05702286ee3700461f84d2b499a0de2a4c99f5cdc"
    family = "AsyncRAT"
    file_name = "c50aaeeb818ba3fd.bin"
    file_type = "exe"
    first_seen = "2026-10-13 03:24:31"
  condition:
    hash.sha256(0, filesize) == "c50aaeeb818ba3fd2ff56ff05702286ee3700461f84d2b499a0de2a4c99f5cdc"
}
```

### Sample 96: `748ea2040710a547`

| Field | Value |
|---|---|
| SHA-256 | `748ea2040710a547411a6f038fea97f16919baaab0d878048b87fd87158b8bfd` |
| Family label | `Gafgyt` |
| File name | `mbupload-gja2vdid.bin` |
| File type | `sh` |
| First seen | `2026-10-13 02:56:04` |
| Reporter | `wristhulk` |
| Tags | `cowrie, downloader, Gafgyt, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `232a72b510614c705fa064b04250129e` |
| SHA-1 | `46ca36e251acdcb762d12875528927ac618900a7` |
| SHA-256 | `748ea2040710a547411a6f038fea97f16919baaab0d878048b87fd87158b8bfd` |
| SHA3-384 | `adb932716b10c99acfc1dd923282a6411ec4c43ab5174edef636a1b99701a30d7582030f09c554a3ed29ac7194140391` |
| TLSH | `T1627172CA13AA053BEE52DA933369840F71D0A6E71D85AF9469DC34FB889DD04306F782` |
| SSDEEP | `96:v3dc3GjGLUdm3KI3Yk39g3FQ32I3XM3w43ufI3rE3WY3pM3o433U3uA3Ow3DfA3R:fdyC2KeYa92Fm2eXiwO4er6WupioO3KU` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_096_748ea204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "748ea2040710a547411a6f038fea97f16919baaab0d878048b87fd87158b8bfd"
    family = "Gafgyt"
    file_name = "mbupload-gja2vdid.bin"
    file_type = "sh"
    first_seen = "2026-10-13 02:56:04"
  condition:
    hash.sha256(0, filesize) == "748ea2040710a547411a6f038fea97f16919baaab0d878048b87fd87158b8bfd"
}
```

### Sample 97: `4d75d51f4439a570`

| Field | Value |
|---|---|
| SHA-256 | `4d75d51f4439a5706e061891065844a5201185fe345ed3f4aa72d8b2ec8bb914` |
| Family label | `PureRAT` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-13 02:44:05` |
| Reporter | `Bitsight` |
| Tags | `A, dropped-by-GCleaner, exe, MIX3.file, PureRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2b6e59dedec39c9633d9d247d3c43d47` |
| SHA-1 | `c3ca3c40acd22ad9fb94b613573a115385697368` |
| SHA-256 | `4d75d51f4439a5706e061891065844a5201185fe345ed3f4aa72d8b2ec8bb914` |
| SHA3-384 | `f64d5be26a7373cda07704a90881a5f1de3dee2777c0269d814dbd6ca69a81759fed191607d7f9bc7f02f938e2afdffb` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1AE942A1B37564E21C2994737D1E7810083DA96833AEBE32B399113D62D437FEEA06797` |
| SSDEEP | `3072:0iRHZGFCerAAtYkbgJ4qC2D5qYgD57A1W05edQLeR0v2dZCNA/qczmYyoci5GBff:0mHsFCbwk6kc4AiAZz1ZPY0dPKVCX` |

#### Technical Assessment

- The sample is tracked as `PureRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureRAT_097_4d75d51f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d75d51f4439a5706e061891065844a5201185fe345ed3f4aa72d8b2ec8bb914"
    family = "PureRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-13 02:44:05"
  condition:
    hash.sha256(0, filesize) == "4d75d51f4439a5706e061891065844a5201185fe345ed3f4aa72d8b2ec8bb914"
}
```

### Sample 98: `f719a1d71332414c`

| Field | Value |
|---|---|
| SHA-256 | `f719a1d71332414c1621b0ceaa56485bfc80bcfb2c072d247b25daecd026aef4` |
| Family label | `AMOS` |
| File name | `macho_f719a1d71332.bin` |
| File type | `macho` |
| First seen | `2026-10-13 02:30:53` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `172ee26bef9e828e2231ea0ac7c8982a` |
| SHA-1 | `7e7025726ab710097958ebb2fece1ad001c0731b` |
| SHA-256 | `f719a1d71332414c1621b0ceaa56485bfc80bcfb2c072d247b25daecd026aef4` |
| SHA3-384 | `cbf036bdd16e60fb7be9ba986533b2255af2e9f3199111851f4447ed09736ce4e3de722a3ad2f7a9d93ea833de682eb9` |
| TLSH | `T17245F1018F668896F4CCE7312A3B4B335E2165B046C951DE63A60F99CE353E3F57B21A` |
| SSDEEP | `24576:qcfEMWV/EuCuK5nCfIoUeY+W+tMUvqeQC0fzC10qSQAl:lEMWx1vUV499Sxl` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_098_f719a1d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f719a1d71332414c1621b0ceaa56485bfc80bcfb2c072d247b25daecd026aef4"
    family = "AMOS"
    file_name = "macho_f719a1d71332.bin"
    file_type = "macho"
    first_seen = "2026-10-13 02:30:53"
  condition:
    hash.sha256(0, filesize) == "f719a1d71332414c1621b0ceaa56485bfc80bcfb2c072d247b25daecd026aef4"
}
```

### Sample 99: `1d129b9c9a6c5aad`

| Field | Value |
|---|---|
| SHA-256 | `1d129b9c9a6c5aad8a22a3f7cbf45da61c7eb9150f160f495bd15a0f2cd1d8af` |
| Family label | `unknown` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-13 02:23:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `83b149cb0f3f959190d3eedac07d8fe3` |
| SHA-1 | `69c4377c021148673c62cb60c1b7e6a69969118b` |
| SHA-256 | `1d129b9c9a6c5aad8a22a3f7cbf45da61c7eb9150f160f495bd15a0f2cd1d8af` |
| SHA3-384 | `e8f4e8a3cf358b7b0a496b378fbbf096c5d433d6bb0989ac8553b72611efec671a0e3fd18c79e14a7e7c65ebce961dcb` |
| TLSH | `T17366F815AD842BEAC46C4B7544FAC95A23B05D140AF14B7A66A4FFEDBC722347F0788C` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:ghku38yKfPx1kp4iPkQZHRIXjBUbIuWt9dxawk5Eb:afPkCLWjhWEb` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_1d129b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d129b9c9a6c5aad8a22a3f7cbf45da61c7eb9150f160f495bd15a0f2cd1d8af"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-13 02:23:33"
  condition:
    hash.sha256(0, filesize) == "1d129b9c9a6c5aad8a22a3f7cbf45da61c7eb9150f160f495bd15a0f2cd1d8af"
}
```

### Sample 100: `3b077941b8b6eb84`

| Field | Value |
|---|---|
| SHA-256 | `3b077941b8b6eb84e861da7c7dc8ab68e0a5acfc7a9a4d3e21c0360fbb1613eb` |
| Family label | `Mirai` |
| File name | `pid.arm5` |
| File type | `elf` |
| First seen | `2026-10-13 02:23:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35246d2dfdef968078b911c07375aed4` |
| SHA-1 | `cdd8edda7b9b696a7af4925ea83c120dbe504617` |
| SHA-256 | `3b077941b8b6eb84e861da7c7dc8ab68e0a5acfc7a9a4d3e21c0360fbb1613eb` |
| SHA3-384 | `4993849bc9d58b035f00f042682ed16bd862d9ec10388b2800624d87ab37f9d78986bda3692b7fbc80b1c8305ca0104b` |
| TLSH | `T1DE840A88E1F0E7DED2D4AA75B31D790E3B230735F1D73146A51AAA3323EB1490ABD911` |
| TELFHASH | `t1ccf05ca0db1d28a9e777f4c167e97d0878ba568afd3514020e419a9db8830c264f3c17` |
| SSDEEP | `6144:MFSK4KlgzaHom5bG/egpSBbKmZKHts8MwHBhEwFf79hmKkvgF7a9R:24uFHomYmgpQex7zbVa9R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_3b077941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b077941b8b6eb84e861da7c7dc8ab68e0a5acfc7a9a4d3e21c0360fbb1613eb"
    family = "Mirai"
    file_name = "pid.arm5"
    file_type = "elf"
    first_seen = "2026-10-13 02:23:30"
  condition:
    hash.sha256(0, filesize) == "3b077941b8b6eb84e861da7c7dc8ab68e0a5acfc7a9a4d3e21c0360fbb1613eb"
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
 * Generated: 2026-10-13T06:52:56.686367+00:00
 */

rule MalwareBazaar_unknown_001_16602885
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "16602885d0f879e4477ad54079a8b04f5c163c539ca9c4c26cc33df98925472b"
    family = "unknown"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-13 06:51:49"
  condition:
    hash.sha256(0, filesize) == "16602885d0f879e4477ad54079a8b04f5c163c539ca9c4c26cc33df98925472b"
}

rule MalwareBazaar_Mirai_002_8d87e9e7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d87e9e7076ec05efe85a83510bfbc87bc680216f4c4a6f9f871990eaa7906b7"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-13 06:46:23"
  condition:
    hash.sha256(0, filesize) == "8d87e9e7076ec05efe85a83510bfbc87bc680216f4c4a6f9f871990eaa7906b7"
}

rule MalwareBazaar_Mirai_003_4f3c9112
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f3c9112b612349ca18cd3bd4ab6905afff34e4d806f9d38ac4c5e41194712aa"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-13 06:41:14"
  condition:
    hash.sha256(0, filesize) == "4f3c9112b612349ca18cd3bd4ab6905afff34e4d806f9d38ac4c5e41194712aa"
}

rule MalwareBazaar_Mirai_004_d1c4adea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97"
    family = "Mirai"
    file_name = "d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97.elf"
    file_type = "elf"
    first_seen = "2026-10-13 06:40:36"
  condition:
    hash.sha256(0, filesize) == "d1c4adea218def895cf49ddcf5af017ff34921913936e8dac9f3f57c1378dc97"
}

rule MalwareBazaar_Mirai_005_ef9131af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ef9131af106c6d7cf77c8d4856c93e18c2c6c038e3584319498f1acc98703c93"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-13 06:37:28"
  condition:
    hash.sha256(0, filesize) == "ef9131af106c6d7cf77c8d4856c93e18c2c6c038e3584319498f1acc98703c93"
}

rule MalwareBazaar_Mirai_006_4f5d0e91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4f5d0e91305ebeae3ef3a16d32103961c401c9061f67076fdc3722693adc74d6"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-13 06:36:15"
  condition:
    hash.sha256(0, filesize) == "4f5d0e91305ebeae3ef3a16d32103961c401c9061f67076fdc3722693adc74d6"
}

rule MalwareBazaar_Mirai_007_cd823efd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cd823efda222cf6a0885d46759e80932f555bf26b0e0c6ee7caf8bbe415bfd3b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-13 06:36:13"
  condition:
    hash.sha256(0, filesize) == "cd823efda222cf6a0885d46759e80932f555bf26b0e0c6ee7caf8bbe415bfd3b"
}

rule MalwareBazaar_Mirai_008_e96178be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e96178beb8202507f8a9dfc51fc6db12bd1848cf158992d6188b0693681dc424"
    family = "Mirai"
    file_name = "dbg"
    file_type = "elf"
    first_seen = "2026-10-13 06:36:11"
  condition:
    hash.sha256(0, filesize) == "e96178beb8202507f8a9dfc51fc6db12bd1848cf158992d6188b0693681dc424"
}

rule MalwareBazaar_Mirai_009_89ade231
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89ade231d9eea23055ab72eddc0b81d80c8d886534ce76821647cbf974410d4d"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-13 06:31:05"
  condition:
    hash.sha256(0, filesize) == "89ade231d9eea23055ab72eddc0b81d80c8d886534ce76821647cbf974410d4d"
}

rule MalwareBazaar_Vidar_010_2c1f19a9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d"
    family = "Vidar"
    file_name = "2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:42"
  condition:
    hash.sha256(0, filesize) == "2c1f19a9ed33cfca89c6527dc3ea1675514022dde6862ad0609ad3d59518155d"
}

rule MalwareBazaar_Vidar_011_f761f56f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432"
    family = "Vidar"
    file_name = "f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:38"
  condition:
    hash.sha256(0, filesize) == "f761f56f9f7f65c5ed6861b696da459bc2e7cfd9ba4caea98be350ef9eafe432"
}

rule MalwareBazaar_Vidar_012_2684dd79
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149"
    family = "Vidar"
    file_name = "2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:34"
  condition:
    hash.sha256(0, filesize) == "2684dd7946751a6b074e124ca46a5da4dca8f663152d219c1e5bb533f39f3149"
}

rule MalwareBazaar_ArkeiStealer_013_b31a87ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee"
    family = "ArkeiStealer"
    file_name = "b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:30"
  condition:
    hash.sha256(0, filesize) == "b31a87efe83fe2d6b4dae35fd02ee024c4988fe6991ba2727c5e03ffb21f92ee"
}

rule MalwareBazaar_unknown_014_3c7e4f7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e"
    family = "unknown"
    file_name = "3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:26"
  condition:
    hash.sha256(0, filesize) == "3c7e4f7adfcc9373f52395f481486aa3af8faf6916b1099b22e9492453be588e"
}

rule MalwareBazaar_Vidar_015_a37845bf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074"
    family = "Vidar"
    file_name = "a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:23"
  condition:
    hash.sha256(0, filesize) == "a37845bf7a3b2d27154fdf24dfa147b1f4e97e6a710123cdb5f1f88bd3299074"
}

rule MalwareBazaar_Vidar_016_adcddb34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77"
    family = "Vidar"
    file_name = "adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:20"
  condition:
    hash.sha256(0, filesize) == "adcddb34f3f1257f66b8666e7416d09fc0a1a247aa43ff01a8541e65294f8d77"
}

rule MalwareBazaar_Vidar_017_65d76e7d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db"
    family = "Vidar"
    file_name = "65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:17"
  condition:
    hash.sha256(0, filesize) == "65d76e7d6460707658cf67b5a47512a95a32b95c299b44d482e30cc3ae2ff7db"
}

rule MalwareBazaar_Vidar_018_e748d92f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9"
    family = "Vidar"
    file_name = "e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:14"
  condition:
    hash.sha256(0, filesize) == "e748d92f5d8f584b964fe723fab979edbd48d4b69407c8a7387e9fd779737de9"
}

rule MalwareBazaar_Vidar_019_7ab8d9e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0"
    family = "Vidar"
    file_name = "7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:11"
  condition:
    hash.sha256(0, filesize) == "7ab8d9e65597bf7a17ea94fec7f405d69149cdbc068649aba85b5abe594103a0"
}

rule MalwareBazaar_Vidar_020_618bc21c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51"
    family = "Vidar"
    file_name = "618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:08"
  condition:
    hash.sha256(0, filesize) == "618bc21cf7dc193fbb7748d2b69518613b176da26c4834eabb8c0f57ef495e51"
}

rule MalwareBazaar_Vidar_021_4c160e5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9"
    family = "Vidar"
    file_name = "4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:04"
  condition:
    hash.sha256(0, filesize) == "4c160e5bebe1495c6fee2660a2529655bc2af20ee23007657c9f88b5d77ae0d9"
}

rule MalwareBazaar_Vidar_022_1a301fde
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6"
    family = "Vidar"
    file_name = "1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:27:01"
  condition:
    hash.sha256(0, filesize) == "1a301fde61e3214c7f446393eef711c0ddc9a88ef955883e72f95699e868e4c6"
}

rule MalwareBazaar_Vidar_023_50424bc0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14"
    family = "Vidar"
    file_name = "50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:58"
  condition:
    hash.sha256(0, filesize) == "50424bc060c6593c8927d60a43f26fbf807230056138039d46f4a42834dcad14"
}

rule MalwareBazaar_Vidar_024_63b838a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc"
    family = "Vidar"
    file_name = "63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:55"
  condition:
    hash.sha256(0, filesize) == "63b838a03da7178eac3cb2d0be7b7e071c7a430d6010699b98ec74e0145408bc"
}

rule MalwareBazaar_Vidar_025_b9413163
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37"
    family = "Vidar"
    file_name = "b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:31"
  condition:
    hash.sha256(0, filesize) == "b941316399a2526959454a603d71d6985247ea578b23f93e6a70d65906fa3b37"
}

rule MalwareBazaar_Vidar_026_266411be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468"
    family = "Vidar"
    file_name = "266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:27"
  condition:
    hash.sha256(0, filesize) == "266411bef009df38a7f27f994573a7ab0a902987471a66367599414bdd001468"
}

rule MalwareBazaar_Vidar_027_754705b5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661"
    family = "Vidar"
    file_name = "754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:24"
  condition:
    hash.sha256(0, filesize) == "754705b56629e4ce14a3396c344a97d4433083f92439db3560bba24168df4661"
}

rule MalwareBazaar_Vidar_028_b0f97047
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7"
    family = "Vidar"
    file_name = "b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:20"
  condition:
    hash.sha256(0, filesize) == "b0f970472a9e2c883c65f127963abcbbac377763fde61f2c2c9efb5405d399c7"
}

rule MalwareBazaar_Vidar_029_e41e5fd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663"
    family = "Vidar"
    file_name = "e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:17"
  condition:
    hash.sha256(0, filesize) == "e41e5fd90907e2f57edd2416191a3a21c699a08cec54e60723ae6409b871d663"
}

rule MalwareBazaar_Vidar_030_f046d52f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3"
    family = "Vidar"
    file_name = "f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:14"
  condition:
    hash.sha256(0, filesize) == "f046d52fafa99ed018e7d1af8edf4d7df03b5a7b82dd11c3b14484d07b6545e3"
}

rule MalwareBazaar_Vidar_031_9569def1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2"
    family = "Vidar"
    file_name = "9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2.bin"
    file_type = "exe"
    first_seen = "2026-10-13 06:26:10"
  condition:
    hash.sha256(0, filesize) == "9569def1fc3d84e662557a62b344594276aa209518a6952e1728a2b64e7760b2"
}

rule MalwareBazaar_Mirai_032_5cb39a8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cb39a8d4e7f3f452a8ff91c83c866dbe7a0c10fd95ccacc772e13329350d993"
    family = "Mirai"
    file_name = "android-arm64"
    file_type = "elf"
    first_seen = "2026-10-13 06:26:03"
  condition:
    hash.sha256(0, filesize) == "5cb39a8d4e7f3f452a8ff91c83c866dbe7a0c10fd95ccacc772e13329350d993"
}

rule MalwareBazaar_Mirai_033_7a66c00d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7a66c00dd4680237bb341163ca6f250c6222c181dd44c42a556b620de8859000"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-10-13 06:26:01"
  condition:
    hash.sha256(0, filesize) == "7a66c00dd4680237bb341163ca6f250c6222c181dd44c42a556b620de8859000"
}

rule MalwareBazaar_unknown_034_4614bb60
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4614bb60faf9c9edfac1fa8c90d0c9f939a495cd47bea531142221f6919cabb1"
    family = "unknown"
    file_name = "macho_4614bb60faf9.bin"
    file_type = "macho"
    first_seen = "2026-10-13 06:22:47"
  condition:
    hash.sha256(0, filesize) == "4614bb60faf9c9edfac1fa8c90d0c9f939a495cd47bea531142221f6919cabb1"
}

rule MalwareBazaar_GCleaner_035_3e83eb09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e83eb0906d4c8e8f94263d3fb5127146238255e627482de75ff3d3a8ae6ae34"
    family = "GCleaner"
    file_name = "file.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:21:58"
  condition:
    hash.sha256(0, filesize) == "3e83eb0906d4c8e8f94263d3fb5127146238255e627482de75ff3d3a8ae6ae34"
}

rule MalwareBazaar_RemcosRAT_036_342c8cbc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1"
    family = "RemcosRAT"
    file_name = "1791829747116b783c49b924ce6d049b5f5c00346c8d4b7fe679e0452e1d24c0b33c31cf43258.dat-decoded"
    file_type = "exe"
    first_seen = "2026-10-13 06:21:54"
  condition:
    hash.sha256(0, filesize) == "342c8cbca7f6c97acbd974963ad9909b9864cf0643244f4565593d8b67b893f1"
}

rule MalwareBazaar_unknown_037_c66116cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c66116cfe82dc563239bfbd7ac4f91e1e9af966f7729212a3c9f32d197bf0985"
    family = "unknown"
    file_name = "besofluck.htA"
    file_type = "hta"
    first_seen = "2026-10-13 06:21:31"
  condition:
    hash.sha256(0, filesize) == "c66116cfe82dc563239bfbd7ac4f91e1e9af966f7729212a3c9f32d197bf0985"
}

rule MalwareBazaar_AgentTesla_038_1fb0b0a0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5"
    family = "AgentTesla"
    file_name = "geen.ps1"
    file_type = "ps1"
    first_seen = "2026-10-13 06:21:06"
  condition:
    hash.sha256(0, filesize) == "1fb0b0a0efd6dac97031183a16a3c1ffb7dbf4a77912280d741cd6fca29c47c5"
}

rule MalwareBazaar_RevStealer_039_30f1a885
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30f1a88560497fdfe4058b60f4c1109f3f470c76b774a718c34e6c1a080219fd"
    family = "RevStealer"
    file_name = "6eq5gvOfRvNmCi54.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:20:35"
  condition:
    hash.sha256(0, filesize) == "30f1a88560497fdfe4058b60f4c1109f3f470c76b774a718c34e6c1a080219fd"
}

rule MalwareBazaar_unknown_040_392bede6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392bede600c5f3202b72e34b0c84d9aad85bf9e8bfed7811e7043410c09b03eb"
    family = "unknown"
    file_name = "24453f26fd490c42009a19e91881e1a1.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:17:31"
  condition:
    hash.sha256(0, filesize) == "392bede600c5f3202b72e34b0c84d9aad85bf9e8bfed7811e7043410c09b03eb"
}

rule MalwareBazaar_unknown_041_971a006d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "971a006d7ad0618bf25aad494adda105c4e0544ae62081577f5be26eb6ba73de"
    family = "unknown"
    file_name = "LX_Cyglye5QY5.js"
    file_type = "js"
    first_seen = "2026-10-13 06:17:19"
  condition:
    hash.sha256(0, filesize) == "971a006d7ad0618bf25aad494adda105c4e0544ae62081577f5be26eb6ba73de"
}

rule MalwareBazaar_unknown_042_b22a88e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b22a88e0510e60d9b4c447794c67da462d73ac4e774bdff1977f8cef1b38e7b3"
    family = "unknown"
    file_name = "fade9fc65c0c51f683156c8296cf55a4.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:16:19"
  condition:
    hash.sha256(0, filesize) == "b22a88e0510e60d9b4c447794c67da462d73ac4e774bdff1977f8cef1b38e7b3"
}

rule MalwareBazaar_Mirai_043_425fddfc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "425fddfc0b8f3b3044dcc4c75dac56bee233784bf3977d620f49f4d280f26fe9"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-13 06:15:57"
  condition:
    hash.sha256(0, filesize) == "425fddfc0b8f3b3044dcc4c75dac56bee233784bf3977d620f49f4d280f26fe9"
}

rule MalwareBazaar_unknown_044_86c5d22a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "86c5d22a1b6525bb6083aa538b2956ec45d4886deddff1db180166a8202e6369"
    family = "unknown"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-10-13 06:10:42"
  condition:
    hash.sha256(0, filesize) == "86c5d22a1b6525bb6083aa538b2956ec45d4886deddff1db180166a8202e6369"
}

rule MalwareBazaar_Mirai_045_e70ffd7f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e70ffd7f676b97c9884d248b00d4bd264b488bea0cfb940fcd1cd2c16931d10f"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-13 06:10:39"
  condition:
    hash.sha256(0, filesize) == "e70ffd7f676b97c9884d248b00d4bd264b488bea0cfb940fcd1cd2c16931d10f"
}

rule MalwareBazaar_unknown_046_7394aeca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7394aecaeda4d0c2fb3fdd5e2acd8fca82be731991130463bdf3344401f75f97"
    family = "unknown"
    file_name = "start.exe"
    file_type = "exe"
    first_seen = "2026-10-13 06:09:44"
  condition:
    hash.sha256(0, filesize) == "7394aecaeda4d0c2fb3fdd5e2acd8fca82be731991130463bdf3344401f75f97"
}

rule MalwareBazaar_AgentTesla_047_3e38de40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e38de4089d16371f2c6f2a49cd34da0877ff90392f430c8c88772927cd14a40"
    family = "AgentTesla"
    file_name = "SOLICITUD DE COTIZACIÓN.JS"
    file_type = "js"
    first_seen = "2026-10-13 06:06:54"
  condition:
    hash.sha256(0, filesize) == "3e38de4089d16371f2c6f2a49cd34da0877ff90392f430c8c88772927cd14a40"
}

rule MalwareBazaar_AgentTesla_048_21f53d2b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
    family = "AgentTesla"
    file_name = "New order PO-22609 Kawasan Perindustrian Bukit Raja.js"
    file_type = "js"
    first_seen = "2026-10-13 06:05:21"
  condition:
    hash.sha256(0, filesize) == "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
}

rule MalwareBazaar_Formbook_049_20ef2e40
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "20ef2e404fab9b92936af4ee20cddf5513cfb909fa5a8fb3a0f9c6b32ee2a17d"
    family = "Formbook"
    file_name = "RFQ – Supply of Carbon Steel Pipes, Fittings, Flanges & Related Piping Materials (SHESB)_xlsx.wsf"
    file_type = "wsf"
    first_seen = "2026-10-13 06:01:45"
  condition:
    hash.sha256(0, filesize) == "20ef2e404fab9b92936af4ee20cddf5513cfb909fa5a8fb3a0f9c6b32ee2a17d"
}

rule MalwareBazaar_unknown_050_125625a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "125625a137697c38b44d050d3a0f96d9ce885bfe7410cf3b82affdd9de36e77c"
    family = "unknown"
    file_name = "bot_linux_x86_32"
    file_type = "elf"
    first_seen = "2026-10-13 06:01:39"
  condition:
    hash.sha256(0, filesize) == "125625a137697c38b44d050d3a0f96d9ce885bfe7410cf3b82affdd9de36e77c"
}

rule MalwareBazaar_unknown_051_06690169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5"
    family = "unknown"
    file_name = "bot_linux_x86_32"
    file_type = "elf"
    first_seen = "2026-10-13 06:00:34"
  condition:
    hash.sha256(0, filesize) == "06690169576f8b79cde6ad07db3891904c889e7500eea643d2bec084f5d6f4c5"
}

rule MalwareBazaar_unknown_052_6662803a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19"
    family = "unknown"
    file_name = "game_library.dll"
    file_type = "exe"
    first_seen = "2026-10-13 05:58:23"
  condition:
    hash.sha256(0, filesize) == "6662803a648165e0900fb2a646c6b03ac0cfae846ef4484c0285ca11172eef19"
}

rule MalwareBazaar_unknown_053_4eab4e84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad"
    family = "unknown"
    file_name = "dsound.dll"
    file_type = "exe"
    first_seen = "2026-10-13 05:57:43"
  condition:
    hash.sha256(0, filesize) == "4eab4e848a9e9802f605930bf330b362416c4044d8698f149fb1e76a75227aad"
}

rule MalwareBazaar_Vidar_054_313fb55e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9"
    family = "Vidar"
    file_name = "313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9.bin"
    file_type = "exe"
    first_seen = "2026-10-13 05:55:33"
  condition:
    hash.sha256(0, filesize) == "313fb55ebf3132807935ae235c72951a0c2078427425eeefa3a2814b15e4e0e9"
}

rule MalwareBazaar_Mirai_055_0ffa7136
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd"
    family = "Mirai"
    file_name = "pid.ppc"
    file_type = "elf"
    first_seen = "2026-10-13 05:54:45"
  condition:
    hash.sha256(0, filesize) == "0ffa713642813fd09a3fb26d5050322305408e046410b60aac0e44041435c3dd"
}

rule MalwareBazaar_Mirai_056_f2a74507
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2a74507f0c0660e1a22e7d2d011529a44347289ff2f1b122ed3e901470aac5f"
    family = "Mirai"
    file_name = "pid.arm6"
    file_type = "elf"
    first_seen = "2026-10-13 05:54:42"
  condition:
    hash.sha256(0, filesize) == "f2a74507f0c0660e1a22e7d2d011529a44347289ff2f1b122ed3e901470aac5f"
}

rule MalwareBazaar_Mirai_057_38f02f4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d"
    family = "Mirai"
    file_name = "38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d.sh"
    file_type = "sh"
    first_seen = "2026-10-13 05:48:43"
  condition:
    hash.sha256(0, filesize) == "38f02f4a4eb8d8291646fde7b40d11d208fc186590ca2a92582150a18055959d"
}

rule MalwareBazaar_SloppyRAT_058_4777c499
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79"
    family = "SloppyRAT"
    file_name = "4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79.bin"
    file_type = "ps1"
    first_seen = "2026-10-13 05:45:35"
  condition:
    hash.sha256(0, filesize) == "4777c49910b352e3c0eedd6ae9e5a74e1c68fe80e09e42fdb0622a1f74835e79"
}

rule MalwareBazaar_Formbook_059_b2a32724
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6"
    family = "Formbook"
    file_name = "b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6.exe"
    file_type = "exe"
    first_seen = "2026-10-13 05:41:02"
  condition:
    hash.sha256(0, filesize) == "b2a327241ee8fdf5f3456cd31cda6e7b4d43e2dde94813f0fa47e69f6d2414b6"
}

rule MalwareBazaar_Mirai_060_68ce321d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "68ce321d9ca45f9f206b03be37395880a124cf7616f65523725e9a6863275505"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-13 05:37:20"
  condition:
    hash.sha256(0, filesize) == "68ce321d9ca45f9f206b03be37395880a124cf7616f65523725e9a6863275505"
}

rule MalwareBazaar_Mirai_061_bd809b2f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bd809b2f625d640a21fc9418538b686639b719f09e6c2efacffa49a7be3f613a"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-13 05:37:18"
  condition:
    hash.sha256(0, filesize) == "bd809b2f625d640a21fc9418538b686639b719f09e6c2efacffa49a7be3f613a"
}

rule MalwareBazaar_Mirai_062_b19f095b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b19f095b2d90e78011178060d8d63aff1c285c5be25f2df949dd8ada442889ff"
    family = "Mirai"
    file_name = "ppc64"
    file_type = "elf"
    first_seen = "2026-10-13 05:37:16"
  condition:
    hash.sha256(0, filesize) == "b19f095b2d90e78011178060d8d63aff1c285c5be25f2df949dd8ada442889ff"
}

rule MalwareBazaar_Mirai_063_e4023b4b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e4023b4b7a693fb18338f8a1c9c3c2998c6d3150dcf2528dec5025840e44036f"
    family = "Mirai"
    file_name = "EkSgbins.sh"
    file_type = "sh"
    first_seen = "2026-10-13 05:31:56"
  condition:
    hash.sha256(0, filesize) == "e4023b4b7a693fb18338f8a1c9c3c2998c6d3150dcf2528dec5025840e44036f"
}

rule MalwareBazaar_Mirai_064_ad0d27be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ad0d27bee2efabe56d584238d605fafd6ad6edbfae29b8a86f6b0c1bce4e1a2a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:51"
  condition:
    hash.sha256(0, filesize) == "ad0d27bee2efabe56d584238d605fafd6ad6edbfae29b8a86f6b0c1bce4e1a2a"
}

rule MalwareBazaar_Mirai_065_34c3c6f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34c3c6f2d3920e8643cdbd0bd7e66bba8d2a066ddd9e3eacd8c19b1c7694bce7"
    family = "Mirai"
    file_name = "bot.ppc440"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:48"
  condition:
    hash.sha256(0, filesize) == "34c3c6f2d3920e8643cdbd0bd7e66bba8d2a066ddd9e3eacd8c19b1c7694bce7"
}

rule MalwareBazaar_Mirai_066_3cc6e26d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3cc6e26d1ac6aa7e804a51dbebb7edd134e3e48097b0bce49a85d1e1b0671e3a"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:46"
  condition:
    hash.sha256(0, filesize) == "3cc6e26d1ac6aa7e804a51dbebb7edd134e3e48097b0bce49a85d1e1b0671e3a"
}

rule MalwareBazaar_Mirai_067_7322610f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7322610f54ac41353161f90b35f975125eb65dedb5933c280ed197c8f6638749"
    family = "Mirai"
    file_name = "powerpc"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:43"
  condition:
    hash.sha256(0, filesize) == "7322610f54ac41353161f90b35f975125eb65dedb5933c280ed197c8f6638749"
}

rule MalwareBazaar_Mirai_068_dc2adaa5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc2adaa551af3e6fa6a76ec4f9c9599e39da33705dc22fe186d52f4b3c57a074"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:40"
  condition:
    hash.sha256(0, filesize) == "dc2adaa551af3e6fa6a76ec4f9c9599e39da33705dc22fe186d52f4b3c57a074"
}

rule MalwareBazaar_Gafgyt_069_8323cf5a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8323cf5a01e889abcb3bae7a498f4750fd4ad44f44495ca72fd42319cdd5560a"
    family = "Gafgyt"
    file_name = "armv4l"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:37"
  condition:
    hash.sha256(0, filesize) == "8323cf5a01e889abcb3bae7a498f4750fd4ad44f44495ca72fd42319cdd5560a"
}

rule MalwareBazaar_Mirai_070_3e95e873
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e95e873dedae3cbe5458444b3cca9270a7d8dfcc998eb79adc651a04c518413"
    family = "Mirai"
    file_name = "i586"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:34"
  condition:
    hash.sha256(0, filesize) == "3e95e873dedae3cbe5458444b3cca9270a7d8dfcc998eb79adc651a04c518413"
}

rule MalwareBazaar_Mirai_071_56c3e4dd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "56c3e4dd1d1a7e32c9fb9f43bf14d23bb4d5ece5aff9adf933c3bfde15cd26d5"
    family = "Mirai"
    file_name = "sparc"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:32"
  condition:
    hash.sha256(0, filesize) == "56c3e4dd1d1a7e32c9fb9f43bf14d23bb4d5ece5aff9adf933c3bfde15cd26d5"
}

rule MalwareBazaar_Mirai_072_8141fb25
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8141fb252441eb74264b6adf1d3e2c887620f3e1afcd0506186b936439ccd665"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:28"
  condition:
    hash.sha256(0, filesize) == "8141fb252441eb74264b6adf1d3e2c887620f3e1afcd0506186b936439ccd665"
}

rule MalwareBazaar_Gafgyt_073_03d477d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "03d477d4a5e14e77a482ef3b2a4f755ae73c02f167af38471e4f247639554ccf"
    family = "Gafgyt"
    file_name = "armv5l"
    file_type = "elf"
    first_seen = "2026-10-13 05:31:25"
  condition:
    hash.sha256(0, filesize) == "03d477d4a5e14e77a482ef3b2a4f755ae73c02f167af38471e4f247639554ccf"
}

rule MalwareBazaar_Mirai_074_3e68de6f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e68de6f60c7fb5911837df0a5ce6a9aafd4e54a53af4c21bd8472fe16df4c67"
    family = "Mirai"
    file_name = "main_ppc"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:13"
  condition:
    hash.sha256(0, filesize) == "3e68de6f60c7fb5911837df0a5ce6a9aafd4e54a53af4c21bd8472fe16df4c67"
}

rule MalwareBazaar_Mirai_075_498ac2d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "498ac2d84c8ea5730bcb960556734a0e7407faeb33fb859f01602b93aed5d786"
    family = "Mirai"
    file_name = "main_mpsl"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:11"
  condition:
    hash.sha256(0, filesize) == "498ac2d84c8ea5730bcb960556734a0e7407faeb33fb859f01602b93aed5d786"
}

rule MalwareBazaar_Mirai_076_d462900f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d462900f4ea70ad634803710b3360bddabb6f74244e38c6c9854f6deb3cf4c6c"
    family = "Mirai"
    file_name = "main_sh4"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:08"
  condition:
    hash.sha256(0, filesize) == "d462900f4ea70ad634803710b3360bddabb6f74244e38c6c9854f6deb3cf4c6c"
}

rule MalwareBazaar_Mirai_077_fef4ca17
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fef4ca17e2e6bf135e017fadbfab10bf89086b878139d6d0ac0d1443f97220d8"
    family = "Mirai"
    file_name = "main_arm5"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:06"
  condition:
    hash.sha256(0, filesize) == "fef4ca17e2e6bf135e017fadbfab10bf89086b878139d6d0ac0d1443f97220d8"
}

rule MalwareBazaar_Mirai_078_d5872fe9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d5872fe90fe7b76308f57b1d1ab7ebeb8eab06e55a67105774e2aa2a4b746720"
    family = "Mirai"
    file_name = "main_m68k"
    file_type = "elf"
    first_seen = "2026-10-13 05:11:04"
  condition:
    hash.sha256(0, filesize) == "d5872fe90fe7b76308f57b1d1ab7ebeb8eab06e55a67105774e2aa2a4b746720"
}

rule MalwareBazaar_NetSupport_079_05bdc124
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31"
    family = "NetSupport"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-13 05:04:00"
  condition:
    hash.sha256(0, filesize) == "05bdc12486c7b3f60e07653b3411be4beee7a29a6547bacd1b775717dbc4ea31"
}

rule MalwareBazaar_Mirai_080_a9133049
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a91330492f0531032816fe6033b0dd3a579b285dff39559a392be153f8dc6d37"
    family = "Mirai"
    file_name = "aisu.i486"
    file_type = "elf"
    first_seen = "2026-10-13 05:02:20"
  condition:
    hash.sha256(0, filesize) == "a91330492f0531032816fe6033b0dd3a579b285dff39559a392be153f8dc6d37"
}

rule MalwareBazaar_Formbook_081_a666c1bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5"
    family = "Formbook"
    file_name = "SOA #Q4-2026.exe"
    file_type = "exe"
    first_seen = "2026-10-13 05:01:11"
  condition:
    hash.sha256(0, filesize) == "a666c1bded48fe95e898d3338a5f5a451668745a415815c8a3a215751ec5a9e5"
}

rule MalwareBazaar_Vidar_082_e07c5e68
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b"
    family = "Vidar"
    file_name = "e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:49:24"
  condition:
    hash.sha256(0, filesize) == "e07c5e686877ffef93fd223bdf420f13e3e0d8fac952336f6f8359d55bc6e06b"
}

rule MalwareBazaar_unknown_083_5cde9484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5cde94846e1e9c2e97d7c6e0b2ce506341f47ad411f305d6de5c4dbf21ccd3e8"
    family = "unknown"
    file_name = "anticheat_update.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:33:46"
  condition:
    hash.sha256(0, filesize) == "5cde94846e1e9c2e97d7c6e0b2ce506341f47ad411f305d6de5c4dbf21ccd3e8"
}

rule MalwareBazaar_unknown_084_1c8db058
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c8db058dd109899cc1fb6ef362fa7b6b7871b3248e510531ed875dcccc1e7f8"
    family = "unknown"
    file_name = "faceit.ps1"
    file_type = "ps1"
    first_seen = "2026-10-13 04:29:49"
  condition:
    hash.sha256(0, filesize) == "1c8db058dd109899cc1fb6ef362fa7b6b7871b3248e510531ed875dcccc1e7f8"
}

rule MalwareBazaar_Formbook_085_9ddd6070
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee"
    family = "Formbook"
    file_name = "QUOTATION_FORMS.js"
    file_type = "js"
    first_seen = "2026-10-13 04:28:49"
  condition:
    hash.sha256(0, filesize) == "9ddd60703a3f6ac15d3f9c1aa435b5fbbbea51724a15e4a50570cd59d2f729ee"
}

rule MalwareBazaar_ValleyRAT_086_c741e678
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c741e6782fb3cf5e1c0e220781de618eae7317b3120bce9c642d7e8d71970957"
    family = "ValleyRAT"
    file_name = "1921841f7abdd3dcd00ba9316aef101f.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:47"
  condition:
    hash.sha256(0, filesize) == "c741e6782fb3cf5e1c0e220781de618eae7317b3120bce9c642d7e8d71970957"
}

rule MalwareBazaar_ValleyRAT_087_fd651349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6513495a7b63565afe836b6e7b3581ed767d66f5b2e31fc642766671d06858"
    family = "ValleyRAT"
    file_name = "0d74b16d2022d70ffd074ecf48579a99.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:43"
  condition:
    hash.sha256(0, filesize) == "fd6513495a7b63565afe836b6e7b3581ed767d66f5b2e31fc642766671d06858"
}

rule MalwareBazaar_DCRat_088_b028b2b4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9"
    family = "DCRat"
    file_name = "A0FFB31D84C2F5FFACD879F4F12C1CE6.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:38"
  condition:
    hash.sha256(0, filesize) == "b028b2b4a6a39c51841a13e12f483b901339995a3ba40f46c63b4055d7a781a9"
}

rule MalwareBazaar_DCRat_089_c6ed1c7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c"
    family = "DCRat"
    file_name = "7B7E613EBF31774A1883442FA1728A9B.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:33"
  condition:
    hash.sha256(0, filesize) == "c6ed1c7e207d9a18d5b8e0a009526da568295cb0de5a030c4607b34cb4edb02c"
}

rule MalwareBazaar_RemcosRAT_090_e0e218a1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2"
    family = "RemcosRAT"
    file_name = "00e1caf43096125ae92ab913d6ee905e.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:28"
  condition:
    hash.sha256(0, filesize) == "e0e218a1ce45c5a7c2e777f52d466334671c583469c6d489a94275c5a3341ab2"
}

rule MalwareBazaar_RemcosRAT_091_bbb93295
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bbb93295a53d22150eef772cc4ab5436e769f97041e741d6377c9373468c03ad"
    family = "RemcosRAT"
    file_name = "SwiftMtc.JS.js"
    file_type = "js"
    first_seen = "2026-10-13 04:15:24"
  condition:
    hash.sha256(0, filesize) == "bbb93295a53d22150eef772cc4ab5436e769f97041e741d6377c9373468c03ad"
}

rule MalwareBazaar_njrat_092_136bfdf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "136bfdf68486a6b8d9acaaf957c4936f4364953c148a7de195b791c875b83452"
    family = "njrat"
    file_name = "8A727EB3C78BA186DFEF3C0EDB90D3BD.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:16"
  condition:
    hash.sha256(0, filesize) == "136bfdf68486a6b8d9acaaf957c4936f4364953c148a7de195b791c875b83452"
}

rule MalwareBazaar_NanoCore_093_41bf4c83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41bf4c830222866a7f4d795937574fb21a4e1a03fc5cb7a80c5399946b01f0eb"
    family = "NanoCore"
    file_name = "24d7969a26c4e42778d6d1cfab4ced2d.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:10"
  condition:
    hash.sha256(0, filesize) == "41bf4c830222866a7f4d795937574fb21a4e1a03fc5cb7a80c5399946b01f0eb"
}

rule MalwareBazaar_NanoCore_094_063a7162
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a"
    family = "NanoCore"
    file_name = "223d1c4d8ffbb76a5638290572fefec9.exe"
    file_type = "exe"
    first_seen = "2026-10-13 04:15:06"
  condition:
    hash.sha256(0, filesize) == "063a716290fe030ad8fc767c7e47ec7e57b26cce7e3c7f466434f07572100a8a"
}

rule MalwareBazaar_AsyncRAT_095_c50aaeeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c50aaeeb818ba3fd2ff56ff05702286ee3700461f84d2b499a0de2a4c99f5cdc"
    family = "AsyncRAT"
    file_name = "c50aaeeb818ba3fd.bin"
    file_type = "exe"
    first_seen = "2026-10-13 03:24:31"
  condition:
    hash.sha256(0, filesize) == "c50aaeeb818ba3fd2ff56ff05702286ee3700461f84d2b499a0de2a4c99f5cdc"
}

rule MalwareBazaar_Gafgyt_096_748ea204
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "748ea2040710a547411a6f038fea97f16919baaab0d878048b87fd87158b8bfd"
    family = "Gafgyt"
    file_name = "mbupload-gja2vdid.bin"
    file_type = "sh"
    first_seen = "2026-10-13 02:56:04"
  condition:
    hash.sha256(0, filesize) == "748ea2040710a547411a6f038fea97f16919baaab0d878048b87fd87158b8bfd"
}

rule MalwareBazaar_PureRAT_097_4d75d51f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4d75d51f4439a5706e061891065844a5201185fe345ed3f4aa72d8b2ec8bb914"
    family = "PureRAT"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-13 02:44:05"
  condition:
    hash.sha256(0, filesize) == "4d75d51f4439a5706e061891065844a5201185fe345ed3f4aa72d8b2ec8bb914"
}

rule MalwareBazaar_AMOS_098_f719a1d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f719a1d71332414c1621b0ceaa56485bfc80bcfb2c072d247b25daecd026aef4"
    family = "AMOS"
    file_name = "macho_f719a1d71332.bin"
    file_type = "macho"
    first_seen = "2026-10-13 02:30:53"
  condition:
    hash.sha256(0, filesize) == "f719a1d71332414c1621b0ceaa56485bfc80bcfb2c072d247b25daecd026aef4"
}

rule MalwareBazaar_unknown_099_1d129b9c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d129b9c9a6c5aad8a22a3f7cbf45da61c7eb9150f160f495bd15a0f2cd1d8af"
    family = "unknown"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-13 02:23:33"
  condition:
    hash.sha256(0, filesize) == "1d129b9c9a6c5aad8a22a3f7cbf45da61c7eb9150f160f495bd15a0f2cd1d8af"
}

rule MalwareBazaar_Mirai_100_3b077941
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3b077941b8b6eb84e861da7c7dc8ab68e0a5acfc7a9a4d3e21c0360fbb1613eb"
    family = "Mirai"
    file_name = "pid.arm5"
    file_type = "elf"
    first_seen = "2026-10-13 02:23:30"
  condition:
    hash.sha256(0, filesize) == "3b077941b8b6eb84e861da7c7dc8ab68e0a5acfc7a9a4d3e21c0360fbb1613eb"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

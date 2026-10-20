# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-20

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 640 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 640 |
| Unique family labels | 9 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 57 |
| Mirai | 31 |
| SalatStealer | 4 |
| Snowlight | 2 |
| AMOS | 2 |
| Loki | 1 |
| RemusStealer | 1 |
| AgentTesla | 1 |
| WannaCry | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 33 |
| js | 21 |
| macho | 20 |
| exe | 14 |
| msi | 5 |
| ps1 | 3 |
| sh | 1 |
| zip | 1 |
| vbs | 1 |
| hta | 1 |

## Per-Sample Analysis

### Sample 1: `9d0c0819b915625b`

| Field | Value |
|---|---|
| SHA-256 | `9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002` |
| Family label | `unknown` |
| File name | `macho_9d0c0819b915.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:51:47` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3d7b6af2acd15e52747f1fd068f7dc22` |
| SHA-1 | `a13cdcd85a1fde08b892d4c56379fd18ae5c8f8f` |
| SHA-256 | `9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002` |
| SHA3-384 | `451a7a4abd037c75a7f1809ecbd809774d54165f86ee64bf5b3bd170e812f7d9da2748f831283a55a7343a262b561625` |
| TLSH | `T14F85E03C7E695356E4C46473DC104F1757A0A6C2BB08FEE86122C627ED39643FA732A6` |
| SSDEEP | `49152:zvtbF8cElUEHfpiSha3xWQ+wuoecq6EHz0W:zv5eAW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_9d0c0819
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002"
    family = "unknown"
    file_name = "macho_9d0c0819b915.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:51:47"
  condition:
    hash.sha256(0, filesize) == "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002"
}
```

### Sample 2: `1b317f7c91282bc4`

| Field | Value |
|---|---|
| SHA-256 | `1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4` |
| Family label | `unknown` |
| File name | `macho_1b317f7c9128.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:51:21` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e0a8bad8a3694f5abdb816b5227ddae` |
| SHA-1 | `f483b792db57555d98cc640a6f156765bda2c439` |
| SHA-256 | `1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4` |
| SHA3-384 | `2459ff983770a2c320797c6c58b4ece53b4c8ab250591335d1d2708c62a06ddfc7ee19d7c886d63f48d74d65626460df` |
| TLSH | `T12F95F1745A752156DF9720F28C0D4FD118E066E04F4CAAE9A220DA8B6F361D7B5F33E2` |
| SSDEEP | `24576:jfOZOGvtJE5rioHyZlCDy3rqwJ7Dfru0uJxtsuWMAHL9VuEHfMK0i3Lx74I12blQ:rZwhzUTF4Oyl0i3N74I12OAFbQrNV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_002_1b317f7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4"
    family = "unknown"
    file_name = "macho_1b317f7c9128.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:51:21"
  condition:
    hash.sha256(0, filesize) == "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4"
}
```

### Sample 3: `b7a942961139b0f2`

| Field | Value |
|---|---|
| SHA-256 | `b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04` |
| Family label | `unknown` |
| File name | `macho_b7a942961139.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:50:39` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b530642cdec273ca5526de03b8c21a18` |
| SHA-1 | `727811ab4e91feae63dd952548ec324d2569b8d6` |
| SHA-256 | `b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04` |
| SHA3-384 | `ed94f5e9f724c38f9d42a3e69fc60e348a13c0ac5514c7b4355a00381846ec63f0d52899bef2aba53a742faba225479f` |
| TLSH | `T161A5F1D06B3A421AD8943172DC1C0F4512E0B7999AE8FBF9A935C7077D35293BA77232` |
| SSDEEP | `24576:5mq1OxqfWLHB6NWqN/9CHEhud5VlSgstufqu7Xo+NwwvPynlD6F6xCKzsZqRLnd2:5mqWrU9mpiY7fvvPynMF6oMfAGVs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_003_b7a94296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04"
    family = "unknown"
    file_name = "macho_b7a942961139.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:50:39"
  condition:
    hash.sha256(0, filesize) == "b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04"
}
```

### Sample 4: `1a68e1064373a2e4`

| Field | Value |
|---|---|
| SHA-256 | `1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e` |
| Family label | `unknown` |
| File name | `macho_1a68e1064373.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:50:11` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4acde16c45eee420ea36e0d0dcaf953c` |
| SHA-1 | `f4f507dd5bc3f3d1daf54861e6c82709613dc62c` |
| SHA-256 | `1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e` |
| SHA3-384 | `f37522e8c14f5c6f2c70cd609683f180154251d0014a7350da1058906a2b54cddb9fea995b2e68b5a91e1b5ce6753e3d` |
| TLSH | `T14CA5E0508F5BB19BD44B00339C9A4F99847020A0DE45DEE95301F3A9DE366E37F52ABB` |
| SSDEEP | `24576:kBMBs94O8qePwnQHZCpgOYGlvlQdMfzf7qdPPVvUxwxr5VP9I+5dmSbfH9Zo/zfM:kBM1pWr2dJxr5VP9I+5dmmdm/g` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_1a68e106
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e"
    family = "unknown"
    file_name = "macho_1a68e1064373.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:50:11"
  condition:
    hash.sha256(0, filesize) == "1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e"
}
```

### Sample 5: `fd82918a68014f37`

| Field | Value |
|---|---|
| SHA-256 | `fd82918a68014f37556f4d80b16ec34a446b96e6f1a0fbce5569165a72aa71ad` |
| Family label | `Mirai` |
| File name | `s390x` |
| File type | `elf` |
| First seen | `2026-10-20 04:32:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b3c569c54d84eccc55b7a7adde1016d` |
| SHA-1 | `a536c3af2edf4cf5e9ed34458e420275f7852a92` |
| SHA-256 | `fd82918a68014f37556f4d80b16ec34a446b96e6f1a0fbce5569165a72aa71ad` |
| SHA3-384 | `b061afca94bc1b22b618bef68f1942e150c64a569a6db45227065f5c0367d97293e2d2415457720ad7a75683afce73a3` |
| TLSH | `T13CA4E7CC51B1E3CED064AD32D22679F68A66123734837A8C61DEEB7711F7246067AE31` |
| SSDEEP | `6144:Li/9ssOGChIFvzfCkOasCfNZ4e9vSl+qyaMx65CfwPWqcR3:GVss9Ch5nasCfNZ4e9Oq65nOq03` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_005_fd82918a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd82918a68014f37556f4d80b16ec34a446b96e6f1a0fbce5569165a72aa71ad"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-10-20 04:32:29"
  condition:
    hash.sha256(0, filesize) == "fd82918a68014f37556f4d80b16ec34a446b96e6f1a0fbce5569165a72aa71ad"
}
```

### Sample 6: `9617d6bd7aa6e4eb`

| Field | Value |
|---|---|
| SHA-256 | `9617d6bd7aa6e4eb557fcb23437f9b5cd6e1363646ca8f25ca5c8a7fbe47432c` |
| Family label | `SalatStealer` |
| File name | `mbupload-4rqeb3gz.bin` |
| File type | `exe` |
| First seen | `2026-10-20 04:30:40` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74c72ddac64eac9e86b1913d56819b28` |
| SHA-1 | `77f382596da88d96d64757bf35d69aeca707e16c` |
| SHA-256 | `9617d6bd7aa6e4eb557fcb23437f9b5cd6e1363646ca8f25ca5c8a7fbe47432c` |
| SHA3-384 | `ce0e343af5b378ad08d9898a528824d32231738d39432ad9d70a8e875f7f203af67a6447aeacfd3a78f260e0ac2ea52b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1E5C65B11FADB95F1E903183141ABB37F23315D048B28DB9BEB547B2AF87B6A11C66305` |
| SSDEEP | `98304:ud1lqNeNV7CgE3yQJ6meir4Vh9C8Ll4tG20CWEp:+qOJEChmeFRHCp` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_006_9617d6bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9617d6bd7aa6e4eb557fcb23437f9b5cd6e1363646ca8f25ca5c8a7fbe47432c"
    family = "SalatStealer"
    file_name = "mbupload-4rqeb3gz.bin"
    file_type = "exe"
    first_seen = "2026-10-20 04:30:40"
  condition:
    hash.sha256(0, filesize) == "9617d6bd7aa6e4eb557fcb23437f9b5cd6e1363646ca8f25ca5c8a7fbe47432c"
}
```

### Sample 7: `500ebf9173407dd0`

| Field | Value |
|---|---|
| SHA-256 | `500ebf9173407dd0fa790182af8b516a9381172b0560e04ae03b4da730eae505` |
| Family label | `SalatStealer` |
| File name | `mbupload-4rqeb3gz.bin` |
| File type | `exe` |
| First seen | `2026-10-20 04:29:29` |
| Reporter | `wristhulk` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94b245b0f717f4102e1628a72ef443b9` |
| SHA-1 | `7d3c7f791ddc13bf9b7ef27972e488d53bddc3c4` |
| SHA-256 | `500ebf9173407dd0fa790182af8b516a9381172b0560e04ae03b4da730eae505` |
| SHA3-384 | `3f5dfec83ee29d391652d70967822887e8be946555024c523b3be9b7e542e4ead38bbde800f02b251b932d9b70dc8328` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T133F533065659E12CC75AF6BF14C4644F7DE7207EA6DA0C74F7678A8F3042A9E2A0C3C6` |
| SSDEEP | `49152:KUNA+vrTE5syncPmy8X+q2TSwVee/S+ltYi7F/7b9U8v1nlFv14zXKfxW5CWOT1M:KyrTE+y+Tq2TVO+ltv/7b6MNxoCT1tt` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_007_500ebf91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "500ebf9173407dd0fa790182af8b516a9381172b0560e04ae03b4da730eae505"
    family = "SalatStealer"
    file_name = "mbupload-4rqeb3gz.bin"
    file_type = "exe"
    first_seen = "2026-10-20 04:29:29"
  condition:
    hash.sha256(0, filesize) == "500ebf9173407dd0fa790182af8b516a9381172b0560e04ae03b4da730eae505"
}
```

### Sample 8: `b2b090f8e7180028`

| Field | Value |
|---|---|
| SHA-256 | `b2b090f8e71800288cf2dfa6bde8e61c043cd34937600458b83e20939d2b1098` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-20 04:29:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54d70234834c1c6865f0c002c28a1dce` |
| SHA-1 | `3bd3c73f11b72acc0847df49cee0031c7d67164a` |
| SHA-256 | `b2b090f8e71800288cf2dfa6bde8e61c043cd34937600458b83e20939d2b1098` |
| SHA3-384 | `a6aac4d60de9fbd037d2ab132548b20ea66aab716eb3f8729950a22e75e4cf911a396df3e994a2a841a79852de7d5eeb` |
| TLSH | `T12FD3E91A7A158FADF28EC63147F78E3156A427D12B92E141E16CDB102F2139D6C4FFA8` |
| TELFHASH | `t1f4311e755b22a1166960dd68ddfe87b1a51a83131784ff33ef2688cc240a04ee72bc4f` |
| SSDEEP | `1536:mfFTBUgJNcwHw9dv6XTf67X2cTD+98NmDsEpopl/Gw07UQ6PL1:mYgJN9H56r88msEWpl/Gw0bm1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_b2b090f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2b090f8e71800288cf2dfa6bde8e61c043cd34937600458b83e20939d2b1098"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-20 04:29:24"
  condition:
    hash.sha256(0, filesize) == "b2b090f8e71800288cf2dfa6bde8e61c043cd34937600458b83e20939d2b1098"
}
```

### Sample 9: `181ce015e92b7982`

| Field | Value |
|---|---|
| SHA-256 | `181ce015e92b79825cf042fcf67ef3ea1e35073f0387e91c3e52a13bd9821c29` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-20 04:29:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `60a6f50508b0de849011cc6458e0299f` |
| SHA-1 | `078280bd01e5f4c83b4d4e32da2f45f1684ae785` |
| SHA-256 | `181ce015e92b79825cf042fcf67ef3ea1e35073f0387e91c3e52a13bd9821c29` |
| SHA3-384 | `33bd23902f5e8e2d7bf0a28f1add7f26c894413ae85cfdc35f213b1f02db5c6d4dfca7c686aaecf8fabb9feb0d33e1fb` |
| TLSH | `T172941A88E1F0E7DAD2C4AA75B31D794D3B230736F1D73146E519AA3223EB1890ABDD11` |
| TELFHASH | `t106f023f0eb7e02d4e002054e41c9e1107678193afb0100d92fc9374f6823f8084d5f5b` |
| SSDEEP | `6144:2NcMgOkWpvMv65okaqS9MFxvwqPEm5PiNza3mxIsLAJwZcKQmemtsHd+ma9yV:6JkwMvXj7PNW3wyKQzHa9y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_181ce015
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "181ce015e92b79825cf042fcf67ef3ea1e35073f0387e91c3e52a13bd9821c29"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-20 04:29:22"
  condition:
    hash.sha256(0, filesize) == "181ce015e92b79825cf042fcf67ef3ea1e35073f0387e91c3e52a13bd9821c29"
}
```

### Sample 10: `66190998e6606df3`

| Field | Value |
|---|---|
| SHA-256 | `66190998e6606df3b635ef7e4e1905f44a869bcce0458325abeb9f05cd02aed5` |
| Family label | `Mirai` |
| File name | `3` |
| File type | `elf` |
| First seen | `2026-10-20 04:26:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e11cfb61dea8d0f073b75a88baba11b7` |
| SHA-1 | `d2fb2dfd6a76bfa1f59bc3ea0f14f04a99335de4` |
| SHA-256 | `66190998e6606df3b635ef7e4e1905f44a869bcce0458325abeb9f05cd02aed5` |
| SHA3-384 | `21a99e3b617f7a71c79fbbfd2fe6e9eb24a573f4a25d170a5ed3409a6c291b3807935bc550356e2751a0e7d7018c10b1` |
| TLSH | `T1E1D4E195F3472F46C4D7E53A948AC652475AE85B33F383093E43A6BA346D3728F28349` |
| SSDEEP | `12288:yau8R1tGebPyLPQVFLymAwQlA0f+fnwjz/CzeZtIufgMdngpZ4J2p5:lu8RtmQVFGm7UfkKZtCw27` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_66190998
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66190998e6606df3b635ef7e4e1905f44a869bcce0458325abeb9f05cd02aed5"
    family = "Mirai"
    file_name = "3"
    file_type = "elf"
    first_seen = "2026-10-20 04:26:31"
  condition:
    hash.sha256(0, filesize) == "66190998e6606df3b635ef7e4e1905f44a869bcce0458325abeb9f05cd02aed5"
}
```

### Sample 11: `230358697a046289`

| Field | Value |
|---|---|
| SHA-256 | `230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d` |
| Family label | `Mirai` |
| File name | `6` |
| File type | `elf` |
| First seen | `2026-10-20 04:26:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `388fabdae67236102d8747a2022766f7` |
| SHA-1 | `1972746e2da908d9b90f879049c89289bc6331f6` |
| SHA-256 | `230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d` |
| SHA3-384 | `8436b04856d32d66829f968181168adc387b72ccd307f719e5d0d292a2b568fe725db1ecd5d737e90b7b38b64c94c680` |
| TLSH | `T1E9256A16EF840FEBC8AFCD30492E835714EDCDD742D1AA3961FC8D48BA5A2595AD348C` |
| SSDEEP | `24576:C3U+OXNdM7QR0pWlJfvqLlVzy0jWhenQmxZZZ6ZZgE:C3Ed8pVzy0iaE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_011_23035869
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d"
    family = "Mirai"
    file_name = "6"
    file_type = "elf"
    first_seen = "2026-10-20 04:26:29"
  condition:
    hash.sha256(0, filesize) == "230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d"
}
```

### Sample 12: `609316b027434e33`

| Field | Value |
|---|---|
| SHA-256 | `609316b027434e338a24c2a2499bb1903c1cdcf3424f13d9d33e00257d805f26` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-20 04:26:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23e20335bd3686867ed227c91f97b7ae` |
| SHA-1 | `70a78789fdaa16f487942a5b706f3f762f6afe9b` |
| SHA-256 | `609316b027434e338a24c2a2499bb1903c1cdcf3424f13d9d33e00257d805f26` |
| SHA3-384 | `dcb092850d5b5781b34bbd352eb9622451e492c98b385d42de25f92a05e639f3e3fed14c9751a188b35c710e660fca0e` |
| TLSH | `T106E33A56E6404B13C0D62775B6EF424533239BA493EB73069928BFF43F8679E0E63A05` |
| TELFHASH | `t1ac310e755b22a1166961dd64d9fe87b1a51983131784ff33df2688cc240904ee72bc5f` |
| SSDEEP | `3072:Wec8Z8iaYCsqdYA9N5hMiZ7cnGXROM/9xlVwyZ:WeEiaYCsqdYsNpNcnGXsM/9Sw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_609316b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "609316b027434e338a24c2a2499bb1903c1cdcf3424f13d9d33e00257d805f26"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-20 04:26:27"
  condition:
    hash.sha256(0, filesize) == "609316b027434e338a24c2a2499bb1903c1cdcf3424f13d9d33e00257d805f26"
}
```

### Sample 13: `f70f77d2ddc78d5f`

| Field | Value |
|---|---|
| SHA-256 | `f70f77d2ddc78d5ff61c890822ec8a5ec2051c630efc14d4e67496956ff933bd` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Heur.14654.12795` |
| File type | `msi` |
| First seen | `2026-10-20 04:26:02` |
| Reporter | `SecuriteInfoCom` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c9a1ea11d8a2a5495a3018ff2400fe37` |
| SHA-1 | `8b604805953a9b98fa946427667880325e8eaa66` |
| SHA-256 | `f70f77d2ddc78d5ff61c890822ec8a5ec2051c630efc14d4e67496956ff933bd` |
| SHA3-384 | `568b61d7cd037b7e36941cf68c58955fa3ccad61c27c710bc690b25aa710086ead1029eea400cb8ce1882d71fe88f4de` |
| TLSH | `T1F9B54C636A50600552B5A8FABEBD5E37794F3409102AD98EFFD30B86F52E6F44802D1F` |
| SSDEEP | `24576:PDcs+zkuBYCbM6UEVfofhGVo59FqYGauw4o4Y01qZtLoNmdTD:Pn8YQuF8VozA3rqZ5ocX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_f70f77d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f70f77d2ddc78d5ff61c890822ec8a5ec2051c630efc14d4e67496956ff933bd"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.14654.12795"
    file_type = "msi"
    first_seen = "2026-10-20 04:26:02"
  condition:
    hash.sha256(0, filesize) == "f70f77d2ddc78d5ff61c890822ec8a5ec2051c630efc14d4e67496956ff933bd"
}
```

### Sample 14: `c47583ad7634aae5`

| Field | Value |
|---|---|
| SHA-256 | `c47583ad7634aae58698370056ca7317a9856e48d381f7cf1412eaa7f7b73476` |
| Family label | `unknown` |
| File name | `c47583ad7634aae5.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:25:57` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ffd4f7759c5ff7e0e1e9e0cf3b90f55` |
| SHA-1 | `761e39c5dc25f3b6e2227a60896414dd53ef3630` |
| SHA-256 | `c47583ad7634aae58698370056ca7317a9856e48d381f7cf1412eaa7f7b73476` |
| SHA3-384 | `208fe25d2a76d33f96a002606acfc0d37c25b4c943138fcd032984b255afd0bb8c381dc5fa258455fb339cf5b2c3d766` |
| TLSH | `T1E8F25F139B1C0A61C55C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB9D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRftPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfUlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_c47583ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c47583ad7634aae58698370056ca7317a9856e48d381f7cf1412eaa7f7b73476"
    family = "unknown"
    file_name = "c47583ad7634aae5.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:25:57"
  condition:
    hash.sha256(0, filesize) == "c47583ad7634aae58698370056ca7317a9856e48d381f7cf1412eaa7f7b73476"
}
```

### Sample 15: `0229775513f13eec`

| Field | Value |
|---|---|
| SHA-256 | `0229775513f13eec54bf2105537fb9512fb0741deed0f07b1f0a323f0600279a` |
| Family label | `unknown` |
| File name | `0229775513f13eec.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:25:49` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1e183ca1ec331f076fd5738a1b230771` |
| SHA-1 | `601da2e41a3abfcec65d96d2b7e7a80b383cc9ed` |
| SHA-256 | `0229775513f13eec54bf2105537fb9512fb0741deed0f07b1f0a323f0600279a` |
| SHA3-384 | `bbb32e8aae46b7a350ad9560a5e05431382caf43b7a6af71b5d07d322c15cb63ab62a4b151f121021b74ca50f84079f5` |
| TLSH | `T19FF24E139B1C1A61C05D633C92BB1B026276F5D086C66B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRThPlxkllLRgowjWaXLRgoz0MLAR:MGL7IKo4Gxcf/mJfglilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_02297755
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0229775513f13eec54bf2105537fb9512fb0741deed0f07b1f0a323f0600279a"
    family = "unknown"
    file_name = "0229775513f13eec.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:25:49"
  condition:
    hash.sha256(0, filesize) == "0229775513f13eec54bf2105537fb9512fb0741deed0f07b1f0a323f0600279a"
}
```

### Sample 16: `61806fd27c93892b`

| Field | Value |
|---|---|
| SHA-256 | `61806fd27c93892b7c553a0bfc9f1f40c129506a828596db61b73ef9023bdd17` |
| Family label | `unknown` |
| File name | `61806fd27c93892b.bin` |
| File type | `macho` |
| First seen | `2026-10-20 04:25:41` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51e86e08aca179f89d13af46a9a660bc` |
| SHA-1 | `90abb623606494fa7cefe49637d87b36f1b1285c` |
| SHA-256 | `61806fd27c93892b7c553a0bfc9f1f40c129506a828596db61b73ef9023bdd17` |
| SHA3-384 | `d57d09b239e745452c22cd108c02476d46af08ace281c57446ab7b1cfa934303636f85c0cb0b03ceaa1c983a07d67c9a` |
| TLSH | `T1E6E23F43AB4C8965C26D92301AF71BC6A616F5B09EE16B875750C7217FE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUuVZqDDt0TOTLZ0BbFw2nHKk6XrMclSibFqAMcl:z4ZZXvv/VZMt0TO2bVH/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_61806fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61806fd27c93892b7c553a0bfc9f1f40c129506a828596db61b73ef9023bdd17"
    family = "unknown"
    file_name = "61806fd27c93892b.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:25:41"
  condition:
    hash.sha256(0, filesize) == "61806fd27c93892b7c553a0bfc9f1f40c129506a828596db61b73ef9023bdd17"
}
```

### Sample 17: `dc35da5b2a0b61c0`

| Field | Value |
|---|---|
| SHA-256 | `dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38` |
| Family label | `unknown` |
| File name | `dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38.sh` |
| File type | `sh` |
| First seen | `2026-10-20 04:20:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b99f652dc5a0f573b5b42bad7fd58c73` |
| SHA-1 | `4030b35765e45651d2567771e258749073fc94f8` |
| SHA-256 | `dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38` |
| SHA3-384 | `7f6a283cb3a8d368a395baa437efde7c3100cd66cf3b3c3f211bbf1496c1caa6279900267152c0954b58bd7f3e6326b4` |
| TLSH | `T1C052873721F08B3297C050C8A2760A614FB29B1B456620B9F4FE6735AF6DA0375E7B61` |
| SSDEEP | `192:cCu6W6p4hvZ5m5FG4j4HKNpivJVsQCGCndITZcF9D+:fJp4hvZ5m5FGGoKNpivJWQCGCndIgD+` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_dc35da5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38"
    family = "unknown"
    file_name = "dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38.sh"
    file_type = "sh"
    first_seen = "2026-10-20 04:20:40"
  condition:
    hash.sha256(0, filesize) == "dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38"
}
```

### Sample 18: `eeb0320322c04a18`

| Field | Value |
|---|---|
| SHA-256 | `eeb0320322c04a18a904e4b99a5338f99ca14c21442c793fdf7efaa7082a4873` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-20 04:14:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19394d54a976f0212e06311799c612fa` |
| SHA-1 | `0eadfe5f38d621b7f972b77d3e640a40a2797570` |
| SHA-256 | `eeb0320322c04a18a904e4b99a5338f99ca14c21442c793fdf7efaa7082a4873` |
| SHA3-384 | `d28d4002bfdeb9cb1ff47f9e6682570bc3011c0a38552cf6a74aa907ddaf04586d7de4cc4996153ce1c41d7fa1762206` |
| TLSH | `T11CA42944B3B1D3CBD284DE7053362B679B6A463238E7B189610FBB7313B317545DAAA0` |
| SSDEEP | `6144:Nb3ZwNG6L5W/EnGY7ENUmFPflayL31mpvMVEQG5tmHJFn8bcJkGhHzCpt7FItJUe:NnK6d39EXmHJmAgFItJUe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_eeb03203
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb0320322c04a18a904e4b99a5338f99ca14c21442c793fdf7efaa7082a4873"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-20 04:14:33"
  condition:
    hash.sha256(0, filesize) == "eeb0320322c04a18a904e4b99a5338f99ca14c21442c793fdf7efaa7082a4873"
}
```

### Sample 19: `8938b1cb68b3189c`

| Field | Value |
|---|---|
| SHA-256 | `8938b1cb68b3189c93f0db674b3c0b40cf35169733b1e1d23aaa37714bcdfaf1` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-20 04:11:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e53dc97abe3a138dc97a46c95d84a54b` |
| SHA-1 | `6ad9fd2f41f650c5cde393fae642e50373d5a3b6` |
| SHA-256 | `8938b1cb68b3189c93f0db674b3c0b40cf35169733b1e1d23aaa37714bcdfaf1` |
| SHA3-384 | `1f78444fa52dadb4c03265cedd2b4adfd7b0cc5d36ed0b3a5f1526b4165db97a9287c1aedf7d0ee578a966a1b9d08228` |
| TLSH | `T121E33B56E7404B13C0D61779BAEF424533239BA493EB73069924AFF43F8679E4E23A05` |
| TELFHASH | `t1ac310e755b22a1166961dd64d9fe87b1a51983131784ff33df2688cc240904ee72bc5f` |
| SSDEEP | `3072:deh8F8ca7Ye6Qxs6o4PRwZfd77cyGbyrV7lC0Vyw:de1ca7Ye6QxsOGdcyGbyrV7UqT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_8938b1cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8938b1cb68b3189c93f0db674b3c0b40cf35169733b1e1d23aaa37714bcdfaf1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-20 04:11:34"
  condition:
    hash.sha256(0, filesize) == "8938b1cb68b3189c93f0db674b3c0b40cf35169733b1e1d23aaa37714bcdfaf1"
}
```

### Sample 20: `c8c889fda0b4f309`

| Field | Value |
|---|---|
| SHA-256 | `c8c889fda0b4f309eb611cb14f00c124e0f1b49873f05545707ca0daa77eca48` |
| Family label | `Loki` |
| File name | `BC1C3537592275D79012B7810F42A3CB.exe` |
| File type | `exe` |
| First seen | `2026-10-20 04:10:06` |
| Reporter | `abuse_ch` |
| Tags | `exe, Loki` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc1c3537592275d79012b7810f42a3cb` |
| SHA-1 | `4d6eb9bf5839d8934b1f396cf988b8debb01a75e` |
| SHA-256 | `c8c889fda0b4f309eb611cb14f00c124e0f1b49873f05545707ca0daa77eca48` |
| SHA3-384 | `dd675dbd3255555cafb8d6cd9571d145c39bcf8da5c7597c2db878eb616059e6613faebf3fed9f0306297886d8e9452c` |
| IMPHASH | `0239fd611af3d0e9b0c46c5837c80e09` |
| TLSH | `T117A32942B2A5C030F7B74DB2BB73A5B7857E7C332D22C84E9352459A14215E1EB7AB13` |
| SSDEEP | `1536:6zvQSZpGS4/31A6mQgL2eYCGDwRcMkVQd8YhY0/EqJIzmd:hSHIG6mQwGmfOQd8YhY0/E0UG` |

#### Technical Assessment

- The sample is tracked as `Loki` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Loki_020_c8c889fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8c889fda0b4f309eb611cb14f00c124e0f1b49873f05545707ca0daa77eca48"
    family = "Loki"
    file_name = "BC1C3537592275D79012B7810F42A3CB.exe"
    file_type = "exe"
    first_seen = "2026-10-20 04:10:06"
  condition:
    hash.sha256(0, filesize) == "c8c889fda0b4f309eb611cb14f00c124e0f1b49873f05545707ca0daa77eca48"
}
```

### Sample 21: `e7f172b1946b0667`

| Field | Value |
|---|---|
| SHA-256 | `e7f172b1946b06674fb57333fdbe46af311a64bda7e104d88d35bf2312f69e14` |
| Family label | `unknown` |
| File name | `mbupload-qd3v0mzy.bin` |
| File type | `exe` |
| First seen | `2026-10-20 04:09:45` |
| Reporter | `wristhulk` |
| Tags | `downloader, exe, go, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fb4e282702484ab6f40db833a77bd0a` |
| SHA-1 | `45519a716b7d80416fbc32150818aba4ea6e9e46` |
| SHA-256 | `e7f172b1946b06674fb57333fdbe46af311a64bda7e104d88d35bf2312f69e14` |
| SHA3-384 | `daa80621df75c9333a8e27db728d3bb8ff0e4e54445189fda1d475a1f0aba0ef9af00a3b903e5276bac275794c917a5b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1DAA69C41FECB98F6E903193001A7B26F67345D014F25CBD7EB647B2AE97B6A11833249` |
| SSDEEP | `196608:JbW048ihnjBqMPxcTzfAsoiMJ19baWCQ:l29fPxcfosu7R` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_021_e7f172b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7f172b1946b06674fb57333fdbe46af311a64bda7e104d88d35bf2312f69e14"
    family = "unknown"
    file_name = "mbupload-qd3v0mzy.bin"
    file_type = "exe"
    first_seen = "2026-10-20 04:09:45"
  condition:
    hash.sha256(0, filesize) == "e7f172b1946b06674fb57333fdbe46af311a64bda7e104d88d35bf2312f69e14"
}
```

### Sample 22: `5c5548382cec7453`

| Field | Value |
|---|---|
| SHA-256 | `5c5548382cec74538a7b81454bfe0868c17d60dc0a74944e92e04b04a12eed0c` |
| Family label | `SalatStealer` |
| File name | `mbupload-tssooaji.bin` |
| File type | `zip` |
| First seen | `2026-10-20 04:09:14` |
| Reporter | `wristhulk` |
| Tags | `SalatStealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8a56cde395f1536fc8321daae9a58eb` |
| SHA-1 | `fdecfd84e2a21ffb06e343f0c6c340e6c6629472` |
| SHA-256 | `5c5548382cec74538a7b81454bfe0868c17d60dc0a74944e92e04b04a12eed0c` |
| SHA3-384 | `294bf5bc30d6353fa82741a3bdc7dbb18c3dfd0345c47e87865d4a2fb1e2503efa5955ac2fe686766348bfd5d5b73e0e` |
| TLSH | `T11A863329624BF053C753EFF82C1E6553DED8622609742D0E3F2528798468CD686D78FE` |
| SSDEEP | `196608:IiSVngKFf5w4xAAyS9Ypud8gSGir5mZTHbYyGDby8zT3WpKOx53Sy:eVgKFxAAySg3/rsHCbLzTDODCy` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_022_5c554838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5548382cec74538a7b81454bfe0868c17d60dc0a74944e92e04b04a12eed0c"
    family = "SalatStealer"
    file_name = "mbupload-tssooaji.bin"
    file_type = "zip"
    first_seen = "2026-10-20 04:09:14"
  condition:
    hash.sha256(0, filesize) == "5c5548382cec74538a7b81454bfe0868c17d60dc0a74944e92e04b04a12eed0c"
}
```

### Sample 23: `6561897bb373f25b`

| Field | Value |
|---|---|
| SHA-256 | `6561897bb373f25b7002a595c69a45292f2abc9e61141ca90fc39ecf8c0979ac` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-20 04:05:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `80b9d31ee08cf7019148a4809e11e47c` |
| SHA-1 | `0f6a5d8a5bae4dbfa790acfd3752de035bb668bc` |
| SHA-256 | `6561897bb373f25b7002a595c69a45292f2abc9e61141ca90fc39ecf8c0979ac` |
| SHA3-384 | `450123f9a069305c2bc5f57f8791d80481969bccc3c138732c88b762e9e02882f1a5cc72f66f1b00e764817f20a9ec1a` |
| TLSH | `T189E32B56EB404B13C0D61779B6EF424533239BA493EB73069924AFF43F8679E4E23A05` |
| TELFHASH | `t1ac310e755b22a1166961dd64d9fe87b1a51983131784ff33df2688cc240904ee72bc5f` |
| SSDEEP | `3072:deh8F8ca7Ye6Qxs6o4PRwZfd77cyGqW9xVlC0Vyw:de1ca7Ye6QxsOGdcyGqW9xVUqT` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_6561897b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6561897bb373f25b7002a595c69a45292f2abc9e61141ca90fc39ecf8c0979ac"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-20 04:05:27"
  condition:
    hash.sha256(0, filesize) == "6561897bb373f25b7002a595c69a45292f2abc9e61141ca90fc39ecf8c0979ac"
}
```

### Sample 24: `a0dc13a8633f257b`

| Field | Value |
|---|---|
| SHA-256 | `a0dc13a8633f257be504004ad534803633faac7f32439069dba8e7fda62b3dc7` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-20 04:03:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b030bc8a9f626b4654c5a36d97e54639` |
| SHA-1 | `4bc827b0baa1f70478ac3382c5c846d5c399c9aa` |
| SHA-256 | `a0dc13a8633f257be504004ad534803633faac7f32439069dba8e7fda62b3dc7` |
| SHA3-384 | `af90bd6d9ce86a5f2d1b78132ebe5ac63c737454291ae1f800c5ca57ed384afc8a5c79aba3bbcbcf2e05026763bcb165` |
| TLSH | `T106840A8D53F1DFDDE258EA3013736D1B9DB6063735D3A186E16EF922236124848AFE60` |
| TELFHASH | `t110f0e52c583c13f0d2c59c6d45dcef00e8a1c5eb54b50e2bc948d865a275f464e00c38` |
| SSDEEP | `6144:m17U88I74q3G8kCD3iTwUrqtmwvAIhyo5XZ7V:O7b8IsWQwC8b5J7V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_a0dc13a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0dc13a8633f257be504004ad534803633faac7f32439069dba8e7fda62b3dc7"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-20 04:03:26"
  condition:
    hash.sha256(0, filesize) == "a0dc13a8633f257be504004ad534803633faac7f32439069dba8e7fda62b3dc7"
}
```

### Sample 25: `1eb74c4c15d5568a`

| Field | Value |
|---|---|
| SHA-256 | `1eb74c4c15d5568a3f3edf53200da3f5e18f7be7d99fdd0c915c77b36c043ddf` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-20 04:02:30` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc57d90ed6a731d2181999ea20aeb9fb` |
| SHA-1 | `5e672644dafdb85ba3daa8fd1e6e2576b908eabe` |
| SHA-256 | `1eb74c4c15d5568a3f3edf53200da3f5e18f7be7d99fdd0c915c77b36c043ddf` |
| SHA3-384 | `8b6cd1b289730cc6249b0e17c6001ef7bd9769dd12d02b72b3545553be69eda04800f98788b2e4d0a060531b31dbd5a7` |
| TLSH | `T1AAC31264778D80F1ED07B5FE92E70E08BBF91EBD0000E516E2F482961A5D68476EB987` |
| SSDEEP | `3072:Yi76/WxgYZYl7Ud70uFDHS4iH8BIwdX4wq0SSEagjVe:YbumxUBFDyRH8BIwy9aAe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_1eb74c4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb74c4c15d5568a3f3edf53200da3f5e18f7be7d99fdd0c915c77b36c043ddf"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-20 04:02:30"
  condition:
    hash.sha256(0, filesize) == "1eb74c4c15d5568a3f3edf53200da3f5e18f7be7d99fdd0c915c77b36c043ddf"
}
```

### Sample 26: `f7915f8dea817c62`

| Field | Value |
|---|---|
| SHA-256 | `f7915f8dea817c62b7bb0a323c73889643bf2db0be921c67d3a11048ef24bb97` |
| Family label | `Mirai` |
| File name | `bot.arm` |
| File type | `elf` |
| First seen | `2026-10-20 04:02:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae5b92453e61ab0b9dce24e134544575` |
| SHA-1 | `ea77f9fc059f71b2963a625c83da1faf66c94a7e` |
| SHA-256 | `f7915f8dea817c62b7bb0a323c73889643bf2db0be921c67d3a11048ef24bb97` |
| SHA3-384 | `b3c7e6354c29e199f386f4aba471793b69b15f279569d7c45acbac0648157e8b958926b0097ce8fec68ad0dc1482cff5` |
| TLSH | `T11C840A88F1E1E7DED2D4AA75B31D780E3B230735E1D73146A51AAA3323EB1490AFD911` |
| TELFHASH | `t140f05c44cc1428f5f7b785e4b6e9f0185cab221d7f6a48528a033a693d821c561f0c1b` |
| SSDEEP | `6144:KOJzSO0mSJSfJ5xCHHMI4i8kce9xbpfvWRVXa7pAAw/PLthZzjHUFia9f:PoOVSJSNRId1Jt6LjSYa9f` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_f7915f8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7915f8dea817c62b7bb0a323c73889643bf2db0be921c67d3a11048ef24bb97"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-10-20 04:02:28"
  condition:
    hash.sha256(0, filesize) == "f7915f8dea817c62b7bb0a323c73889643bf2db0be921c67d3a11048ef24bb97"
}
```

### Sample 27: `029478409d699282`

| Field | Value |
|---|---|
| SHA-256 | `029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2` |
| Family label | `Mirai` |
| File name | `pid.arm6` |
| File type | `elf` |
| First seen | `2026-10-20 03:59:20` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `811e55819aa88125be131e7be589a832` |
| SHA-1 | `f7fc5ce53e6c1ea0308572ff67a01c15cb6c1716` |
| SHA-256 | `029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2` |
| SHA3-384 | `df7313dd2a376da2e117aa707be11c15aeccbd2d616fa76a5c9abc402c5076236deda98ee360cfe8f180a672f78b641d` |
| TLSH | `T157942A88E1F0E7DAD2D4EA75B31D790E77230735F1D73146A519AE3223EB0890ABE911` |
| TELFHASH | `t135f05c9cc89841d5f30b344c521626053a7e1899f71314ea8fc33d3e99116e5e4f4d1b` |
| SSDEEP | `6144:Id3UOKnehpPsWQ8lDV8TtrocSM0oc2uKTFN/rqjxqwAGPwgSbDhW+Cr8Fpa9wz3:IFOWvlJGccp5wEZb1tLa9wz3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_02947840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2"
    family = "Mirai"
    file_name = "pid.arm6"
    file_type = "elf"
    first_seen = "2026-10-20 03:59:20"
  condition:
    hash.sha256(0, filesize) == "029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2"
}
```

### Sample 28: `098b91fd1bcb00ac`

| Field | Value |
|---|---|
| SHA-256 | `098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf` |
| Family label | `Mirai` |
| File name | `pid.x86_64` |
| File type | `elf` |
| First seen | `2026-10-20 03:56:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Hajime, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e7152e6c1409c25165974e1adfd5e08` |
| SHA-1 | `6935b1c55e9e2003b3912c142722597e64bed71e` |
| SHA-256 | `098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf` |
| SHA3-384 | `830f4dd1f11f716add2903d76c1e816745e2995dfeaaf8e0a022355fe91167c6d1fc48a2b0d62d733a39efac3ebf5585` |
| TLSH | `T10E35AF88EAAE7DC6E3CAF77CA7055F91703B72B0E26351E23142525F92D62D887F0521` |
| SSDEEP | `12288:Ck7RFu3qLaVLLmWH0b057QyKGAebw7PUk4GHctXOqmUcdDILwTa9vw5uHrg6:C6uFL1QsbCpDcExdsZzg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_098b91fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf"
    family = "Mirai"
    file_name = "pid.x86_64"
    file_type = "elf"
    first_seen = "2026-10-20 03:56:50"
  condition:
    hash.sha256(0, filesize) == "098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf"
}
```

### Sample 29: `93af664ca7cdd968`

| Field | Value |
|---|---|
| SHA-256 | `93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-10-20 03:54:18` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36c2e54d5539a68f2c7a4a07e24bbb3a` |
| SHA-1 | `79a40a92cc718519fbb39b79dd7be9c8ec6de231` |
| SHA-256 | `93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e` |
| SHA3-384 | `a0dbe29938e6ad908b062268924e378afd5f394e77890a6d9448bc67a70f91353ab98967dd060a7cb9eb6b6a10d771f2` |
| TLSH | `T1E0C35B22363A0B27C0E6A83540F79737B3F65BC92A64920B7A615EDC7F166E035437B4` |
| TELFHASH | `t1f431ec755b22a5166961ed64ddfe8bb1951a83121784ff33df2688cc290a04ee72fc0f` |
| SSDEEP | `1536:BZe4MxyiXFCoRpDBx3eOQue84ltnYyXRDt0MnttI22kOo+okR36Mn/Ohb:Te9bX7pD/zP4l6yh+MnE22lo+FgM8b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_93af664c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-20 03:54:18"
  condition:
    hash.sha256(0, filesize) == "93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e"
}
```

### Sample 30: `88183421d4b66670`

| Field | Value |
|---|---|
| SHA-256 | `88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Heur.31998.2837` |
| File type | `msi` |
| First seen | `2026-10-20 03:52:03` |
| Reporter | `SecuriteInfoCom` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a6917eada01c4108d5edcc4d5e46b907` |
| SHA-1 | `f7b889e4af6d2c9e5d3d24ed3aa66a286985cca9` |
| SHA-256 | `88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25` |
| SHA3-384 | `74c09af4b3b7a53b5e7860ff61a77a8b4a9cc8adce22817a81fc2dc3d6a294f4f2a3bafa3c3b12f8dac07df446df32ec` |
| TLSH | `T143B54C636A50600546B5A8FABEBD5E37694F3409102AD98EFFD31B86F12E6F44C02D1F` |
| SSDEEP | `24576:5Dcs+zkuBYCbM6UEVfofhGVo59FqYGauw4o4Y01qZtLoNmeYM:5n8YQuF8VozA3rqZ5o1b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_88183421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.31998.2837"
    file_type = "msi"
    first_seen = "2026-10-20 03:52:03"
  condition:
    hash.sha256(0, filesize) == "88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25"
}
```

### Sample 31: `1f7c7b85548cf833`

| Field | Value |
|---|---|
| SHA-256 | `1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c` |
| Family label | `Mirai` |
| File name | `1` |
| File type | `elf` |
| First seen | `2026-10-20 03:51:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f11d4de22f87afd245a5d9011af71278` |
| SHA-1 | `08ab53b5c087f642eed2bb3ee75fa4dcfe151473` |
| SHA-256 | `1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c` |
| SHA3-384 | `443a8968dadd8540681b5bed3b5823ae335667624d97919076f4642394a75160a20d1adeabdf046422d54fe6ee32b9e8` |
| TLSH | `T173A423ADD51449B047F69B3488B6E30CFD956B0EF303AA1B58CDBEF1916FCA06291B10` |
| SSDEEP | `12288:WdUaxyTYIG/k3LNAg7OEQs8n3BDL86hDUG3HiQGWA8:WdbxyTY56iO8nB8JGXiDWA8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_1f7c7b85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c"
    family = "Mirai"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-10-20 03:51:22"
  condition:
    hash.sha256(0, filesize) == "1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c"
}
```

### Sample 32: `3a2e3adaa695e37a`

| Field | Value |
|---|---|
| SHA-256 | `3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-20 03:48:24` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dd1ccb49423d61a3fcdc7bbd212daff` |
| SHA-1 | `7a7f2af51ac9e509b708beaaf4d060087d108ac2` |
| SHA-256 | `3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1` |
| SHA3-384 | `9a15f9a67a2a0dec9da5005306e5243603bdd307659310261db6969719680670f418b4e28e62d659942153cedee0503b` |
| TLSH | `T1C5944A88E2E3E2FDF159D9701316BA0F5D3145363053F689E39EB97393B624045AEA38` |
| TELFHASH | `t12b8195a01fa29cf8e3169dc883f355256c7d9949fb524af08aa1f42e3c250c144e4d77` |
| SSDEEP | `12288:h2D0sMQCVe/Anr2Ed0/CmnSjS9M01a9JjOwS:hQseYr2Ed0/CmnSjS9M0cLzS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_3a2e3ada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-20 03:48:24"
  condition:
    hash.sha256(0, filesize) == "3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1"
}
```

### Sample 33: `7b7b37e805c6749f`

| Field | Value |
|---|---|
| SHA-256 | `7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-20 03:48:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1455c9a3b1c0dda8256854fcc97ef2df` |
| SHA-1 | `f928180032b981834a2432e623abe3af02d71a62` |
| SHA-256 | `7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6` |
| SHA3-384 | `6cf824614a0b5c9bbf82ab809ea3fdd4cd58b602e2542b1b13b31e01d517f50cc75c6d525925189b2d7369ee10b8639b` |
| TLSH | `T158942A88A2F5FBDEE296FD3983017C0A5C298B317883754561AEF97313B72410AF9D61` |
| SSDEEP | `6144:JFqB7xkzCCHQfNzQAzJtCyU3cazfm+9IABXqeGNzh/qeavi7/8T8G8:+7LCCLzJpUx7m+bXIE/T8x` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_033_7b7b37e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-20 03:48:22"
  condition:
    hash.sha256(0, filesize) == "7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6"
}
```

### Sample 34: `4a203def15c9d4b3`

| Field | Value |
|---|---|
| SHA-256 | `4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-10-20 03:45:22` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f29b778e3c4277bfdcb9f0bdc6876cd5` |
| SHA-1 | `4dd6cff858b3b63378e0891d3c708850bd98e828` |
| SHA-256 | `4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2` |
| SHA3-384 | `ef0e0d7e61a1f89591fbcccc6a4dc1ece8dc35940c722b3f47806e1857ffecd4ba87fb2531c7e79856371255e0ad4b4f` |
| TLSH | `T1DBB33A12B3290957D09749B11AEF1BF183B6ECD026F1B244952EBFA40733BB51485F9B` |
| TELFHASH | `t10f3110755b22a1166960dd64ddfe87b1a51983231784ff33df2688cc240904ee72bc4f` |
| SSDEEP | `1536:0Jr5/y+gximXiUQyZ+zltTUtTe4JThvdpl4BYOhiptsQCK8:q5/y+gfiU6zltgtTeelm5hUS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_4a203def
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-20 03:45:22"
  condition:
    hash.sha256(0, filesize) == "4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2"
}
```

### Sample 35: `fd6fb49be7e0202c`

| Field | Value |
|---|---|
| SHA-256 | `fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb` |
| Family label | `Mirai` |
| File name | `8` |
| File type | `elf` |
| First seen | `2026-10-20 03:42:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d73ccccfa49bfea9be3d7a778630d1db` |
| SHA-1 | `340a40db42bdc8fc243cc4b7f3629b62e2d7c320` |
| SHA-256 | `fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb` |
| SHA3-384 | `33388517c2a58b8084a46cef36c00dcd0c82d44db4ea116dabfc20874136c612a56b9ef7e41ffbe2d1eb3327b38463eb` |
| TLSH | `T15AF4D0B3E6705EE6C01A0BF424FDD3348F05B69203577594F6BA8244186F6B6BE9A370` |
| SSDEEP | `12288:HzmLXcJ5dmE+XKGWsm5M5y3/jEkyn4z0BFECKWcbQ0cs/MD9AxdQpZZlAdNsv6:a45Yvw5lrGm0QmQZW+sy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_fd6fb49b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb"
    family = "Mirai"
    file_name = "8"
    file_type = "elf"
    first_seen = "2026-10-20 03:42:35"
  condition:
    hash.sha256(0, filesize) == "fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb"
}
```

### Sample 36: `889643499f343736`

| Field | Value |
|---|---|
| SHA-256 | `889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-20 03:37:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `19b3aeb747793dc70b2b8064e4d9a627` |
| SHA-1 | `f2ef4dfcbee15c61caaadb47a206dcaee3307c71` |
| SHA-256 | `889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a` |
| SHA3-384 | `1b8c87f2b11696787cf9a2afcc3744f4a64bfc66cc87837f8acf6596171f8e87291a1ff9497c51d060f43ba3f022b3b5` |
| TLSH | `T1D9732913B54280FCC58AC1340B5ABA3EDD37B4FC2268F6A63BD0FA226D96D215D1ED45` |
| TELFHASH | `t1b62102b1353619a0a1fbf5a5a344e51019610a7120d638f2e4b278fadf65bc20e76c77` |
| SSDEEP | `1536:LEe85xmrO8q4tzVBVQi6dam3ux9VvGWkV4PTQx6IDQ/HwjJg:f85xmrtq4hVB+huxTG/4Pkx6t/QjJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_88964349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-20 03:37:34"
  condition:
    hash.sha256(0, filesize) == "889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a"
}
```

### Sample 37: `2efd63cc32630d6a`

| Field | Value |
|---|---|
| SHA-256 | `2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-20 03:32:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5a9ca792c007d1e6334d72f1ee80b985` |
| SHA-1 | `7f889f606177174e3d7431d9965cc19f3688e128` |
| SHA-256 | `2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5` |
| SHA3-384 | `da4dbfb5625daab08a59b600b7ef16bc7ccf9c6a8e8a87de642c5e0668beb9afb0f330c4f0c6017825fb1733e493398f` |
| TLSH | `T145732999F8418723C6D1167BBA6E028D372657ECE2EA721399215F6137C782B0D37E42` |
| TELFHASH | `t1ab31c0e1cf8d15ecbbe1c644434a1379beda35a497102a65cf3e7b0f82075c1ba66031` |
| SSDEEP | `1536:H4kIKoQTd7e7fzZUxwJ1EGSvWBeZwjlYhGF0Nq8MPl7OUuev/N:HrIwTd7ehAwvEGSvegclYoF0NqBPl7Oc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_037_2efd63cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-20 03:32:34"
  condition:
    hash.sha256(0, filesize) == "2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5"
}
```

### Sample 38: `92f859eb329b97f2`

| Field | Value |
|---|---|
| SHA-256 | `92f859eb329b97f289bd7b864f27559bb8a70a56fd165bbc5bf27751b62ff94a` |
| Family label | `Mirai` |
| File name | `5` |
| File type | `elf` |
| First seen | `2026-10-20 03:30:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff10c48ed145c6f07ae7cb0f8a5568b7` |
| SHA-1 | `560e32342a9618c9551d061a5170521f8e2c9920` |
| SHA-256 | `92f859eb329b97f289bd7b864f27559bb8a70a56fd165bbc5bf27751b62ff94a` |
| SHA3-384 | `2afb4066970e9ae781041dd11ce9be61e05b8c00eacbaeb299f1e528e5653f76cc9339f82a5a1b032eef8ac447ce3846` |
| TLSH | `T1A7256D6377218F58F365D27005F38A659AA921B30BF284C6A3BCD1107A5076D6C6FFE8` |
| TELFHASH | `t16551bf58097813e4a3616c5d09edff36d6a220df7e1a2c378a10e86ee769f838d10c1d` |
| SSDEEP | `12288:Mm55TvwLqV/K/bZFpWh6QNyrwxW4queGpiwxFwe6Y1nW4fclCgpZ1L19oTNusmF:MmI/FFoUoW4qFGpiw1nWs4b19B` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_038_92f859eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f859eb329b97f289bd7b864f27559bb8a70a56fd165bbc5bf27751b62ff94a"
    family = "Mirai"
    file_name = "5"
    file_type = "elf"
    first_seen = "2026-10-20 03:30:12"
  condition:
    hash.sha256(0, filesize) == "92f859eb329b97f289bd7b864f27559bb8a70a56fd165bbc5bf27751b62ff94a"
}
```

### Sample 39: `7ed1a70669992020`

| Field | Value |
|---|---|
| SHA-256 | `7ed1a706699920206b95e93f869602d8b546f278f7e7e528f42dede04b42ce75` |
| Family label | `unknown` |
| File name | `MV S-BREEZE MAIN VESSEL INFORMATION.js` |
| File type | `js` |
| First seen | `2026-10-20 03:28:49` |
| Reporter | `threatcat_ch` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94a4282366abafefd12774cec02262e3` |
| SHA-1 | `ddfa072d3ab39fa51a08088c124e8a519a4ca439` |
| SHA-256 | `7ed1a706699920206b95e93f869602d8b546f278f7e7e528f42dede04b42ce75` |
| SHA3-384 | `9b72b2491a42cfce4484d9df498cb2b94154f797af64eb6a1e495d9746d6b7e653f51dd97dca247f51c3f2d7a734575f` |
| TLSH | `T1262502578F005FAB00602B1555AC310DBDE8662264449AE5341F6EBE7B39F205FBEBE3` |
| SSDEEP | `24576:/YPQTttrygR7GTgz7taNSl8gezujFaqHFcJwBpPFDm8WfV7D4:tr3a8eOWm1WfN8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_7ed1a706
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ed1a706699920206b95e93f869602d8b546f278f7e7e528f42dede04b42ce75"
    family = "unknown"
    file_name = "MV S-BREEZE MAIN VESSEL INFORMATION.js"
    file_type = "js"
    first_seen = "2026-10-20 03:28:49"
  condition:
    hash.sha256(0, filesize) == "7ed1a706699920206b95e93f869602d8b546f278f7e7e528f42dede04b42ce75"
}
```

### Sample 40: `9208a826c900f6a2`

| Field | Value |
|---|---|
| SHA-256 | `9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666` |
| Family label | `unknown` |
| File name | `9208a826c900f6a2.bin` |
| File type | `macho` |
| First seen | `2026-10-20 03:26:30` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a4291e12bc7d9271e53bfa1192cbff5a` |
| SHA-1 | `bc6b9ed0ae8cecfedcbcb783bdeb6648b818c7fe` |
| SHA-256 | `9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666` |
| SHA3-384 | `72f649be208d80d800c6bd3a87415ee3b6a2a9bf378649563b26b64001687cf8d9398751fb2d0ae037d6a266c0c6fd50` |
| TLSH | `T1D7F25F139B1C1A61C05D633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRvPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfClilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_040_9208a826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666"
    family = "unknown"
    file_name = "9208a826c900f6a2.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:30"
  condition:
    hash.sha256(0, filesize) == "9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666"
}
```

### Sample 41: `f5da783380784216`

| Field | Value |
|---|---|
| SHA-256 | `f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0` |
| Family label | `unknown` |
| File name | `f5da783380784216.bin` |
| File type | `macho` |
| First seen | `2026-10-20 03:26:22` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0f10f20b3d7f115480227b733434bb53` |
| SHA-1 | `d18e8c03cbb13cf5776f7aadf2b3d296619fdd00` |
| SHA-256 | `f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0` |
| SHA3-384 | `012e3664b8b9b8d2df5a46321626bfea69f1242c5d179d3000c5ca4f5a2343f9ca06f4feee8228d9597c7e6fd130c161` |
| TLSH | `T180E25F43675C5929D04D83B962FB1B576609F8B009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZE85DbDP67li97WsCvwYjqclS06W1YbqclSl:GI285DbDylwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_041_f5da7833
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0"
    family = "unknown"
    file_name = "f5da783380784216.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:22"
  condition:
    hash.sha256(0, filesize) == "f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0"
}
```

### Sample 42: `c018650f7847d056`

| Field | Value |
|---|---|
| SHA-256 | `c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924` |
| Family label | `unknown` |
| File name | `c018650f7847d056.bin` |
| File type | `macho` |
| First seen | `2026-10-20 03:26:08` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b8e4c37f438841aea766a5035f60e21` |
| SHA-1 | `2d2e5e1bcf800cc9a942473d9b8934e3963e491b` |
| SHA-256 | `c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924` |
| SHA3-384 | `26bab341251d61aa1af353d376c1f3ae0c194c65ed9bca45301b1af18d1914b3986a435c9d03737bb2e730ef55f9516e` |
| TLSH | `T1CFE24F43675C5929D05D83BA62FB1B576609F8B009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEa5DbDP67li97WsCNfwYjqclS06W1YbqclSl:GI2a5DbDyvfwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_c018650f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924"
    family = "unknown"
    file_name = "c018650f7847d056.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:08"
  condition:
    hash.sha256(0, filesize) == "c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924"
}
```

### Sample 43: `f7046c0941b75bdb`

| Field | Value |
|---|---|
| SHA-256 | `f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623` |
| Family label | `unknown` |
| File name | `f7046c0941b75bdb.bin` |
| File type | `macho` |
| First seen | `2026-10-20 03:26:00` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4fa0744385515e05bd250b0f79fea2e` |
| SHA-1 | `00e3672f62bfcb024fad41866544bcab2935a57d` |
| SHA-256 | `f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623` |
| SHA3-384 | `33e97f5b06a209bc41cbe019288fa9ac9b974581098ac4868e40322f76484990756eb0f86800464dd090aa4795bad3d5` |
| TLSH | `T1F6E25043675C5929D05D83B962FB5B976609F8A009D45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEn5DbDP67li97WsCbwYjqclS06W1YbqclSl:GI2n5DbDyFwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_f7046c09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623"
    family = "unknown"
    file_name = "f7046c0941b75bdb.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:00"
  condition:
    hash.sha256(0, filesize) == "f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623"
}
```

### Sample 44: `c53e6d86609593c0`

| Field | Value |
|---|---|
| SHA-256 | `c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c` |
| Family label | `Mirai` |
| File name | `c53e6d86609593c0.bin` |
| File type | `elf` |
| First seen | `2026-10-20 03:25:50` |
| Reporter | `Tuxxin` |
| Tags | `elf, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `86cf6a1be237cc5c5f81534107fa15e0` |
| SHA-1 | `dfe6f08c2c34ddccbc60ebacabef60c14a3fbe71` |
| SHA-256 | `c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c` |
| SHA3-384 | `462b732378f1dfaf0e894d82c9d148fb1df26d7c8d62154e639ba2dfb2cd893558be09a2893edb64fc50ab2d8d72f109` |
| TLSH | `T1298349C1FA83E4F5F89705755137E3369733E139101AEA87D369AE32ECA1950DA0B398` |
| TELFHASH | `t1a841e4f36ebb4cfcf7a1a888871e675326269577096032b444b29c9536fadc540b5c34` |
| SSDEEP | `1536:DkNbRkodaCXAZMW0KgjTJK2SBVlkitz0ZiGwVSS0It:DMbRkodawsM5KghCVLtzoiGE7V` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_c53e6d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c"
    family = "Mirai"
    file_name = "c53e6d86609593c0.bin"
    file_type = "elf"
    first_seen = "2026-10-20 03:25:50"
  condition:
    hash.sha256(0, filesize) == "c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c"
}
```

### Sample 45: `98b43dca907880c9`

| Field | Value |
|---|---|
| SHA-256 | `98b43dca907880c96d2e5ec3e4c3d0cd2c13e441cd99de9523278ed4530d980c` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-10-20 03:20:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2bc6021ccfd09921c76a94d0a6b61cb` |
| SHA-1 | `cd4531f36698b2931da09251a7f16f2de202ddd0` |
| SHA-256 | `98b43dca907880c96d2e5ec3e4c3d0cd2c13e441cd99de9523278ed4530d980c` |
| SHA3-384 | `d8e66f8ca9d55b60dcf0b866bf4788a0f7d7d1039ad7b512d7f212f5e9608b6f697448af694f6c7d393a2bbe6026a807` |
| TLSH | `T17AD32A07BFA10FFBD85BCE3702EB0B21158DD95A23926B367138DD68B64728A16D3D50` |
| TELFHASH | `t1f4311e755b22a1166960dd68ddfe87b1a51a83131784ff33ef2688cc240a04ee72bc4f` |
| SSDEEP | `1536:XJQT5SdsKBSsooJZboeJhrF7wJ04lYPhvyKg86KuZmn+jre8PL1:XJQlusKBfoo3Ee3rWsPsKtXimnUrx1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_98b43dca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98b43dca907880c96d2e5ec3e4c3d0cd2c13e441cd99de9523278ed4530d980c"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-20 03:20:08"
  condition:
    hash.sha256(0, filesize) == "98b43dca907880c96d2e5ec3e4c3d0cd2c13e441cd99de9523278ed4530d980c"
}
```

### Sample 46: `ec289ea419e078ce`

| Field | Value |
|---|---|
| SHA-256 | `ec289ea419e078cec42b2d3e0692c03a1ee406e568459c03d859e5497ed42acb` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-20 03:12:40` |
| Reporter | `Bitsight` |
| Tags | `c9fb6dca12e42250d8dd37f6e159359f, dropped-by-remus, exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd54c4388754fc8c900bad8d29ad4a0c` |
| SHA-1 | `fe68d45bd5b9ae14f938a9831bb6efbcedb2f31e` |
| SHA-256 | `ec289ea419e078cec42b2d3e0692c03a1ee406e568459c03d859e5497ed42acb` |
| SHA3-384 | `5118ed91ff410d6d8390a293a0450dcb87b7bfaf459a048a60a1dff45c0a8ea29932e4e23b7364e1004a4a76eae1ad3b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C9B71203FD9545E8C1AAE634C6739212BA717C49873123E76B90F3782F72BC4AA79750` |
| SSDEEP | `786432:yW+NLcLLBQzjOKQNvnF5uFEnbN7CJ7zOziE0T+Y8VvOwSVHYBMRNGUTcOF9yGqUV:m6LdQzjmNvGERaK/mx81ZSVH+MRNGick` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_046_ec289ea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec289ea419e078cec42b2d3e0692c03a1ee406e568459c03d859e5497ed42acb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 03:12:40"
  condition:
    hash.sha256(0, filesize) == "ec289ea419e078cec42b2d3e0692c03a1ee406e568459c03d859e5497ed42acb"
}
```

### Sample 47: `54b72985c8594611`

| Field | Value |
|---|---|
| SHA-256 | `54b72985c8594611acd5600e76c5c435aa4128b0cd23d454eabef2702770bc6f` |
| Family label | `unknown` |
| File name | `PURCHASE INQUIRY  DAEP-DWCESTUAELT-9771 [EXPANSION PROJECT] AL MAKTOUM INTERNATIONAL AIRPORT (DWC) DUBAI.vbs` |
| File type | `vbs` |
| First seen | `2026-10-20 03:03:34` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5738ecafb04c2146a096b49ac5bec1bd` |
| SHA-1 | `56de232bfc84673ddac3de918cd304742a11b54a` |
| SHA-256 | `54b72985c8594611acd5600e76c5c435aa4128b0cd23d454eabef2702770bc6f` |
| SHA3-384 | `2282c3dfa6fdfb0f5277382540538e01448f7be3a1fce57a16dceac2a17bd612b8ae10a78c9e37159eba2d964705c862` |
| TLSH | `T100749DE15F852A018F25EB97CEAC897A53C02F32A2D06C70DDD609DC2128F59A1DFBD5` |
| SSDEEP | `1536:PV3esopYanWwOU7i/+U5DxjB0etpFb+UXhpaU:PVOsaoF+UNdB511h0U` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_54b72985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54b72985c8594611acd5600e76c5c435aa4128b0cd23d454eabef2702770bc6f"
    family = "unknown"
    file_name = "PURCHASE INQUIRY  DAEP-DWCESTUAELT-9771 [EXPANSION PROJECT] AL MAKTOUM INTERNATIONAL AIRPORT (DWC) DUBAI.vbs"
    file_type = "vbs"
    first_seen = "2026-10-20 03:03:34"
  condition:
    hash.sha256(0, filesize) == "54b72985c8594611acd5600e76c5c435aa4128b0cd23d454eabef2702770bc6f"
}
```

### Sample 48: `67cfc503966fd56d`

| Field | Value |
|---|---|
| SHA-256 | `67cfc503966fd56d77c58cc8a689b94c6d9ba32e262646630cc55fc82037c06e` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-10-20 03:00:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf9ef27a695be34cec876f74f63e0bae` |
| SHA-1 | `c4b71ca5d7550cb05eae46546c04e1d4a60e4a8c` |
| SHA-256 | `67cfc503966fd56d77c58cc8a689b94c6d9ba32e262646630cc55fc82037c06e` |
| SHA3-384 | `9fe369ff8655094daf990a641aef532d0da4b4fd076925a858df15cd9230db21cf139b05d5b5d455f97127319765eef8` |
| TLSH | `T16CA34B13D5614AA3C0835FB925F78E790B13A8A24B121F71562DCFF80A43DCDBC59BA6` |
| TELFHASH | `t178310c755b22a1166960dda4d9fe87b1a51a83131784ff33ef2688cc640a04ee72bc4f` |
| SSDEEP | `1536:BqRGA08VRPpDet4oTOvp8G+RkQnu5E4kA9lcCzIdC:BqRuaetnKRJsYEEEC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_67cfc503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67cfc503966fd56d77c58cc8a689b94c6d9ba32e262646630cc55fc82037c06e"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-20 03:00:17"
  condition:
    hash.sha256(0, filesize) == "67cfc503966fd56d77c58cc8a689b94c6d9ba32e262646630cc55fc82037c06e"
}
```

### Sample 49: `911b4fe6d1761eed`

| Field | Value |
|---|---|
| SHA-256 | `911b4fe6d1761eed5bc7ade69ac55b3c8f726cbd7e3d613ea34bd2bbf107e9c6` |
| Family label | `unknown` |
| File name | `Price Request List  #GSGPRO202600197.exe` |
| File type | `exe` |
| First seen | `2026-10-20 02:57:45` |
| Reporter | `threatcat_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3538ff52e4bd1fb7c700d3a68a4d7c2b` |
| SHA-1 | `f5709ca7b5cb96bb8cc574b6cd7154cab8de80b6` |
| SHA-256 | `911b4fe6d1761eed5bc7ade69ac55b3c8f726cbd7e3d613ea34bd2bbf107e9c6` |
| SHA3-384 | `b12370104fd4bd408f6d6ff019400625dabca1254532e1cbb912868de5d1dcca8444de7dcb91afdf3a47b34723a8c71b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T170E4F124676BE913D4B6437909F0E33043B1AF5CE513D31B9EEA6DDB3912B846998383` |
| SSDEEP | `12288:hTYayIc5uayzMjThnwSgJQ4Op3qei373Q+NX+L9GKG7:1uIiz5nwPzOsDJ4C7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_911b4fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "911b4fe6d1761eed5bc7ade69ac55b3c8f726cbd7e3d613ea34bd2bbf107e9c6"
    family = "unknown"
    file_name = "Price Request List  #GSGPRO202600197.exe"
    file_type = "exe"
    first_seen = "2026-10-20 02:57:45"
  condition:
    hash.sha256(0, filesize) == "911b4fe6d1761eed5bc7ade69ac55b3c8f726cbd7e3d613ea34bd2bbf107e9c6"
}
```

### Sample 50: `80330f59bad607ce`

| Field | Value |
|---|---|
| SHA-256 | `80330f59bad607ce2d4918b2da68c01a3a6bdbb79ba4427fa49f96ae3b80839c` |
| Family label | `unknown` |
| File name | `80330f59bad607ce.js` |
| File type | `js` |
| First seen | `2026-10-20 02:56:07` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41df9baa7e7384c28d39b3bef659b4f4` |
| SHA-1 | `eded65f06b92938b46746c90eb01ef23d50c7d08` |
| SHA-256 | `80330f59bad607ce2d4918b2da68c01a3a6bdbb79ba4427fa49f96ae3b80839c` |
| SHA3-384 | `39852559af2b094d3cdf0af7c6a8c40a4412ba885c92268fe975ce6481fd300249bd5d63b89381b1017713b3f1a8714d` |
| TLSH | `T1F8722AF87765206A03633532607F9102D177EB118D5B9050A2E28A917DECFABE677FC8` |
| SSDEEP | `384:DPgrrNbSeKaCJlcK1BTg9P0pB1xAvnQ7D+sjNU:0vNbSpaSWK1BTg2pvxAvnQ7yspU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_050_80330f59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80330f59bad607ce2d4918b2da68c01a3a6bdbb79ba4427fa49f96ae3b80839c"
    family = "unknown"
    file_name = "80330f59bad607ce.js"
    file_type = "js"
    first_seen = "2026-10-20 02:56:07"
  condition:
    hash.sha256(0, filesize) == "80330f59bad607ce2d4918b2da68c01a3a6bdbb79ba4427fa49f96ae3b80839c"
}
```

### Sample 51: `5414de616cb7cad3`

| Field | Value |
|---|---|
| SHA-256 | `5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30` |
| Family label | `unknown` |
| File name | `export.php` |
| File type | `exe` |
| First seen | `2026-10-20 02:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4e9b523f07c5e9ecd045597f5343c589` |
| SHA-1 | `088bc52858afc282cf1324088272efdc343be603` |
| SHA-256 | `5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30` |
| SHA3-384 | `fedf7bd94bd9dcfdf804c1955243316364b2b682ad0294decc4aa6fe1ed200149accc85aa0d1a6be267389b989b609a7` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T13D25F18FFBB8718EE10DB4F0550CF42164A0BDA9361B93D3911B57B45EC8E48DE2A3A5` |
| SSDEEP | `24576:90V6Ab8/tDF04Z8jiQHILC4eNs4/b7g+coOJG:glI/txNiAas4/nhc` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_5414de61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-20 02:52:08"
  condition:
    hash.sha256(0, filesize) == "5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30"
}
```

### Sample 52: `1a9d8635574518b8`

| Field | Value |
|---|---|
| SHA-256 | `1a9d8635574518b8f27e220016cabc5b68d5cce8e56057a4545e4adc981c09ce` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-20 02:46:50` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-Vidar, exe, f7e0bdc53604a00d861131d2693a943c` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e309a612d2160d8e250d86829a63fbb` |
| SHA-1 | `fc299229fecb8e3a6adc7af64bc244166c15cd64` |
| SHA-256 | `1a9d8635574518b8f27e220016cabc5b68d5cce8e56057a4545e4adc981c09ce` |
| SHA3-384 | `33d93adba5b523efb27efc89da9051ea8a22456efa77cd1d97f9d44071bb55c97e2bcde1bd31ff3c31db6ef352155af1` |
| IMPHASH | `bc25f71d23cbd283d915e6c90569d62a` |
| TLSH | `T11645CE61B3812DF8F72D81F68651DD27976E38122AD058AB42FC374A0E266D08FF97D1` |
| SSDEEP | `12288:12P20gIc9KvSNI8MWDSmdIq48t6RlwbGTTETsgmDYzVFEKtpWdB+Xd0awCrrQG62:12P2Rveo4O6RGCwTgY3ntpOTV12` |
| ICON-DHASH | `6816706969710620` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_052_1a9d8635
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a9d8635574518b8f27e220016cabc5b68d5cce8e56057a4545e4adc981c09ce"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 02:46:50"
  condition:
    hash.sha256(0, filesize) == "1a9d8635574518b8f27e220016cabc5b68d5cce8e56057a4545e4adc981c09ce"
}
```

### Sample 53: `78d62fc5a747d68a`

| Field | Value |
|---|---|
| SHA-256 | `78d62fc5a747d68ae531a1cd1e4f6a384545ca2dd5192abb5e9406855651a803` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Heur.10656.3336` |
| File type | `msi` |
| First seen | `2026-10-20 02:46:12` |
| Reporter | `SecuriteInfoCom` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1def105adc234c8440300f28616e49ed` |
| SHA-1 | `65d8b11d17e0f564ad1811d9b06a20c1a8ad61a2` |
| SHA-256 | `78d62fc5a747d68ae531a1cd1e4f6a384545ca2dd5192abb5e9406855651a803` |
| SHA3-384 | `3595c104b13e9c4484cdaec8857c4fae39c4b3d083a277676ac9dbb45e195bd722c606a772b47dda3004dd8c603cbbc0` |
| TLSH | `T15AB54C636A50600552B5A8FABEBD5E37795F3409102AD98EFED30B86F12E6F44C02D1F` |
| SSDEEP | `24576:4Dcs+zkuBYCbM6UEVfofhGVo59FqYGauw4o4Y01qZtLoNmC30:4n8YQuF8VozA3rqZ5o/E` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_78d62fc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d62fc5a747d68ae531a1cd1e4f6a384545ca2dd5192abb5e9406855651a803"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.10656.3336"
    file_type = "msi"
    first_seen = "2026-10-20 02:46:12"
  condition:
    hash.sha256(0, filesize) == "78d62fc5a747d68ae531a1cd1e4f6a384545ca2dd5192abb5e9406855651a803"
}
```

### Sample 54: `570e354d5ba56a24`

| Field | Value |
|---|---|
| SHA-256 | `570e354d5ba56a244fe1b6d08ae36a5c6e489fb53a710524afe065cedfac5f30` |
| Family label | `unknown` |
| File name | `570e354d.ps1` |
| File type | `ps1` |
| First seen | `2026-10-20 02:41:21` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, miner, powershell, telegram` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `edf8fc2c9371c31a3e9abeba9884c214` |
| SHA-1 | `c6127231737cb89eed97f47c4019e0d38db1c3d7` |
| SHA-256 | `570e354d5ba56a244fe1b6d08ae36a5c6e489fb53a710524afe065cedfac5f30` |
| SHA3-384 | `800d37cd85056dfc2a8fce3442ed2725ab189e3cb564c3b5a38b2b30bdd209d32cb91ea749893a06c4fd00928c39246f` |
| TLSH | `T16051CA53871302A1E5F1534AD9C2B7619D26806EC51D2438B1DC621B0AD05F00FBBF87` |
| SSDEEP | `48:dah+PsR1RzDaPNRpE4LDB9cSPM8D53mB5mGb7bMbvo3EvMbv1DqLwgjH5Lr:r0N0Nf/d9NPnHGfgs0vMbFEd` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_570e354d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "570e354d5ba56a244fe1b6d08ae36a5c6e489fb53a710524afe065cedfac5f30"
    family = "unknown"
    file_name = "570e354d.ps1"
    file_type = "ps1"
    first_seen = "2026-10-20 02:41:21"
  condition:
    hash.sha256(0, filesize) == "570e354d5ba56a244fe1b6d08ae36a5c6e489fb53a710524afe065cedfac5f30"
}
```

### Sample 55: `9165aca66a9d89b7`

| Field | Value |
|---|---|
| SHA-256 | `9165aca66a9d89b749236dc2f49186c042cfff76acaba9696fc9b1b0e798fab9` |
| Family label | `unknown` |
| File name | `vnc_bootstrap.ps1` |
| File type | `ps1` |
| First seen | `2026-10-20 02:41:19` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4b4d4981cced060972729091f7de789e` |
| SHA-1 | `a6a44cb3a32fce98bda658ad22510899e9f59205` |
| SHA-256 | `9165aca66a9d89b749236dc2f49186c042cfff76acaba9696fc9b1b0e798fab9` |
| SHA3-384 | `b11884f34f7466621d23980e078ff05527e9d112e18ba541aae4ba23a19b83772f03b67a359f9efe65d34214d8c7a8c8` |
| TLSH | `T1C4A2C6D6A9D091F424A360185E8EC252F23A603771F9FD50BCCDD7A98F9693C227836D` |
| SSDEEP | `384:92rTXs66vi4kP+zzkr+mqsSc1e6y6HyAmwW/vP2vP2Kn0:WXn4kP+zzkr+mqspIZp8p0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_9165aca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9165aca66a9d89b749236dc2f49186c042cfff76acaba9696fc9b1b0e798fab9"
    family = "unknown"
    file_name = "vnc_bootstrap.ps1"
    file_type = "ps1"
    first_seen = "2026-10-20 02:41:19"
  condition:
    hash.sha256(0, filesize) == "9165aca66a9d89b749236dc2f49186c042cfff76acaba9696fc9b1b0e798fab9"
}
```

### Sample 56: `e5ff711ca8d505be`

| Field | Value |
|---|---|
| SHA-256 | `e5ff711ca8d505be6f83ac1cd7a1615143e7568c776be3be390e59846e3466a0` |
| Family label | `unknown` |
| File name | `info.txt` |
| File type | `js` |
| First seen | `2026-10-20 02:41:15` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, js, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c4f2816e2e354d4e399f4b12deae996` |
| SHA-1 | `362ce4226c628ec46cfce8c32a9868de29539a05` |
| SHA-256 | `e5ff711ca8d505be6f83ac1cd7a1615143e7568c776be3be390e59846e3466a0` |
| SHA3-384 | `fa33701d823ad30a714f1f54bd2a93aa4d859e3993e6a6985ef81249d2c824ee4a0b614a8521cc6f0fafabcb888dd2ab` |
| TLSH | `T11342E72969036219A2B3037ED9863548FD2B043B46122244719C81E86FF53BDC3F6EEF` |
| SSDEEP | `192:qgVGf9nfQ8Do4EcpH/JAfBwTEVdm/yiCu99zXnRCGGXEkvUzhQhbcPMXGzh0R6lB:qgVGfxAfCX9zXkGGUk6huozP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_e5ff711c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5ff711ca8d505be6f83ac1cd7a1615143e7568c776be3be390e59846e3466a0"
    family = "unknown"
    file_name = "info.txt"
    file_type = "js"
    first_seen = "2026-10-20 02:41:15"
  condition:
    hash.sha256(0, filesize) == "e5ff711ca8d505be6f83ac1cd7a1615143e7568c776be3be390e59846e3466a0"
}
```

### Sample 57: `696fc814fa188e91`

| Field | Value |
|---|---|
| SHA-256 | `696fc814fa188e918e59cf4046c7f62062a61f5ea1bf66da59961851db10a0d5` |
| Family label | `unknown` |
| File name | `main_v4.js` |
| File type | `js` |
| First seen | `2026-10-20 02:41:13` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `389b294da604ae04cff759451789754e` |
| SHA-1 | `821a54327280bb06801062002609c76e96c7c446` |
| SHA-256 | `696fc814fa188e918e59cf4046c7f62062a61f5ea1bf66da59961851db10a0d5` |
| SHA3-384 | `832badde32d3d18c9d0cc5a3c1d5e199ac27766b8ede1cf19d2335459846b240850a085aa1dad4244a2bfec86f547c93` |
| TLSH | `T18DB5ADD433C0E40762CE1B63BF06BAEDE07BA8B664C8A94782547A9D64BC517D5B0DF0` |
| SSDEEP | `49152:8QTBVzFejxNOihED6f50TeafdCYhZ03Nb:Q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_696fc814
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "696fc814fa188e918e59cf4046c7f62062a61f5ea1bf66da59961851db10a0d5"
    family = "unknown"
    file_name = "main_v4.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:13"
  condition:
    hash.sha256(0, filesize) == "696fc814fa188e918e59cf4046c7f62062a61f5ea1bf66da59961851db10a0d5"
}
```

### Sample 58: `c946dc76e0b39974`

| Field | Value |
|---|---|
| SHA-256 | `c946dc76e0b39974450fb22127bef7b216f6217b5f36644a0ce8caedf330df18` |
| Family label | `unknown` |
| File name | `main_v3.js` |
| File type | `js` |
| First seen | `2026-10-20 02:41:10` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6fa465d81afee23c47eb79fd025943ef` |
| SHA-1 | `d21aa451454952462f56dd4dcef8798bf48c1bf7` |
| SHA-256 | `c946dc76e0b39974450fb22127bef7b216f6217b5f36644a0ce8caedf330df18` |
| SHA3-384 | `72f5734c0a37a29b410e28c91b224580edff8c82a938a810bbd0a609e87cf15bdd82d46160fb0030d348514d64040851` |
| TLSH | `T18BB5BBD437C1E417628E0B63FF06BAE9E13BA8B668C8A54792507A8C64BC507D5F4DF0` |
| SSDEEP | `49152:I7nfQVuZpemB0RyeEVyUoq8H4W45/qqpNz+gto4:4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_c946dc76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c946dc76e0b39974450fb22127bef7b216f6217b5f36644a0ce8caedf330df18"
    family = "unknown"
    file_name = "main_v3.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:10"
  condition:
    hash.sha256(0, filesize) == "c946dc76e0b39974450fb22127bef7b216f6217b5f36644a0ce8caedf330df18"
}
```

### Sample 59: `11410cdf29bc1f1d`

| Field | Value |
|---|---|
| SHA-256 | `11410cdf29bc1f1ded6fd7dae48e20cf71fd9cb11d8deafce54a76fd582c319e` |
| Family label | `unknown` |
| File name | `main_v2.js` |
| File type | `js` |
| First seen | `2026-10-20 02:41:07` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f3890d0e1a671e5b780e482defe2022` |
| SHA-1 | `f62bdba0d6d57fef2bbfb4b2603a8f8b6bc83fed` |
| SHA-256 | `11410cdf29bc1f1ded6fd7dae48e20cf71fd9cb11d8deafce54a76fd582c319e` |
| SHA3-384 | `3528462707beb7b6ee89540b640cf4235045b81497ccc4fb56ba098d58a88fab4f95e17052253e9a569e01a4e4452997` |
| TLSH | `T10DB5BED467C1E403228E0B63BF06BAF9E13FA8B668C8A947C254799D64BC517D5B0DF0` |
| SSDEEP | `24576:WD2tiYU4HIdI4NSW3zpL3nHtBE127xGE1ctcpIBDApjpAZJRKLc6zvkUN:Wy0YU4HIW4Nv3zprHbE1oCZ+L66` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_11410cdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11410cdf29bc1f1ded6fd7dae48e20cf71fd9cb11d8deafce54a76fd582c319e"
    family = "unknown"
    file_name = "main_v2.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:07"
  condition:
    hash.sha256(0, filesize) == "11410cdf29bc1f1ded6fd7dae48e20cf71fd9cb11d8deafce54a76fd582c319e"
}
```

### Sample 60: `4c56e9af087b0264`

| Field | Value |
|---|---|
| SHA-256 | `4c56e9af087b0264e0e0c9cb061fd87151e10a544dff0c6b6bc37547ef05334a` |
| Family label | `unknown` |
| File name | `main_v1.js` |
| File type | `js` |
| First seen | `2026-10-20 02:41:04` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0fe4c5d41336b6048cc32106ac615ae2` |
| SHA-1 | `04457bac0c342e1eeee8a4bb1bdb64d4c5742d4e` |
| SHA-256 | `4c56e9af087b0264e0e0c9cb061fd87151e10a544dff0c6b6bc37547ef05334a` |
| SHA3-384 | `acfd8cd4ee9ccd801b89f7b4cc8048540f1579cb84447e1513e359eae0763a6c99e19c1baa456c2720549b9619223be8` |
| TLSH | `T10D3513843BC1F807164F4B33B71776F5D12EA856A188E88FE2047D59E4AC923EAD4DB1` |
| SSDEEP | `24576:iT2oy+APSEAVMmlL8Fm+VPVWpMn3SdPJvKXOVJgOvVZ7n6y/qgV:iT2q+SrMyYocEOEJvKXOVJgOvVZb6yyE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_4c56e9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c56e9af087b0264e0e0c9cb061fd87151e10a544dff0c6b6bc37547ef05334a"
    family = "unknown"
    file_name = "main_v1.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:04"
  condition:
    hash.sha256(0, filesize) == "4c56e9af087b0264e0e0c9cb061fd87151e10a544dff0c6b6bc37547ef05334a"
}
```

### Sample 61: `3913a1f77203ebb9`

| Field | Value |
|---|---|
| SHA-256 | `3913a1f77203ebb9e0991e1881279fa6172c9b8fde993fdc5d5be96254cd246f` |
| Family label | `unknown` |
| File name | `hello.hta` |
| File type | `hta` |
| First seen | `2026-10-20 02:40:56` |
| Reporter | `Darkfibr` |
| Tags | `etherhiding, freight-lure, nodejs, rat, vnc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11e67c1d8c74edef80702d15b1561fff` |
| SHA-1 | `fe6160da01751c01bc68333cdf2b874fdd1f6c36` |
| SHA-256 | `3913a1f77203ebb9e0991e1881279fa6172c9b8fde993fdc5d5be96254cd246f` |
| SHA3-384 | `f2235fb487a4d7ff749284e554bb4e0a6c77d46f50427e296567c569d5cfb7cac2a03c64858583de9d38be7621864549` |
| TLSH | `T195F0AB27116C96C1865DB5A100DCBCD0A66646AB42C00E8370CE10053F48A2C804BFDA` |
| SSDEEP | `12:cDkE5NUZqxqfNRu2ZKgUnK/HKe3CxiHoQL:K5NUwGNo2ZKjUKunD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `hta`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_061_3913a1f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3913a1f77203ebb9e0991e1881279fa6172c9b8fde993fdc5d5be96254cd246f"
    family = "unknown"
    file_name = "hello.hta"
    file_type = "hta"
    first_seen = "2026-10-20 02:40:56"
  condition:
    hash.sha256(0, filesize) == "3913a1f77203ebb9e0991e1881279fa6172c9b8fde993fdc5d5be96254cd246f"
}
```

### Sample 62: `0e814f4d934e4a57`

| Field | Value |
|---|---|
| SHA-256 | `0e814f4d934e4a574a914c319367dbe3793ee40ccf58ca3d26763d722216cbac` |
| Family label | `unknown` |
| File name | `0e814f4d934e4a57.bin` |
| File type | `macho` |
| First seen | `2026-10-20 02:25:49` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `16c7a146c567d4e157b78e0198a31f2b` |
| SHA-1 | `98f14e152b1672e940612aa3ebe375ace23096ef` |
| SHA-256 | `0e814f4d934e4a574a914c319367dbe3793ee40ccf58ca3d26763d722216cbac` |
| SHA3-384 | `664473297c1af048e82fed09677abb8aa7f55d5c4369f669584c04a269c8eed19e8cbed2c0cab824afe99be85d36308f` |
| TLSH | `T190E22D43AB4C8965C26D92301AF71BC6A615F5B09EE16B875750C7217FE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvUGVZqDDt0TOTLZ0BbFw2oHKk6XrMclSibFqAMcl:z4ZZXvvXVZMt0TO2bV4/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_062_0e814f4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e814f4d934e4a574a914c319367dbe3793ee40ccf58ca3d26763d722216cbac"
    family = "unknown"
    file_name = "0e814f4d934e4a57.bin"
    file_type = "macho"
    first_seen = "2026-10-20 02:25:49"
  condition:
    hash.sha256(0, filesize) == "0e814f4d934e4a574a914c319367dbe3793ee40ccf58ca3d26763d722216cbac"
}
```

### Sample 63: `884c70bde746092d`

| Field | Value |
|---|---|
| SHA-256 | `884c70bde746092d710d0b217cd23bd314de54fc3a23d0f96928815d92222201` |
| Family label | `unknown` |
| File name | `884c70bde746092d.bin` |
| File type | `macho` |
| First seen | `2026-10-20 02:25:40` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7ed538dd1824c4a5dfe703afc7f2321` |
| SHA-1 | `6563a3fbc448aad251cf472df06f87d2ad49594f` |
| SHA-256 | `884c70bde746092d710d0b217cd23bd314de54fc3a23d0f96928815d92222201` |
| SHA3-384 | `04d550e0e8d61683b54a16ea0fb9dbfbd4b8e29eee2848dc517c93cb8c77895981681c39f6658280fda809fc89319eea` |
| TLSH | `T1E1F24E139B1C0A61C05C633C92BB1B026236F5D086C56B674B10C72CAFCA3C5BDB5D8B` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRPPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfmlilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_884c70bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "884c70bde746092d710d0b217cd23bd314de54fc3a23d0f96928815d92222201"
    family = "unknown"
    file_name = "884c70bde746092d.bin"
    file_type = "macho"
    first_seen = "2026-10-20 02:25:40"
  condition:
    hash.sha256(0, filesize) == "884c70bde746092d710d0b217cd23bd314de54fc3a23d0f96928815d92222201"
}
```

### Sample 64: `48e9eab9bb48d75b`

| Field | Value |
|---|---|
| SHA-256 | `48e9eab9bb48d75bd70a989fe1eaf610fbfdadf8fc21bbfd63dd40e2c2504ff7` |
| Family label | `Mirai` |
| File name | `48e9eab9bb48d75b.bin` |
| File type | `elf` |
| First seen | `2026-10-20 02:25:32` |
| Reporter | `Tuxxin` |
| Tags | `elf, gafgyt, mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0735c9468434e0ac42203c8c5f87b755` |
| SHA-1 | `3ef830c6aff0108ff5eff5313685e87b2eb9b037` |
| SHA-256 | `48e9eab9bb48d75bd70a989fe1eaf610fbfdadf8fc21bbfd63dd40e2c2504ff7` |
| SHA3-384 | `bb6cc65e39132d8873f174b9efbef3b249e7f1b489389370cf1dc54371af997a9274bfb2c21994556296c2b70f27bc9e` |
| TLSH | `T1B4B35B417359844BE2DB0DB1293FABF593DED2A121E0A7C2650DEB4F8231A32554AFCD` |
| SSDEEP | `1536:eOfbNcgXuK/p+rkrLYIHiv2ceW6/J2uYorjatubqsrxEpoYjOTVslSBSvyxq2VU:rfbrX9+3eWEGYwdptjhvvoVU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_48e9eab9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e9eab9bb48d75bd70a989fe1eaf610fbfdadf8fc21bbfd63dd40e2c2504ff7"
    family = "Mirai"
    file_name = "48e9eab9bb48d75b.bin"
    file_type = "elf"
    first_seen = "2026-10-20 02:25:32"
  condition:
    hash.sha256(0, filesize) == "48e9eab9bb48d75bd70a989fe1eaf610fbfdadf8fc21bbfd63dd40e2c2504ff7"
}
```

### Sample 65: `05ca064a34061e79`

| Field | Value |
|---|---|
| SHA-256 | `05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b` |
| Family label | `unknown` |
| File name | `05ca064a34061e79.bin` |
| File type | `macho` |
| First seen | `2026-10-20 02:25:22` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49b5f14740c549ecdf19c6be838de5ba` |
| SHA-1 | `a0972ed216cfafaceb6ef84f0d0e30501d935ea1` |
| SHA-256 | `05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b` |
| SHA3-384 | `bbfc5ac6a0e7a2bcfd1369a918461bea16c424cab560b5de6b64421c0a4f2499e635e31d8af10fde0322207ac8326d4b` |
| TLSH | `T118E25F43675C5929D05D83BE22FB1B976609F9A00AD45B432F50DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEa5DbDP67li97WsClwYjqclS06W1YbqclSl:GI2a5DbDyHwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_065_05ca064a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b"
    family = "unknown"
    file_name = "05ca064a34061e79.bin"
    file_type = "macho"
    first_seen = "2026-10-20 02:25:22"
  condition:
    hash.sha256(0, filesize) == "05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b"
}
```

### Sample 66: `92e1930e6de81598`

| Field | Value |
|---|---|
| SHA-256 | `92e1930e6de81598b979d0623013f768be028242e8b10ffa44785cb1b4d6f6ec` |
| Family label | `Mirai` |
| File name | `92e1930e6de81598.bin` |
| File type | `elf` |
| First seen | `2026-10-20 02:25:15` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `11743b0b6d35319e204573141575dd67` |
| SHA-1 | `8cc8f36ff9e6174776f5cb24bc4a7614fbfb43c4` |
| SHA-256 | `92e1930e6de81598b979d0623013f768be028242e8b10ffa44785cb1b4d6f6ec` |
| SHA3-384 | `5cde5378cd496de2c663eb5d1a03ae5356e8683765d1ebc7c3e5ecfb58917ff4cb0339ec2c7aacf0ab6aad3f2e1ae9fe` |
| TLSH | `T1AE125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5RlTTej6TNJ9VeNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTBTTfTpVSdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_066_92e1930e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92e1930e6de81598b979d0623013f768be028242e8b10ffa44785cb1b4d6f6ec"
    family = "Mirai"
    file_name = "92e1930e6de81598.bin"
    file_type = "elf"
    first_seen = "2026-10-20 02:25:15"
  condition:
    hash.sha256(0, filesize) == "92e1930e6de81598b979d0623013f768be028242e8b10ffa44785cb1b4d6f6ec"
}
```

### Sample 67: `085dc35f07a9b087`

| Field | Value |
|---|---|
| SHA-256 | `085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7` |
| Family label | `Snowlight` |
| File name | `085dc35f07a9b087.bin` |
| File type | `elf` |
| First seen | `2026-10-20 02:25:06` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7f0aa27ca68fd034e83ca5d02a794a88` |
| SHA-1 | `6739f4b438064ffd49734bf69249dc8197164e48` |
| SHA-256 | `085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7` |
| SHA3-384 | `5825e3b56f11d653fbdf2a6c30ac4014c97dab8aff5cb9a9186885587b17d6330a4bb38291a590e16d9dffb1b88d8c32` |
| TLSH | `T120123047A2D0CE3FC8D953384467122472B794BEDF629713064815B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS69H5ML09V1J9G8YmW+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHmZMWT1YmLhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_067_085dc35f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7"
    family = "Snowlight"
    file_name = "085dc35f07a9b087.bin"
    file_type = "elf"
    first_seen = "2026-10-20 02:25:06"
  condition:
    hash.sha256(0, filesize) == "085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7"
}
```

### Sample 68: `0a7271ec4b47e3f4`

| Field | Value |
|---|---|
| SHA-256 | `0a7271ec4b47e3f4af8a0c86b0577a552d94268662da785fef2d13671bf0be0e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-20 02:13:34` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, MIX8.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ead24d772b15a7700dbe9460dd145517` |
| SHA-1 | `9bd4fd9dd27cfea7cf027ea8c66a3ee098a7b544` |
| SHA-256 | `0a7271ec4b47e3f4af8a0c86b0577a552d94268662da785fef2d13671bf0be0e` |
| SHA3-384 | `876b5ce998a09f430ceeee1ed1d8429f60eb508e3b1f6cbb22832a3b75fb7cbb09d79c2c002b659f7e52ce4b259042b0` |
| IMPHASH | `ed8b780a3ce7ca4aba78a21f6bc3d4e0` |
| TLSH | `T1CA765943EC9559E5C0AED631CA66A113BB307C496B2523D31B60F2346F73BD0AEB9358` |
| SSDEEP | `49152:MNBBZc9yukx1tWxgix65lJxDZmQuOhasbZ+U4A/QD8ZOpLSkTsRQLoV7p0I5aOKm:MLPkNxgfvnL4iO8mL9+Q/bMUdEFX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_0a7271ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a7271ec4b47e3f4af8a0c86b0577a552d94268662da785fef2d13671bf0be0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 02:13:34"
  condition:
    hash.sha256(0, filesize) == "0a7271ec4b47e3f4af8a0c86b0577a552d94268662da785fef2d13671bf0be0e"
}
```

### Sample 69: `f189bdd403dd6058`

| Field | Value |
|---|---|
| SHA-256 | `f189bdd403dd605860ef3430c3a6cde7690820647a1c878d8714e3728c845303` |
| Family label | `unknown` |
| File name | `SecuriteInfo.com.Heur.9029.26114` |
| File type | `msi` |
| First seen | `2026-10-20 02:00:29` |
| Reporter | `SecuriteInfoCom` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e7926f9d96c07198119d093c4555f29b` |
| SHA-1 | `f754dad5bd033f5c13d259d7d3388a362829888e` |
| SHA-256 | `f189bdd403dd605860ef3430c3a6cde7690820647a1c878d8714e3728c845303` |
| SHA3-384 | `b4a106f8b2132832bec739ba6f673bdf31fce405b0ad588bc01f23fa4ec81a82929ee4a3485e4e0e3832b73a8df6c993` |
| TLSH | `T106B55C636A50600642B5A8FABEBD5E37795F340D102AD98EFFD30B86E51E6F44802D1F` |
| SSDEEP | `24576:2fxK1PcpukylEL3CJEdBPHjzWO1UauftimpvpYe0DZp52lHF6Y5mJYAppfSKMxAL:2QSdDSidBLZUamiuX0Df52lMUlltQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_f189bdd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f189bdd403dd605860ef3430c3a6cde7690820647a1c878d8714e3728c845303"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.9029.26114"
    file_type = "msi"
    first_seen = "2026-10-20 02:00:29"
  condition:
    hash.sha256(0, filesize) == "f189bdd403dd605860ef3430c3a6cde7690820647a1c878d8714e3728c845303"
}
```

### Sample 70: `e5e44b52a0f49822`

| Field | Value |
|---|---|
| SHA-256 | `e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d` |
| Family label | `unknown` |
| File name | `e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d.msi` |
| File type | `msi` |
| First seen | `2026-10-20 01:52:56` |
| Reporter | `Tuxxin` |
| Tags | `msi` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e84bcb3a32a6dbd9c200a04ddd98e95c` |
| SHA-1 | `04853efe4732190c558c3040fc8e55df5ea29a5c` |
| SHA-256 | `e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d` |
| SHA3-384 | `ab054d0a7084a98eb8ea92c66afe4aa03182e5558db94a9a69d62cbc034a48a56976f898061bb6ef802082c298c22105` |
| TLSH | `T1DE65234D3A678F63C0A915780563CF3843BA5D847B1A8AC37B94B7183DB77A54AD322C` |
| SSDEEP | `24576:csuDXXva104BMeRocDP1NhhQEJBDYkaTz4Mcctdrbf6zncNynD6BRMhUT:cVX//i5oojQc0HUmdruzcNynD6q4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_e5e44b52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d"
    family = "unknown"
    file_name = "e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d.msi"
    file_type = "msi"
    first_seen = "2026-10-20 01:52:56"
  condition:
    hash.sha256(0, filesize) == "e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d"
}
```

### Sample 71: `233a34e56f0fb194`

| Field | Value |
|---|---|
| SHA-256 | `233a34e56f0fb194bf3019e1fbe1f5fbd9ad23a800b7f5d3d58d4fc38ed44382` |
| Family label | `unknown` |
| File name | `export.php` |
| File type | `exe` |
| First seen | `2026-10-20 01:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67d734942ed7c5ddee2466ccb815530f` |
| SHA-1 | `3208c03639d81012d221578fa254d81433c7a15a` |
| SHA-256 | `233a34e56f0fb194bf3019e1fbe1f5fbd9ad23a800b7f5d3d58d4fc38ed44382` |
| SHA3-384 | `1f43ff589558ee67d8512e9735daeeaa2867a1670ba20dcb31d2377472a5924ddf00e1aa64b08559ea02951f3772829a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1BD25F19D29C010BDF012C4F157B178BE9121593E5BBCD72A86C93248B69C5FEFE936A0` |
| SSDEEP | `24576:nqGyuHafANv1wI36SWnM1swUignChXS/R:QENNwi2kju` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_233a34e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "233a34e56f0fb194bf3019e1fbe1f5fbd9ad23a800b7f5d3d58d4fc38ed44382"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-20 01:52:08"
  condition:
    hash.sha256(0, filesize) == "233a34e56f0fb194bf3019e1fbe1f5fbd9ad23a800b7f5d3d58d4fc38ed44382"
}
```

### Sample 72: `ebd743e86e20d111`

| Field | Value |
|---|---|
| SHA-256 | `ebd743e86e20d1111f6686328608d6539b2315be8f3b0c4afab37dd5baa2db15` |
| Family label | `unknown` |
| File name | `SearchFilterHost.exe` |
| File type | `exe` |
| First seen | `2026-10-20 01:48:29` |
| Reporter | `AmadeyHunter` |
| Tags | `Coin, CoinMiner, exe, miner` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `862af37b8851f2b67fe0b358e3e9c52b` |
| SHA-1 | `1a8ba8c08a1734dff96812f94d503d541a0306a7` |
| SHA-256 | `ebd743e86e20d1111f6686328608d6539b2315be8f3b0c4afab37dd5baa2db15` |
| SHA3-384 | `dd48f6f22355cbf98eda22fe59e1d45f9ab4e5225f3937e7be6092c092d2007e0fa7c0ecf3c8e2aa61b9132cba5b65c4` |
| IMPHASH | `25ff23752fc067807cf0ac51a752609e` |
| TLSH | `T1AF873306ABB058F9D562E47C518F732EBA31BCA4479696CB539023301E537E8E83DF25` |
| SSDEEP | `786432:YaZW42aR1UPIDkKY3gy3MI5ED9eM+L82kBxNjrrbd+f1r4OW:YkRh1ozKY/3MI5ED9187uxNjPbd+f1r8` |
| ICON-DHASH | `2996969696969696` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_ebd743e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd743e86e20d1111f6686328608d6539b2315be8f3b0c4afab37dd5baa2db15"
    family = "unknown"
    file_name = "SearchFilterHost.exe"
    file_type = "exe"
    first_seen = "2026-10-20 01:48:29"
  condition:
    hash.sha256(0, filesize) == "ebd743e86e20d1111f6686328608d6539b2315be8f3b0c4afab37dd5baa2db15"
}
```

### Sample 73: `dd4dbf4effc6542f`

| Field | Value |
|---|---|
| SHA-256 | `dd4dbf4effc6542f3669012faa31c2babf852ef16f9cb0e46bacebc320787c29` |
| Family label | `SalatStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-20 01:43:39` |
| Reporter | `Bitsight` |
| Tags | `521048dd5a8917782e586ac60bc1eceb, dropped-by-remus, exe, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cd88c9f7b2bd5f5d326100761d57749d` |
| SHA-1 | `fb0bef7ef70478c26fcead019ec5f88a0ea8c2a5` |
| SHA-256 | `dd4dbf4effc6542f3669012faa31c2babf852ef16f9cb0e46bacebc320787c29` |
| SHA3-384 | `8ba47aa320020f2c8c43857792da47784283e4b4cfa2f92d4f16ecc20c82e276aa678d06efeebf14a40a78929d6dca0f` |
| IMPHASH | `1465e7eab8316965aaa8e0b0ce1d221d` |
| TLSH | `T1C5A733A7B58929DBC0619BBC90929364A17C56210E934DCF3EC2BA348F77F864DF6470` |
| SSDEEP | `786432:1SieTRLCBy9Ch1xRIOPlUqjAPjJu8P434PBJXbIhyc9j3vdxutFkKDDlm5dfV5+:1SieThCB6CjjgTdp4I5/0dct5DlwfH+` |
| ICON-DHASH | `2996969696969696` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_073_dd4dbf4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd4dbf4effc6542f3669012faa31c2babf852ef16f9cb0e46bacebc320787c29"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 01:43:39"
  condition:
    hash.sha256(0, filesize) == "dd4dbf4effc6542f3669012faa31c2babf852ef16f9cb0e46bacebc320787c29"
}
```

### Sample 74: `22af957e2884da7c`

| Field | Value |
|---|---|
| SHA-256 | `22af957e2884da7ce1300a5f50d967a3c5c76d23f6d03989e490de511c2fdbde` |
| Family label | `RemusStealer` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-20 01:42:52` |
| Reporter | `Bitsight` |
| Tags | `521048dd5a8917782e586ac60bc1eceb, dropped-by-remus, exe, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8608c4eebd12be0a9841d7601efac66b` |
| SHA-1 | `9513c69705ad9f0851393533a6eda2671906e52a` |
| SHA-256 | `22af957e2884da7ce1300a5f50d967a3c5c76d23f6d03989e490de511c2fdbde` |
| SHA3-384 | `012df8292eb999c086031b9d01ba3fc1aa21daf8ed7962d0bd3a47280906a6f01c6385bfa43b10bb1d194a630db6e8bd` |
| IMPHASH | `9b058488174f51c3c8c67bbfc5f71010` |
| TLSH | `T14225E033F95942A8CB7CB0B768A8B7409A887B069F67B1BC3B8F34837452C577565306` |
| SSDEEP | `24576:6RqCmPdEqRAtp9il+uPzyk6Io7YORD2D:6gnPdEqWprEMLvD4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_074_22af957e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22af957e2884da7ce1300a5f50d967a3c5c76d23f6d03989e490de511c2fdbde"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 01:42:52"
  condition:
    hash.sha256(0, filesize) == "22af957e2884da7ce1300a5f50d967a3c5c76d23f6d03989e490de511c2fdbde"
}
```

### Sample 75: `863ea1012d137989`

| Field | Value |
|---|---|
| SHA-256 | `863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107` |
| Family label | `AMOS` |
| File name | `macho_863ea1012d13.bin` |
| File type | `macho` |
| First seen | `2026-10-20 01:41:23` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `98ff3b141ccf61fc6c6c2dd3fa999687` |
| SHA-1 | `8a03b67ac5da544cac4a4c08c2137c6b50251110` |
| SHA-256 | `863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107` |
| SHA3-384 | `1d145f397a3c24d9c7a67b67c6bfc0af19122f51bee98d20f36e8014b7038e697e1fdd423bbd766cc648e37fc94ed686` |
| TLSH | `T17595F1702A7A5219E4CA6473EC194F0905A073A16B4CFAE5D62CC73A1F366D3B5BB313` |
| SSDEEP | `24576:A1rrGV2ULJP3H4TRVjOTpEnW0n+936WranB5zToZz2W7tR334vpXzQD3x:A1iVPITf3W0n+xRranP8ZRYvlI` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_075_863ea101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107"
    family = "AMOS"
    file_name = "macho_863ea1012d13.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:41:23"
  condition:
    hash.sha256(0, filesize) == "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107"
}
```

### Sample 76: `f2d4c3ce8d9a11fc`

| Field | Value |
|---|---|
| SHA-256 | `f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98` |
| Family label | `Mirai` |
| File name | `f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98.elf` |
| File type | `elf` |
| First seen | `2026-10-20 01:31:42` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `852d4daa4ad53e740a49354a14c083d3` |
| SHA-1 | `7d8907f9e48b80d510c66791711c66114faeaeb4` |
| SHA-256 | `f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98` |
| SHA3-384 | `f9d2cb386151d6a10f4a0162e54be93276cc80de9d21ebeb0eb7c50a16dbbaa512baceb5657af126984fa03394f58c9f` |
| TLSH | `T1BB936BC19243D8F1ED494174203EF337A632EDB81068FEE3F755A672A4219A5B14AF4E` |
| TELFHASH | `t13b31d1f966360ca8bbc0a801f30e5761be5de73b25206a9349b318743126d8313bbd39` |
| SSDEEP | `1536:ANBacYV8zaqh/1XPvCWLM0yo0ijLmTAJyvGYPKBXKdPxMG6LDSLf236nIXUCZLPw:CMP6aqh9XPvHlJ0SLm8JyvGYPoXKdPxF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_f2d4c3ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98"
    family = "Mirai"
    file_name = "f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98.elf"
    file_type = "elf"
    first_seen = "2026-10-20 01:31:42"
  condition:
    hash.sha256(0, filesize) == "f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98"
}
```

### Sample 77: `45b4cf5074a13d67`

| Field | Value |
|---|---|
| SHA-256 | `45b4cf5074a13d67d69725e8b43442efd350f1adf9e404f83d564bd0cccf911f` |
| Family label | `unknown` |
| File name | `45b4cf5074a13d67.bin` |
| File type | `macho` |
| First seen | `2026-10-20 01:25:36` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5efb2d469445a112899fdc82b50cca34` |
| SHA-1 | `9ccc6eff57edb8b2db67b4d47c87cb61de82be6d` |
| SHA-256 | `45b4cf5074a13d67d69725e8b43442efd350f1adf9e404f83d564bd0cccf911f` |
| SHA3-384 | `ff17370c2293f5ed9f553460cc862d4e2827915012c0f1c7bfea55218ac5c070a5ca822c0f9c56763dd4299bf4bf4b2c` |
| TLSH | `T1B3E22C43AB4C8965C26D52301AF71BC6A615F5B09EE16B8B5760C7217EE13883C72E8F` |
| SSDEEP | `96:x94ZZh5vvU5VZqDDt0TOTLZ0BbFw2VHKk6XrMclSibFqAMcl:z4ZZXvvMVZMt0TO2bVR/6bMclRbJMcl` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_45b4cf50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45b4cf5074a13d67d69725e8b43442efd350f1adf9e404f83d564bd0cccf911f"
    family = "unknown"
    file_name = "45b4cf5074a13d67.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:25:36"
  condition:
    hash.sha256(0, filesize) == "45b4cf5074a13d67d69725e8b43442efd350f1adf9e404f83d564bd0cccf911f"
}
```

### Sample 78: `c1ab182921c11bcf`

| Field | Value |
|---|---|
| SHA-256 | `c1ab182921c11bcf03f9e8a8456fb51424f4053f38cb0bc8bb9e1e8f1d4a4023` |
| Family label | `unknown` |
| File name | `c1ab182921c11bcf.bin` |
| File type | `macho` |
| First seen | `2026-10-20 01:25:25` |
| Reporter | `Tuxxin` |
| Tags | `macho, snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fb69c7ffbc6e8a29b5f1d13b511d494` |
| SHA-1 | `5813b8f59a78807d9a8b97753d5b0c14eee0ce4f` |
| SHA-256 | `c1ab182921c11bcf03f9e8a8456fb51424f4053f38cb0bc8bb9e1e8f1d4a4023` |
| SHA3-384 | `9a97a1d2c87d4b94e15f93e686709c8c62d8dc5dd9d98b2967fc83c735d5f19d9591f43719a98e1e0d322deb54a915a4` |
| TLSH | `T143E23D43AB4C8965C26D52301AF70BC6A616F5B09EE16B875750C7217EE13883C72E8F` |
| SSDEEP | `192:z4ZZXvvtVZMt0TO2bVlw/6bMclRbJMcl:z4P3tyMlRb/l` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_c1ab1829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ab182921c11bcf03f9e8a8456fb51424f4053f38cb0bc8bb9e1e8f1d4a4023"
    family = "unknown"
    file_name = "c1ab182921c11bcf.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:25:25"
  condition:
    hash.sha256(0, filesize) == "c1ab182921c11bcf03f9e8a8456fb51424f4053f38cb0bc8bb9e1e8f1d4a4023"
}
```

### Sample 79: `b10b0a0544ca4878`

| Field | Value |
|---|---|
| SHA-256 | `b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b` |
| Family label | `Snowlight` |
| File name | `b10b0a0544ca4878.bin` |
| File type | `elf` |
| First seen | `2026-10-20 01:25:16` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `746031aa2478b754ffabf984567def15` |
| SHA-1 | `0110be1661f2e43c8ef46c5561d0ee9fab51311b` |
| SHA-256 | `b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b` |
| SHA3-384 | `3210dca65c17cab81636d1b2dc7c75c0e0efffe08e3fede4e36c9263b6d7721c328943da3de830951572bbfe97252a6f` |
| TLSH | `T1D2E16317E2E2CD32D8D4137E55930A1A223DC8659E83DF132D0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3+Jheuhij5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcbuJhAVZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_079_b10b0a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b"
    family = "Snowlight"
    file_name = "b10b0a0544ca4878.bin"
    file_type = "elf"
    first_seen = "2026-10-20 01:25:16"
  condition:
    hash.sha256(0, filesize) == "b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b"
}
```

### Sample 80: `c2f58a161506ee7e`

| Field | Value |
|---|---|
| SHA-256 | `c2f58a161506ee7edf25f833ceb4bc8033398deedc148e1e3454d651d1a4f15c` |
| Family label | `unknown` |
| File name | `c2f58a161506ee7e.bin` |
| File type | `macho` |
| First seen | `2026-10-20 01:25:08` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eab9ee820b8c6210b842c16b0408d416` |
| SHA-1 | `ca0006a398d6fa87a7ea4bf01c4bd0998fe497a3` |
| SHA-256 | `c2f58a161506ee7edf25f833ceb4bc8033398deedc148e1e3454d651d1a4f15c` |
| SHA3-384 | `a987f7401f4a80be2a741ec1e42e5b1e3851017cc55774453015ba5f98eedebdaa1ddcf69b6703480ee5bd9b3a42e60e` |
| TLSH | `T12DE24E43675C5929D05D83BA22FB1B976609F8A009D45B432F90DA282FE23C47CB0EDB` |
| SSDEEP | `96:xcIZEsua5DbDP67li97WsCGwYjqclS06W1YbqclSl:GI2Za5DbDywwYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_c2f58a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2f58a161506ee7edf25f833ceb4bc8033398deedc148e1e3454d651d1a4f15c"
    family = "unknown"
    file_name = "c2f58a161506ee7e.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:25:08"
  condition:
    hash.sha256(0, filesize) == "c2f58a161506ee7edf25f833ceb4bc8033398deedc148e1e3454d651d1a4f15c"
}
```

### Sample 81: `3ec8837c16bd8102`

| Field | Value |
|---|---|
| SHA-256 | `3ec8837c16bd8102549bddfeaffecf69c9344cd7f960534ecb3a846366de33ae` |
| Family label | `Mirai` |
| File name | `3ec8837c16bd8102.bin` |
| File type | `elf` |
| First seen | `2026-10-20 01:25:01` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1fff091ee11ffe6c96ecf7b16e723d34` |
| SHA-1 | `fd8307a731537f850bf792ac3eb4c75c8a33abea` |
| SHA-256 | `3ec8837c16bd8102549bddfeaffecf69c9344cd7f960534ecb3a846366de33ae` |
| SHA3-384 | `c1468f82e6ae5419937c9d24d3943b258221358454f51bc0c1ce258dabba76d805375308ec77ff6d67985a92f3b24a3b` |
| TLSH | `T1FF125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65766E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9VeNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpVSdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_3ec8837c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ec8837c16bd8102549bddfeaffecf69c9344cd7f960534ecb3a846366de33ae"
    family = "Mirai"
    file_name = "3ec8837c16bd8102.bin"
    file_type = "elf"
    first_seen = "2026-10-20 01:25:01"
  condition:
    hash.sha256(0, filesize) == "3ec8837c16bd8102549bddfeaffecf69c9344cd7f960534ecb3a846366de33ae"
}
```

### Sample 82: `d45671c07cec7b37`

| Field | Value |
|---|---|
| SHA-256 | `d45671c07cec7b3728e2c7466a2e8559a4080ca6c592e65b3f11077fb868fad0` |
| Family label | `Mirai` |
| File name | `d45671c07cec7b37.bin` |
| File type | `elf` |
| First seen | `2026-10-20 01:24:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, vshell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b3aaad8005323c6288da2fcb9e144a92` |
| SHA-1 | `e2a62a59fb99da0ce7da6727817ba0db160f1597` |
| SHA-256 | `d45671c07cec7b3728e2c7466a2e8559a4080ca6c592e65b3f11077fb868fad0` |
| SHA3-384 | `9cd5fe04c8e018d97096a0f3e93ae7355bfda27379a53d760055a2b2d8a0f1291f9a20d1de84886fcd250ddccbec3667` |
| TLSH | `T145125047A2D1CE7BC8E813384467122472BBD47ADFA29713050C65B67E923D81E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5nPlTTej6TNJ9VFNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTTTTfTpVVdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_d45671c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45671c07cec7b3728e2c7466a2e8559a4080ca6c592e65b3f11077fb868fad0"
    family = "Mirai"
    file_name = "d45671c07cec7b37.bin"
    file_type = "elf"
    first_seen = "2026-10-20 01:24:52"
  condition:
    hash.sha256(0, filesize) == "d45671c07cec7b3728e2c7466a2e8559a4080ca6c592e65b3f11077fb868fad0"
}
```

### Sample 83: `fd5107d131d0cbd1`

| Field | Value |
|---|---|
| SHA-256 | `fd5107d131d0cbd11a1546b0b2b295cd2060fa28ec0d324a292d9f688a72b0d1` |
| Family label | `unknown` |
| File name | `fd5107d131d0cbd1.js` |
| File type | `js` |
| First seen | `2026-10-20 01:17:12` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ce6140c800832767f5c2e66dc9f74b8` |
| SHA-1 | `b5f6c9c8968fd92d91d1555e39523707e9899c4a` |
| SHA-256 | `fd5107d131d0cbd11a1546b0b2b295cd2060fa28ec0d324a292d9f688a72b0d1` |
| SHA3-384 | `372e8b429747ca4ccac46f97240e8ac5c132f06eb3f4522ebc664d93172c1bb7c3c1f48b5fb59385a77d9ab9e520cb97` |
| TLSH | `T1BE722AF87765206A03633532607F9102E177EB118D5B9050A2E28A917DECF6BE677FC8` |
| SSDEEP | `384:D0grrNbSeKaCJlcK1BTg9P0pB1xAvnQ7D+sjNU:1vNbSpaSWK1BTg2pvxAvnQ7yspU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_fd5107d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd5107d131d0cbd11a1546b0b2b295cd2060fa28ec0d324a292d9f688a72b0d1"
    family = "unknown"
    file_name = "fd5107d131d0cbd1.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:12"
  condition:
    hash.sha256(0, filesize) == "fd5107d131d0cbd11a1546b0b2b295cd2060fa28ec0d324a292d9f688a72b0d1"
}
```

### Sample 84: `e235880c3212fd2c`

| Field | Value |
|---|---|
| SHA-256 | `e235880c3212fd2cbc620064832188e7cbb111c32d661dc72389eb22966ad148` |
| Family label | `unknown` |
| File name | `e235880c3212fd2c.js` |
| File type | `js` |
| First seen | `2026-10-20 01:17:09` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f15e7e70bedc28b2c0fb1def27fe2e20` |
| SHA-1 | `151be9d2e4369688fb3bffe6784d1e22bcd1e4a6` |
| SHA-256 | `e235880c3212fd2cbc620064832188e7cbb111c32d661dc72389eb22966ad148` |
| SHA3-384 | `95adda08d41f7747c3640b458057ca7418306123b833431e144acb9a259caa539bf91e6fc45225ba2210c5ff365c9d5c` |
| TLSH | `T1C27209F87676216A03233932207F9102E133DB515D5B9050A2D28A857DECF6BD67BFD8` |
| SSDEEP | `192:DYWuW0rQVacSLRyfh5pCta+DJzWa8P6tkGT6x9P7BpUPJsFIIJXqDAlAqwnp/7R0:DRuVQsSMaiJZtTg9PlpsxaAnnp/FqN9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_e235880c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e235880c3212fd2cbc620064832188e7cbb111c32d661dc72389eb22966ad148"
    family = "unknown"
    file_name = "e235880c3212fd2c.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:09"
  condition:
    hash.sha256(0, filesize) == "e235880c3212fd2cbc620064832188e7cbb111c32d661dc72389eb22966ad148"
}
```

### Sample 85: `c900dc386ca43fce`

| Field | Value |
|---|---|
| SHA-256 | `c900dc386ca43fceea4c5405d740da248fbee7a1991b7b25648af0b8885d9f10` |
| Family label | `unknown` |
| File name | `c900dc386ca43fce.js` |
| File type | `js` |
| First seen | `2026-10-20 01:17:06` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `db290a1935292cc819dcf6f111b9ce78` |
| SHA-1 | `d09835b2cf0d11f8287de3d20139c2f2d714ad8c` |
| SHA-256 | `c900dc386ca43fceea4c5405d740da248fbee7a1991b7b25648af0b8885d9f10` |
| SHA3-384 | `b32d33045f1be70763a18fed128156f614a2b3facb54f37413a47ec4374d140ba2648382c667f4b7f47eaea2a41e7b1d` |
| TLSH | `T1C2F58603A1E1386604D35EB63D2741CAEC2D8FAF508CA6B8B54DF838B9E5165E5EC770` |
| SSDEEP | `24576:1av32zvdvgzvp1fdaV3CMCeCbC6CLpNb4j9CWCgChCMCCqqbDDX36loUT9FusNFF:y8vd1c3bWar8CXz5gJ5t8rQLFebdr+js` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_c900dc38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c900dc386ca43fceea4c5405d740da248fbee7a1991b7b25648af0b8885d9f10"
    family = "unknown"
    file_name = "c900dc386ca43fce.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:06"
  condition:
    hash.sha256(0, filesize) == "c900dc386ca43fceea4c5405d740da248fbee7a1991b7b25648af0b8885d9f10"
}
```

### Sample 86: `c91cb19e0837fc6a`

| Field | Value |
|---|---|
| SHA-256 | `c91cb19e0837fc6a31267347cecc637f4d55391a1bd515a8bfcd5235b6bd7b94` |
| Family label | `unknown` |
| File name | `c91cb19e0837fc6a.js` |
| File type | `js` |
| First seen | `2026-10-20 01:17:01` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `650bd9431d186e3d677019ac0c6a2a83` |
| SHA-1 | `fe0765c6aea88e0a46c821d511ee43edbb00fe42` |
| SHA-256 | `c91cb19e0837fc6a31267347cecc637f4d55391a1bd515a8bfcd5235b6bd7b94` |
| SHA3-384 | `43e4649b06f05d6f1e047cc176df6484a679823f260b376e766befffc4693d85e85146c7d630d369baded1f7e589c3e5` |
| TLSH | `T1507219F87776216A03233932207F9102E133DA515D5B9050A2D28A847DECF6BE67BFD8` |
| SSDEEP | `192:DzWuW0rQVacSLRyfh5pCta+DJzWa8P6tkGT6x9P7BpUPJsFIIJXqDAlAqwnp/7R0:D6uVQsSMaiJZtTg9PlpsxaAnnp/FqN9` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_c91cb19e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c91cb19e0837fc6a31267347cecc637f4d55391a1bd515a8bfcd5235b6bd7b94"
    family = "unknown"
    file_name = "c91cb19e0837fc6a.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:01"
  condition:
    hash.sha256(0, filesize) == "c91cb19e0837fc6a31267347cecc637f4d55391a1bd515a8bfcd5235b6bd7b94"
}
```

### Sample 87: `4b0b40bb1deee416`

| Field | Value |
|---|---|
| SHA-256 | `4b0b40bb1deee416990ef60d7a8c3c07358b22c5d2699c9032eecaea44d75fae` |
| Family label | `unknown` |
| File name | `4b0b40bb1deee416.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:53` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a06a105ed1ea20aa753b42c0e2d51f7a` |
| SHA-1 | `5faf1a9a90085dc4d181a74604766a3a2361d711` |
| SHA-256 | `4b0b40bb1deee416990ef60d7a8c3c07358b22c5d2699c9032eecaea44d75fae` |
| SHA3-384 | `a4e2b7722914e5142c5dcb43ef3f0e9beee094d4d7b21cb780cc42565ea48d044451bcf66a9765d814582008a395320b` |
| TLSH | `T1B402B2553FE8F4C227D69BF7322F61EDF95A295F5844080BF112BD80BDA4A22E5C2631` |
| SSDEEP | `192:s3ZxIyxoe0T+rcSdfB5alCASCUgs6MjDeUmBPRA95bUoPQu6hE:s3IMoaBMhSC8GOnbUooub` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_4b0b40bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b0b40bb1deee416990ef60d7a8c3c07358b22c5d2699c9032eecaea44d75fae"
    family = "unknown"
    file_name = "4b0b40bb1deee416.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:53"
  condition:
    hash.sha256(0, filesize) == "4b0b40bb1deee416990ef60d7a8c3c07358b22c5d2699c9032eecaea44d75fae"
}
```

### Sample 88: `5d5839dc4e0d081a`

| Field | Value |
|---|---|
| SHA-256 | `5d5839dc4e0d081a8d4587ec41208561d8895406dab4fc4ea30cc903326bded3` |
| Family label | `unknown` |
| File name | `5d5839dc4e0d081a.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:50` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abe0c1ef2c11f78cbfae4d32f14b778d` |
| SHA-1 | `d7f888c22921a8f18ee7c8e360d104f5c235dd12` |
| SHA-256 | `5d5839dc4e0d081a8d4587ec41208561d8895406dab4fc4ea30cc903326bded3` |
| SHA3-384 | `6e1338f8c48c0abc41178bbff7815d9e12ad0154d0e0f97e6fc12f470d0a9ddcb6b785a693d62bc6d2f5277c92d6579d` |
| TLSH | `T1A4722AF87765206A03633532207F9102E177EB118D5B9050A2E28A917DECF6BE677FC8` |
| SSDEEP | `384:DVgrrNbSeKaCJlcK1BTg9P0pB1xAvnQ7D+sjNU:CvNbSpaSWK1BTg2pvxAvnQ7yspU` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_5d5839dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5839dc4e0d081a8d4587ec41208561d8895406dab4fc4ea30cc903326bded3"
    family = "unknown"
    file_name = "5d5839dc4e0d081a.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:50"
  condition:
    hash.sha256(0, filesize) == "5d5839dc4e0d081a8d4587ec41208561d8895406dab4fc4ea30cc903326bded3"
}
```

### Sample 89: `3e2ff76f5b81c576`

| Field | Value |
|---|---|
| SHA-256 | `3e2ff76f5b81c576ee2fa5328d90cdb9452eb1430b63b4941107ef94c030541d` |
| Family label | `unknown` |
| File name | `3e2ff76f5b81c576.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:46` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3ab124cc0fa06836ecb624c8c46ff421` |
| SHA-1 | `0748a29165167097499b6254c21ba8b2b2d33304` |
| SHA-256 | `3e2ff76f5b81c576ee2fa5328d90cdb9452eb1430b63b4941107ef94c030541d` |
| SHA3-384 | `f706ffdb40b46af4a49c4f4b78d05ccd45a46b371fc955b82e4cdc956955dd7ecaa3f4485f0b2664118abd4d1eae51f6` |
| TLSH | `T18AB501994C2346A5969C02B87C6F0BC83AA46BDCE4CCD72F9435D0B277D62EF10D7866` |
| SSDEEP | `24576:h3d6VJHMCSSg4VrRWiFWeb/T3dPZvRPfGodaxAKegf7yQmPenkDF4l1d+UhGHzKi:v6/+S/bTtjfGPWLULQlhP62fX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_3e2ff76f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e2ff76f5b81c576ee2fa5328d90cdb9452eb1430b63b4941107ef94c030541d"
    family = "unknown"
    file_name = "3e2ff76f5b81c576.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:46"
  condition:
    hash.sha256(0, filesize) == "3e2ff76f5b81c576ee2fa5328d90cdb9452eb1430b63b4941107ef94c030541d"
}
```

### Sample 90: `99149794ab1aba9c`

| Field | Value |
|---|---|
| SHA-256 | `99149794ab1aba9c851c83644e2abab10335b93b59d9b64901325eaefaad16c6` |
| Family label | `unknown` |
| File name | `99149794ab1aba9c.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:40` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5c2c26a565d5a0c6e4d9a9258069c3b` |
| SHA-1 | `3b0965cbbd8677a7f3831a80f6721bae76ea1b7b` |
| SHA-256 | `99149794ab1aba9c851c83644e2abab10335b93b59d9b64901325eaefaad16c6` |
| SHA3-384 | `df6e31bcfaaecb9aed3c85788c3a10152224934ed29d8f5c734a67ccc5379d8e5bf3b5f84432f8ad3d29d45bd5d80213` |
| TLSH | `T1897353374445CF649718C815163E5EC89902FA2693E2E31D70CCF732A9AD4EEEF1AD98` |
| SSDEEP | `192:6Kd+gDaDsaCaasagsals+g9axAadKd+g5aMCa6s+g9aMua1aasamFavKd+gZagFa:xfAYc2O4VaR7nKM8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_99149794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99149794ab1aba9c851c83644e2abab10335b93b59d9b64901325eaefaad16c6"
    family = "unknown"
    file_name = "99149794ab1aba9c.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:40"
  condition:
    hash.sha256(0, filesize) == "99149794ab1aba9c851c83644e2abab10335b93b59d9b64901325eaefaad16c6"
}
```

### Sample 91: `8564a2b3645ec26e`

| Field | Value |
|---|---|
| SHA-256 | `8564a2b3645ec26e4333ae0d291ad854b3e06d4a87df133a3d2bd1a32d8fdcff` |
| Family label | `AgentTesla` |
| File name | `8564a2b3645ec26e.ps1` |
| File type | `ps1` |
| First seen | `2026-10-20 01:16:33` |
| Reporter | `Tuxxin` |
| Tags | `agenttesla, ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b1dea2fc1c358a04e78ab8693a84c062` |
| SHA-1 | `c6ef8158a283a5635b05704c22d6d4ec401e89b7` |
| SHA-256 | `8564a2b3645ec26e4333ae0d291ad854b3e06d4a87df133a3d2bd1a32d8fdcff` |
| SHA3-384 | `8510f6b9573d4f1a68170ceddef7a2122c2e2cc77c03613b868be828c8089025a2ef7c1b255578f13aa90ef60718a8b0` |
| TLSH | `T190352368525D0ADC062591A63A5ABD0534AD23C35D4A130A73FC82B53BFD5A4EFA3CB3` |
| SSDEEP | `24576:poqZXmzTCGNDw93/XPEH5Nhyq0Jj8CzxC7XNpOgh2q+fO:j2nCiMvXPe5AJPmPOK` |

#### Technical Assessment

- The sample is tracked as `AgentTesla` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AgentTesla_091_8564a2b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8564a2b3645ec26e4333ae0d291ad854b3e06d4a87df133a3d2bd1a32d8fdcff"
    family = "AgentTesla"
    file_name = "8564a2b3645ec26e.ps1"
    file_type = "ps1"
    first_seen = "2026-10-20 01:16:33"
  condition:
    hash.sha256(0, filesize) == "8564a2b3645ec26e4333ae0d291ad854b3e06d4a87df133a3d2bd1a32d8fdcff"
}
```

### Sample 92: `cc2b99703f6d6f33`

| Field | Value |
|---|---|
| SHA-256 | `cc2b99703f6d6f33a1e4613291719f29c932d6e9fe577cc5ce0aa41b56ae5ba8` |
| Family label | `unknown` |
| File name | `cc2b99703f6d6f33.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:14` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `034ed50bddff711efbd8ed836be7129e` |
| SHA-1 | `5e82271e4da5142cb7c0b44fd3798b41826c42f3` |
| SHA-256 | `cc2b99703f6d6f33a1e4613291719f29c932d6e9fe577cc5ce0aa41b56ae5ba8` |
| SHA3-384 | `e600bc97046c4d1b410ccf57dcc29cea8130980771a32801c19347ac6b76065deec6b7fac90d2c11fe38fc3b34d3487f` |
| TLSH | `T1BB81060DFBE4A6605E7760E4CABE09A9767A3117778A5940FC1C6D903B9623991C3C2C` |
| SSDEEP | `96:laCz2NuqHu8FANfx8aF9OkSFh5xJlkx9DUJATBcT:oCmFA56EMkSdcrTBcT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_cc2b9970
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc2b99703f6d6f33a1e4613291719f29c932d6e9fe577cc5ce0aa41b56ae5ba8"
    family = "unknown"
    file_name = "cc2b99703f6d6f33.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:14"
  condition:
    hash.sha256(0, filesize) == "cc2b99703f6d6f33a1e4613291719f29c932d6e9fe577cc5ce0aa41b56ae5ba8"
}
```

### Sample 93: `8024680621f7b655`

| Field | Value |
|---|---|
| SHA-256 | `8024680621f7b655dcd13afbcd0f97fcad083faf0516e26c2b09d4c9b65b8b03` |
| Family label | `unknown` |
| File name | `8024680621f7b655.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:11` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13fbf18faee48b09a8558d2f11572c7d` |
| SHA-1 | `e0ef3185ddc7330dd94c545042ba0c6550448737` |
| SHA-256 | `8024680621f7b655dcd13afbcd0f97fcad083faf0516e26c2b09d4c9b65b8b03` |
| SHA3-384 | `af233e9fbeb2e13136b03a8f4c64e3d10f0631de8860201335e14f00c96e10810a4ee2e327adf5ce2c0a4f2b5c6c363a` |
| TLSH | `T1E4721A7D73B93075D0E728AA193F5205B072A5222D06C090D526DB982FBCF479937FAC` |
| SSDEEP | `192:P3qIrKIQ8r89O2gfG+Z+fhLwzpiPPDCtd8odPIuYx4QgfA5XBSVJg8GLGtkRZrI:fqI+IvrOA1EYpijCjPIuYx4QAgHLKm8` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_80246806
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8024680621f7b655dcd13afbcd0f97fcad083faf0516e26c2b09d4c9b65b8b03"
    family = "unknown"
    file_name = "8024680621f7b655.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:11"
  condition:
    hash.sha256(0, filesize) == "8024680621f7b655dcd13afbcd0f97fcad083faf0516e26c2b09d4c9b65b8b03"
}
```

### Sample 94: `fc9f05ec4ff59d9a`

| Field | Value |
|---|---|
| SHA-256 | `fc9f05ec4ff59d9adf00e6285605d710bb6294e13e077cc9184171c543be06af` |
| Family label | `unknown` |
| File name | `fc9f05ec4ff59d9a.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:07` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f67afdeb1b515bc108779e1da9df7c6` |
| SHA-1 | `0cbb3e2ad3ec8a94a7c2e0cc26583a1f47acd770` |
| SHA-256 | `fc9f05ec4ff59d9adf00e6285605d710bb6294e13e077cc9184171c543be06af` |
| SHA3-384 | `15b459e063c81b2b9a089b7b0f307fe15bc31e43bfdaadab7ecc54b0d93b8e384d045300240f61f9b4a11e94fe42b59c` |
| TLSH | `T12FA1F865F1FA32B481DE284D281F772CA4F9D220D6A08423E269DE4454E8FCB69F3DD4` |
| SSDEEP | `96:MXMn5BcJGHqTqdjQXtH/odjB4EQ8lPBqqTdefeekwB11a0nZwFgAJ:MWsGKRdHZ8lPBrdebkwBPZwFgAJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_fc9f05ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc9f05ec4ff59d9adf00e6285605d710bb6294e13e077cc9184171c543be06af"
    family = "unknown"
    file_name = "fc9f05ec4ff59d9a.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:07"
  condition:
    hash.sha256(0, filesize) == "fc9f05ec4ff59d9adf00e6285605d710bb6294e13e077cc9184171c543be06af"
}
```

### Sample 95: `f4f2edb42276779b`

| Field | Value |
|---|---|
| SHA-256 | `f4f2edb42276779b7758621e29f4cbef1af9a44e0708fb8f24618375914d763d` |
| Family label | `unknown` |
| File name | `f4f2edb42276779b.js` |
| File type | `js` |
| First seen | `2026-10-20 01:16:04` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c1aba220687bfc8ea8df24a74be12c9` |
| SHA-1 | `568d7ed04368efaacf4a592b04f7e5a2c06d49d3` |
| SHA-256 | `f4f2edb42276779b7758621e29f4cbef1af9a44e0708fb8f24618375914d763d` |
| SHA3-384 | `8ad82030768b83d67cee4fae2273851da18174da0503fae547cdb5c9748d0b4ba5a5c6bdf71b6a1a3caa9f49779c7b37` |
| TLSH | `T1CC43C5097CE761264A53B0BA67EFB445FA26C42B6315D450F85E433C2F90F2442BDEEA` |
| SSDEEP | `1536:9RCJ6/KpVsnUMxvXmET56JYFE7qbe/7Y8fjWWy+4GrkfwuXxJ44ipW/VPRLq277P:9j/FjzarzCT71PtnB` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_f4f2edb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f2edb42276779b7758621e29f4cbef1af9a44e0708fb8f24618375914d763d"
    family = "unknown"
    file_name = "f4f2edb42276779b.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:04"
  condition:
    hash.sha256(0, filesize) == "f4f2edb42276779b7758621e29f4cbef1af9a44e0708fb8f24618375914d763d"
}
```

### Sample 96: `ac4484f6139484fd`

| Field | Value |
|---|---|
| SHA-256 | `ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4` |
| Family label | `unknown` |
| File name | `macho_ac4484f61394.bin` |
| File type | `macho` |
| First seen | `2026-10-20 01:15:46` |
| Reporter | `c4ffeine` |
| Tags | `ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fa5f9c4518e840a3068ee494ee81a57d` |
| SHA-1 | `7ab13e92f25f392ab964c10600fa3a399072d4cd` |
| SHA-256 | `ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4` |
| SHA3-384 | `9ee437d0f7bc3abad55a102757e01f5dfae221045b06f60f5b3a532ebf836131c4542fa492ae7e5c27dea5b8dc9cc30b` |
| TLSH | `T1ED85E1114A1FA09AD40911738C940B5984F4AD80CD0DEFEE5392B7A6EF3B39777226B7` |
| SSDEEP | `24576:HnNUj4YAIBdjYosFxLh5vTCbcdPSYl8BmtYDd3LXAEOITtu1+3t+sDwpcLYnh7:6jq9HPQd3LXAJIZuY9n3ih7` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_096_ac4484f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4"
    family = "unknown"
    file_name = "macho_ac4484f61394.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:15:46"
  condition:
    hash.sha256(0, filesize) == "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4"
}
```

### Sample 97: `1de2505c805069ad`

| Field | Value |
|---|---|
| SHA-256 | `1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d` |
| Family label | `WannaCry` |
| File name | `1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d` |
| File type | `exe` |
| First seen | `2026-10-20 01:15:07` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c45e616d499d5e938bd4051bf67b4bad` |
| SHA-1 | `0817be22ffca826d975878e3f9dd660378bc6132` |
| SHA-256 | `1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d` |
| SHA3-384 | `a2c6b14f2d444becdc84ede7ee7d67d9625391a4ffc3387bcb0ac55016183aec007c4c8aa33eaccae1f090a41e43d394` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T16E362359327CC1BCD1061A7844B78E27E3B37C5A16FE5B0F8B40866A1E13B55EBA4B43` |
| SSDEEP | `49152:jnznjQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAARdhnv:DT8qPoBhz1aRxcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_097_1de2505c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d"
    family = "WannaCry"
    file_name = "1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d"
    file_type = "exe"
    first_seen = "2026-10-20 01:15:07"
  condition:
    hash.sha256(0, filesize) == "1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d"
}
```

### Sample 98: `392070b982e06331`

| Field | Value |
|---|---|
| SHA-256 | `392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90` |
| Family label | `AMOS` |
| File name | `macho_392070b982e0.bin` |
| File type | `macho` |
| First seen | `2026-10-20 01:12:28` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `38d21b7460582bb4ba6982c46de8e820` |
| SHA-1 | `d043c4c8161cc6a72f45ff463138ae1283d4a8f1` |
| SHA-256 | `392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90` |
| SHA3-384 | `1da953e28824a874356428d90be62f8ff47d92041c961fd179162bf302bce898f5dfe287ca4bff314b18bb940e0cdfe6` |
| TLSH | `T142A5E0419E1FA1DBD44A1133DCAA0F6980745080DE48EEEA5341F3ABDE3679377538BA` |
| SSDEEP | `24576:v7WViXWDGqL3y1QiAI0ti+ZY+2nab0PhZ/wIEhDcOruiFBCl0y5f3KUvNqm7Kd3A:JeH152GBCl0Wf6aNqmG4nTJ3zuuP` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_098_392070b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90"
    family = "AMOS"
    file_name = "macho_392070b982e0.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:12:28"
  condition:
    hash.sha256(0, filesize) == "392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90"
}
```

### Sample 99: `eff2758b70648c8d`

| Field | Value |
|---|---|
| SHA-256 | `eff2758b70648c8d361b0fa5f159cdca4c5dc199dcc0cb4a4abb8dd35d2e356c` |
| Family label | `unknown` |
| File name | `eff2758b70648c8d.js` |
| File type | `js` |
| First seen | `2026-10-20 01:12:11` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8ee708f3cd1a3ccf46e6b66a3652940e` |
| SHA-1 | `cdcddb0fdd42519b144813e7c0fa821d8cdfd668` |
| SHA-256 | `eff2758b70648c8d361b0fa5f159cdca4c5dc199dcc0cb4a4abb8dd35d2e356c` |
| SHA3-384 | `05dec7ba0232a4495c85752d265c25364ef624cb491538ceb0207dd02075564ac554c791a6745af1c5e661e9ec2990d7` |
| TLSH | `T17CA1C665F1FA71B481CA2849281FB72C64F9D23096A08462E255DE4464E8FCB59F3DD4` |
| SSDEEP | `96:anmXMn5BcJGHqTqdjQXtH/odjB4EIlPBqqTdefeekwB11a0wcwFgAJ:omWsGKRdHllPBrdebkwBP3wFgAJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_eff2758b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff2758b70648c8d361b0fa5f159cdca4c5dc199dcc0cb4a4abb8dd35d2e356c"
    family = "unknown"
    file_name = "eff2758b70648c8d.js"
    file_type = "js"
    first_seen = "2026-10-20 01:12:11"
  condition:
    hash.sha256(0, filesize) == "eff2758b70648c8d361b0fa5f159cdca4c5dc199dcc0cb4a4abb8dd35d2e356c"
}
```

### Sample 100: `d7909ea6c6d7b137`

| Field | Value |
|---|---|
| SHA-256 | `d7909ea6c6d7b137e42144281b4f6d1286179fc9fcad52ab0ed5ec14991d9907` |
| Family label | `unknown` |
| File name | `d7909ea6c6d7b137.js` |
| File type | `js` |
| First seen | `2026-10-20 01:12:07` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bc140ef93198a971c1f79b43beff7f43` |
| SHA-1 | `df75e863532fc720eab1a8c7055371946b03dc90` |
| SHA-256 | `d7909ea6c6d7b137e42144281b4f6d1286179fc9fcad52ab0ed5ec14991d9907` |
| SHA3-384 | `478ac414471fb91d88dbf20917ddb245dcef1ff369c680027923132397170a3782782e18ff27016e9f0a166930971af9` |
| TLSH | `T132A1C765F1FA71B481CA284D281F772C68F9D230E6A08462E259DE4454F8FCB59F3DD4` |
| SSDEEP | `96:VXMn5BcJGHqTqdjQXtH/odjB4E/lPBqqTdefeekwB11a0TpwFgAJ:VWsGKRdH2lPBrdebkwBPtwFgAJ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_100_d7909ea6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7909ea6c6d7b137e42144281b4f6d1286179fc9fcad52ab0ed5ec14991d9907"
    family = "unknown"
    file_name = "d7909ea6c6d7b137.js"
    file_type = "js"
    first_seen = "2026-10-20 01:12:07"
  condition:
    hash.sha256(0, filesize) == "d7909ea6c6d7b137e42144281b4f6d1286179fc9fcad52ab0ed5ec14991d9907"
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
 * Generated: 2026-10-20T04:59:58.695108+00:00
 */

rule MalwareBazaar_unknown_001_9d0c0819
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002"
    family = "unknown"
    file_name = "macho_9d0c0819b915.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:51:47"
  condition:
    hash.sha256(0, filesize) == "9d0c0819b915625b6c7bc2898cb5f1248df6ab941ce86447c059c4d6de5e0002"
}

rule MalwareBazaar_unknown_002_1b317f7c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4"
    family = "unknown"
    file_name = "macho_1b317f7c9128.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:51:21"
  condition:
    hash.sha256(0, filesize) == "1b317f7c91282bc41153d12a28a41a883eeb655c245e76f8c3142a8cc8458bb4"
}

rule MalwareBazaar_unknown_003_b7a94296
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04"
    family = "unknown"
    file_name = "macho_b7a942961139.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:50:39"
  condition:
    hash.sha256(0, filesize) == "b7a942961139b0f25e83e2bc6ce0eea66e363d7cbe7a2d10b28c040b56eebe04"
}

rule MalwareBazaar_unknown_004_1a68e106
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e"
    family = "unknown"
    file_name = "macho_1a68e1064373.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:50:11"
  condition:
    hash.sha256(0, filesize) == "1a68e1064373a2e4a1a62dd3522e485e8a97bb408496d4aa4f01d78f0224196e"
}

rule MalwareBazaar_Mirai_005_fd82918a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd82918a68014f37556f4d80b16ec34a446b96e6f1a0fbce5569165a72aa71ad"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-10-20 04:32:29"
  condition:
    hash.sha256(0, filesize) == "fd82918a68014f37556f4d80b16ec34a446b96e6f1a0fbce5569165a72aa71ad"
}

rule MalwareBazaar_SalatStealer_006_9617d6bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9617d6bd7aa6e4eb557fcb23437f9b5cd6e1363646ca8f25ca5c8a7fbe47432c"
    family = "SalatStealer"
    file_name = "mbupload-4rqeb3gz.bin"
    file_type = "exe"
    first_seen = "2026-10-20 04:30:40"
  condition:
    hash.sha256(0, filesize) == "9617d6bd7aa6e4eb557fcb23437f9b5cd6e1363646ca8f25ca5c8a7fbe47432c"
}

rule MalwareBazaar_SalatStealer_007_500ebf91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "500ebf9173407dd0fa790182af8b516a9381172b0560e04ae03b4da730eae505"
    family = "SalatStealer"
    file_name = "mbupload-4rqeb3gz.bin"
    file_type = "exe"
    first_seen = "2026-10-20 04:29:29"
  condition:
    hash.sha256(0, filesize) == "500ebf9173407dd0fa790182af8b516a9381172b0560e04ae03b4da730eae505"
}

rule MalwareBazaar_Mirai_008_b2b090f8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2b090f8e71800288cf2dfa6bde8e61c043cd34937600458b83e20939d2b1098"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-20 04:29:24"
  condition:
    hash.sha256(0, filesize) == "b2b090f8e71800288cf2dfa6bde8e61c043cd34937600458b83e20939d2b1098"
}

rule MalwareBazaar_Mirai_009_181ce015
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "181ce015e92b79825cf042fcf67ef3ea1e35073f0387e91c3e52a13bd9821c29"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-20 04:29:22"
  condition:
    hash.sha256(0, filesize) == "181ce015e92b79825cf042fcf67ef3ea1e35073f0387e91c3e52a13bd9821c29"
}

rule MalwareBazaar_Mirai_010_66190998
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66190998e6606df3b635ef7e4e1905f44a869bcce0458325abeb9f05cd02aed5"
    family = "Mirai"
    file_name = "3"
    file_type = "elf"
    first_seen = "2026-10-20 04:26:31"
  condition:
    hash.sha256(0, filesize) == "66190998e6606df3b635ef7e4e1905f44a869bcce0458325abeb9f05cd02aed5"
}

rule MalwareBazaar_Mirai_011_23035869
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d"
    family = "Mirai"
    file_name = "6"
    file_type = "elf"
    first_seen = "2026-10-20 04:26:29"
  condition:
    hash.sha256(0, filesize) == "230358697a04628990cfa14a90b7c3d241a0575fba7d8fb0891492973c6e4b7d"
}

rule MalwareBazaar_Mirai_012_609316b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "609316b027434e338a24c2a2499bb1903c1cdcf3424f13d9d33e00257d805f26"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-20 04:26:27"
  condition:
    hash.sha256(0, filesize) == "609316b027434e338a24c2a2499bb1903c1cdcf3424f13d9d33e00257d805f26"
}

rule MalwareBazaar_unknown_013_f70f77d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f70f77d2ddc78d5ff61c890822ec8a5ec2051c630efc14d4e67496956ff933bd"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.14654.12795"
    file_type = "msi"
    first_seen = "2026-10-20 04:26:02"
  condition:
    hash.sha256(0, filesize) == "f70f77d2ddc78d5ff61c890822ec8a5ec2051c630efc14d4e67496956ff933bd"
}

rule MalwareBazaar_unknown_014_c47583ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c47583ad7634aae58698370056ca7317a9856e48d381f7cf1412eaa7f7b73476"
    family = "unknown"
    file_name = "c47583ad7634aae5.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:25:57"
  condition:
    hash.sha256(0, filesize) == "c47583ad7634aae58698370056ca7317a9856e48d381f7cf1412eaa7f7b73476"
}

rule MalwareBazaar_unknown_015_02297755
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0229775513f13eec54bf2105537fb9512fb0741deed0f07b1f0a323f0600279a"
    family = "unknown"
    file_name = "0229775513f13eec.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:25:49"
  condition:
    hash.sha256(0, filesize) == "0229775513f13eec54bf2105537fb9512fb0741deed0f07b1f0a323f0600279a"
}

rule MalwareBazaar_unknown_016_61806fd2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "61806fd27c93892b7c553a0bfc9f1f40c129506a828596db61b73ef9023bdd17"
    family = "unknown"
    file_name = "61806fd27c93892b.bin"
    file_type = "macho"
    first_seen = "2026-10-20 04:25:41"
  condition:
    hash.sha256(0, filesize) == "61806fd27c93892b7c553a0bfc9f1f40c129506a828596db61b73ef9023bdd17"
}

rule MalwareBazaar_unknown_017_dc35da5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38"
    family = "unknown"
    file_name = "dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38.sh"
    file_type = "sh"
    first_seen = "2026-10-20 04:20:40"
  condition:
    hash.sha256(0, filesize) == "dc35da5b2a0b61c043af1d0d3b3ddca7e3179dae47102fdb970938f9977e9e38"
}

rule MalwareBazaar_Mirai_018_eeb03203
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eeb0320322c04a18a904e4b99a5338f99ca14c21442c793fdf7efaa7082a4873"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-20 04:14:33"
  condition:
    hash.sha256(0, filesize) == "eeb0320322c04a18a904e4b99a5338f99ca14c21442c793fdf7efaa7082a4873"
}

rule MalwareBazaar_Mirai_019_8938b1cb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8938b1cb68b3189c93f0db674b3c0b40cf35169733b1e1d23aaa37714bcdfaf1"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-20 04:11:34"
  condition:
    hash.sha256(0, filesize) == "8938b1cb68b3189c93f0db674b3c0b40cf35169733b1e1d23aaa37714bcdfaf1"
}

rule MalwareBazaar_Loki_020_c8c889fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c8c889fda0b4f309eb611cb14f00c124e0f1b49873f05545707ca0daa77eca48"
    family = "Loki"
    file_name = "BC1C3537592275D79012B7810F42A3CB.exe"
    file_type = "exe"
    first_seen = "2026-10-20 04:10:06"
  condition:
    hash.sha256(0, filesize) == "c8c889fda0b4f309eb611cb14f00c124e0f1b49873f05545707ca0daa77eca48"
}

rule MalwareBazaar_unknown_021_e7f172b1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e7f172b1946b06674fb57333fdbe46af311a64bda7e104d88d35bf2312f69e14"
    family = "unknown"
    file_name = "mbupload-qd3v0mzy.bin"
    file_type = "exe"
    first_seen = "2026-10-20 04:09:45"
  condition:
    hash.sha256(0, filesize) == "e7f172b1946b06674fb57333fdbe46af311a64bda7e104d88d35bf2312f69e14"
}

rule MalwareBazaar_SalatStealer_022_5c554838
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5c5548382cec74538a7b81454bfe0868c17d60dc0a74944e92e04b04a12eed0c"
    family = "SalatStealer"
    file_name = "mbupload-tssooaji.bin"
    file_type = "zip"
    first_seen = "2026-10-20 04:09:14"
  condition:
    hash.sha256(0, filesize) == "5c5548382cec74538a7b81454bfe0868c17d60dc0a74944e92e04b04a12eed0c"
}

rule MalwareBazaar_Mirai_023_6561897b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6561897bb373f25b7002a595c69a45292f2abc9e61141ca90fc39ecf8c0979ac"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-20 04:05:27"
  condition:
    hash.sha256(0, filesize) == "6561897bb373f25b7002a595c69a45292f2abc9e61141ca90fc39ecf8c0979ac"
}

rule MalwareBazaar_Mirai_024_a0dc13a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0dc13a8633f257be504004ad534803633faac7f32439069dba8e7fda62b3dc7"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-20 04:03:26"
  condition:
    hash.sha256(0, filesize) == "a0dc13a8633f257be504004ad534803633faac7f32439069dba8e7fda62b3dc7"
}

rule MalwareBazaar_Mirai_025_1eb74c4c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1eb74c4c15d5568a3f3edf53200da3f5e18f7be7d99fdd0c915c77b36c043ddf"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-20 04:02:30"
  condition:
    hash.sha256(0, filesize) == "1eb74c4c15d5568a3f3edf53200da3f5e18f7be7d99fdd0c915c77b36c043ddf"
}

rule MalwareBazaar_Mirai_026_f7915f8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7915f8dea817c62b7bb0a323c73889643bf2db0be921c67d3a11048ef24bb97"
    family = "Mirai"
    file_name = "bot.arm"
    file_type = "elf"
    first_seen = "2026-10-20 04:02:28"
  condition:
    hash.sha256(0, filesize) == "f7915f8dea817c62b7bb0a323c73889643bf2db0be921c67d3a11048ef24bb97"
}

rule MalwareBazaar_Mirai_027_02947840
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2"
    family = "Mirai"
    file_name = "pid.arm6"
    file_type = "elf"
    first_seen = "2026-10-20 03:59:20"
  condition:
    hash.sha256(0, filesize) == "029478409d6992823305cc3d10a87752b9cc7ab0f6c45bb486e96c897801b9c2"
}

rule MalwareBazaar_Mirai_028_098b91fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf"
    family = "Mirai"
    file_name = "pid.x86_64"
    file_type = "elf"
    first_seen = "2026-10-20 03:56:50"
  condition:
    hash.sha256(0, filesize) == "098b91fd1bcb00ace97418c0e463316fa26d37c4b6cda4dbd0b52421659b0eaf"
}

rule MalwareBazaar_Mirai_029_93af664c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-20 03:54:18"
  condition:
    hash.sha256(0, filesize) == "93af664ca7cdd9682c89d3999802e0cdc763898a66cf5e013b58b5f4a8eccc4e"
}

rule MalwareBazaar_unknown_030_88183421
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.31998.2837"
    file_type = "msi"
    first_seen = "2026-10-20 03:52:03"
  condition:
    hash.sha256(0, filesize) == "88183421d4b666703af8021ecc56438e2708afb961845887e92d63ad63161e25"
}

rule MalwareBazaar_Mirai_031_1f7c7b85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c"
    family = "Mirai"
    file_name = "1"
    file_type = "elf"
    first_seen = "2026-10-20 03:51:22"
  condition:
    hash.sha256(0, filesize) == "1f7c7b85548cf8338f74e6d73c8ac7cb707bc87b087ce86f93b5922c0739d39c"
}

rule MalwareBazaar_Mirai_032_3a2e3ada
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-20 03:48:24"
  condition:
    hash.sha256(0, filesize) == "3a2e3adaa695e37aa5437af52f275fb30c45cf8ae865b88eae21218435cb6ea1"
}

rule MalwareBazaar_Mirai_033_7b7b37e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-20 03:48:22"
  condition:
    hash.sha256(0, filesize) == "7b7b37e805c6749feb65d02f6be3724fef181e95faa993ddd77ccac8df366af6"
}

rule MalwareBazaar_Mirai_034_4a203def
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-10-20 03:45:22"
  condition:
    hash.sha256(0, filesize) == "4a203def15c9d4b30d4602ed9db960d0407a6ba04114a64091b9658c5cd011f2"
}

rule MalwareBazaar_Mirai_035_fd6fb49b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb"
    family = "Mirai"
    file_name = "8"
    file_type = "elf"
    first_seen = "2026-10-20 03:42:35"
  condition:
    hash.sha256(0, filesize) == "fd6fb49be7e0202cba66080524a06072328f285446a50cb679645f99a19d04bb"
}

rule MalwareBazaar_Mirai_036_88964349
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-20 03:37:34"
  condition:
    hash.sha256(0, filesize) == "889643499f34373689fc109d7e09f764848e71082ec8d7de499b27c2c3892f4a"
}

rule MalwareBazaar_Mirai_037_2efd63cc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-20 03:32:34"
  condition:
    hash.sha256(0, filesize) == "2efd63cc32630d6a630dac0ca70afd9ff65a87826153678b0c89841a88308fc5"
}

rule MalwareBazaar_Mirai_038_92f859eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92f859eb329b97f289bd7b864f27559bb8a70a56fd165bbc5bf27751b62ff94a"
    family = "Mirai"
    file_name = "5"
    file_type = "elf"
    first_seen = "2026-10-20 03:30:12"
  condition:
    hash.sha256(0, filesize) == "92f859eb329b97f289bd7b864f27559bb8a70a56fd165bbc5bf27751b62ff94a"
}

rule MalwareBazaar_unknown_039_7ed1a706
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7ed1a706699920206b95e93f869602d8b546f278f7e7e528f42dede04b42ce75"
    family = "unknown"
    file_name = "MV S-BREEZE MAIN VESSEL INFORMATION.js"
    file_type = "js"
    first_seen = "2026-10-20 03:28:49"
  condition:
    hash.sha256(0, filesize) == "7ed1a706699920206b95e93f869602d8b546f278f7e7e528f42dede04b42ce75"
}

rule MalwareBazaar_unknown_040_9208a826
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666"
    family = "unknown"
    file_name = "9208a826c900f6a2.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:30"
  condition:
    hash.sha256(0, filesize) == "9208a826c900f6a2677b2943b28c6f7016e06bfcc605e2c054a4a124ac027666"
}

rule MalwareBazaar_unknown_041_f5da7833
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0"
    family = "unknown"
    file_name = "f5da783380784216.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:22"
  condition:
    hash.sha256(0, filesize) == "f5da783380784216a5979a7ac7285792a4ca2e04a4a7c3bd921ef9a7f5eaa3a0"
}

rule MalwareBazaar_unknown_042_c018650f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924"
    family = "unknown"
    file_name = "c018650f7847d056.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:08"
  condition:
    hash.sha256(0, filesize) == "c018650f7847d0566d56933e5953bdd5227133f645cba35d3c1e69879b455924"
}

rule MalwareBazaar_unknown_043_f7046c09
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623"
    family = "unknown"
    file_name = "f7046c0941b75bdb.bin"
    file_type = "macho"
    first_seen = "2026-10-20 03:26:00"
  condition:
    hash.sha256(0, filesize) == "f7046c0941b75bdbf5f547d4c0b70f3d41bdd50b36f49e42e29ceaee3671e623"
}

rule MalwareBazaar_Mirai_044_c53e6d86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c"
    family = "Mirai"
    file_name = "c53e6d86609593c0.bin"
    file_type = "elf"
    first_seen = "2026-10-20 03:25:50"
  condition:
    hash.sha256(0, filesize) == "c53e6d86609593c0e0afeb913924c007f970cb5be07aff5cc414e7f9ef542a1c"
}

rule MalwareBazaar_Mirai_045_98b43dca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98b43dca907880c96d2e5ec3e4c3d0cd2c13e441cd99de9523278ed4530d980c"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-10-20 03:20:08"
  condition:
    hash.sha256(0, filesize) == "98b43dca907880c96d2e5ec3e4c3d0cd2c13e441cd99de9523278ed4530d980c"
}

rule MalwareBazaar_unknown_046_ec289ea4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ec289ea419e078cec42b2d3e0692c03a1ee406e568459c03d859e5497ed42acb"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 03:12:40"
  condition:
    hash.sha256(0, filesize) == "ec289ea419e078cec42b2d3e0692c03a1ee406e568459c03d859e5497ed42acb"
}

rule MalwareBazaar_unknown_047_54b72985
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "54b72985c8594611acd5600e76c5c435aa4128b0cd23d454eabef2702770bc6f"
    family = "unknown"
    file_name = "PURCHASE INQUIRY  DAEP-DWCESTUAELT-9771 [EXPANSION PROJECT] AL MAKTOUM INTERNATIONAL AIRPORT (DWC) DUBAI.vbs"
    file_type = "vbs"
    first_seen = "2026-10-20 03:03:34"
  condition:
    hash.sha256(0, filesize) == "54b72985c8594611acd5600e76c5c435aa4128b0cd23d454eabef2702770bc6f"
}

rule MalwareBazaar_Mirai_048_67cfc503
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "67cfc503966fd56d77c58cc8a689b94c6d9ba32e262646630cc55fc82037c06e"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-10-20 03:00:17"
  condition:
    hash.sha256(0, filesize) == "67cfc503966fd56d77c58cc8a689b94c6d9ba32e262646630cc55fc82037c06e"
}

rule MalwareBazaar_unknown_049_911b4fe6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "911b4fe6d1761eed5bc7ade69ac55b3c8f726cbd7e3d613ea34bd2bbf107e9c6"
    family = "unknown"
    file_name = "Price Request List  #GSGPRO202600197.exe"
    file_type = "exe"
    first_seen = "2026-10-20 02:57:45"
  condition:
    hash.sha256(0, filesize) == "911b4fe6d1761eed5bc7ade69ac55b3c8f726cbd7e3d613ea34bd2bbf107e9c6"
}

rule MalwareBazaar_unknown_050_80330f59
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "80330f59bad607ce2d4918b2da68c01a3a6bdbb79ba4427fa49f96ae3b80839c"
    family = "unknown"
    file_name = "80330f59bad607ce.js"
    file_type = "js"
    first_seen = "2026-10-20 02:56:07"
  condition:
    hash.sha256(0, filesize) == "80330f59bad607ce2d4918b2da68c01a3a6bdbb79ba4427fa49f96ae3b80839c"
}

rule MalwareBazaar_unknown_051_5414de61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-20 02:52:08"
  condition:
    hash.sha256(0, filesize) == "5414de616cb7cad3e8652004e8aff3a067ed97a30a781c2fe73bb5f029efac30"
}

rule MalwareBazaar_unknown_052_1a9d8635
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1a9d8635574518b8f27e220016cabc5b68d5cce8e56057a4545e4adc981c09ce"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 02:46:50"
  condition:
    hash.sha256(0, filesize) == "1a9d8635574518b8f27e220016cabc5b68d5cce8e56057a4545e4adc981c09ce"
}

rule MalwareBazaar_unknown_053_78d62fc5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78d62fc5a747d68ae531a1cd1e4f6a384545ca2dd5192abb5e9406855651a803"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.10656.3336"
    file_type = "msi"
    first_seen = "2026-10-20 02:46:12"
  condition:
    hash.sha256(0, filesize) == "78d62fc5a747d68ae531a1cd1e4f6a384545ca2dd5192abb5e9406855651a803"
}

rule MalwareBazaar_unknown_054_570e354d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "570e354d5ba56a244fe1b6d08ae36a5c6e489fb53a710524afe065cedfac5f30"
    family = "unknown"
    file_name = "570e354d.ps1"
    file_type = "ps1"
    first_seen = "2026-10-20 02:41:21"
  condition:
    hash.sha256(0, filesize) == "570e354d5ba56a244fe1b6d08ae36a5c6e489fb53a710524afe065cedfac5f30"
}

rule MalwareBazaar_unknown_055_9165aca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9165aca66a9d89b749236dc2f49186c042cfff76acaba9696fc9b1b0e798fab9"
    family = "unknown"
    file_name = "vnc_bootstrap.ps1"
    file_type = "ps1"
    first_seen = "2026-10-20 02:41:19"
  condition:
    hash.sha256(0, filesize) == "9165aca66a9d89b749236dc2f49186c042cfff76acaba9696fc9b1b0e798fab9"
}

rule MalwareBazaar_unknown_056_e5ff711c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5ff711ca8d505be6f83ac1cd7a1615143e7568c776be3be390e59846e3466a0"
    family = "unknown"
    file_name = "info.txt"
    file_type = "js"
    first_seen = "2026-10-20 02:41:15"
  condition:
    hash.sha256(0, filesize) == "e5ff711ca8d505be6f83ac1cd7a1615143e7568c776be3be390e59846e3466a0"
}

rule MalwareBazaar_unknown_057_696fc814
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "696fc814fa188e918e59cf4046c7f62062a61f5ea1bf66da59961851db10a0d5"
    family = "unknown"
    file_name = "main_v4.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:13"
  condition:
    hash.sha256(0, filesize) == "696fc814fa188e918e59cf4046c7f62062a61f5ea1bf66da59961851db10a0d5"
}

rule MalwareBazaar_unknown_058_c946dc76
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c946dc76e0b39974450fb22127bef7b216f6217b5f36644a0ce8caedf330df18"
    family = "unknown"
    file_name = "main_v3.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:10"
  condition:
    hash.sha256(0, filesize) == "c946dc76e0b39974450fb22127bef7b216f6217b5f36644a0ce8caedf330df18"
}

rule MalwareBazaar_unknown_059_11410cdf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11410cdf29bc1f1ded6fd7dae48e20cf71fd9cb11d8deafce54a76fd582c319e"
    family = "unknown"
    file_name = "main_v2.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:07"
  condition:
    hash.sha256(0, filesize) == "11410cdf29bc1f1ded6fd7dae48e20cf71fd9cb11d8deafce54a76fd582c319e"
}

rule MalwareBazaar_unknown_060_4c56e9af
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c56e9af087b0264e0e0c9cb061fd87151e10a544dff0c6b6bc37547ef05334a"
    family = "unknown"
    file_name = "main_v1.js"
    file_type = "js"
    first_seen = "2026-10-20 02:41:04"
  condition:
    hash.sha256(0, filesize) == "4c56e9af087b0264e0e0c9cb061fd87151e10a544dff0c6b6bc37547ef05334a"
}

rule MalwareBazaar_unknown_061_3913a1f7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3913a1f77203ebb9e0991e1881279fa6172c9b8fde993fdc5d5be96254cd246f"
    family = "unknown"
    file_name = "hello.hta"
    file_type = "hta"
    first_seen = "2026-10-20 02:40:56"
  condition:
    hash.sha256(0, filesize) == "3913a1f77203ebb9e0991e1881279fa6172c9b8fde993fdc5d5be96254cd246f"
}

rule MalwareBazaar_unknown_062_0e814f4d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0e814f4d934e4a574a914c319367dbe3793ee40ccf58ca3d26763d722216cbac"
    family = "unknown"
    file_name = "0e814f4d934e4a57.bin"
    file_type = "macho"
    first_seen = "2026-10-20 02:25:49"
  condition:
    hash.sha256(0, filesize) == "0e814f4d934e4a574a914c319367dbe3793ee40ccf58ca3d26763d722216cbac"
}

rule MalwareBazaar_unknown_063_884c70bd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "884c70bde746092d710d0b217cd23bd314de54fc3a23d0f96928815d92222201"
    family = "unknown"
    file_name = "884c70bde746092d.bin"
    file_type = "macho"
    first_seen = "2026-10-20 02:25:40"
  condition:
    hash.sha256(0, filesize) == "884c70bde746092d710d0b217cd23bd314de54fc3a23d0f96928815d92222201"
}

rule MalwareBazaar_Mirai_064_48e9eab9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "48e9eab9bb48d75bd70a989fe1eaf610fbfdadf8fc21bbfd63dd40e2c2504ff7"
    family = "Mirai"
    file_name = "48e9eab9bb48d75b.bin"
    file_type = "elf"
    first_seen = "2026-10-20 02:25:32"
  condition:
    hash.sha256(0, filesize) == "48e9eab9bb48d75bd70a989fe1eaf610fbfdadf8fc21bbfd63dd40e2c2504ff7"
}

rule MalwareBazaar_unknown_065_05ca064a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b"
    family = "unknown"
    file_name = "05ca064a34061e79.bin"
    file_type = "macho"
    first_seen = "2026-10-20 02:25:22"
  condition:
    hash.sha256(0, filesize) == "05ca064a34061e79b6c21da0c508689eaf29369f850f27c86f645724b528990b"
}

rule MalwareBazaar_Mirai_066_92e1930e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92e1930e6de81598b979d0623013f768be028242e8b10ffa44785cb1b4d6f6ec"
    family = "Mirai"
    file_name = "92e1930e6de81598.bin"
    file_type = "elf"
    first_seen = "2026-10-20 02:25:15"
  condition:
    hash.sha256(0, filesize) == "92e1930e6de81598b979d0623013f768be028242e8b10ffa44785cb1b4d6f6ec"
}

rule MalwareBazaar_Snowlight_067_085dc35f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7"
    family = "Snowlight"
    file_name = "085dc35f07a9b087.bin"
    file_type = "elf"
    first_seen = "2026-10-20 02:25:06"
  condition:
    hash.sha256(0, filesize) == "085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7"
}

rule MalwareBazaar_unknown_068_0a7271ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0a7271ec4b47e3f4af8a0c86b0577a552d94268662da785fef2d13671bf0be0e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 02:13:34"
  condition:
    hash.sha256(0, filesize) == "0a7271ec4b47e3f4af8a0c86b0577a552d94268662da785fef2d13671bf0be0e"
}

rule MalwareBazaar_unknown_069_f189bdd4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f189bdd403dd605860ef3430c3a6cde7690820647a1c878d8714e3728c845303"
    family = "unknown"
    file_name = "SecuriteInfo.com.Heur.9029.26114"
    file_type = "msi"
    first_seen = "2026-10-20 02:00:29"
  condition:
    hash.sha256(0, filesize) == "f189bdd403dd605860ef3430c3a6cde7690820647a1c878d8714e3728c845303"
}

rule MalwareBazaar_unknown_070_e5e44b52
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d"
    family = "unknown"
    file_name = "e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d.msi"
    file_type = "msi"
    first_seen = "2026-10-20 01:52:56"
  condition:
    hash.sha256(0, filesize) == "e5e44b52a0f49822871439bd790ae6a662d2e462fd1924efb2429c09e13ac79d"
}

rule MalwareBazaar_unknown_071_233a34e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "233a34e56f0fb194bf3019e1fbe1f5fbd9ad23a800b7f5d3d58d4fc38ed44382"
    family = "unknown"
    file_name = "export.php"
    file_type = "exe"
    first_seen = "2026-10-20 01:52:08"
  condition:
    hash.sha256(0, filesize) == "233a34e56f0fb194bf3019e1fbe1f5fbd9ad23a800b7f5d3d58d4fc38ed44382"
}

rule MalwareBazaar_unknown_072_ebd743e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ebd743e86e20d1111f6686328608d6539b2315be8f3b0c4afab37dd5baa2db15"
    family = "unknown"
    file_name = "SearchFilterHost.exe"
    file_type = "exe"
    first_seen = "2026-10-20 01:48:29"
  condition:
    hash.sha256(0, filesize) == "ebd743e86e20d1111f6686328608d6539b2315be8f3b0c4afab37dd5baa2db15"
}

rule MalwareBazaar_SalatStealer_073_dd4dbf4e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dd4dbf4effc6542f3669012faa31c2babf852ef16f9cb0e46bacebc320787c29"
    family = "SalatStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 01:43:39"
  condition:
    hash.sha256(0, filesize) == "dd4dbf4effc6542f3669012faa31c2babf852ef16f9cb0e46bacebc320787c29"
}

rule MalwareBazaar_RemusStealer_074_22af957e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "22af957e2884da7ce1300a5f50d967a3c5c76d23f6d03989e490de511c2fdbde"
    family = "RemusStealer"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-20 01:42:52"
  condition:
    hash.sha256(0, filesize) == "22af957e2884da7ce1300a5f50d967a3c5c76d23f6d03989e490de511c2fdbde"
}

rule MalwareBazaar_AMOS_075_863ea101
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107"
    family = "AMOS"
    file_name = "macho_863ea1012d13.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:41:23"
  condition:
    hash.sha256(0, filesize) == "863ea1012d1379896cba11f581f4a8e8c86143297f5cdf4c432a8d652a717107"
}

rule MalwareBazaar_Mirai_076_f2d4c3ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98"
    family = "Mirai"
    file_name = "f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98.elf"
    file_type = "elf"
    first_seen = "2026-10-20 01:31:42"
  condition:
    hash.sha256(0, filesize) == "f2d4c3ce8d9a11fc7d49741daa4b3b3e3f20470da598eccf99c1c644fb436d98"
}

rule MalwareBazaar_unknown_077_45b4cf50
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "45b4cf5074a13d67d69725e8b43442efd350f1adf9e404f83d564bd0cccf911f"
    family = "unknown"
    file_name = "45b4cf5074a13d67.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:25:36"
  condition:
    hash.sha256(0, filesize) == "45b4cf5074a13d67d69725e8b43442efd350f1adf9e404f83d564bd0cccf911f"
}

rule MalwareBazaar_unknown_078_c1ab1829
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c1ab182921c11bcf03f9e8a8456fb51424f4053f38cb0bc8bb9e1e8f1d4a4023"
    family = "unknown"
    file_name = "c1ab182921c11bcf.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:25:25"
  condition:
    hash.sha256(0, filesize) == "c1ab182921c11bcf03f9e8a8456fb51424f4053f38cb0bc8bb9e1e8f1d4a4023"
}

rule MalwareBazaar_Snowlight_079_b10b0a05
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b"
    family = "Snowlight"
    file_name = "b10b0a0544ca4878.bin"
    file_type = "elf"
    first_seen = "2026-10-20 01:25:16"
  condition:
    hash.sha256(0, filesize) == "b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b"
}

rule MalwareBazaar_unknown_080_c2f58a16
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c2f58a161506ee7edf25f833ceb4bc8033398deedc148e1e3454d651d1a4f15c"
    family = "unknown"
    file_name = "c2f58a161506ee7e.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:25:08"
  condition:
    hash.sha256(0, filesize) == "c2f58a161506ee7edf25f833ceb4bc8033398deedc148e1e3454d651d1a4f15c"
}

rule MalwareBazaar_Mirai_081_3ec8837c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ec8837c16bd8102549bddfeaffecf69c9344cd7f960534ecb3a846366de33ae"
    family = "Mirai"
    file_name = "3ec8837c16bd8102.bin"
    file_type = "elf"
    first_seen = "2026-10-20 01:25:01"
  condition:
    hash.sha256(0, filesize) == "3ec8837c16bd8102549bddfeaffecf69c9344cd7f960534ecb3a846366de33ae"
}

rule MalwareBazaar_Mirai_082_d45671c0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d45671c07cec7b3728e2c7466a2e8559a4080ca6c592e65b3f11077fb868fad0"
    family = "Mirai"
    file_name = "d45671c07cec7b37.bin"
    file_type = "elf"
    first_seen = "2026-10-20 01:24:52"
  condition:
    hash.sha256(0, filesize) == "d45671c07cec7b3728e2c7466a2e8559a4080ca6c592e65b3f11077fb868fad0"
}

rule MalwareBazaar_unknown_083_fd5107d1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd5107d131d0cbd11a1546b0b2b295cd2060fa28ec0d324a292d9f688a72b0d1"
    family = "unknown"
    file_name = "fd5107d131d0cbd1.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:12"
  condition:
    hash.sha256(0, filesize) == "fd5107d131d0cbd11a1546b0b2b295cd2060fa28ec0d324a292d9f688a72b0d1"
}

rule MalwareBazaar_unknown_084_e235880c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e235880c3212fd2cbc620064832188e7cbb111c32d661dc72389eb22966ad148"
    family = "unknown"
    file_name = "e235880c3212fd2c.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:09"
  condition:
    hash.sha256(0, filesize) == "e235880c3212fd2cbc620064832188e7cbb111c32d661dc72389eb22966ad148"
}

rule MalwareBazaar_unknown_085_c900dc38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c900dc386ca43fceea4c5405d740da248fbee7a1991b7b25648af0b8885d9f10"
    family = "unknown"
    file_name = "c900dc386ca43fce.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:06"
  condition:
    hash.sha256(0, filesize) == "c900dc386ca43fceea4c5405d740da248fbee7a1991b7b25648af0b8885d9f10"
}

rule MalwareBazaar_unknown_086_c91cb19e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c91cb19e0837fc6a31267347cecc637f4d55391a1bd515a8bfcd5235b6bd7b94"
    family = "unknown"
    file_name = "c91cb19e0837fc6a.js"
    file_type = "js"
    first_seen = "2026-10-20 01:17:01"
  condition:
    hash.sha256(0, filesize) == "c91cb19e0837fc6a31267347cecc637f4d55391a1bd515a8bfcd5235b6bd7b94"
}

rule MalwareBazaar_unknown_087_4b0b40bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b0b40bb1deee416990ef60d7a8c3c07358b22c5d2699c9032eecaea44d75fae"
    family = "unknown"
    file_name = "4b0b40bb1deee416.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:53"
  condition:
    hash.sha256(0, filesize) == "4b0b40bb1deee416990ef60d7a8c3c07358b22c5d2699c9032eecaea44d75fae"
}

rule MalwareBazaar_unknown_088_5d5839dc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d5839dc4e0d081a8d4587ec41208561d8895406dab4fc4ea30cc903326bded3"
    family = "unknown"
    file_name = "5d5839dc4e0d081a.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:50"
  condition:
    hash.sha256(0, filesize) == "5d5839dc4e0d081a8d4587ec41208561d8895406dab4fc4ea30cc903326bded3"
}

rule MalwareBazaar_unknown_089_3e2ff76f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e2ff76f5b81c576ee2fa5328d90cdb9452eb1430b63b4941107ef94c030541d"
    family = "unknown"
    file_name = "3e2ff76f5b81c576.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:46"
  condition:
    hash.sha256(0, filesize) == "3e2ff76f5b81c576ee2fa5328d90cdb9452eb1430b63b4941107ef94c030541d"
}

rule MalwareBazaar_unknown_090_99149794
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "99149794ab1aba9c851c83644e2abab10335b93b59d9b64901325eaefaad16c6"
    family = "unknown"
    file_name = "99149794ab1aba9c.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:40"
  condition:
    hash.sha256(0, filesize) == "99149794ab1aba9c851c83644e2abab10335b93b59d9b64901325eaefaad16c6"
}

rule MalwareBazaar_AgentTesla_091_8564a2b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8564a2b3645ec26e4333ae0d291ad854b3e06d4a87df133a3d2bd1a32d8fdcff"
    family = "AgentTesla"
    file_name = "8564a2b3645ec26e.ps1"
    file_type = "ps1"
    first_seen = "2026-10-20 01:16:33"
  condition:
    hash.sha256(0, filesize) == "8564a2b3645ec26e4333ae0d291ad854b3e06d4a87df133a3d2bd1a32d8fdcff"
}

rule MalwareBazaar_unknown_092_cc2b9970
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc2b99703f6d6f33a1e4613291719f29c932d6e9fe577cc5ce0aa41b56ae5ba8"
    family = "unknown"
    file_name = "cc2b99703f6d6f33.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:14"
  condition:
    hash.sha256(0, filesize) == "cc2b99703f6d6f33a1e4613291719f29c932d6e9fe577cc5ce0aa41b56ae5ba8"
}

rule MalwareBazaar_unknown_093_80246806
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8024680621f7b655dcd13afbcd0f97fcad083faf0516e26c2b09d4c9b65b8b03"
    family = "unknown"
    file_name = "8024680621f7b655.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:11"
  condition:
    hash.sha256(0, filesize) == "8024680621f7b655dcd13afbcd0f97fcad083faf0516e26c2b09d4c9b65b8b03"
}

rule MalwareBazaar_unknown_094_fc9f05ec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc9f05ec4ff59d9adf00e6285605d710bb6294e13e077cc9184171c543be06af"
    family = "unknown"
    file_name = "fc9f05ec4ff59d9a.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:07"
  condition:
    hash.sha256(0, filesize) == "fc9f05ec4ff59d9adf00e6285605d710bb6294e13e077cc9184171c543be06af"
}

rule MalwareBazaar_unknown_095_f4f2edb4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4f2edb42276779b7758621e29f4cbef1af9a44e0708fb8f24618375914d763d"
    family = "unknown"
    file_name = "f4f2edb42276779b.js"
    file_type = "js"
    first_seen = "2026-10-20 01:16:04"
  condition:
    hash.sha256(0, filesize) == "f4f2edb42276779b7758621e29f4cbef1af9a44e0708fb8f24618375914d763d"
}

rule MalwareBazaar_unknown_096_ac4484f6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4"
    family = "unknown"
    file_name = "macho_ac4484f61394.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:15:46"
  condition:
    hash.sha256(0, filesize) == "ac4484f6139484fd0099d9fa54d6feebb91c26418f4e7aed9eba6185da58b7d4"
}

rule MalwareBazaar_WannaCry_097_1de2505c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d"
    family = "WannaCry"
    file_name = "1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d"
    file_type = "exe"
    first_seen = "2026-10-20 01:15:07"
  condition:
    hash.sha256(0, filesize) == "1de2505c805069ad682fc83b735a1b6e94874e23d32d8429a1e4489cc7185e1d"
}

rule MalwareBazaar_AMOS_098_392070b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90"
    family = "AMOS"
    file_name = "macho_392070b982e0.bin"
    file_type = "macho"
    first_seen = "2026-10-20 01:12:28"
  condition:
    hash.sha256(0, filesize) == "392070b982e06331e6daaa38cc8bd713b6f47b5f884d2973a908b6190cf44d90"
}

rule MalwareBazaar_unknown_099_eff2758b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff2758b70648c8d361b0fa5f159cdca4c5dc199dcc0cb4a4abb8dd35d2e356c"
    family = "unknown"
    file_name = "eff2758b70648c8d.js"
    file_type = "js"
    first_seen = "2026-10-20 01:12:11"
  condition:
    hash.sha256(0, filesize) == "eff2758b70648c8d361b0fa5f159cdca4c5dc199dcc0cb4a4abb8dd35d2e356c"
}

rule MalwareBazaar_unknown_100_d7909ea6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d7909ea6c6d7b137e42144281b4f6d1286179fc9fcad52ab0ed5ec14991d9907"
    family = "unknown"
    file_name = "d7909ea6c6d7b137.js"
    file_type = "js"
    first_seen = "2026-10-20 01:12:07"
  condition:
    hash.sha256(0, filesize) == "d7909ea6c6d7b137e42144281b4f6d1286179fc9fcad52ab0ed5ec14991d9907"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

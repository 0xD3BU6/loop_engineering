# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-11-16

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 663 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 663 |
| Unique family labels | 11 |
| Unique file types | 10 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 41 |
| unknown | 28 |
| SalatStealer | 8 |
| WARDENStealer | 7 |
| GuLoader | 5 |
| Snowlight | 3 |
| Prometei | 3 |
| WannaCry | 2 |
| CoinMiner | 1 |
| Babadeda | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 52 |
| exe | 19 |
| sh | 7 |
| js | 6 |
| vbs | 5 |
| bat | 4 |
| macho | 3 |
| apk | 2 |
| zip | 1 |
| ps1 | 1 |

## Per-Sample Analysis

### Sample 1: `64a5883ce5cb0ef1`

| Field | Value |
|---|---|
| SHA-256 | `64a5883ce5cb0ef168ffd915b436e68ce3af6431bf7917860ff72ad0d4867f43` |
| Family label | `unknown` |
| File name | `modules.cache` |
| File type | `zip` |
| First seen | `2026-11-16 06:30:37` |
| Reporter | `anonymous` |
| Tags | `etherhiding, ewa, IRAHook, jar, java, RAT, stealer, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c6ed6f03a97bfb12a5ec09c838388097` |
| SHA-1 | `146b3d75bf9261325aeee6a9e7fe5af9e0a0f81e` |
| SHA-256 | `64a5883ce5cb0ef168ffd915b436e68ce3af6431bf7917860ff72ad0d4867f43` |
| SHA3-384 | `4ea0c9e4faf964a258c711b4ab6729587160917b79988ce7ddee213d2a0c08897323db446f296c2131d64b40988882d7` |
| TLSH | `T1F27733A37DCEE529D867D0B351C28357A43A12D9A80AC02F4AE04DD95D31FCA4752FED` |
| SSDEEP | `786432:6WCXbk4po3pTraXTX+YLDMZqDxg+jNgwPO1Rh5CBiu8nm1ZrOZ:PCLkfpHaXXLgZqlVjNgt1IBiu8mA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_64a5883c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64a5883ce5cb0ef168ffd915b436e68ce3af6431bf7917860ff72ad0d4867f43"
    family = "unknown"
    file_name = "modules.cache"
    file_type = "zip"
    first_seen = "2026-11-16 06:30:37"
  condition:
    hash.sha256(0, filesize) == "64a5883ce5cb0ef168ffd915b436e68ce3af6431bf7917860ff72ad0d4867f43"
}
```

### Sample 2: `a6472588a0acc1a2`

| Field | Value |
|---|---|
| SHA-256 | `a6472588a0acc1a2d99e497ae2a1d1f995ab76339f44fe2d11f0f345f7008198` |
| Family label | `SalatStealer` |
| File name | `a6472588a0acc1a2.bin` |
| File type | `bat` |
| First seen | `2026-11-16 06:25:06` |
| Reporter | `Tuxxin` |
| Tags | `bat, powershell, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f68cbb67650a9e6a55cb069ab4a55c6` |
| SHA-1 | `b572005549580e3376c5d36592f68f43533eb206` |
| SHA-256 | `a6472588a0acc1a2d99e497ae2a1d1f995ab76339f44fe2d11f0f345f7008198` |
| SHA3-384 | `8eb294e78207a02e09024c47db71b711f628df5c77e4d2e06ba7d53a407c4d1eb3f6bea49460e0247a7679b78558177b` |
| TLSH | `T1D5D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzM:r` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_002_a6472588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6472588a0acc1a2d99e497ae2a1d1f995ab76339f44fe2d11f0f345f7008198"
    family = "SalatStealer"
    file_name = "a6472588a0acc1a2.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:25:06"
  condition:
    hash.sha256(0, filesize) == "a6472588a0acc1a2d99e497ae2a1d1f995ab76339f44fe2d11f0f345f7008198"
}
```

### Sample 3: `4da2697ef60997de`

| Field | Value |
|---|---|
| SHA-256 | `4da2697ef60997de5a547a7ea90c1bea72ff3302a78f92a39abb69eb55b876e4` |
| Family label | `SalatStealer` |
| File name | `4da2697ef60997de.bin` |
| File type | `bat` |
| First seen | `2026-11-16 06:24:58` |
| Reporter | `Tuxxin` |
| Tags | `bat, powershell, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4a2845b766054717be595312d7f3054e` |
| SHA-1 | `52960989be75367076bfc6d330f0f4622b0e4d0e` |
| SHA-256 | `4da2697ef60997de5a547a7ea90c1bea72ff3302a78f92a39abb69eb55b876e4` |
| SHA3-384 | `a14a4fa2d13132cb305fb91708e35fd1d39edb1f05b3ab2dc27410ca2fb54755ae1211fdba8edb1f431bad037da19a20` |
| TLSH | `T17ED69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzC:l` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_003_4da2697e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4da2697ef60997de5a547a7ea90c1bea72ff3302a78f92a39abb69eb55b876e4"
    family = "SalatStealer"
    file_name = "4da2697ef60997de.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:24:58"
  condition:
    hash.sha256(0, filesize) == "4da2697ef60997de5a547a7ea90c1bea72ff3302a78f92a39abb69eb55b876e4"
}
```

### Sample 4: `70ac4181bd8e58f5`

| Field | Value |
|---|---|
| SHA-256 | `70ac4181bd8e58f5de3c9072fa43399f39becbae14df999dcd13446dc9c396d2` |
| Family label | `SalatStealer` |
| File name | `70ac4181bd8e58f5.bin` |
| File type | `bat` |
| First seen | `2026-11-16 06:24:50` |
| Reporter | `Tuxxin` |
| Tags | `bat, powershell, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cf2f5ad458deef34996801ad3fab1ec6` |
| SHA-1 | `b47562dad4395c4a43892b54969ca43666d05681` |
| SHA-256 | `70ac4181bd8e58f5de3c9072fa43399f39becbae14df999dcd13446dc9c396d2` |
| SHA3-384 | `f77a782ee257dcd7af4bbb4d7a77721c43c992a730fdb29770675784bec6482c9a5feb815b66611af769314a3e34b939` |
| TLSH | `T131D69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzb:g` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_004_70ac4181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ac4181bd8e58f5de3c9072fa43399f39becbae14df999dcd13446dc9c396d2"
    family = "SalatStealer"
    file_name = "70ac4181bd8e58f5.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:24:50"
  condition:
    hash.sha256(0, filesize) == "70ac4181bd8e58f5de3c9072fa43399f39becbae14df999dcd13446dc9c396d2"
}
```

### Sample 5: `4a83b3c7c4b15fe2`

| Field | Value |
|---|---|
| SHA-256 | `4a83b3c7c4b15fe2823ed045f539eafb87bd2cb08f0b02240f512332b384c228` |
| Family label | `SalatStealer` |
| File name | `4a83b3c7c4b15fe2.bin` |
| File type | `bat` |
| First seen | `2026-11-16 06:24:41` |
| Reporter | `Tuxxin` |
| Tags | `bat, powershell, SalatStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `05a8037db6e4b8e40deede8fe712c962` |
| SHA-1 | `86f91835aab3447df9fbeff7fe73cd3203f89b32` |
| SHA-256 | `4a83b3c7c4b15fe2823ed045f539eafb87bd2cb08f0b02240f512332b384c228` |
| SHA3-384 | `d77a562777f2611e762eec245a106d4d9ee3026c8829bb7f9b4d28833d32adb012e0a5da6f9258516b8dbc14de8aefdf` |
| TLSH | `T15CD69C322603BCFA3F6E6EC599142D404C4D3D974254C9A4BE4EF8B3A6DE1486FAE474` |
| SSDEEP | `49152:GYJZB1zf1AShb/lCG17d1wXhQ1+DxnSstWu5Ju2WrTmBGS4as+hQ8jxK9pXYHdzk:D` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_005_4a83b3c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a83b3c7c4b15fe2823ed045f539eafb87bd2cb08f0b02240f512332b384c228"
    family = "SalatStealer"
    file_name = "4a83b3c7c4b15fe2.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:24:41"
  condition:
    hash.sha256(0, filesize) == "4a83b3c7c4b15fe2823ed045f539eafb87bd2cb08f0b02240f512332b384c228"
}
```

### Sample 6: `a1fd1cccce94a929`

| Field | Value |
|---|---|
| SHA-256 | `a1fd1cccce94a92961705679613a6c27e6e53e09a77fe4fd00e94f9ea46a2de7` |
| Family label | `Mirai` |
| File name | `armv6l` |
| File type | `elf` |
| First seen | `2026-11-16 05:46:12` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9337e821d86c91b576820e43c053feec` |
| SHA-1 | `3522180372a3089f4252ed15cf346eac729c69ca` |
| SHA-256 | `a1fd1cccce94a92961705679613a6c27e6e53e09a77fe4fd00e94f9ea46a2de7` |
| SHA3-384 | `db78d9f96b01c44065ca0c754cf28b53b2041a44be83cb4c0c6205a750669ae1f1df6cdfe2d4beff1ec90dd9c1d5406c` |
| TLSH | `T158E4396ABD5298A0C4D455BAB75DC2EC330793B9D3EAB207CD05CB24A9CF9894D3D381` |
| TELFHASH | `t150219e389ea93826b3c4dabdf256d02610710c0a69f535d81e92494fdd42d8605bf81e` |
| SSDEEP | `12288:7n6lOxWDaZGExHPzh4T0Acws5SrRwGR2Rp6yk:bOOcOGt5Rwp` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_006_a1fd1ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1fd1cccce94a92961705679613a6c27e6e53e09a77fe4fd00e94f9ea46a2de7"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:12"
  condition:
    hash.sha256(0, filesize) == "a1fd1cccce94a92961705679613a6c27e6e53e09a77fe4fd00e94f9ea46a2de7"
}
```

### Sample 7: `fd2abb575a45805e`

| Field | Value |
|---|---|
| SHA-256 | `fd2abb575a45805ed719a9069660ce35b412a391a021cb16e9db137811dc056d` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-16 05:46:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6cc02a81f0f1ce0799c980c33aebe629` |
| SHA-1 | `964104bf0027f2015374ba31b796dad61afd4efe` |
| SHA-256 | `fd2abb575a45805ed719a9069660ce35b412a391a021cb16e9db137811dc056d` |
| SHA3-384 | `d72e6439ae24964f4d74bf37da0bcf2c52576555c62b507f2eff85d83a859d1073b68c7fbae06a26decb0c02991eb6af` |
| TLSH | `T11CE45D07F9A0CDB4D5B291B0508E97398921D8391363D98FDE87ED70BD1E190AB2D36E` |
| TELFHASH | `t138c164e046e46de479f04919e7fcf270d97760fa378834b0a8723c95ca1ada21525f4d` |
| SSDEEP | `12288:uX5fHdiKjZWYy7O4MFpNhh9olp2pKs5ISl0mjsLeqxtrj:O5liKjZWwZoj9SqekF` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_fd2abb57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd2abb575a45805ed719a9069660ce35b412a391a021cb16e9db137811dc056d"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:09"
  condition:
    hash.sha256(0, filesize) == "fd2abb575a45805ed719a9069660ce35b412a391a021cb16e9db137811dc056d"
}
```

### Sample 8: `a5dbdaf26db7ac09`

| Field | Value |
|---|---|
| SHA-256 | `a5dbdaf26db7ac09728bd6d0ee874796ac7981434f68dd52c7692511200cd042` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-16 05:46:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb7c5cfd6dfdcf77e98ab037715b5bc4` |
| SHA-1 | `7a4fb803ff1fdd5b5426ef55781a3aeca51a2e90` |
| SHA-256 | `a5dbdaf26db7ac09728bd6d0ee874796ac7981434f68dd52c7692511200cd042` |
| SHA3-384 | `cbda437505675ca3cae12a8408ba89a1d1f880760ca41c9d7dba538faef631b246e36dce6d14159c75c6a42b946f7bbb` |
| TLSH | `T1F2556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSd:SDjxB4m5n8XlaPWi+d+a4TjxQP4z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_008_a5dbdaf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5dbdaf26db7ac09728bd6d0ee874796ac7981434f68dd52c7692511200cd042"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:06"
  condition:
    hash.sha256(0, filesize) == "a5dbdaf26db7ac09728bd6d0ee874796ac7981434f68dd52c7692511200cd042"
}
```

### Sample 9: `6ee744ca88b4f449`

| Field | Value |
|---|---|
| SHA-256 | `6ee744ca88b4f449d90463f607966a19426d61eff5d017d54923a1c61ca5a966` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-16 05:46:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a714cc1631e0b677726ccf6c99b44e0` |
| SHA-1 | `080ab126af6a62f3eecc53d6c4d35d3086ec6a9b` |
| SHA-256 | `6ee744ca88b4f449d90463f607966a19426d61eff5d017d54923a1c61ca5a966` |
| SHA3-384 | `a5eb0fe29802478f13f0c0ce96d7f7f3959d326c4a8375ef73329d7b242d57894696bd05fe04e33d7a1cbe7c9f98c4d9` |
| TLSH | `T1F6556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS4:SDjxB4m5n8XlaPWi+d+a4TjxQP4O` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_009_6ee744ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee744ca88b4f449d90463f607966a19426d61eff5d017d54923a1c61ca5a966"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:03"
  condition:
    hash.sha256(0, filesize) == "6ee744ca88b4f449d90463f607966a19426d61eff5d017d54923a1c61ca5a966"
}
```

### Sample 10: `acd9ad86d2dab62c`

| Field | Value |
|---|---|
| SHA-256 | `acd9ad86d2dab62c58bb8523a5673b3fc40f062c5bf5ffd5649d7cecfea32ac4` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-16 05:43:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae5cd586ec96374dc53f0c9410b661bd` |
| SHA-1 | `248fee65dbf02d389687ec0311eb264a1a596d47` |
| SHA-256 | `acd9ad86d2dab62c58bb8523a5673b3fc40f062c5bf5ffd5649d7cecfea32ac4` |
| SHA3-384 | `a5f41f79f8828ff20bb0de128075ae99b97d6b5b176f355d1dd7d6aa5c16814151e9b22bbe2f612ca6118550c774088b` |
| TLSH | `T18E556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS8:SDjxB4m5n8XlaPWi+d+a4TjxQP4e` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_010_acd9ad86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acd9ad86d2dab62c58bb8523a5673b3fc40f062c5bf5ffd5649d7cecfea32ac4"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:43:04"
  condition:
    hash.sha256(0, filesize) == "acd9ad86d2dab62c58bb8523a5673b3fc40f062c5bf5ffd5649d7cecfea32ac4"
}
```

### Sample 11: `60364fc8ef0b6624`

| Field | Value |
|---|---|
| SHA-256 | `60364fc8ef0b6624d84e5b87a03097c9af21daddb6862ff46f0f225ec09409b8` |
| Family label | `unknown` |
| File name | `rev.sh` |
| File type | `sh` |
| First seen | `2026-11-16 05:38:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9163346b23f6c0fba22a848cbca26d8` |
| SHA-1 | `4a44c66f01df1e97def5a81d5f0e8c2bc84f753f` |
| SHA-256 | `60364fc8ef0b6624d84e5b87a03097c9af21daddb6862ff46f0f225ec09409b8` |
| SHA3-384 | `28a966400a1923a2e737af3d19f6ee1f8123c9a3fe06b2de1689f3e81870e2dc99437339aaf9938fc8687276878d093b` |
| TLSH | `T16D21AFB2A2F16D753B7044987145D17036DA3B53EF9CDDE2493CA9A13A23945E0A4F10` |
| SSDEEP | `24:w1NLYe/55er+SrNvNSL5lOKY0TGz5lOKY0TGP:wTMx6SuOKY0TGGKY0TGP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_60364fc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60364fc8ef0b6624d84e5b87a03097c9af21daddb6862ff46f0f225ec09409b8"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-11-16 05:38:07"
  condition:
    hash.sha256(0, filesize) == "60364fc8ef0b6624d84e5b87a03097c9af21daddb6862ff46f0f225ec09409b8"
}
```

### Sample 12: `c219de851107e407`

| Field | Value |
|---|---|
| SHA-256 | `c219de851107e407846103c04bde115fb80103a7d94ca6747c63b3e507dc226f` |
| Family label | `Mirai` |
| File name | `i686` |
| File type | `elf` |
| First seen | `2026-11-16 05:38:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `725db7a1cca46eecae2fa9e442afb30b` |
| SHA-1 | `c237f6783466aa771ccc73fb5f6d748bc0a1b11d` |
| SHA-256 | `c219de851107e407846103c04bde115fb80103a7d94ca6747c63b3e507dc226f` |
| SHA3-384 | `9c01827618822e5c08079f88dfa9ea0407ad9c6605e7be16c309d4362f852888d24526c77d1bc4d33be78a35a57d7c2e` |
| TLSH | `T1C4E45C07F9A0CDB4D5B291B0508E97398821D8391363D98FDE87ED70BD1E590AB2D36E` |
| TELFHASH | `t1e9c162b046942df0a8f48529ebfdf130f57750fa379829b064357ca5da35ea5202af0e` |
| SSDEEP | `12288:mXegQUub3jvoS46SE8r4hyqO6fzHcTSRUTsc+eo/M:WejD3j4OVzGSh7b` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_012_c219de85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c219de851107e407846103c04bde115fb80103a7d94ca6747c63b3e507dc226f"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-16 05:38:04"
  condition:
    hash.sha256(0, filesize) == "c219de851107e407846103c04bde115fb80103a7d94ca6747c63b3e507dc226f"
}
```

### Sample 13: `def1c414fad5b057`

| Field | Value |
|---|---|
| SHA-256 | `def1c414fad5b057004795c8799e38873607e3a88c537488be3af67ec806f737` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-16 05:37:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc9091e2b03ee18928919d65734a2c48` |
| SHA-1 | `90ac22c65e2a35fd732822fb8c7e70736a3d59a5` |
| SHA-256 | `def1c414fad5b057004795c8799e38873607e3a88c537488be3af67ec806f737` |
| SHA3-384 | `90b8e0a5d38db296216392791ef9c0e6b3d1c370ecbdcd157d9b52b593e2ac3aa015abff1bf9fc130e8454498db394f1` |
| TLSH | `T14CD34A17B4D1C0FDC8D9C2B84B9FE226D973B4291138B11E27D86E276E8DE211F6D624` |
| TELFHASH | `t17b5189703d693850b2ebf677a346d1b5dc390a3104e030e5cab27deadf11b901d628a7` |
| SSDEEP | `1536:3aQb5xf5YvHqFAyPcacb/BhtTI5lDe9+wST77nQzKeEe3rGv:3aQDGZyPEb/BhtT6De9K7sKti6v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_def1c414
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "def1c414fad5b057004795c8799e38873607e3a88c537488be3af67ec806f737"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-16 05:37:04"
  condition:
    hash.sha256(0, filesize) == "def1c414fad5b057004795c8799e38873607e3a88c537488be3af67ec806f737"
}
```

### Sample 14: `619875311cb93e58`

| Field | Value |
|---|---|
| SHA-256 | `619875311cb93e5831314a5e93de40a5fbc144f2dbbc282dac81c4b85e1b7d34` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-16 05:33:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `917e045d9a5d4aeef3285417ca2d3afc` |
| SHA-1 | `b0e29585c67b1dc5a880a852b75b3ea66755bf52` |
| SHA-256 | `619875311cb93e5831314a5e93de40a5fbc144f2dbbc282dac81c4b85e1b7d34` |
| SHA3-384 | `568ca75a225755a4e0807a765d174069899a2dca1391014cfb04a14fa09846160f1366d6fb02a2205becc2a3364dd2b4` |
| TLSH | `T152C3E995FD555B12C6C261BBFB4E438C7B2A1768D3EE72039D256F24378B85B0E3A102` |
| TELFHASH | `t120d02b6a17f125ec9bf18686828d62f8656532b52640111dfe5f5f2f11b39c0322683d` |
| SSDEEP | `1536:oAx+7AbwP3uA5HXAD6J67K4/41lqcOfQhoIHPloEwyweRl7PO86Du1gnGOekBQ:s0bO3uyAM6u4/F4hFvjK+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_014_61987531
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "619875311cb93e5831314a5e93de40a5fbc144f2dbbc282dac81c4b85e1b7d34"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-16 05:33:05"
  condition:
    hash.sha256(0, filesize) == "619875311cb93e5831314a5e93de40a5fbc144f2dbbc282dac81c4b85e1b7d34"
}
```

### Sample 15: `d2d9fed670a9bd44`

| Field | Value |
|---|---|
| SHA-256 | `d2d9fed670a9bd445f19369f6143984ae69684bc112b52745536276e2f6c6a3b` |
| Family label | `unknown` |
| File name | `c` |
| File type | `sh` |
| First seen | `2026-11-16 05:32:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e1a84906af03e207b7aa26e849eb39f` |
| SHA-1 | `802b3ea7207c951b854bd4132c34668d825eb633` |
| SHA-256 | `d2d9fed670a9bd445f19369f6143984ae69684bc112b52745536276e2f6c6a3b` |
| SHA3-384 | `a3d4f46eae23634553ba4a253120585126ca87dfc6e920d0d5bbec1d5f59dd8c260b8320e48f0229e501d0f03190ece0` |
| TLSH | `T159218FDA96A1BE7158D6ED1F733B94AC2060C4CB12D75F86FCAC383D988DC18B002B58` |
| SSDEEP | `24:18zRsFthXTJkjJgQtc4ZDTc61nK3/NIVEpWI3buUvgxV:ezR0dOjJgB4ZDv1naOEpWkb5YxV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_d2d9fed6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d9fed670a9bd445f19369f6143984ae69684bc112b52745536276e2f6c6a3b"
    family = "unknown"
    file_name = "c"
    file_type = "sh"
    first_seen = "2026-11-16 05:32:07"
  condition:
    hash.sha256(0, filesize) == "d2d9fed670a9bd445f19369f6143984ae69684bc112b52745536276e2f6c6a3b"
}
```

### Sample 16: `a9e79b42858a89ec`

| Field | Value |
|---|---|
| SHA-256 | `a9e79b42858a89ec1be3c30edc811f73a4ba6f6234509a066a2cf8d42f78fd74` |
| Family label | `Mirai` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-11-16 05:32:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `21bea000d8cab8cba01d557814deb488` |
| SHA-1 | `57c00a504caf37abd7e65516a6e4d06d14f3c2ff` |
| SHA-256 | `a9e79b42858a89ec1be3c30edc811f73a4ba6f6234509a066a2cf8d42f78fd74` |
| SHA3-384 | `c4e0d315c096396985b7c646ee756277e404028ac33452908d7f5c1b22ac4aa722790f99bba4eb8836c04b9cbaaeba27` |
| TLSH | `T1A9E44B96BD519890C4E45ABAF719C2DC330393B9D3FA720ACD05C674A9CF8994D39BC2` |
| TELFHASH | `t11c22aaa14eed25d8f5e59564d2cfe23a9a33643e3ad134728da5fc8f8a629c00436c1d` |
| SSDEEP | `12288:97nSGAerSneNt1eHvlkcroBezg0dcz/fBA:9bSKrKYHBA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_016_a9e79b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9e79b42858a89ec1be3c30edc811f73a4ba6f6234509a066a2cf8d42f78fd74"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-16 05:32:04"
  condition:
    hash.sha256(0, filesize) == "a9e79b42858a89ec1be3c30edc811f73a4ba6f6234509a066a2cf8d42f78fd74"
}
```

### Sample 17: `59b6431ac5fc6c7e`

| Field | Value |
|---|---|
| SHA-256 | `59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-11-16 05:28:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ef54d6305b8baee49f4bdd9516939875` |
| SHA-1 | `064f113b3bea23b070543275c798eb50b11fbbfb` |
| SHA-256 | `59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40` |
| SHA3-384 | `61cd674c7c0efd993f959750dbda5ad0d881d7b53d69bf3ff08fe68fdff806f27cb1cc0522832bac9d2cc9274c863ba9` |
| TLSH | `T159153B43BE49DEC5CC6CCFB0A75CC725649460C687E6B216FABCABC8A7583101E5B49C` |
| SSDEEP | `12288:7XPS+6Qyi67ar83mT63P8DemslQhzwQrH:LPz6hb7ar83Df8ib6hL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_59b6431a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-16 05:28:08"
  condition:
    hash.sha256(0, filesize) == "59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40"
}
```

### Sample 18: `77456632a5c2b722`

| Field | Value |
|---|---|
| SHA-256 | `77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-16 05:28:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3ec379530548f19f45d3f6996cdc67b` |
| SHA-1 | `07fba455b1374f456047448c845572e8b0efdd0a` |
| SHA-256 | `77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0` |
| SHA3-384 | `2cd24d3df2044b0f3bf6fb0b65b643d3277afeae9225551fd722a4f14f8f29528728a4f25184f47c0cd4f5eb1a110732` |
| TLSH | `T126556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSs:SDjxB4m5n8XlaPWi+d+a4TjxQP46` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_77456632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:28:05"
  condition:
    hash.sha256(0, filesize) == "77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0"
}
```

### Sample 19: `d54a695c3923ab2c`

| Field | Value |
|---|---|
| SHA-256 | `d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-11-16 05:27:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e08ac252d5f4132ba2530014e87570f9` |
| SHA-1 | `41a8d4390069359ee1d4ea45e68cd020bf967280` |
| SHA-256 | `d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691` |
| SHA3-384 | `7f9db84d81834933ac15bd0c441fdab86470f9437964c8c4e2a3ae18897a7397aa2baca3d2ce641fb521c09a0e11a6e2` |
| TLSH | `T143141946EB408B13C0D727B9F7DF425133239B6897A77305A628ABB43F8679E4F22505` |
| TELFHASH | `t1d1210f9661bd826a6ea12828dd7c4bf205129b223391be30ef09c8c4582b007f564d5f` |
| SSDEEP | `3072:kVdGZ7FdYqltKW+jawxDfeNg9jNXZ7/DWeSZhoNM/RWbKSGDmpS2ebOBAdaB:kbeYqlwPjawxDmmjFZ7/DWeMGNM/RMK4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_019_d54a695c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-11-16 05:27:04"
  condition:
    hash.sha256(0, filesize) == "d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691"
}
```

### Sample 20: `1409798cde3af583`

| Field | Value |
|---|---|
| SHA-256 | `1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-11-16 05:24:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a9190d04cf76b0be6eb0c13cb813231` |
| SHA-1 | `df14d35a1aadee6ce04121538f835061a0d1624f` |
| SHA-256 | `1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01` |
| SHA3-384 | `baa5ed7bd270085b84df4f59b986772020d3b83086bc27aca8815399cbbec74a602b8c6572cbbaffc6176f70ea4c3ec8` |
| TLSH | `T182F3C71AAF510EBBDCAFDD3702E9064139CCA51722B43B753674D528F94A90F4AE3C68` |
| SSDEEP | `1536:zTlA5RtLINNU2woiYLQeiC/1sMsCo82daYRVuZvzv8TXHpqYu4zpIyDgfcOILN2N:3lSRBu6TOPV+aYm4ZPzptgEOWO` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_1409798c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-16 05:24:03"
  condition:
    hash.sha256(0, filesize) == "1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01"
}
```

### Sample 21: `b48c71dac86b74e1`

| Field | Value |
|---|---|
| SHA-256 | `b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-11-16 05:22:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e757adbfa9c4503c549b8df170439818` |
| SHA-1 | `809dcdaea605c28dcfe42eef17206f812f47cd89` |
| SHA-256 | `b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7` |
| SHA3-384 | `4dafeba82b9d6eba7f653fcbe691895163eca78ca6cb7bf1b032b88c6c0220b9ed73b4232e1e6ed3eceb4882f662e1af` |
| TLSH | `T1DB935BC6FA93D5F2F89705B1613B5B224B33D43A6029EA41C7296C36CC56901E62B7BC` |
| TELFHASH | `t1725136f63e7608fcf351ac4dd34e6b93ab1aca77162135b500e3692637f7aa18061834` |
| SSDEEP | `1536:P2vYvE45f7dVRubjf/EoxwlqIxSUERX+16hvS:ZvEgJ6HfMSEYUSXZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_b48c71da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-16 05:22:04"
  condition:
    hash.sha256(0, filesize) == "b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7"
}
```

### Sample 22: `88c32e47bcf484de`

| Field | Value |
|---|---|
| SHA-256 | `88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40` |
| Family label | `Mirai` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-11-16 05:20:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3f295e4cd1a6a13e599f3db33b329650` |
| SHA-1 | `0eab5a642510221ec0ed383d9734631026be453e` |
| SHA-256 | `88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40` |
| SHA3-384 | `b53d3e859f8144b242b32f9c69a319a0b492234fcbe99e596ee615ecb78396cd5f6452b7b91a8703c52eda46d435d73e` |
| TLSH | `T148F49D4995EC6C21DAC5F07C98480BF4A32BB4D907B5D3BDAE13A64DDE046E0A77C3A1` |
| SSDEEP | `12288:2FDGQ6IVNq1yPRtjGB6GvRt9K+ImqDdghOrI2o65:kDG1IV/Djo6GvRtbe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_022_88c32e47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-16 05:20:04"
  condition:
    hash.sha256(0, filesize) == "88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40"
}
```

### Sample 23: `35f32b517039e4bc`

| Field | Value |
|---|---|
| SHA-256 | `35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-11-16 05:17:59` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ea844921c3db8693e9862cf561c4153a` |
| SHA-1 | `685f58518707cb069153dc88c7c81cc677759a40` |
| SHA-256 | `35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199` |
| SHA3-384 | `a692c9227e6945359ecf9f73cb1a0ca10d57f3111140672eab29fc66c54fc16fafee6a9b085bac84ff4e93f284a5ff47` |
| TLSH | `T10EF47D1777B164ACD466C134568F43B1D7E9F0A2226ABB6B8BCBE5707D04CD16B0C32A` |
| TELFHASH | `t184e14851a3e03ea87bf0821343f2681b4ebb15d49286199ea3743bd5cf56f530b29c76` |
| SSDEEP | `12288:IrgT0gRFBhH/JJQZqxQ6A2zZW0Yrd8TT+uYQIZ6q:EgwgZZ/fQZqxQ6AAMNh+KuYQIQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_023_35f32b51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-16 05:17:59"
  condition:
    hash.sha256(0, filesize) == "35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199"
}
```

### Sample 24: `78a495e04a829a4e`

| Field | Value |
|---|---|
| SHA-256 | `78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-16 05:17:57` |
| Reporter | `adliwahid` |
| Tags | `Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b4bc5e4fa8e86494057d812b85956a06` |
| SHA-1 | `889283cd4443f7bc2ff7464d09d8b83c98ea7828` |
| SHA-256 | `78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a` |
| SHA3-384 | `fe9e49284de043f5d0dc36f5dced0f08f3a62dc98900099f1995531344dd9f3da43e77b83d1541a91c550ecabbf6ec4d` |
| TLSH | `T1BE155C6BFFA1DFE9C413C5301AB1D77081826C6219A5BA66A370F72CFB241483E5B6D1` |
| SSDEEP | `12288:mmP8IPeI/gzrca/Bt9Iz75G0J9unDSWX67x52s46:mC85Bp81G06wV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_78a495e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-16 05:17:57"
  condition:
    hash.sha256(0, filesize) == "78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a"
}
```

### Sample 25: `dabc05223d247ffa`

| Field | Value |
|---|---|
| SHA-256 | `dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-11-16 05:16:11` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a424f7cda2eb625545d519405614ad4c` |
| SHA-1 | `2cf7c5fa8d198943fbec6e29038e47fb2014ad09` |
| SHA-256 | `dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2` |
| SHA3-384 | `96800866280b116e45f46f27c73f4f9b2786bafb8cb6fe3def1cd03bfe33016c26cffd3f53501873a49df74098b4fa5b` |
| TLSH | `T1D8E307D7F900DABAF80EE73748530509B130BBA249925B737257353BED3A1981477E8A` |
| SSDEEP | `3072:uM41eWP85sysi4jR5DW6Wrf0jJrENmVOjbiBLggwlyMAY76:H4LPppjR5zWEFENgLrwlyMb6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_dabc0522
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:11"
  condition:
    hash.sha256(0, filesize) == "dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2"
}
```

### Sample 26: `c20f4bf9d239489b`

| Field | Value |
|---|---|
| SHA-256 | `c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-16 05:16:09` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c4951d4077171ab87ce03c012064ea3` |
| SHA-1 | `c62c502e9981b9a4cbc00ea9d6376067dadb16ec` |
| SHA-256 | `c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b` |
| SHA3-384 | `1e4422024bc68d083c393dc14985bc01b960841f2576ed658fe7abe3de37fa9b818d34f9881a186ac2f3a46eb414e4c4` |
| TLSH | `T17DF3885E6E228F7EF27C873047F74A20979D23DA22E1D684D2ACC1145F2425E645FBAC` |
| TELFHASH | `t1b84161184e7813e4a7356c4d569dfb37e67730da3e166c338e11e49aa769d839d20c0c` |
| SSDEEP | `3072:QEvFqqSQ8/oi7I3GvCKbQIy6ibQ6P7LVxY:QEvFqqSQ8/IW1lyXQ6TL7Y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_c20f4bf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:09"
  condition:
    hash.sha256(0, filesize) == "c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b"
}
```

### Sample 27: `1c00f4f523080384`

| Field | Value |
|---|---|
| SHA-256 | `1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-11-16 05:16:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f9fdb9d3565f10960d1cf97ce532fe13` |
| SHA-1 | `16951ca83b0215ce62ef6c21e76e28e6d5913078` |
| SHA-256 | `1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0` |
| SHA3-384 | `596741e1e212074faebea9f9d0f61de867f1a30fb522e75806eb1e5cc8bc340cb943a9afceca9fec88a99f8c23fc07f0` |
| TLSH | `T167C3F895F8509B23C6C651BBFF4E438C7B26176CD2EE720399256F25378B46B0E3A142` |
| TELFHASH | `t1a590024251a051dde1e20641c21a41fe9860760741552d457d9e095925bd8805517860` |
| SSDEEP | `1536:OVtiGuSidkAyAcAD630k7UCxHvTh0lEDTfbQgK7lQBwywNhHQp1rJ/wv+OxLzFvp:cduxdkFAyVbxH5Db0gmL5p` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_1c00f4f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:06"
  condition:
    hash.sha256(0, filesize) == "1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0"
}
```

### Sample 28: `c93858738a995794`

| Field | Value |
|---|---|
| SHA-256 | `c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-11-16 05:16:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bbdd7d50edad87ffa0335f047d9b19a5` |
| SHA-1 | `1ff5cebaa3d40a5bf92ce9ce1544d22dc93deda3` |
| SHA-256 | `c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7` |
| SHA3-384 | `01046dacfb0120c429cd70675ac9a5865806873bf1a577e25346cc92522a27d10602a007bd604ad13d0653ec40ba2499` |
| TLSH | `T1EBC33A06B30C0947E2633EF43B3F27E1D3DF9A8121A4F680255FAA8991B2D365586DDD` |
| SSDEEP | `1536:H1wg2bA7O4rhsc7Jkx69zqr1q2Rk0vpzQUmRn3PovAytFNz/sbHTOknqrhZDg:xZr7KxCqkz0tmF9yVDg` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_c9385873
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:03"
  condition:
    hash.sha256(0, filesize) == "c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7"
}
```

### Sample 29: `a381cfea5c8e152d`

| Field | Value |
|---|---|
| SHA-256 | `a381cfea5c8e152d55b5c6c1e2123d34b704f225830f41b306f4e10c9d126e15` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-16 05:13:03` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d1b97438d226cd26174115d63c648b49` |
| SHA-1 | `974bc58a626758659833bd14b66213b206099686` |
| SHA-256 | `a381cfea5c8e152d55b5c6c1e2123d34b704f225830f41b306f4e10c9d126e15` |
| SHA3-384 | `3227bcd2e28058d04434063f10cc7941c202431481e92ff41181d42005c60e0bd6c1c3b72ad5e2b2358cdc225a3f35df` |
| TLSH | `T1D0556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSQ:SDjxB4m5n8XlaPWi+d+a4TjxQP4G` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_a381cfea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a381cfea5c8e152d55b5c6c1e2123d34b704f225830f41b306f4e10c9d126e15"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:13:03"
  condition:
    hash.sha256(0, filesize) == "a381cfea5c8e152d55b5c6c1e2123d34b704f225830f41b306f4e10c9d126e15"
}
```

### Sample 30: `9e36446c383f3614`

| Field | Value |
|---|---|
| SHA-256 | `9e36446c383f361406c4734667b586052916a74fcbc754ff4347f6cd3f75e5bb` |
| Family label | `unknown` |
| File name | `9e36446c383f3614.ps1` |
| File type | `ps1` |
| First seen | `2026-11-16 05:12:18` |
| Reporter | `Tuxxin` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7439a29027933650a43d19022d761c53` |
| SHA-1 | `9bb26e28bb54d71ad54da782e4231086d386127c` |
| SHA-256 | `9e36446c383f361406c4734667b586052916a74fcbc754ff4347f6cd3f75e5bb` |
| SHA3-384 | `24866b7fbd50d7486224641f8fc276e17fe2e18f6236e2471734626ef61ae5c70e9d1f7c50386f4c634602a7b0af0062` |
| TLSH | `T1688176D53DADE11C0BC2D5E215F1E188D119563F01571E78F2DC86946FD43A583EEA88` |
| SSDEEP | `96:MVmPE5hIFDaOdNljSFF5vUxTPDgUbv5KINNpx/7:g4E5vOdNRSFFFArgqvpxT` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_9e36446c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e36446c383f361406c4734667b586052916a74fcbc754ff4347f6cd3f75e5bb"
    family = "unknown"
    file_name = "9e36446c383f3614.ps1"
    file_type = "ps1"
    first_seen = "2026-11-16 05:12:18"
  condition:
    hash.sha256(0, filesize) == "9e36446c383f361406c4734667b586052916a74fcbc754ff4347f6cd3f75e5bb"
}
```

### Sample 31: `202ab923caad6c68`

| Field | Value |
|---|---|
| SHA-256 | `202ab923caad6c68cfa1654a9d8bb0178d9868446f1a713a53ae932c0e0a24f0` |
| Family label | `Mirai` |
| File name | `sh4` |
| File type | `elf` |
| First seen | `2026-11-16 05:04:06` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1ffdc6a14c213844b1219b9b9fa86439` |
| SHA-1 | `ce1c2da57c9c50c010e9dfef6830d9fba2ed4003` |
| SHA-256 | `202ab923caad6c68cfa1654a9d8bb0178d9868446f1a713a53ae932c0e0a24f0` |
| SHA3-384 | `b53a8e3979e1d58e98b278a9a3041adf7952cfb887791be8789e906aa532ee43d5859d0be4b597931afce1503bcef919` |
| TLSH | `T178B36C73DC796F58D629D4B4B0B58F781B93A551828B2FAE1477C2748043C8DF60A3B8` |
| SSDEEP | `1536:i8a3sIvMZr2Ce2KDoRh7VeM3DsdPEYbBIMbWS2AxSd2tUBj:itMZr2rDIp3DsZ1BpbWPXduUBj` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_202ab923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202ab923caad6c68cfa1654a9d8bb0178d9868446f1a713a53ae932c0e0a24f0"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-16 05:04:06"
  condition:
    hash.sha256(0, filesize) == "202ab923caad6c68cfa1654a9d8bb0178d9868446f1a713a53ae932c0e0a24f0"
}
```

### Sample 32: `4e039b8335f759c2`

| Field | Value |
|---|---|
| SHA-256 | `4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-11-16 04:29:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `daf0b685662d9d62eb8481a52225ae9e` |
| SHA-1 | `47e8670fa8a3c85cb8c8d3c832c0ee8097488887` |
| SHA-256 | `4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934` |
| SHA3-384 | `512e768803eed3bc1098116aeac9b59a8733e1b929df1abd67b1a4598311848f5582023e9ae6be62315e64b083e7ae0f` |
| TLSH | `T115D30856F9819B11D5C151BAFE0E128E77131B7CE2DE72029D24AB307B8B8BF0E3A515` |
| TELFHASH | `t1abe0eb0fca381fecf3c00343821f811b4baa31ca1a0163878244378b4c328a3302b834` |
| SSDEEP | `3072:5y5UahIxQ4fDEPL2a0SbkWXzEACA4xoZ:5y5NhX4fwPyapFzEO4xoZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_4e039b83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-16 04:29:04"
  condition:
    hash.sha256(0, filesize) == "4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934"
}
```

### Sample 33: `9989b1edad0749e3`

| Field | Value |
|---|---|
| SHA-256 | `9989b1edad0749e3dcbce815276abc271e91d75f11d3ddb0bf20b935c009442f` |
| Family label | `unknown` |
| File name | `e` |
| File type | `sh` |
| First seen | `2026-11-16 04:08:05` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1eeb9c97bf3f2562a54e675fb74e2e51` |
| SHA-1 | `53960f8cf7e78c1a9611b74ae7be7754199ea35e` |
| SHA-256 | `9989b1edad0749e3dcbce815276abc271e91d75f11d3ddb0bf20b935c009442f` |
| SHA3-384 | `61d36aa479be7a67af2ebff2395e0162dfaefffc83e1ef6e3309cb6bdacdc9361112e92556e815b4e18d3613148f4875` |
| TLSH | `T16D3190DA66B27E746CA6ED23336F445835A0D0C751C66F06BCEC38F998CEE047042A93` |
| SSDEEP | `24:IPhiBW2zcsFtJTJBsUgQtc4kTc6qnKb/NIVkspWLbubv+xV:qQc2zc0JEUgB4kvqnOOJpWLb6WxV` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_9989b1ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9989b1edad0749e3dcbce815276abc271e91d75f11d3ddb0bf20b935c009442f"
    family = "unknown"
    file_name = "e"
    file_type = "sh"
    first_seen = "2026-11-16 04:08:05"
  condition:
    hash.sha256(0, filesize) == "9989b1edad0749e3dcbce815276abc271e91d75f11d3ddb0bf20b935c009442f"
}
```

### Sample 34: `2403bcc927beb7b3`

| Field | Value |
|---|---|
| SHA-256 | `2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-16 03:39:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d04ce0378c4bb4fd6f5aa78d9299074` |
| SHA-1 | `f92f477558d43c08f5b6d9aeb8dfe6b03a38feeb` |
| SHA-256 | `2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f` |
| SHA3-384 | `2443d9e871927b5e3d5c9ef4bcfa312331980b177f108c9992b6b5616fb11e05f1b7f0e7b410787faa556579e7354965` |
| TLSH | `T152556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSg:SDjxB4m5n8XlaPWi+d+a4TjxQP4a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_2403bcc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 03:39:04"
  condition:
    hash.sha256(0, filesize) == "2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f"
}
```

### Sample 35: `a5cd1aa138dc2c5c`

| Field | Value |
|---|---|
| SHA-256 | `a5cd1aa138dc2c5ccb71a1e76f74f76c9518d2fc096c06b05ea3c72df2e5defb` |
| Family label | `GuLoader` |
| File name | `Foldningsstningerne.vbs` |
| File type | `vbs` |
| First seen | `2026-11-16 03:24:19` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ac1791fc8faf059d164c8f87f71a6185` |
| SHA-1 | `e39ec4455810b10b989c3a2d16258c9751bf69f5` |
| SHA-256 | `a5cd1aa138dc2c5ccb71a1e76f74f76c9518d2fc096c06b05ea3c72df2e5defb` |
| SHA3-384 | `d208d26ca2ca7c3746c7cd349b11500d42ffb2acf8cf07350c27983e5ff1156fe7a8330a6dd47de7b9bbc9929a2a9811` |
| TLSH | `T1AD73183FA93C3735090B32BDEF43E871C5BE41B5021253A36DC422995F3635AAEB8196` |
| SSDEEP | `1536:BE6jGYICCqlPhNH4H6PS58FEIw+E0yiZvCPgd4R/e4oIUlZp:BECGtJqlPhNYH6PS58FEIRZ9CPvGI2` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_035_a5cd1aa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5cd1aa138dc2c5ccb71a1e76f74f76c9518d2fc096c06b05ea3c72df2e5defb"
    family = "GuLoader"
    file_name = "Foldningsstningerne.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 03:24:19"
  condition:
    hash.sha256(0, filesize) == "a5cd1aa138dc2c5ccb71a1e76f74f76c9518d2fc096c06b05ea3c72df2e5defb"
}
```

### Sample 36: `34d80d781c26ab65`

| Field | Value |
|---|---|
| SHA-256 | `34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27` |
| Family label | `WARDENStealer` |
| File name | `34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27.exe` |
| File type | `exe` |
| First seen | `2026-11-16 03:21:29` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `303290c2aa61f554ecee564826ef52c7` |
| SHA-1 | `0f2aaffcf9e1aa28d14f9de76e4e65e5717fbd9f` |
| SHA-256 | `34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27` |
| SHA3-384 | `053f76e208febb311128d15121c905fdc3381b8fbd1b13854f7f68f4c88f60983d78b03446d7ef66643cfbc71b56ade6` |
| IMPHASH | `c9fc6842a9ffa78b3264669c6970a158` |
| TLSH | `T13DE40182F7A150E9C12BC67846161612FAB17C540B2096FF67D9A77A0F63AE18F3DF10` |
| SSDEEP | `12288:wO/Gy5aCXUar+L2N5jToJ0QepLVpTgTKq1J181Bt5ffQQLw5Zjx24gL8:wO3aLoVTAULngFJ181BTfQQLQZtpz` |
| ICON-DHASH | `1048b27171b24810` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_036_34d80d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27"
    family = "WARDENStealer"
    file_name = "34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27.exe"
    file_type = "exe"
    first_seen = "2026-11-16 03:21:29"
  condition:
    hash.sha256(0, filesize) == "34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27"
}
```

### Sample 37: `8207cfeb69013150`

| Field | Value |
|---|---|
| SHA-256 | `8207cfeb69013150389c476f5ea0c0e9c996aaed7089e3699c7a23d48b161fb9` |
| Family label | `GuLoader` |
| File name | `PO Revised.vbs` |
| File type | `vbs` |
| First seen | `2026-11-16 02:44:59` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9d2cf6b670f5200402b559fbb4b97ae8` |
| SHA-1 | `6364d1cf771c51d48f8017eb1131631de346ce4a` |
| SHA-256 | `8207cfeb69013150389c476f5ea0c0e9c996aaed7089e3699c7a23d48b161fb9` |
| SHA3-384 | `d75a5aa167b482a759ebc6b2d00b0a60b292b7ea9ae89ce00326c888240e9cb989f499bdf48d8411f6f540e86b97ce8b` |
| TLSH | `T141834C1A9B1223238EC711F496F14878C5D8D11D293DAA637D6E1B0F522796CF3BAD0E` |
| SSDEEP | `1536:odbV92srlr3U4h8dWM4ifItoMBJr8VVbjGH:olCs5R8dWJ9/BeV5GH` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_037_8207cfeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8207cfeb69013150389c476f5ea0c0e9c996aaed7089e3699c7a23d48b161fb9"
    family = "GuLoader"
    file_name = "PO Revised.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 02:44:59"
  condition:
    hash.sha256(0, filesize) == "8207cfeb69013150389c476f5ea0c0e9c996aaed7089e3699c7a23d48b161fb9"
}
```

### Sample 38: `7c47f9d4b9496f75`

| Field | Value |
|---|---|
| SHA-256 | `7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3` |
| Family label | `WannaCry` |
| File name | `7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3` |
| File type | `exe` |
| First seen | `2026-11-16 02:15:26` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b2c7385fdef634c89a6531a7450f3711` |
| SHA-1 | `7a79726f7ec9d1f77f04238b46c08f1193987e02` |
| SHA-256 | `7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3` |
| SHA3-384 | `4863dc587879d961f05938b70318992fdb60ab5211054c69e282dbc9addf197b94b66aa820be8fb39008c7e49a51a018` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1CF36239932BC91FCD106197884B78D16F3B37C5A12FD5B0F8B404A6A1E53B96FB60B42` |
| SSDEEP | `49152:jnsnsQqMSPbcBVQejSINRq+TSqTdX1HkQo6SAARdhnv:DM/qPoBhuaRqcSUDk36SAEdhv` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_038_7c47f9d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3"
    family = "WannaCry"
    file_name = "7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3"
    file_type = "exe"
    first_seen = "2026-11-16 02:15:26"
  condition:
    hash.sha256(0, filesize) == "7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3"
}
```

### Sample 39: `742aa247d5a8a476`

| Field | Value |
|---|---|
| SHA-256 | `742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12` |
| Family label | `WannaCry` |
| File name | `742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12` |
| File type | `exe` |
| First seen | `2026-11-16 02:15:19` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `439cd9a053509a47c340df134f88b0a2` |
| SHA-1 | `c5c01876e0f49233c3979d7371d61f55b095ffa3` |
| SHA-256 | `742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12` |
| SHA3-384 | `c5deb60d6c1bdb763f6a190aab218a4d9cac6114c4e08efb3ee14de5f62463bbf0dcda77f128c767233aa991819b7804` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T13A36125863F86224F3775EB53EF64D265B72F8A3A9118A4D0160834A0C33F65DF52B2E` |
| SSDEEP | `98304:DXDqPoBhz1aR236SAEdhvxWa9P593R8yAVp2:DXDqPe1C23ZAEUadzR8yc4` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_039_742aa247
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12"
    family = "WannaCry"
    file_name = "742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12"
    file_type = "exe"
    first_seen = "2026-11-16 02:15:19"
  condition:
    hash.sha256(0, filesize) == "742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12"
}
```

### Sample 40: `3978407c1e5dbc2e`

| Field | Value |
|---|---|
| SHA-256 | `3978407c1e5dbc2e437207665c95a31e8bd3ae934d15cab4d4f6c2d1161f6740` |
| Family label | `GuLoader` |
| File name | `Selvbefrugtningen.vbs` |
| File type | `vbs` |
| First seen | `2026-11-16 01:43:04` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6f5a688d3daedbe61d8c83036b59bc53` |
| SHA-1 | `bb7b6e82a86c498cdb1090b9c07a53ccf8e6728f` |
| SHA-256 | `3978407c1e5dbc2e437207665c95a31e8bd3ae934d15cab4d4f6c2d1161f6740` |
| SHA3-384 | `595897c2446a2c7c9a1df849bcc5d425126ba296b1841195acd11681096e6838b87b60d16e8d666dd7ccb09b90db190d` |
| TLSH | `T15373C135ABFF0F17CA7B33A9EC44DAD1CD688105C2161077AD846A58600E2D8E7BDE5B` |
| SSDEEP | `1536:6ZJLcEV3J3CFeK4tykVyrL1nSyZhWGS4VAGLrYbw:6Hw0JCMfYkVyrFDJVBgw` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_040_3978407c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3978407c1e5dbc2e437207665c95a31e8bd3ae934d15cab4d4f6c2d1161f6740"
    family = "GuLoader"
    file_name = "Selvbefrugtningen.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 01:43:04"
  condition:
    hash.sha256(0, filesize) == "3978407c1e5dbc2e437207665c95a31e8bd3ae934d15cab4d4f6c2d1161f6740"
}
```

### Sample 41: `0c9218fbb35de0a5`

| Field | Value |
|---|---|
| SHA-256 | `0c9218fbb35de0a5048b9d57a397f8c5437876017b1667dbb2560a01c366be4b` |
| Family label | `GuLoader` |
| File name | `Macrozoogonidium.vbs` |
| File type | `vbs` |
| First seen | `2026-11-16 01:33:25` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b8ac02eabe6a4e1b378219954255c843` |
| SHA-1 | `698cfb5113137970963f87b8ecb9931c11d770ee` |
| SHA-256 | `0c9218fbb35de0a5048b9d57a397f8c5437876017b1667dbb2560a01c366be4b` |
| SHA3-384 | `c24780cad77feac4a911a6bfd454bebf118fd079e0ab9ee85e8f028e46acd79440ae836c2c3258325c20dc9b63f1d6d7` |
| TLSH | `T15B738E37FB741D7D8E4B37BDA885B897C6B84126C1121075AD88E2CD50862DCE6E933B` |
| SSDEEP | `768:Mfds/kX27lZ/69Ot3MnnJTYtS54saOSvXkRuCd89GYh1tw7Ui+dsfquFe/3s5+yv:MVGPlhH8nJTfxqvMMGWiLJs3sDAa5/W2` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_041_0c9218fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c9218fbb35de0a5048b9d57a397f8c5437876017b1667dbb2560a01c366be4b"
    family = "GuLoader"
    file_name = "Macrozoogonidium.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 01:33:25"
  condition:
    hash.sha256(0, filesize) == "0c9218fbb35de0a5048b9d57a397f8c5437876017b1667dbb2560a01c366be4b"
}
```

### Sample 42: `d2c8b634fba9b551`

| Field | Value |
|---|---|
| SHA-256 | `d2c8b634fba9b551ac802ed158a23c58a08f5b1d74af20afc20eb71c48ed465d` |
| Family label | `unknown` |
| File name | `d2c8b634fba9b551.js` |
| File type | `js` |
| First seen | `2026-11-16 01:02:33` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b7d77bbc78d838287dfe0ca53717e816` |
| SHA-1 | `71e05741b699dc47760a94a773a5d3dbcfd7287c` |
| SHA-256 | `d2c8b634fba9b551ac802ed158a23c58a08f5b1d74af20afc20eb71c48ed465d` |
| SHA3-384 | `d355c39aed6645093d26f349a53d3e427a016e645b9470e1dd68db328d93d41015924b895b7ba06958b2573db7ce1ad0` |
| TLSH | `T1C383F8DF77CA702247AB30B9006F550BF276199D684D4400F159D8E9BCB8A4A827BF7E` |
| SSDEEP | `1536:iRUX9uDgwxcy2KVBNwchN6SLaHEk2BSrBESp+a/IEk4aAocVi8SMBQ47GKO:aHNwcv9VBQpLl88SMBQ47GKO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_d2c8b634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c8b634fba9b551ac802ed158a23c58a08f5b1d74af20afc20eb71c48ed465d"
    family = "unknown"
    file_name = "d2c8b634fba9b551.js"
    file_type = "js"
    first_seen = "2026-11-16 01:02:33"
  condition:
    hash.sha256(0, filesize) == "d2c8b634fba9b551ac802ed158a23c58a08f5b1d74af20afc20eb71c48ed465d"
}
```

### Sample 43: `2198115682867995`

| Field | Value |
|---|---|
| SHA-256 | `21981156828679957bf94133162863398eb5dab72641181921aad955c8e1d28a` |
| Family label | `unknown` |
| File name | `2198115682867995.js` |
| File type | `js` |
| First seen | `2026-11-16 01:02:22` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4be27ae178baf6ee26c0dd61c89c9895` |
| SHA-1 | `52c31a420d0963755c8400e970552d87c8846433` |
| SHA-256 | `21981156828679957bf94133162863398eb5dab72641181921aad955c8e1d28a` |
| SHA3-384 | `b2cbe547f25edd0f0e1f1570449b5348cf73e6fd968ef0cfe6c46af988f87b1a6537fe94717d8de78513c998f6034d0c` |
| TLSH | `T181F2825A30FB203B0273217E0FAB522E3331A0137549D959BE5D9748AFD1669D1F2BE8` |
| SSDEEP | `384:2H6cctVV3M4SjbporeLv1pWHLhC6h6d0M4nnpyHxdtx:2HQvsporeLv1pWHLhC6h6kpyXj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_21981156
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21981156828679957bf94133162863398eb5dab72641181921aad955c8e1d28a"
    family = "unknown"
    file_name = "2198115682867995.js"
    file_type = "js"
    first_seen = "2026-11-16 01:02:22"
  condition:
    hash.sha256(0, filesize) == "21981156828679957bf94133162863398eb5dab72641181921aad955c8e1d28a"
}
```

### Sample 44: `f6854d35569d9112`

| Field | Value |
|---|---|
| SHA-256 | `f6854d35569d9112f5e02c5a4be16711d7bf942e957301b35a02779d6bacf9dc` |
| Family label | `unknown` |
| File name | `f6854d35569d9112.js` |
| File type | `js` |
| First seen | `2026-11-16 00:57:32` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28413a74338d731025026dd241b7c220` |
| SHA-1 | `c38c92558edc6728bcdd06f0356099086890d041` |
| SHA-256 | `f6854d35569d9112f5e02c5a4be16711d7bf942e957301b35a02779d6bacf9dc` |
| SHA3-384 | `a8db24c1748a49fb8ab42f1833d2d89e4dffeb6dbade58234b92c0c46d5cb3229f303d53cb6f4072d6bcf1901a840d1f` |
| TLSH | `T14CF2825A30FB203B0273217E0FAB522E3331A0137549D959BE5D9748AFD1669D1F2BE8` |
| SSDEEP | `384:MH6cctVV3M4SjbporeLv1pWHLhC6h6d0M4nnpyHxdtx:MHQvsporeLv1pWHLhC6h6kpyXj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_044_f6854d35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6854d35569d9112f5e02c5a4be16711d7bf942e957301b35a02779d6bacf9dc"
    family = "unknown"
    file_name = "f6854d35569d9112.js"
    file_type = "js"
    first_seen = "2026-11-16 00:57:32"
  condition:
    hash.sha256(0, filesize) == "f6854d35569d9112f5e02c5a4be16711d7bf942e957301b35a02779d6bacf9dc"
}
```

### Sample 45: `66f861a8217cf2a4`

| Field | Value |
|---|---|
| SHA-256 | `66f861a8217cf2a4b5e8d3f620eb02a8b01440db5d63c06c05c4b44b698414a5` |
| Family label | `unknown` |
| File name | `66f861a8217cf2a4.js` |
| File type | `js` |
| First seen | `2026-11-16 00:57:21` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `020bf611061b9b2086295d81a953ac87` |
| SHA-1 | `bed25058108235223dfacd4266289bf6c9b8a635` |
| SHA-256 | `66f861a8217cf2a4b5e8d3f620eb02a8b01440db5d63c06c05c4b44b698414a5` |
| SHA3-384 | `c46a7f15c1d71d069bf4a087bcd6d4231c251eb94314ac06056adbf110a527126b3afb05b661e257708de13b2f391f51` |
| TLSH | `T1C0F2825A30FB203B0273217E0FAB522E3331A0137549D959BE5D9748AFD1669D1F2BE8` |
| SSDEEP | `384:AH6cctVV3M4SjbporeLv1pWHLhC6h6d0M4nnpyHxdtx:AHQvsporeLv1pWHLhC6h6kpyXj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_66f861a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66f861a8217cf2a4b5e8d3f620eb02a8b01440db5d63c06c05c4b44b698414a5"
    family = "unknown"
    file_name = "66f861a8217cf2a4.js"
    file_type = "js"
    first_seen = "2026-11-16 00:57:21"
  condition:
    hash.sha256(0, filesize) == "66f861a8217cf2a4b5e8d3f620eb02a8b01440db5d63c06c05c4b44b698414a5"
}
```

### Sample 46: `74d98120c968be2d`

| Field | Value |
|---|---|
| SHA-256 | `74d98120c968be2d9d346ea501eb62a75d5694ba3de610dbfcc5214227abbe9a` |
| Family label | `GuLoader` |
| File name | `Cyanocitta.vbs` |
| File type | `vbs` |
| First seen | `2026-11-16 00:45:10` |
| Reporter | `threatcat_ch` |
| Tags | `GuLoader, vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b832b359b8da8dfb55539529d9abebc3` |
| SHA-1 | `0414ad155c223747a5dc7bccc3e7f0a24adf7a13` |
| SHA-256 | `74d98120c968be2d9d346ea501eb62a75d5694ba3de610dbfcc5214227abbe9a` |
| SHA3-384 | `ce06b1ca24773e4283f79cfafb2689e68e5f6e2430fed9e82cc6c068f2b38f28d84b89a6a77f1634edfade29fc2673b6` |
| TLSH | `T17C73C41599E6312FBDCA3394A488C85085E84165091630B06DFF6B1F6B27DBCF3AFD1A` |
| SSDEEP | `1536:jVO2SIfhxHlIuSLOJxUjNW8WdrU1DL2EcO:jw4fnhSLwCDWS6ED` |

#### Technical Assessment

- The sample is tracked as `GuLoader` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_GuLoader_046_74d98120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74d98120c968be2d9d346ea501eb62a75d5694ba3de610dbfcc5214227abbe9a"
    family = "GuLoader"
    file_name = "Cyanocitta.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 00:45:10"
  condition:
    hash.sha256(0, filesize) == "74d98120c968be2d9d346ea501eb62a75d5694ba3de610dbfcc5214227abbe9a"
}
```

### Sample 47: `6204b27f17dd7735`

| Field | Value |
|---|---|
| SHA-256 | `6204b27f17dd77358341cb3190c6abec6357daab1af105df8257f149c3d67c79` |
| Family label | `SalatStealer` |
| File name | `62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:39:19` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `386495b51b730d7d7dbeb9624653fdd2` |
| SHA-1 | `8af42abdea9822c0a5db036f5e005e708253628f` |
| SHA-256 | `6204b27f17dd77358341cb3190c6abec6357daab1af105df8257f149c3d67c79` |
| SHA3-384 | `a6a9f35d4b82aa8b37588a0310659b0556508cdd1ce2762dd4ffebdfaa1d65ae9506f41d3384467d101b8e5da4b8726b` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1D1C63941FE9B54F5E9035831616BF23F23305D008B24CBEBEB443A6BF87B695197A219` |
| SSDEEP | `98304:RJtPDpGNPl8J3ViajGF4WH830oP1Xdv8mV4k9KYcQ1rgB3hrEH:dDLQajGFgPP1eS/9KYcQpgB3h4H` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_047_6204b27f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6204b27f17dd77358341cb3190c6abec6357daab1af105df8257f149c3d67c79"
    family = "SalatStealer"
    file_name = "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:39:19"
  condition:
    hash.sha256(0, filesize) == "6204b27f17dd77358341cb3190c6abec6357daab1af105df8257f149c3d67c79"
}
```

### Sample 48: `62c9f98edf33cfb6`

| Field | Value |
|---|---|
| SHA-256 | `62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d` |
| Family label | `SalatStealer` |
| File name | `62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:38:38` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0e3d36bedd65ec99a91084fbcba46851` |
| SHA-1 | `4e5292f811b84a3c9574720fc44784f1cbe53129` |
| SHA-256 | `62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d` |
| SHA3-384 | `d4e0825e8b19aab968edc52671c35cdf2c92726b332945a3077d84c3e383c06a10755fb4e04f621ea704c1579ac46eb3` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1F9F5331F46BB8853E7794AFE2BE66EC11AC54EFF4C8256140DA01D70DD82EAC8C4D47A` |
| SSDEEP | `49152:ht2yQwGXnQvjFwE71pTRCrYFLjWMnU5haQEdquGyeCuLLUUw+L5ul90gGvY6LKY6:dUUhlPRwm76tWqCClcknvY6` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_048_62c9f98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d"
    family = "SalatStealer"
    file_name = "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:38:38"
  condition:
    hash.sha256(0, filesize) == "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d"
}
```

### Sample 49: `5d91e967b6dc6ff6`

| Field | Value |
|---|---|
| SHA-256 | `5d91e967b6dc6ff678ff83a10bda5b04b87f34f9d886bf1138f593e411bcef99` |
| Family label | `SalatStealer` |
| File name | `7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:32:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `234426939296e6caf3ca7eecbb5c4f25` |
| SHA-1 | `7053c59b5dae85795774d660f3d35a9721ad14d3` |
| SHA-256 | `5d91e967b6dc6ff678ff83a10bda5b04b87f34f9d886bf1138f593e411bcef99` |
| SHA3-384 | `a3db414fc5b9792bd7875ab829a17b1b4e8387244d4fdea5560143f0f50b9637f05e7ad05b6e22a9777531036a35769c` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1C4C64A41FE8B54F5F9031831616BF23F63305D048B25CBEBEB443A6BF87B695192A219` |
| SSDEEP | `98304:UGRerdtv7ZMYrdVAEaqt1fTnmh5N6EGsAqo4k9KYcQ1rgB3haEJ:CrT0xqjk5NhAX/9KYcQpgB3hHJ` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_049_5d91e967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d91e967b6dc6ff678ff83a10bda5b04b87f34f9d886bf1138f593e411bcef99"
    family = "SalatStealer"
    file_name = "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:32:16"
  condition:
    hash.sha256(0, filesize) == "5d91e967b6dc6ff678ff83a10bda5b04b87f34f9d886bf1138f593e411bcef99"
}
```

### Sample 50: `7be9b26d9f166944`

| Field | Value |
|---|---|
| SHA-256 | `7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b` |
| Family label | `SalatStealer` |
| File name | `7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:31:45` |
| Reporter | `Tuxxin` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `30c6ad5aa4d6730d9a506c9cbc49cb7d` |
| SHA-1 | `181bafd4f6c6fc29af5f081a2a36f464793937b6` |
| SHA-256 | `7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b` |
| SHA3-384 | `c5abb22dd7ba9bc799f700b44b54a8b13de4f7e71d4c1a8220c885fa3a68d9871125802ee23378e2b5ec4bcbeefa7665` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T17DF533A40300AB3FD2E020B65E7138905A995C74BCBA662EFA352617CCF3D779E5D385` |
| SSDEEP | `49152:KboBgGfkYMMhz4vb9Hi4AAJXDTrhqv1RYw4b+DheaTu9y+dsZyg/kr9/YpTcYkqU:PBxMMhzW9HGA1rPUU9BdsZygMVgTc3v` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_050_7be9b26d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b"
    family = "SalatStealer"
    file_name = "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:31:45"
  condition:
    hash.sha256(0, filesize) == "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b"
}
```

### Sample 51: `f6225d34167de297`

| Field | Value |
|---|---|
| SHA-256 | `f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6` |
| Family label | `unknown` |
| File name | `f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:31:34` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64055ee50bf1bd9ca84b1ce7f8ac3a74` |
| SHA-1 | `cbba6ee7aa8d665346795ca2af57053829767b69` |
| SHA-256 | `f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6` |
| SHA3-384 | `0f55ea251a68f92c70ff20f2ee3af646df04f716a8351a86c88864b58ae227aa86d99af104af2fbc207614808c6d7934` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1B6B2E70537F88116F2FF1B7C69B202210776BC569924DBDE1E85509E0DB6B80C9A1BB7` |
| SSDEEP | `384:cE7HF8zUezvvMe9pCv26XI10dSs1xzvpIeJqaMQN8L4Mlr8mNPM:cE7HqdzvEe9pGJ/SGO/QN8L4MumO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_f6225d34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6"
    family = "unknown"
    file_name = "f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:31:34"
  condition:
    hash.sha256(0, filesize) == "f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6"
}
```

### Sample 52: `215bd89fa1c2a6c4`

| Field | Value |
|---|---|
| SHA-256 | `215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f` |
| Family label | `WARDENStealer` |
| File name | `215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:27:36` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8686c5f7499630435faaa3266c72cca4` |
| SHA-1 | `dcb28bd67be1256d76d796f142d9ead4e3b3b6b2` |
| SHA-256 | `215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f` |
| SHA3-384 | `82b486265ad3f99e58a4c64187a281236b140012abd705ebb1f4b2225f1c0df8885b291d1f34a773cc14b9d81c76da4a` |
| IMPHASH | `cb7c4252c5f0d06c50931ad1da297916` |
| TLSH | `T179F4F142FA8153F8D42BC67847264512E6B1BC550B709AFF27A01B6B1E36AE0CF3E754` |
| SSDEEP | `12288:ayk21g7IctycbHHlv6f71eDRN/X05X1pbL+CpJohwxmJ+gjEl5Ynou:aX6g7IctLiz8N+lpfJoY5gcY` |
| ICON-DHASH | `106c9a72729a6410` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_052_215bd89f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f"
    family = "WARDENStealer"
    file_name = "215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:27:36"
  condition:
    hash.sha256(0, filesize) == "215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f"
}
```

### Sample 53: `fc535f9ad0af6b02`

| Field | Value |
|---|---|
| SHA-256 | `fc535f9ad0af6b02b9e0a9448fc699493f76c7fce539275cda17183f17c669bb` |
| Family label | `unknown` |
| File name | `fc535f9ad0af6b02.js` |
| File type | `js` |
| First seen | `2026-11-16 00:27:18` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f14e9905fc0700dd4932b263e3641983` |
| SHA-1 | `c3a216ed45566156492b479726fd6d4ab364870e` |
| SHA-256 | `fc535f9ad0af6b02b9e0a9448fc699493f76c7fce539275cda17183f17c669bb` |
| SHA3-384 | `ba8cb14b8819fde53d09fe0adda62493abb650c930ec2bbe3e58f248a91f277f1081743dbed726ac2d3093f2843e50ff` |
| TLSH | `T1A9830ADD72C6B06247AB71BA407F550BF236189D684D8410F129E8E9BC74A4E823BF7D` |
| SSDEEP | `1536:jLiBdiaWLOczCmZx6+VWuGzQNOzdn6x2RZd9SEnk9HB96c9Yo/NWLbVj3kC6tk:5kn6x2xe9NK6nC6q` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_053_fc535f9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc535f9ad0af6b02b9e0a9448fc699493f76c7fce539275cda17183f17c669bb"
    family = "unknown"
    file_name = "fc535f9ad0af6b02.js"
    file_type = "js"
    first_seen = "2026-11-16 00:27:18"
  condition:
    hash.sha256(0, filesize) == "fc535f9ad0af6b02b9e0a9448fc699493f76c7fce539275cda17183f17c669bb"
}
```

### Sample 54: `de0b3ca680c665b3`

| Field | Value |
|---|---|
| SHA-256 | `de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa` |
| Family label | `unknown` |
| File name | `de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:23:35` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a5daa665bb712f2f85231317374901a0` |
| SHA-1 | `8057a55b5f9500cc7f4e64d422611d1b51906280` |
| SHA-256 | `de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa` |
| SHA3-384 | `2b730be8b14032b074ef9097e97b13ca1062c02c8092f93714c39bb6cc437a951f224e1cf34d187e435250e86a0c4f34` |
| TLSH | `T11C3533A432A5E1B3C5D336BCA760DD85897DA32B75E1EF0D09E010A4BC3A7D41E6A307` |
| SSDEEP | `12288:Yl/+7qVafyc3IIaWz2W/lD1OnDH/tcN0UZFisyrsUAdrpm+kWUto9IRemi0qd8hT:2MI3+mDHF6sLIUsrLYm0PtFusyFQIx` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_de0b3ca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa"
    family = "unknown"
    file_name = "de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:23:35"
  condition:
    hash.sha256(0, filesize) == "de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa"
}
```

### Sample 55: `41269193f2807fc7`

| Field | Value |
|---|---|
| SHA-256 | `41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5` |
| Family label | `unknown` |
| File name | `41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:14:38` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cc1068725a328027189c4dd6448eb579` |
| SHA-1 | `e3392139ea2a490d8a4a428c65b08904867665de` |
| SHA-256 | `41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5` |
| SHA3-384 | `98cb20659d564f91999e63a53f2c1b314668b7c040220e8ac610afe9800f74be91103bcea5d493b386507b47aade4741` |
| TLSH | `T1F6E13482B9D6CE3BCCA9627A1673C6203372C551AB435B17210C48753D83AAC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsHLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvag/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_055_41269193
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5"
    family = "unknown"
    file_name = "41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:14:38"
  condition:
    hash.sha256(0, filesize) == "41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5"
}
```

### Sample 56: `98b3cfaf8f37bae7`

| Field | Value |
|---|---|
| SHA-256 | `98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5` |
| Family label | `WARDENStealer` |
| File name | `98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:14:31` |
| Reporter | `Tuxxin` |
| Tags | `exe, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `47e74b103ba3055ef19b75ae7469f92c` |
| SHA-1 | `eb9657b25a15e2f5d919613dbc500997d5bca2e6` |
| SHA-256 | `98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5` |
| SHA3-384 | `3d25efe10a3c5e8fa1a85599d2bb0d88b2b319a4686eda1355568c61882540f45da13bb879787786d699fa68460b3efb` |
| IMPHASH | `1ae01f4e15c8017d4ece967caddc38c2` |
| TLSH | `T138E4F042FAD507FCD427C13A46961626EAB1BC454B619AFF13A4172F1F22AD08F3EB14` |
| SSDEEP | `12288:hXZW2FFj3gcxbWX/OQZskL+UtQVFUta5pr1uPVq6P0hkXzrcbkHkqRFqhQ:5ZW2zwm0sOQ7Uta5prwd7PkEwbkHkqRo` |
| ICON-DHASH | `0cb27969b9093000` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_056_98b3cfaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5"
    family = "WARDENStealer"
    file_name = "98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:14:31"
  condition:
    hash.sha256(0, filesize) == "98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5"
}
```

### Sample 57: `0112160ffe71e1c8`

| Field | Value |
|---|---|
| SHA-256 | `0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc` |
| Family label | `unknown` |
| File name | `0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:14:25` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `851b211c6ccae47f52fcf6913749d32c` |
| SHA-1 | `2bc6da1e79fd6778239ecd02751997b7ce7b1d62` |
| SHA-256 | `0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc` |
| SHA3-384 | `cbb37d159d92b07ae32b7ddf341008745502af9eba2684364491aa4e704c5e0455e9ee9c4b643d04faa7a7ec6cd0ea2e` |
| TLSH | `T1D0E12382BDD6CE3BCCA9627A1673C6203372C551AB439B17210C48753D83AEC6D76B95` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScsaLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSvfg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_057_0112160f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc"
    family = "unknown"
    file_name = "0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:14:25"
  condition:
    hash.sha256(0, filesize) == "0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc"
}
```

### Sample 58: `8e132450a9152669`

| Field | Value |
|---|---|
| SHA-256 | `8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f` |
| Family label | `unknown` |
| File name | `8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:13:31` |
| Reporter | `Tuxxin` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e31f6dbdec7aff1e1601619143423401` |
| SHA-1 | `82302172485e013ee7ed99e8b9497354f0250a60` |
| SHA-256 | `8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f` |
| SHA3-384 | `cb2e0cd49ffff15d3343a459bf847182324748066899330a9b2badc4cdfe34e0979d70b4a41a93390423f6c3b99bcbd6` |
| TLSH | `T1BEE14482BDD6CE3BCCA9627A1673C6203372C951AB439B17210C48753D83AEC6D76BD5` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:8xJFWLccScs0GLmg/vdpklpqxMYc3O9Ff721a5BI31HBgVcgOu8+TiImDW:tccSv0bg/F+QGO9FfN+1H6VcggDW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_058_8e132450
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f"
    family = "unknown"
    file_name = "8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:13:31"
  condition:
    hash.sha256(0, filesize) == "8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f"
}
```

### Sample 59: `d04d3959f49981e0`

| Field | Value |
|---|---|
| SHA-256 | `d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e` |
| Family label | `unknown` |
| File name | `d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e.bin` |
| File type | `macho` |
| First seen | `2026-11-16 00:13:26` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fdba5a974dbf9220b9e7417cf44978a8` |
| SHA-1 | `0876097e7b0b49dfbb92e11d9b9cd3a2fe62222b` |
| SHA-256 | `d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e` |
| SHA3-384 | `4ab865fb7f30e92976b9d07a256358a8a5316fe83e2ca4410cf63734ed7a91e4a36383bede0a3223973a09ca15b80bcf` |
| TLSH | `T118F25F139B1C0A61C05C633C92BB1B026276F5D086C56B674B10C72CAFCA3C5BDB5D87` |
| SSDEEP | `48:MGLMqlGI9IKU2yqm3DaORJncf4gmJBkeDxPMRBPlxkllLRgowjWaXLRgoz0MLAau:MGL7IKo4Gxcf/mJfklilltg1jJtgSNu` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_059_d04d3959
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e"
    family = "unknown"
    file_name = "d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e.bin"
    file_type = "macho"
    first_seen = "2026-11-16 00:13:26"
  condition:
    hash.sha256(0, filesize) == "d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e"
}
```

### Sample 60: `0d0a8119baab1ace`

| Field | Value |
|---|---|
| SHA-256 | `0d0a8119baab1ace1a56f8ce2270c0c0b06aaeff72aa9fb9331fa0568dc13c69` |
| Family label | `unknown` |
| File name | `0d0a8119baab1ace.js` |
| File type | `js` |
| First seen | `2026-11-16 00:12:21` |
| Reporter | `Tuxxin` |
| Tags | `js` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f18cf03335964889dadde7218027ff10` |
| SHA-1 | `9cd0604cb7fc9b8ec160a4d55c55ed5b3a8dfad9` |
| SHA-256 | `0d0a8119baab1ace1a56f8ce2270c0c0b06aaeff72aa9fb9331fa0568dc13c69` |
| SHA3-384 | `af61e65923784e80716bceafa35cfad9f8f5da3bf436b6c733cd9c6b14b2b94c40c2453986cb2ec4386711f5fa1742cc` |
| TLSH | `T11FE31D8ABAE721319227F03D8F6FD809B136544F1E99FE00794C82655F1893C97B6F98` |
| SSDEEP | `3072:L4lYNoJVDbRuo2rqKBzpL4CztThLQ7m+Z9A:Uyo/DbUrqKBzpL4IThLQi+Z9A` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `js`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_060_0d0a8119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0a8119baab1ace1a56f8ce2270c0c0b06aaeff72aa9fb9331fa0568dc13c69"
    family = "unknown"
    file_name = "0d0a8119baab1ace.js"
    file_type = "js"
    first_seen = "2026-11-16 00:12:21"
  condition:
    hash.sha256(0, filesize) == "0d0a8119baab1ace1a56f8ce2270c0c0b06aaeff72aa9fb9331fa0568dc13c69"
}
```

### Sample 61: `3439d85429affb37`

| Field | Value |
|---|---|
| SHA-256 | `3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4` |
| Family label | `Mirai` |
| File name | `3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:12:03` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8665cd0ac5f7efd3c4dc1606ec9fb4be` |
| SHA-1 | `b27dbdda5e6c9c7c8f95347ba5235ba32a0d9f3d` |
| SHA-256 | `3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4` |
| SHA3-384 | `d5f40f67883854297ec2d51fbdbf70794249ac54d9ac96562e81e54c5bba87300e62bd7b94029815bc58b7e9fb198257` |
| TLSH | `T157125147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5AlTTej6TNJ9VxNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTcTTfTpV5dfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_3439d854
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4"
    family = "Mirai"
    file_name = "3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:12:03"
  condition:
    hash.sha256(0, filesize) == "3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4"
}
```

### Sample 62: `35d2a8f92ffde391`

| Field | Value |
|---|---|
| SHA-256 | `35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d` |
| Family label | `Snowlight` |
| File name | `35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:11:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e254112552ba7dfd6d4860e27950b85f` |
| SHA-1 | `79d2854c75ab9e7137bb77b68d16230c31cfc7c2` |
| SHA-256 | `35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d` |
| SHA3-384 | `c28d9bea8008baeeafba46afe13d7b34d775021fba64d40fe675059acdcdcfac41a90674e74865b3975dde1b2386fcd1` |
| TLSH | `T19A124047A2D0CE3FC8D953384467122472B394BEDF629713064915B53F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6KH5ML09V1J9G8YmAM+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHNZMWT1YmshrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_062_35d2a8f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d"
    family = "Snowlight"
    file_name = "35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:11:57"
  condition:
    hash.sha256(0, filesize) == "35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d"
}
```

### Sample 63: `8207337a41518f7d`

| Field | Value |
|---|---|
| SHA-256 | `8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b` |
| Family label | `unknown` |
| File name | `8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b.bin` |
| File type | `macho` |
| First seen | `2026-11-16 00:11:53` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53a9077ce41ae77264d4f31230820729` |
| SHA-1 | `9201cb475a6393ee943d6b2fdc50e06768515e78` |
| SHA-256 | `8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b` |
| SHA3-384 | `79035107550724b04ae908b097f78458c9eb413022c862027832b1f217c4f3d87f3d27cbe9edef3bca0e7d837aca9ee4` |
| TLSH | `T197E24E43675C5929D05D83BA22FB1B976609F8A009D45B432F50DA282FE23C47CB0FDB` |
| SSDEEP | `96:xcIZEN+5DbDP67li97WsCFwYjqclS06W1YbqclSl:GI2N+5DbDy3wYjqcll6W+qclW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_063_8207337a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b"
    family = "unknown"
    file_name = "8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b.bin"
    file_type = "macho"
    first_seen = "2026-11-16 00:11:53"
  condition:
    hash.sha256(0, filesize) == "8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b"
}
```

### Sample 64: `6cfe047998db4236`

| Field | Value |
|---|---|
| SHA-256 | `6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c` |
| Family label | `unknown` |
| File name | `6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:09:32` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c350de5702352af2e71300e4ab846c8b` |
| SHA-1 | `4f39d9d3c25be3358e6ef4c8f011e708e78fefe9` |
| SHA-256 | `6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c` |
| SHA3-384 | `2fab00494d464c6a874fb80fa94c44e74119275405aece5856210c87ecfd29004d9da54871f426dbee32525fbae6863a` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T16C14E04477F88123E6FE2BB5787602404A77781A9975DB5E1A9E01CC2EB3B10CA61F73` |
| SSDEEP | `3072:Txc43a7N48lFetcVI+5GL9z89CcjsQi+BwuBuZlzXZRDxR8nirzfVl8O1rETAiP4:Txc4Ki8lYtcVI+Cdi9sx+B/BuZlzXZRA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_064_6cfe0479
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c"
    family = "unknown"
    file_name = "6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:09:32"
  condition:
    hash.sha256(0, filesize) == "6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c"
}
```

### Sample 65: `94b10cb6cb7f640b`

| Field | Value |
|---|---|
| SHA-256 | `94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a` |
| Family label | `Mirai` |
| File name | `94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:09:26` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d70727a4ff766da3e69490ab9e27d3c9` |
| SHA-1 | `0a8cd8f0a1101c1e8f662de96794d406bddb50d4` |
| SHA-256 | `94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a` |
| SHA3-384 | `12a486a5dd9e7e0bb823fd8de43ec74be261ca40af2e5c3e9be067f645ebb8411487f589c3787652493083a98bd79fd2` |
| TLSH | `T1CBE16207E2D5CE72D8CD133847935749213AC86EAB83EF03650C1999EE43BDC7A63652` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `192:fsuqD7vccFS146owz7cSym4S2ofahbpZiQ:fsue7c9JDFym4Sw/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_94b10cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a"
    family = "Mirai"
    file_name = "94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:09:26"
  condition:
    hash.sha256(0, filesize) == "94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a"
}
```

### Sample 66: `4dcb0202fe8b2d4d`

| Field | Value |
|---|---|
| SHA-256 | `4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d` |
| Family label | `CoinMiner` |
| File name | `4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:09:21` |
| Reporter | `Tuxxin` |
| Tags | `CoinMiner, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c78d9355b8b1a4bd64ca09b56e24998c` |
| SHA-1 | `bba6c3a04e6938f5028e0fa8686e7f033fd05142` |
| SHA-256 | `4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d` |
| SHA3-384 | `1378748c94a01289eb76d5681305123787324591b4934eef9ff1c2d1984490c399914e6cc60f88515f9c15fdf1df5d85` |
| IMPHASH | `aa8a1208116bd0375bd710de6ca07ba2` |
| TLSH | `T10F063327D37342BFDC07A6B098D05EF18514BC9246A0E9AD1634B9355F4E4788A6FFB0` |
| SSDEEP | `98304:Yb+oZbwSofjncJQjIntq5Gc9CuldszYeBWQNl19WQux:Mobno6W0HCqdsGQCBx` |
| ICON-DHASH | `f0c4824ccecef4f8` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_066_4dcb0202
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d"
    family = "CoinMiner"
    file_name = "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:09:21"
  condition:
    hash.sha256(0, filesize) == "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d"
}
```

### Sample 67: `e689fc21c768fd74`

| Field | Value |
|---|---|
| SHA-256 | `e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac` |
| Family label | `Snowlight` |
| File name | `e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:08:27` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d88038595a1a21f395f93d70369b54eb` |
| SHA-1 | `7cbe4dcfe3ed5040a585296c58c310c70e9b92dd` |
| SHA-256 | `e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac` |
| SHA3-384 | `f6e383f145af9161cb8471dc3ecbc0cb5a9f1538a793cadee7f0c057c4ce80f2e90294517c4ce34b4a51192a6493abd0` |
| TLSH | `T144123F47A2D0CE3FC8D9533844A7122472B794BEDF629713064915B63F427E81E6EB8B` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:GqTVJWWGXzS6fH5ML09V1J9G8YmJY+hrsrwegVekrf7mxaamBFBp8sBRnsH5vZAC:GqnWWHoZMWT1YmrhrsnurfjTr8sbnsl` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_067_e689fc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac"
    family = "Snowlight"
    file_name = "e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:08:27"
  condition:
    hash.sha256(0, filesize) == "e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac"
}
```

### Sample 68: `b2a245b35db086da`

| Field | Value |
|---|---|
| SHA-256 | `b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a` |
| Family label | `unknown` |
| File name | `b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a.bin` |
| File type | `macho` |
| First seen | `2026-11-16 00:07:03` |
| Reporter | `Tuxxin` |
| Tags | `macho` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `acbeee265df077300a2b147a5767a51a` |
| SHA-1 | `ddb4581fdba24db0c4f241f39fb24913b14e0c75` |
| SHA-256 | `b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a` |
| SHA3-384 | `1aa74bcca3e77fea81e30602666894d6e735bcafc3112f2e969fe04345375f97f8d133bce80e9bbb1903bc58edd5725b` |
| TLSH | `T128F263239B1C5922C48C623842BB6742A23BF5A145D677B74B00872DAFCA3C5BDE5D87` |
| SSDEEP | `96:RUdKC8jTDj5lpWK7TH84z1dgngS6BndngN/4B0:RUdp8j3jvpWK7b8MdgngBFdngN/4B0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_068_b2a245b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a"
    family = "unknown"
    file_name = "b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a.bin"
    file_type = "macho"
    first_seen = "2026-11-16 00:07:03"
  condition:
    hash.sha256(0, filesize) == "b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a"
}
```

### Sample 69: `e0a15e5c83b4c136`

| Field | Value |
|---|---|
| SHA-256 | `e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c` |
| Family label | `Mirai` |
| File name | `e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:06:57` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3e60df4094cb3a233c11c2ffae5e3d6a` |
| SHA-1 | `7f372da0230f609ac910c084962bd4a8b19f5aca` |
| SHA-256 | `e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c` |
| SHA3-384 | `46e228bfedbed6709a6bbc575c6737fcac27ada19d64dbe0d9269c3191e9e9111df9706779a6223ebca5de35401e7538` |
| TLSH | `T175124147A2D1CE7FC8E813384467122472BBD47ADFA29713050C65B66E923DC1E6DF8A` |
| TELFHASH | `t159b02b025470414c8ff221380c24cc831202c1a3c9415f608d40f740ca3f08d804cf4d` |
| SSDEEP | `96:GjOTpJ4WHbHf5/PlTTej6TNJ9VaNddfs2oYJYoBSf7meaamBFBp8hBdZvZ4:G6z4WTN9TTfTpVGdfs2So8f2Tr8h3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_e0a15e5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c"
    family = "Mirai"
    file_name = "e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:06:57"
  condition:
    hash.sha256(0, filesize) == "e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c"
}
```

### Sample 70: `15a04b36da197603`

| Field | Value |
|---|---|
| SHA-256 | `15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef` |
| Family label | `Snowlight` |
| File name | `15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:06:52` |
| Reporter | `Tuxxin` |
| Tags | `elf, Snowlight` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06aaa32db29da5b521a088582f701050` |
| SHA-1 | `4f97a3275012b591ea0ee771834dee18f0a3cbd7` |
| SHA-256 | `15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef` |
| SHA3-384 | `2969d157911d2ccb9c415825828e866fb87a9ca6cc6db06e1b3f4c12bb36b34777bd4712d13f79861ddde1412c8757f6` |
| TLSH | `T1BBE17117E2E2CD32D8D4137E45930A1A223DC8659E83DF132E0C896D2E537DCBA72B56` |
| TELFHASH | `t112b09b025470515d9bf561781c2588971245c1a3c5415f505d51f7549a3f48d905cb55` |
| SSDEEP | `96:f6u6TiUBOUw3SIJheuhiDr5Zz/cq/BK+M3mh/W785/f7kbalBgBi5pzBIQ:fEcb7JhABZz/cl+M2x/fLbpziQ` |

#### Technical Assessment

- The sample is tracked as `Snowlight` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Snowlight_070_15a04b36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef"
    family = "Snowlight"
    file_name = "15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:06:52"
  condition:
    hash.sha256(0, filesize) == "15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef"
}
```

### Sample 71: `29b34620572119a0`

| Field | Value |
|---|---|
| SHA-256 | `29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8` |
| Family label | `Mirai` |
| File name | `29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8.elf` |
| File type | `elf` |
| First seen | `2026-11-16 00:03:25` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1de09917cfb52b5ef092c2b75dcc565c` |
| SHA-1 | `6fe78cfbd1f9adc9cac42cd5738aefc4d9eabff4` |
| SHA-256 | `29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8` |
| SHA3-384 | `6828c621b583782b4368c586d1fddda172006b0fe051ce04fa03f53081bc3a6b732df97b5ad0720e7f3065fa3f7282e4` |
| TLSH | `T148F31A86BC818B12C6D161B6FB1F92CD371743B8D3E67103CD18AB29674B86B0E3B651` |
| TELFHASH | `t1308122505b9816bcb2f2c1d0cdbea12ad9f637ad17007017cb65ab7e6e439c1b076817` |
| SSDEEP | `3072:5yEDTIWnNRod98LprxsCc3EcSFWCGc3r5KbFK99ZVcgcvNZrW68SG9S:5BVNRoSYj3nWWCv5KbFKHbcgclg/V9` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_29b34620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8"
    family = "Mirai"
    file_name = "29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:03:25"
  condition:
    hash.sha256(0, filesize) == "29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8"
}
```

### Sample 72: `b516047dbfe91c6b`

| Field | Value |
|---|---|
| SHA-256 | `b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0` |
| Family label | `unknown` |
| File name | `b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:02:30` |
| Reporter | `Tuxxin` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a971691b8cb69949993d74203046ca47` |
| SHA-1 | `ced8759b31a3cb8ba4187bed9d834d8e87c90e75` |
| SHA-256 | `b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0` |
| SHA3-384 | `9436a78f077bb52e67a0d40446ca2c50915c649722585e47a637a58704c75edf9268927fd2bf4912e89b32ada10411ef` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T18435230722CC889DD5BF83F858EA0E6619B5F433B277E68C8ED598AD68133D20D85357` |
| SSDEEP | `24576:CeurX6S2bhU+K8d6knjYuMPzUdttVl/XVDfzWIJnZNdANK/:C3ZIhU+K0jjMPz0bVltpBZUI` |
| ICON-DHASH | `aa174d4d575f2f2b` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_072_b516047d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0"
    family = "unknown"
    file_name = "b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:02:30"
  condition:
    hash.sha256(0, filesize) == "b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0"
}
```

### Sample 73: `d315b6d2da5d28f0`

| Field | Value |
|---|---|
| SHA-256 | `d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00` |
| Family label | `Babadeda` |
| File name | `d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00.exe` |
| File type | `exe` |
| First seen | `2026-11-16 00:02:23` |
| Reporter | `Tuxxin` |
| Tags | `Babadeda, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d8cdb0c9890d58a8bbb138f572676bc0` |
| SHA-1 | `5b8d14130f3b7f7f5ad3d9eb8b1ebd728cf6c265` |
| SHA-256 | `d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00` |
| SHA3-384 | `eb64c5db83e955278665ed746c985cd6dee629c13f1bb55b9e40e3e72c12d6df95e1532ba1768b2187ee2750ba0f5f4f` |
| IMPHASH | `5877688b4859ffd051f6be3b8e0cd533` |
| TLSH | `T165937D41F3E241F7E9F10A3100A6752FA73663249724A8DBC34C3D829953AD5AA3D3F9` |
| SSDEEP | `1536:77fPGykbOqjoHm4pICdfkLtAfupcWX50MxFY+yIOlnToIf2xLZ0ROI:Xq6+ouCpk2mpcWJ0r+QNTBf2H0J` |

#### Technical Assessment

- The sample is tracked as `Babadeda` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Babadeda_073_d315b6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00"
    family = "Babadeda"
    file_name = "d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:02:23"
  condition:
    hash.sha256(0, filesize) == "d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00"
}
```

### Sample 74: `08508c6cffa68f9f`

| Field | Value |
|---|---|
| SHA-256 | `08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d` |
| Family label | `unknown` |
| File name | `SMBC-Card.apk` |
| File type | `apk` |
| First seen | `2026-11-15 23:55:07` |
| Reporter | `masaomi346` |
| Tags | `apk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a86843576ec0748c0db66fdb8a0756cd` |
| SHA-1 | `19f4d62bfb3b11f306c43ee17af9abb8f52ec6a9` |
| SHA-256 | `08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d` |
| SHA3-384 | `d421b0aea7c6cbb65bdbf9fab81034189b280e3a63eca20f5b0bbf5a2e7926966d4d1ec759501e3613930839ef86c78d` |
| TLSH | `T123272257FBC4697AF4F7A3350875A221E9079C318B53928B9814323C68F76D41F9AEC8` |
| SSDEEP | `393216:caGU678QmvUQNLf6ebiLGDfMIX5sAXJHgCnLYRmkyIy5q:ckFTH3GLEfM+sIgCnQmg` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_074_08508c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d"
    family = "unknown"
    file_name = "SMBC-Card.apk"
    file_type = "apk"
    first_seen = "2026-11-15 23:55:07"
  condition:
    hash.sha256(0, filesize) == "08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d"
}
```

### Sample 75: `c3f64d23ea037172`

| Field | Value |
|---|---|
| SHA-256 | `c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-15 23:47:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b72132da99ef89110c4932e6f328bb8a` |
| SHA-1 | `fa32c58a64c2f5752d5e07f0618bf057df94abac` |
| SHA-256 | `c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad` |
| SHA3-384 | `2a60924a2cfd3d64b0a2645411c5d79f02f70aefed9d6249d4540b33a4628159f467170253ea4e14f9d0a071b35b2532` |
| TLSH | `T1C2556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSk:SDjxB4m5n8XlaPWi+d+a4TjxQP4q` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_c3f64d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:47:04"
  condition:
    hash.sha256(0, filesize) == "c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad"
}
```

### Sample 76: `2ef0ef302b23311f`

| Field | Value |
|---|---|
| SHA-256 | `2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-15 23:44:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `168e8f1eb89363436db703b198c5e247` |
| SHA-1 | `a6a7c94eab209cd231c596f05c34824ec5553c49` |
| SHA-256 | `2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8` |
| SHA3-384 | `3ee67beabe47982fdaa20f61b66c09707cff7c4e59c16d841e93c1868dfa80bf3bc7211b8a89bcee377cdf275bc163de` |
| TLSH | `T172556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSK:SDjxB4m5n8XlaPWi+d+a4TjxQP4g` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_2ef0ef30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:44:04"
  condition:
    hash.sha256(0, filesize) == "2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8"
}
```

### Sample 77: `57392f84cdbeb0cb`

| Field | Value |
|---|---|
| SHA-256 | `57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-15 23:33:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7a82ec0062d0fcf343e347740c7135fe` |
| SHA-1 | `ec5f3a181447acd519cb776c8b5a218b6ca279e0` |
| SHA-256 | `57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c` |
| SHA3-384 | `053bd5d3f893b0330d330091a1568a6a8fb071d1f286c17874512434f6994f2d6f7a2e93b1b86a7e19c9e6fe1bee0f52` |
| TLSH | `T1D4556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSG:SDjxB4m5n8XlaPWi+d+a4TjxQP4M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_57392f84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:33:04"
  condition:
    hash.sha256(0, filesize) == "57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c"
}
```

### Sample 78: `b1c7903423b432c0`

| Field | Value |
|---|---|
| SHA-256 | `b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851` |
| Family label | `unknown` |
| File name | `iitm` |
| File type | `elf` |
| First seen | `2026-11-15 23:24:29` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `01d4c9aff977635e277efa7f6b2c5b36` |
| SHA-1 | `053b11e18f1df0051c77e892322ef2e90a09d43e` |
| SHA-256 | `b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851` |
| SHA3-384 | `3059d4c48c90e3d8a9b21f184d76b53d8dfcf5eee3b2e69fd597d4961f61c39ee786a44d0990f2e35d6f9bfc7f1bb104` |
| TLSH | `T156D59D07F9B244ECD9BACD78C74EE533E62578994122332B3BD05B102E66E15AF0C796` |
| SSDEEP | `49152:Vdi/UAPTsL/Yzi5lzAnhWrXcri9DwIU6i5bAD5M:Vd3VlYgsQP+5cM` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_078_b1c79034
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851"
    family = "unknown"
    file_name = "iitm"
    file_type = "elf"
    first_seen = "2026-11-15 23:24:29"
  condition:
    hash.sha256(0, filesize) == "b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851"
}
```

### Sample 79: `3c96e3462baf4b78`

| Field | Value |
|---|---|
| SHA-256 | `3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7` |
| Family label | `unknown` |
| File name | `iitms.sh` |
| File type | `sh` |
| First seen | `2026-11-15 23:24:27` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `686ddebe457b1001a6c05259eeda5052` |
| SHA-1 | `e76841b01dba3002b24ece2150c01cf1a8036b68` |
| SHA-256 | `3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7` |
| SHA3-384 | `713ca8ce5c29d915639b4fcb05f0aa125f01b53a6efe0890364357d46a85ce3e355da768ecb1590e7488508e74bc40ae` |
| TLSH | `T18281EBEEAB20EDB436354625509E61CC7C06E33789A27D1DF45D8C08F39D853A177A1B` |
| SSDEEP | `96:i3WI/NGKXdV5Pc9RLe5a9zfFOLu/F4H4FPhIwEO:i3WI/NGKXdVVcDL19JGu/FO4FpIwEO` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_3c96e346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7"
    family = "unknown"
    file_name = "iitms.sh"
    file_type = "sh"
    first_seen = "2026-11-15 23:24:27"
  condition:
    hash.sha256(0, filesize) == "3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7"
}
```

### Sample 80: `6bca3c88150ce668`

| Field | Value |
|---|---|
| SHA-256 | `6bca3c88150ce668a6d4604a057701f1b1d2314d9e6c97f10d53232bcea94920` |
| Family label | `Prometei` |
| File name | `zsvc` |
| File type | `elf` |
| First seen | `2026-11-15 23:23:46` |
| Reporter | `adliwahid` |
| Tags | `Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0077817621c0bb0ca857f40e10652bb9` |
| SHA-1 | `87ce31cfe61bbb86766957b79914bc7340d7113a` |
| SHA-256 | `6bca3c88150ce668a6d4604a057701f1b1d2314d9e6c97f10d53232bcea94920` |
| SHA3-384 | `48c5a2fc743eb890641ea75cddc1197f147d860d28b7e2406809702f740312fe402c32a91d75569a462851b45a8a5feb` |
| TLSH | `T1269423FA5B8EF2FB09127F7027A0980181B47470F99D675986CBFDDA0FA52679CC8118` |
| SSDEEP | `12288:4a6aYYIX2dWVxeJAaLYxAOfUhjXb44UfhlBeLV:V+2WejYxUxs2` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_080_6bca3c88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bca3c88150ce668a6d4604a057701f1b1d2314d9e6c97f10d53232bcea94920"
    family = "Prometei"
    file_name = "zsvc"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:46"
  condition:
    hash.sha256(0, filesize) == "6bca3c88150ce668a6d4604a057701f1b1d2314d9e6c97f10d53232bcea94920"
}
```

### Sample 81: `1b063de46a666519`

| Field | Value |
|---|---|
| SHA-256 | `1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68` |
| Family label | `Prometei` |
| File name | `zsvc` |
| File type | `elf` |
| First seen | `2026-11-15 23:23:44` |
| Reporter | `adliwahid` |
| Tags | `Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dfbc1ab15d815e2c5e4277452b67f75` |
| SHA-1 | `31ec6fd4b1a0b00c8cd5f29060184acf9fc0f4da` |
| SHA-256 | `1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68` |
| SHA3-384 | `0015901834a2184141ce57b8cdca79959918a80fe1fdfa3cb54a0215a8eb01711de8120486a0c285632b7f68a6659367` |
| TLSH | `T19D9423FA5B8EF2FB49127F7027A0980181A47470F99D775986CBFEDA0FA52639CC4118` |
| SSDEEP | `12288:4a6aYYIX2dWVxeJAaLYxAOfUhjXb44UfhlBeLa:V+2WejYxUxsB` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_081_1b063de4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68"
    family = "Prometei"
    file_name = "zsvc"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:44"
  condition:
    hash.sha256(0, filesize) == "1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68"
}
```

### Sample 82: `a3b45ae61c66a2f8`

| Field | Value |
|---|---|
| SHA-256 | `a3b45ae61c66a2f87b03e734b079bdf17a7e0f4be4414fd1d224ed7945d4e4bc` |
| Family label | `Prometei` |
| File name | `zsvc` |
| File type | `elf` |
| First seen | `2026-11-15 23:23:42` |
| Reporter | `adliwahid` |
| Tags | `Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7618641241d951934f063b4030012c6b` |
| SHA-1 | `0b9f2f508849d0ad9d3daad85afefe84595c8db9` |
| SHA-256 | `a3b45ae61c66a2f87b03e734b079bdf17a7e0f4be4414fd1d224ed7945d4e4bc` |
| SHA3-384 | `2340e915e9618ba13e995ee0593bee61cda67cc3b1d15cdb8d6fc7b3d29067d03a9182560f0528c8e4362552ca7fd370` |
| TLSH | `T1F19423FBD6C0430F8F16117C277A6E22D2C6553539ED6AB0C62CF8AE0E792075944EA7` |
| SSDEEP | `12288:4h/taqLkdfH8ytYiflIw0BEmWVeygFurhC5:4YdkVLwKvyaJ5` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_082_a3b45ae6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3b45ae61c66a2f87b03e734b079bdf17a7e0f4be4414fd1d224ed7945d4e4bc"
    family = "Prometei"
    file_name = "zsvc"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:42"
  condition:
    hash.sha256(0, filesize) == "a3b45ae61c66a2f87b03e734b079bdf17a7e0f4be4414fd1d224ed7945d4e4bc"
}
```

### Sample 83: `3263f21b34e559f7`

| Field | Value |
|---|---|
| SHA-256 | `3263f21b34e559f70585f232cfc2e929c56bb9c8ab97692c5955ff7a435d2f33` |
| Family label | `unknown` |
| File name | `load.sh` |
| File type | `sh` |
| First seen | `2026-11-15 23:23:40` |
| Reporter | `adliwahid` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1c353a76ac2087ec095bf3aacd227ce6` |
| SHA-1 | `914159eaa6be915b08bf0b3d98ea1e95053cdc66` |
| SHA-256 | `3263f21b34e559f70585f232cfc2e929c56bb9c8ab97692c5955ff7a435d2f33` |
| SHA3-384 | `b6bee7dd2a1b369547350982c94a298e1f358e473a385590e603fc09308005f555350c6f0c7a58cabada00eeba89e757` |
| TLSH | `T11451039A69A3D67643CB84701F87B341E346154304A7C8D4B15E7D313FEA051FD61EAA` |
| SSDEEP | `48:XmVdtxzIIamf1KG1efwFWZY4r/YNgNimQp/P8p1Mlm7BFInKIYgVDF9jQuv4jQE0:0d78/mdwfkepbgnm/onKI3VDvcwGBBy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_083_3263f21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3263f21b34e559f70585f232cfc2e929c56bb9c8ab97692c5955ff7a435d2f33"
    family = "unknown"
    file_name = "load.sh"
    file_type = "sh"
    first_seen = "2026-11-15 23:23:40"
  condition:
    hash.sha256(0, filesize) == "3263f21b34e559f70585f232cfc2e929c56bb9c8ab97692c5955ff7a435d2f33"
}
```

### Sample 84: `19cbc5253a3c932c`

| Field | Value |
|---|---|
| SHA-256 | `19cbc5253a3c932c096f33660c557a200cc2fadf1908379f8323d9bae6fc4195` |
| Family label | `unknown` |
| File name | `kworker` |
| File type | `elf` |
| First seen | `2026-11-15 23:23:38` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36a5ab0a984f6e3a9e176e9e4d4b845e` |
| SHA-1 | `c5a453bbe92f8c401ec0e0737a6ce253b88d4944` |
| SHA-256 | `19cbc5253a3c932c096f33660c557a200cc2fadf1908379f8323d9bae6fc4195` |
| SHA3-384 | `51a5d473b4a22356ff9b16bfa67fd631524448a03d23e1b64bea51e10cdcbbd6ad4ad30721abf332c2d8e6516416098e` |
| TLSH | `T184C5C447E8F550E8C0FEC4798766E617BEB2708A0638375B6FA196211F16FB0B4AD704` |
| SSDEEP | `49152:TJpiMVSXf5rcoa4wBCD92LHpi/rn16wl/hcwv8A/SKt3:TvYxnw7iDqUSS` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_19cbc525
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19cbc5253a3c932c096f33660c557a200cc2fadf1908379f8323d9bae6fc4195"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:38"
  condition:
    hash.sha256(0, filesize) == "19cbc5253a3c932c096f33660c557a200cc2fadf1908379f8323d9bae6fc4195"
}
```

### Sample 85: `26ee025519438aa7`

| Field | Value |
|---|---|
| SHA-256 | `26ee025519438aa7963d470639eeff1cb6f41d1c026a396e03acd142959d3f03` |
| Family label | `unknown` |
| File name | `imp_amd64` |
| File type | `elf` |
| First seen | `2026-11-15 23:23:36` |
| Reporter | `adliwahid` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12070ba863ce18403ed26823d0620df4` |
| SHA-1 | `e856939bda81db51071a23737beefa395dc443e6` |
| SHA-256 | `26ee025519438aa7963d470639eeff1cb6f41d1c026a396e03acd142959d3f03` |
| SHA3-384 | `aa50b858ced8331b106aa35768441a3e365008a4bbc30ab658a8c383af92569e2c877e839bb14721b532e680a70ae56c` |
| TLSH | `T15CE63B0BF9A951E9C0AEC574CAB7A123BB317C8D5A30271B1F95F6243F33BA0A559704` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `196608:zqw7i2USkwCnPN1GQSxMIoadRAGUAt0XwR91yxLCPW:2IiCCnl1niJNY++` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_085_26ee0255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26ee025519438aa7963d470639eeff1cb6f41d1c026a396e03acd142959d3f03"
    family = "unknown"
    file_name = "imp_amd64"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:36"
  condition:
    hash.sha256(0, filesize) == "26ee025519438aa7963d470639eeff1cb6f41d1c026a396e03acd142959d3f03"
}
```

### Sample 86: `a07605f271a730f2`

| Field | Value |
|---|---|
| SHA-256 | `a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95` |
| Family label | `Mirai` |
| File name | `llx.apk` |
| File type | `apk` |
| First seen | `2026-11-15 23:23:10` |
| Reporter | `adliwahid` |
| Tags | `Mirai, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64078063d1c9924532ecadad14de73f4` |
| SHA-1 | `66cc4299661bbbad5de33d8bd12c48fb47554237` |
| SHA-256 | `a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95` |
| SHA3-384 | `9e7918c63217795e38a2297beb50011b3bfbf63fd4784903d3f6e2a510cdf70db68713867c93809989c250e8b40d2ae9` |
| TLSH | `T178642283BF5C8852F2FAB0B49E7C95B39627C5C831525E42B25C22A2679B5047B1CF1F` |
| SSDEEP | `6144:YknW1kkD+09eu16dkXES7qfwS3tuhlCf+Km+blwGvdn6ni8f:YknW1TD+qePLSKwS3YlCf+EJn6niQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_086_a07605f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95"
    family = "Mirai"
    file_name = "llx.apk"
    file_type = "apk"
    first_seen = "2026-11-15 23:23:10"
  condition:
    hash.sha256(0, filesize) == "a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95"
}
```

### Sample 87: `c4fb91392c9addcf`

| Field | Value |
|---|---|
| SHA-256 | `c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-15 23:23:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1b0aa45ab35fca41c590891d8af438b4` |
| SHA-1 | `88eb4f0eefa00c703d8513ac5ae25cc243a8f21d` |
| SHA-256 | `c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384` |
| SHA3-384 | `0ab57717af68248656bcb42e799a952c2624208fb82a08c254b30c410f5de07d525220918dc1024d6d2ae8d2ef68a022` |
| TLSH | `T1A5556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcS1:SDjxB4m5n8XlaPWi+d+a4TjxQP43` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_087_c4fb9139
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:05"
  condition:
    hash.sha256(0, filesize) == "c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384"
}
```

### Sample 88: `10eb259b4fdd9b45`

| Field | Value |
|---|---|
| SHA-256 | `10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-11-15 23:22:48` |
| Reporter | `adliwahid` |
| Tags | `Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74db3a9cc71db83c9878276ce0596d81` |
| SHA-1 | `baa64ee5a27567be51de003778ed5a3f7002d439` |
| SHA-256 | `10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45` |
| SHA3-384 | `43cb84bf45a6c59943f25514a03257cf8260bd3bb2ce87f81ea20d48c936ea0dcfca348807d37d1a0ed44810dcfc1fba` |
| TLSH | `T10F732A51F8819623C6D522B6FB6E428D372653E8E3DE7203AD215F20778682F0D37E95` |
| TELFHASH | `t1b841bbe39a9419dd7be0874481cd923a99f434ec1b102a5bdf2dab9f4187ec1700e837` |
| SSDEEP | `1536:jadhzUG5jNeVOsMjy7xT0fu0XlZgy/+ewkyqIuo1XzIWqcb:GhdZOwfuSlZg9LqITXscb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_088_10eb259b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-15 23:22:48"
  condition:
    hash.sha256(0, filesize) == "10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45"
}
```

### Sample 89: `b3d162cff7c3915a`

| Field | Value |
|---|---|
| SHA-256 | `b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-11-15 23:22:46` |
| Reporter | `adliwahid` |
| Tags | `Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `980b95b7a844a06ee0b1f226f620d723` |
| SHA-1 | `02f93a04d5e369f687534153dda8b249cf776e35` |
| SHA-256 | `b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50` |
| SHA3-384 | `86e5002eb872afa062a69981ad79a531168654fdd051c1a0066163194016ef9c211ed63ca84a7a8d818b666f1fe01776` |
| TLSH | `T135A3B80E6E218FBDF699C63557B75E21A65833C726E1C642E26CD7102F6034E241FFA8` |
| TELFHASH | `t13521815c4a7422e467355c99265efbb7d16130ef2b216d378f0179adabbdd421d00c0c` |
| SSDEEP | `1536:3XVRlQLM2aMYLSRXJlo3hlrV2pfP+IeUziUXzIWUpJ:3j2LM2amRM3hlrVqPsUXOpJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_b3d162cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-15 23:22:46"
  condition:
    hash.sha256(0, filesize) == "b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50"
}
```

### Sample 90: `6ba0ddb2dc99ab11`

| Field | Value |
|---|---|
| SHA-256 | `6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d` |
| Family label | `Mirai` |
| File name | `cc9x86` |
| File type | `elf` |
| First seen | `2026-11-15 23:21:58` |
| Reporter | `adliwahid` |
| Tags | `Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e96cf072f42a17be4a0db383a4704118` |
| SHA-1 | `09900744e5224ce750b2187a120d470e9d5b1700` |
| SHA-256 | `6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d` |
| SHA3-384 | `672d2bff5350ebf53e5af0d5345c972a7159acd4689830a0956d4980f2e24f2e4d3d3e7d78e1e5eb01fdfcc62f59a9f8` |
| TLSH | `T11FA35B17A652C67AC0C356F52BDB96615123BC3E0F32720A73D87DE62F368D82D69702` |
| TELFHASH | `t131210046a1fa8a3d5ff228246cbc46b5059267273361bf70af19c5d05c3b002e939ecb` |
| SSDEEP | `3072:nd0w2Udg1o89XuDkelw9Uo23m3mDk1cwxc635v:j8NKjCZ3mDk1cwxc635v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_6ba0ddb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d"
    family = "Mirai"
    file_name = "cc9x86"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:58"
  condition:
    hash.sha256(0, filesize) == "6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d"
}
```

### Sample 91: `b8b9264e0acef29c`

| Field | Value |
|---|---|
| SHA-256 | `b8b9264e0acef29c0502c7836dfdcf9d9c13aaec23b04b37d0e167036a6f84e5` |
| Family label | `Mirai` |
| File name | `cc9mips` |
| File type | `elf` |
| First seen | `2026-11-15 23:21:56` |
| Reporter | `adliwahid` |
| Tags | `Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c0d106adf0b07805091677d360c4c24` |
| SHA-1 | `b8ed9315e5973c4262ba4e5c5be4e12bda0ccae7` |
| SHA-256 | `b8b9264e0acef29c0502c7836dfdcf9d9c13aaec23b04b37d0e167036a6f84e5` |
| SHA3-384 | `22724739a4f1a5a0d1e9a80d8e308844cfda41880c66e9c16c8d71d78917e7209caa98f72546f0fede67add3fbd4958f` |
| TLSH | `T189D3852A7E21ABFEE168863107F35F7087952D9236A19385F26CFB581E7128C1C5F790` |
| TELFHASH | `t10211d046a1fa856d5ff228246cbc46b5154166237361bf70af0985d41c3b002a979ecb` |
| SSDEEP | `1536:BtVN37Kq8bV+zemyPUk+aofie2rK5O9HUfke8PCxMDpoZ4FImlP+s4z0PTD/v:Tl2HtHUfAaymZ4FImlWs4z0PTD/v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_b8b9264e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8b9264e0acef29c0502c7836dfdcf9d9c13aaec23b04b37d0e167036a6f84e5"
    family = "Mirai"
    file_name = "cc9mips"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:56"
  condition:
    hash.sha256(0, filesize) == "b8b9264e0acef29c0502c7836dfdcf9d9c13aaec23b04b37d0e167036a6f84e5"
}
```

### Sample 92: `4a7af39b0d749640`

| Field | Value |
|---|---|
| SHA-256 | `4a7af39b0d7496404ee3c5435c46e99a831137ebf2d1b7fe62d0a0a62c658621` |
| Family label | `Mirai` |
| File name | `cc9mpsl` |
| File type | `elf` |
| First seen | `2026-11-15 23:21:54` |
| Reporter | `adliwahid` |
| Tags | `Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `071806dd47ae98f201082489cd5a1f8c` |
| SHA-1 | `713a605934e4d2ef986f56f52c6793abbf387373` |
| SHA-256 | `4a7af39b0d7496404ee3c5435c46e99a831137ebf2d1b7fe62d0a0a62c658621` |
| SHA3-384 | `441138f994ae0fa101dac1d48f5093f4fe9084f0799a88d96425bb22a63ebea39d969440687f46993245e5732b25b1c8` |
| TLSH | `T14AD3B717AB218EB7D84ECE3306AA4501108DDD5612D96F6FB2B4F96CE76B84F08E3D44` |
| TELFHASH | `t10211d046a1fa856d5ff228246cbc46b5154166237361bf70af0985d41c3b002a979ecb` |
| SSDEEP | `1536:lceTLQAxHtkQdPQQyWZL/80fekB/oHLympcoDl7DhcfImlP+s4z0PTD/v:lDQQb4Y/VslJqImlWs4z0PTD/v` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_092_4a7af39b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a7af39b0d7496404ee3c5435c46e99a831137ebf2d1b7fe62d0a0a62c658621"
    family = "Mirai"
    file_name = "cc9mpsl"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:54"
  condition:
    hash.sha256(0, filesize) == "4a7af39b0d7496404ee3c5435c46e99a831137ebf2d1b7fe62d0a0a62c658621"
}
```

### Sample 93: `eff6664c9de3d6bd`

| Field | Value |
|---|---|
| SHA-256 | `eff6664c9de3d6bd06e88fa4edf5074e8d67efee8d9f35bbd5c80e051f53d5ae` |
| Family label | `Gafgyt` |
| File name | `bins.sh` |
| File type | `sh` |
| First seen | `2026-11-15 23:21:52` |
| Reporter | `adliwahid` |
| Tags | `Gafgyt` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49fdb17fbdb4cd5c06bdb7c45e53cb25` |
| SHA-1 | `4baefa4761817be997f33f6e8619fd0d72f5aeef` |
| SHA-256 | `eff6664c9de3d6bd06e88fa4edf5074e8d67efee8d9f35bbd5c80e051f53d5ae` |
| SHA3-384 | `a2d60fa7e1752d29e6c84196198d5b6cc1509cb652ca1fc9defef1e0e8eabe4a13699faae1b9ba1cafe7e3c4d0fe4199` |
| TLSH | `T11921EADB22B519303C91E82B31BAA804719492DB18CE7F0AE8DD7FE9048DE0B6454B97` |
| SSDEEP | `24:v2aDvrJbp3ifsBNIYNksCdZs9PZqsZ7La:v2aDvVN3iUxNJC8JdZHa` |

#### Technical Assessment

- The sample is tracked as `Gafgyt` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Gafgyt_093_eff6664c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff6664c9de3d6bd06e88fa4edf5074e8d67efee8d9f35bbd5c80e051f53d5ae"
    family = "Gafgyt"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-11-15 23:21:52"
  condition:
    hash.sha256(0, filesize) == "eff6664c9de3d6bd06e88fa4edf5074e8d67efee8d9f35bbd5c80e051f53d5ae"
}
```

### Sample 94: `597eb9162a0410ae`

| Field | Value |
|---|---|
| SHA-256 | `597eb9162a0410ae7cd21d19ad14a8f94f04cb7ffa290c918dd8c4425fee16e5` |
| Family label | `Mirai` |
| File name | `cc9sh4` |
| File type | `elf` |
| First seen | `2026-11-15 23:21:50` |
| Reporter | `adliwahid` |
| Tags | `Gafgyt, Mirai, Torii` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ded37dfa8930912e7e506528e26aef81` |
| SHA-1 | `ad6494f4d2029e850933a60d6da0022019059f78` |
| SHA-256 | `597eb9162a0410ae7cd21d19ad14a8f94f04cb7ffa290c918dd8c4425fee16e5` |
| SHA3-384 | `ad0dfee4d2095df09a068f4f0b62fed88acf64531ba34bc522902da6d1ec183792cd6617db2466b9e3366f6d09f1dc48` |
| TLSH | `T1CC93384799619FB7C186A9B126F759300713AD124F0F1B98B12DBAF4473B9CDB80E7A0` |
| TELFHASH | `t1bc11f346a1fa856d5ff228245cbc46b5154167237361bf70af0985d45c3b002e939ecb` |
| SSDEEP | `1536:fqTghk4gebzgK2rlJDQ/LZ5pZdC0BG/9tngmmycgYvLusIAWb:yTWbfzn2PQ/Dds/YmDcgYvysIAWb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_597eb916
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "597eb9162a0410ae7cd21d19ad14a8f94f04cb7ffa290c918dd8c4425fee16e5"
    family = "Mirai"
    file_name = "cc9sh4"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:50"
  condition:
    hash.sha256(0, filesize) == "597eb9162a0410ae7cd21d19ad14a8f94f04cb7ffa290c918dd8c4425fee16e5"
}
```

### Sample 95: `2fe1dfb1fe30ea13`

| Field | Value |
|---|---|
| SHA-256 | `2fe1dfb1fe30ea13afafbc95663258018d46fae1cbee45b08ab8c5d68303d298` |
| Family label | `unknown` |
| File name | `tot` |
| File type | `sh` |
| First seen | `2026-11-15 23:14:04` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb6dae4e1d74ef7e11776f3696dac385` |
| SHA-1 | `4cfcc55a954146b00a8f22562ddd16c5ff7588fb` |
| SHA-256 | `2fe1dfb1fe30ea13afafbc95663258018d46fae1cbee45b08ab8c5d68303d298` |
| SHA3-384 | `abbe7621ac06632a4f38c2e8c77f455d202ed6e260ba404342572a94397088608e1e5169e637ffe840a26a6e26bed8ad` |
| TLSH | `T10601D4CA0A5AD2995845EFAD79F00576D3CCBB5532F4E23CF5E38821098840E365AB6B` |
| SSDEEP | `12:mwsEf+PXEf+Pif+Piif+PhEf+PtBf+PRof+P3f+PTf+PAf+Pkf+:psbXbxixhbwR34MPD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_2fe1dfb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fe1dfb1fe30ea13afafbc95663258018d46fae1cbee45b08ab8c5d68303d298"
    family = "unknown"
    file_name = "tot"
    file_type = "sh"
    first_seen = "2026-11-15 23:14:04"
  condition:
    hash.sha256(0, filesize) == "2fe1dfb1fe30ea13afafbc95663258018d46fae1cbee45b08ab8c5d68303d298"
}
```

### Sample 96: `f4ce200ae8377344`

| Field | Value |
|---|---|
| SHA-256 | `f4ce200ae8377344546c5f6bc8e75b6165c66b934254b6c6f7f42ce145304da7` |
| Family label | `Mirai` |
| File name | `na` |
| File type | `elf` |
| First seen | `2026-11-15 23:07:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, Prometei` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `23afe9cb7feaa118b1ca64a1ab609d3c` |
| SHA-1 | `34a5be707baafe33db26a7fe3cd50ee7c9de80e2` |
| SHA-256 | `f4ce200ae8377344546c5f6bc8e75b6165c66b934254b6c6f7f42ce145304da7` |
| SHA3-384 | `a8d12c4e5fb36d3cbac9db92a369dde5d232a9a21d386f6a7fe0c3cef4ee618d3ec3fc322f961034a908df2faf612297` |
| TLSH | `T133556BBBF2A770BCC167D030478BCBA2AC35B4B501212D7B61C4A9763D62DE11766B27` |
| TELFHASH | `t10ad1bb700bf635b061dbca20f343f1754d3214ba65f439e42662be88ef95e414c6e52b` |
| SSDEEP | `24576:S7PjxB4gb5n8X1zaP7axA+d+a4TIucpWETPjkjcSU:SDjxB4m5n8XlaPWi+d+a4TjxQP46` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_f4ce200a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4ce200ae8377344546c5f6bc8e75b6165c66b934254b6c6f7f42ce145304da7"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:07:04"
  condition:
    hash.sha256(0, filesize) == "f4ce200ae8377344546c5f6bc8e75b6165c66b934254b6c6f7f42ce145304da7"
}
```

### Sample 97: `435e9e9e3f5f5350`

| Field | Value |
|---|---|
| SHA-256 | `435e9e9e3f5f53506e6c137a9565a42d096ac5ad47d59d93d41130f1d56a0bfe` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-15 22:39:16` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `54c384ee5e9b3d260e64bd13cd2660a3` |
| SHA-1 | `f9d0ea8ab545114a0b72f88c188534ab9ad393cf` |
| SHA-256 | `435e9e9e3f5f53506e6c137a9565a42d096ac5ad47d59d93d41130f1d56a0bfe` |
| SHA3-384 | `2584091e2ec224d80968129f4efba22d467ea8af19b71071a181c58fd7b4502533b90d8ab198180e33318fb1cb6318c7` |
| IMPHASH | `bd84352b4439a7f95c7b717514c55fd1` |
| TLSH | `T178E4F154F7661699E8398734C8A34D1547A63C025F21A8FF87CD63AA0E137D09B3EB39` |
| SSDEEP | `12288:Vw5ARC2I82TWZ01R0pm67keK+KIiGME0RfZbQLxP8U7QUTAQGYFPMv:VwKeWweR/JMjRxQT7bTAQnMv` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_097_435e9e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "435e9e9e3f5f53506e6c137a9565a42d096ac5ad47d59d93d41130f1d56a0bfe"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:39:16"
  condition:
    hash.sha256(0, filesize) == "435e9e9e3f5f53506e6c137a9565a42d096ac5ad47d59d93d41130f1d56a0bfe"
}
```

### Sample 98: `aa1a7ce32192a198`

| Field | Value |
|---|---|
| SHA-256 | `aa1a7ce32192a1984384d1e1d3d104537175b5103cd176887f5862476fe4d8e5` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-15 22:38:39` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, stealer, upx, warden, wardenstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0b38726cb69f3d5269084406686c49c6` |
| SHA-1 | `62bd2683b31f63a05cb20028719c3fd41b90a120` |
| SHA-256 | `aa1a7ce32192a1984384d1e1d3d104537175b5103cd176887f5862476fe4d8e5` |
| SHA3-384 | `4ea8398b92408de87d98ffd9fa8e9c2827b3ff7cde0789152217d3349a281ef2b05ed283928eb04e4af9bc1b87ed3398` |
| IMPHASH | `9c99bf82237676706b9b7bccac7f4694` |
| TLSH | `T1E29423503321E1BCC28844BF265CF4AC0AF279ADA73145FD1ADE524B496A78F35221F7` |
| SSDEEP | `6144:BzE9nu0tt579cDpDO2DC9ODo04FOxu68RvsdN+h3Ky1JM67lLdq/xSbfu:Uu0tT7yNOjtYuTsNW3KCC6sUbfu` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_098_aa1a7ce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa1a7ce32192a1984384d1e1d3d104537175b5103cd176887f5862476fe4d8e5"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:38:39"
  condition:
    hash.sha256(0, filesize) == "aa1a7ce32192a1984384d1e1d3d104537175b5103cd176887f5862476fe4d8e5"
}
```

### Sample 99: `2537279c002df00c`

| Field | Value |
|---|---|
| SHA-256 | `2537279c002df00c699d275b4a9da608300ea85691ddf7f876a2bdf3620d17d6` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-15 22:38:14` |
| Reporter | `abuse_ch` |
| Tags | `exe, upx-dec, WARDENStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `67449214d1f3bb6f4a6697bd16fffdb7` |
| SHA-1 | `39ddff7679c612bca9caddfe7b6aab3988c8c362` |
| SHA-256 | `2537279c002df00c699d275b4a9da608300ea85691ddf7f876a2bdf3620d17d6` |
| SHA3-384 | `b6988bfab2b82f0c2250e3092b70b72f42a265f43c64791bb2223b280ca40c300d4e604c4420f97920861455cbdcd9bb` |
| IMPHASH | `e95d940f5bec5e03b56e07d0b3e8085b` |
| TLSH | `T1DDE402E1FE9516EAE839D538458764068BB67C110B50ACEB52E0373F0E377D4A736E0A` |
| SSDEEP | `12288:WlBQPfwEJ+YaYKZErxPZ8NAh/6wP45ZO9EYqnMWSaThvyUIvDDkVZo+ecj2t:WlBQYFZ2xPZ8NrgSHY+MWSkhvyUIrDHH` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_099_2537279c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2537279c002df00c699d275b4a9da608300ea85691ddf7f876a2bdf3620d17d6"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:38:14"
  condition:
    hash.sha256(0, filesize) == "2537279c002df00c699d275b4a9da608300ea85691ddf7f876a2bdf3620d17d6"
}
```

### Sample 100: `5e444e380ac29fd3`

| Field | Value |
|---|---|
| SHA-256 | `5e444e380ac29fd399033b5e640ef8790defd964747a1f26e37200072ce0f1ef` |
| Family label | `WARDENStealer` |
| File name | `jli.dll` |
| File type | `exe` |
| First seen | `2026-11-15 22:37:47` |
| Reporter | `AmadeyHunter` |
| Tags | `exe, hyperfinex, stealer, warden, wardenstealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06d46fa22ceef9c21935bf15e69b3b30` |
| SHA-1 | `a101dea1f5fccf374d0c11ec346fda0e54176c50` |
| SHA-256 | `5e444e380ac29fd399033b5e640ef8790defd964747a1f26e37200072ce0f1ef` |
| SHA3-384 | `319133d4c9c61ce14e46b2e5099668ce45ebdcaf5df12345c8efe0ece17328a6ae8f8f063f20b4689697ebe03891f1c1` |
| IMPHASH | `7034072c3a055a14e3c0a74728f6e2cb` |
| TLSH | `T16CE4F154F7661699E8398734C8A3491547A63C025F21A8FF87CD63AB0E137D09B3EB39` |
| SSDEEP | `12288:Sw5ARC2I82TWZw1R0pm67keK+KIiGME0RfrbQLxP8U7QUTAQGYFPMv:SwKeWUeR/JMjRHQT7bTAQnMv` |

#### Technical Assessment

- The sample is tracked as `WARDENStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WARDENStealer_100_5e444e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e444e380ac29fd399033b5e640ef8790defd964747a1f26e37200072ce0f1ef"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:37:47"
  condition:
    hash.sha256(0, filesize) == "5e444e380ac29fd399033b5e640ef8790defd964747a1f26e37200072ce0f1ef"
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
 * Generated: 2026-11-16T06:45:18.659097+00:00
 */

rule MalwareBazaar_unknown_001_64a5883c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "64a5883ce5cb0ef168ffd915b436e68ce3af6431bf7917860ff72ad0d4867f43"
    family = "unknown"
    file_name = "modules.cache"
    file_type = "zip"
    first_seen = "2026-11-16 06:30:37"
  condition:
    hash.sha256(0, filesize) == "64a5883ce5cb0ef168ffd915b436e68ce3af6431bf7917860ff72ad0d4867f43"
}

rule MalwareBazaar_SalatStealer_002_a6472588
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a6472588a0acc1a2d99e497ae2a1d1f995ab76339f44fe2d11f0f345f7008198"
    family = "SalatStealer"
    file_name = "a6472588a0acc1a2.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:25:06"
  condition:
    hash.sha256(0, filesize) == "a6472588a0acc1a2d99e497ae2a1d1f995ab76339f44fe2d11f0f345f7008198"
}

rule MalwareBazaar_SalatStealer_003_4da2697e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4da2697ef60997de5a547a7ea90c1bea72ff3302a78f92a39abb69eb55b876e4"
    family = "SalatStealer"
    file_name = "4da2697ef60997de.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:24:58"
  condition:
    hash.sha256(0, filesize) == "4da2697ef60997de5a547a7ea90c1bea72ff3302a78f92a39abb69eb55b876e4"
}

rule MalwareBazaar_SalatStealer_004_70ac4181
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "70ac4181bd8e58f5de3c9072fa43399f39becbae14df999dcd13446dc9c396d2"
    family = "SalatStealer"
    file_name = "70ac4181bd8e58f5.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:24:50"
  condition:
    hash.sha256(0, filesize) == "70ac4181bd8e58f5de3c9072fa43399f39becbae14df999dcd13446dc9c396d2"
}

rule MalwareBazaar_SalatStealer_005_4a83b3c7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a83b3c7c4b15fe2823ed045f539eafb87bd2cb08f0b02240f512332b384c228"
    family = "SalatStealer"
    file_name = "4a83b3c7c4b15fe2.bin"
    file_type = "bat"
    first_seen = "2026-11-16 06:24:41"
  condition:
    hash.sha256(0, filesize) == "4a83b3c7c4b15fe2823ed045f539eafb87bd2cb08f0b02240f512332b384c228"
}

rule MalwareBazaar_Mirai_006_a1fd1ccc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a1fd1cccce94a92961705679613a6c27e6e53e09a77fe4fd00e94f9ea46a2de7"
    family = "Mirai"
    file_name = "armv6l"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:12"
  condition:
    hash.sha256(0, filesize) == "a1fd1cccce94a92961705679613a6c27e6e53e09a77fe4fd00e94f9ea46a2de7"
}

rule MalwareBazaar_Mirai_007_fd2abb57
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fd2abb575a45805ed719a9069660ce35b412a391a021cb16e9db137811dc056d"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:09"
  condition:
    hash.sha256(0, filesize) == "fd2abb575a45805ed719a9069660ce35b412a391a021cb16e9db137811dc056d"
}

rule MalwareBazaar_Mirai_008_a5dbdaf2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5dbdaf26db7ac09728bd6d0ee874796ac7981434f68dd52c7692511200cd042"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:06"
  condition:
    hash.sha256(0, filesize) == "a5dbdaf26db7ac09728bd6d0ee874796ac7981434f68dd52c7692511200cd042"
}

rule MalwareBazaar_Mirai_009_6ee744ca
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ee744ca88b4f449d90463f607966a19426d61eff5d017d54923a1c61ca5a966"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:46:03"
  condition:
    hash.sha256(0, filesize) == "6ee744ca88b4f449d90463f607966a19426d61eff5d017d54923a1c61ca5a966"
}

rule MalwareBazaar_Mirai_010_acd9ad86
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "acd9ad86d2dab62c58bb8523a5673b3fc40f062c5bf5ffd5649d7cecfea32ac4"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:43:04"
  condition:
    hash.sha256(0, filesize) == "acd9ad86d2dab62c58bb8523a5673b3fc40f062c5bf5ffd5649d7cecfea32ac4"
}

rule MalwareBazaar_unknown_011_60364fc8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60364fc8ef0b6624d84e5b87a03097c9af21daddb6862ff46f0f225ec09409b8"
    family = "unknown"
    file_name = "rev.sh"
    file_type = "sh"
    first_seen = "2026-11-16 05:38:07"
  condition:
    hash.sha256(0, filesize) == "60364fc8ef0b6624d84e5b87a03097c9af21daddb6862ff46f0f225ec09409b8"
}

rule MalwareBazaar_Mirai_012_c219de85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c219de851107e407846103c04bde115fb80103a7d94ca6747c63b3e507dc226f"
    family = "Mirai"
    file_name = "i686"
    file_type = "elf"
    first_seen = "2026-11-16 05:38:04"
  condition:
    hash.sha256(0, filesize) == "c219de851107e407846103c04bde115fb80103a7d94ca6747c63b3e507dc226f"
}

rule MalwareBazaar_Mirai_013_def1c414
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "def1c414fad5b057004795c8799e38873607e3a88c537488be3af67ec806f737"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-16 05:37:04"
  condition:
    hash.sha256(0, filesize) == "def1c414fad5b057004795c8799e38873607e3a88c537488be3af67ec806f737"
}

rule MalwareBazaar_Mirai_014_61987531
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "619875311cb93e5831314a5e93de40a5fbc144f2dbbc282dac81c4b85e1b7d34"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-16 05:33:05"
  condition:
    hash.sha256(0, filesize) == "619875311cb93e5831314a5e93de40a5fbc144f2dbbc282dac81c4b85e1b7d34"
}

rule MalwareBazaar_unknown_015_d2d9fed6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2d9fed670a9bd445f19369f6143984ae69684bc112b52745536276e2f6c6a3b"
    family = "unknown"
    file_name = "c"
    file_type = "sh"
    first_seen = "2026-11-16 05:32:07"
  condition:
    hash.sha256(0, filesize) == "d2d9fed670a9bd445f19369f6143984ae69684bc112b52745536276e2f6c6a3b"
}

rule MalwareBazaar_Mirai_016_a9e79b42
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9e79b42858a89ec1be3c30edc811f73a4ba6f6234509a066a2cf8d42f78fd74"
    family = "Mirai"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-11-16 05:32:04"
  condition:
    hash.sha256(0, filesize) == "a9e79b42858a89ec1be3c30edc811f73a4ba6f6234509a066a2cf8d42f78fd74"
}

rule MalwareBazaar_Mirai_017_59b6431a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-11-16 05:28:08"
  condition:
    hash.sha256(0, filesize) == "59b6431ac5fc6c7ec49bf1342e23b328745badd2e9d58cf497aca28959253d40"
}

rule MalwareBazaar_Mirai_018_77456632
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:28:05"
  condition:
    hash.sha256(0, filesize) == "77456632a5c2b72225bd52f9d39e1b9913e646a40a1621996576fb571b337ef0"
}

rule MalwareBazaar_Mirai_019_d54a695c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-11-16 05:27:04"
  condition:
    hash.sha256(0, filesize) == "d54a695c3923ab2cf250ec6733e4aee2f906cc9d77665aa27303b44314db2691"
}

rule MalwareBazaar_Mirai_020_1409798c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-11-16 05:24:03"
  condition:
    hash.sha256(0, filesize) == "1409798cde3af5837c769e95ed0d12dac10521eeb75f729cd0c0c601a5ce9b01"
}

rule MalwareBazaar_Mirai_021_b48c71da
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-11-16 05:22:04"
  condition:
    hash.sha256(0, filesize) == "b48c71dac86b74e15394ca0f8f907933678755af1358f810420e06d858f873e7"
}

rule MalwareBazaar_Mirai_022_88c32e47
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40"
    family = "Mirai"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-11-16 05:20:04"
  condition:
    hash.sha256(0, filesize) == "88c32e47bcf484deb8742bce6e1009d3cd0c7b5dee1154526c9083aa6fdd6d40"
}

rule MalwareBazaar_Mirai_023_35f32b51
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-11-16 05:17:59"
  condition:
    hash.sha256(0, filesize) == "35f32b517039e4bcc492631ebf6ef9221d45caae1da7b22746edb4a52d555199"
}

rule MalwareBazaar_Mirai_024_78a495e0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-16 05:17:57"
  condition:
    hash.sha256(0, filesize) == "78a495e04a829a4e99474bed6e171b5598235f1efd95ad9f9fe4e15fb63cf13a"
}

rule MalwareBazaar_Mirai_025_dabc0522
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:11"
  condition:
    hash.sha256(0, filesize) == "dabc05223d247ffae366a88206ab9b7129decdfb9d5e56b4094ffe641cba8cf2"
}

rule MalwareBazaar_Mirai_026_c20f4bf9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:09"
  condition:
    hash.sha256(0, filesize) == "c20f4bf9d239489be7a18ab095bb2e79c53f2b9c1eb488978e696c30b51a4f7b"
}

rule MalwareBazaar_Mirai_027_1c00f4f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:06"
  condition:
    hash.sha256(0, filesize) == "1c00f4f523080384356ac5a1fef2dab343e4141a880cb703cc9013353a8ed1c0"
}

rule MalwareBazaar_Mirai_028_c9385873
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-11-16 05:16:03"
  condition:
    hash.sha256(0, filesize) == "c93858738a995794a92cd7aa209de01c35f0841735b6c66f72fc5f258ac3acf7"
}

rule MalwareBazaar_Mirai_029_a381cfea
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a381cfea5c8e152d55b5c6c1e2123d34b704f225830f41b306f4e10c9d126e15"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 05:13:03"
  condition:
    hash.sha256(0, filesize) == "a381cfea5c8e152d55b5c6c1e2123d34b704f225830f41b306f4e10c9d126e15"
}

rule MalwareBazaar_unknown_030_9e36446c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9e36446c383f361406c4734667b586052916a74fcbc754ff4347f6cd3f75e5bb"
    family = "unknown"
    file_name = "9e36446c383f3614.ps1"
    file_type = "ps1"
    first_seen = "2026-11-16 05:12:18"
  condition:
    hash.sha256(0, filesize) == "9e36446c383f361406c4734667b586052916a74fcbc754ff4347f6cd3f75e5bb"
}

rule MalwareBazaar_Mirai_031_202ab923
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "202ab923caad6c68cfa1654a9d8bb0178d9868446f1a713a53ae932c0e0a24f0"
    family = "Mirai"
    file_name = "sh4"
    file_type = "elf"
    first_seen = "2026-11-16 05:04:06"
  condition:
    hash.sha256(0, filesize) == "202ab923caad6c68cfa1654a9d8bb0178d9868446f1a713a53ae932c0e0a24f0"
}

rule MalwareBazaar_Mirai_032_4e039b83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-11-16 04:29:04"
  condition:
    hash.sha256(0, filesize) == "4e039b8335f759c200f6dbb723244fb12a572ee1c18749166d8ecbce1db5b934"
}

rule MalwareBazaar_unknown_033_9989b1ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9989b1edad0749e3dcbce815276abc271e91d75f11d3ddb0bf20b935c009442f"
    family = "unknown"
    file_name = "e"
    file_type = "sh"
    first_seen = "2026-11-16 04:08:05"
  condition:
    hash.sha256(0, filesize) == "9989b1edad0749e3dcbce815276abc271e91d75f11d3ddb0bf20b935c009442f"
}

rule MalwareBazaar_Mirai_034_2403bcc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-16 03:39:04"
  condition:
    hash.sha256(0, filesize) == "2403bcc927beb7b39dc4abeaa424879efd6fc90da87f2bffecaea6dc55297f7f"
}

rule MalwareBazaar_GuLoader_035_a5cd1aa1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a5cd1aa138dc2c5ccb71a1e76f74f76c9518d2fc096c06b05ea3c72df2e5defb"
    family = "GuLoader"
    file_name = "Foldningsstningerne.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 03:24:19"
  condition:
    hash.sha256(0, filesize) == "a5cd1aa138dc2c5ccb71a1e76f74f76c9518d2fc096c06b05ea3c72df2e5defb"
}

rule MalwareBazaar_WARDENStealer_036_34d80d78
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27"
    family = "WARDENStealer"
    file_name = "34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27.exe"
    file_type = "exe"
    first_seen = "2026-11-16 03:21:29"
  condition:
    hash.sha256(0, filesize) == "34d80d781c26ab65851cd81d7f154ac6f4cd3fd52828d150704c0a606a08cf27"
}

rule MalwareBazaar_GuLoader_037_8207cfeb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8207cfeb69013150389c476f5ea0c0e9c996aaed7089e3699c7a23d48b161fb9"
    family = "GuLoader"
    file_name = "PO Revised.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 02:44:59"
  condition:
    hash.sha256(0, filesize) == "8207cfeb69013150389c476f5ea0c0e9c996aaed7089e3699c7a23d48b161fb9"
}

rule MalwareBazaar_WannaCry_038_7c47f9d4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3"
    family = "WannaCry"
    file_name = "7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3"
    file_type = "exe"
    first_seen = "2026-11-16 02:15:26"
  condition:
    hash.sha256(0, filesize) == "7c47f9d4b9496f75a37f5faae7c182da88c486de1025f2ad19ffe0fa6a61d8b3"
}

rule MalwareBazaar_WannaCry_039_742aa247
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12"
    family = "WannaCry"
    file_name = "742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12"
    file_type = "exe"
    first_seen = "2026-11-16 02:15:19"
  condition:
    hash.sha256(0, filesize) == "742aa247d5a8a4766fd7daedc8b8b281f6321fe425f19a2e311a53fdc9e7dd12"
}

rule MalwareBazaar_GuLoader_040_3978407c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3978407c1e5dbc2e437207665c95a31e8bd3ae934d15cab4d4f6c2d1161f6740"
    family = "GuLoader"
    file_name = "Selvbefrugtningen.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 01:43:04"
  condition:
    hash.sha256(0, filesize) == "3978407c1e5dbc2e437207665c95a31e8bd3ae934d15cab4d4f6c2d1161f6740"
}

rule MalwareBazaar_GuLoader_041_0c9218fb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c9218fbb35de0a5048b9d57a397f8c5437876017b1667dbb2560a01c366be4b"
    family = "GuLoader"
    file_name = "Macrozoogonidium.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 01:33:25"
  condition:
    hash.sha256(0, filesize) == "0c9218fbb35de0a5048b9d57a397f8c5437876017b1667dbb2560a01c366be4b"
}

rule MalwareBazaar_unknown_042_d2c8b634
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d2c8b634fba9b551ac802ed158a23c58a08f5b1d74af20afc20eb71c48ed465d"
    family = "unknown"
    file_name = "d2c8b634fba9b551.js"
    file_type = "js"
    first_seen = "2026-11-16 01:02:33"
  condition:
    hash.sha256(0, filesize) == "d2c8b634fba9b551ac802ed158a23c58a08f5b1d74af20afc20eb71c48ed465d"
}

rule MalwareBazaar_unknown_043_21981156
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "21981156828679957bf94133162863398eb5dab72641181921aad955c8e1d28a"
    family = "unknown"
    file_name = "2198115682867995.js"
    file_type = "js"
    first_seen = "2026-11-16 01:02:22"
  condition:
    hash.sha256(0, filesize) == "21981156828679957bf94133162863398eb5dab72641181921aad955c8e1d28a"
}

rule MalwareBazaar_unknown_044_f6854d35
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6854d35569d9112f5e02c5a4be16711d7bf942e957301b35a02779d6bacf9dc"
    family = "unknown"
    file_name = "f6854d35569d9112.js"
    file_type = "js"
    first_seen = "2026-11-16 00:57:32"
  condition:
    hash.sha256(0, filesize) == "f6854d35569d9112f5e02c5a4be16711d7bf942e957301b35a02779d6bacf9dc"
}

rule MalwareBazaar_unknown_045_66f861a8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "66f861a8217cf2a4b5e8d3f620eb02a8b01440db5d63c06c05c4b44b698414a5"
    family = "unknown"
    file_name = "66f861a8217cf2a4.js"
    file_type = "js"
    first_seen = "2026-11-16 00:57:21"
  condition:
    hash.sha256(0, filesize) == "66f861a8217cf2a4b5e8d3f620eb02a8b01440db5d63c06c05c4b44b698414a5"
}

rule MalwareBazaar_GuLoader_046_74d98120
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "74d98120c968be2d9d346ea501eb62a75d5694ba3de610dbfcc5214227abbe9a"
    family = "GuLoader"
    file_name = "Cyanocitta.vbs"
    file_type = "vbs"
    first_seen = "2026-11-16 00:45:10"
  condition:
    hash.sha256(0, filesize) == "74d98120c968be2d9d346ea501eb62a75d5694ba3de610dbfcc5214227abbe9a"
}

rule MalwareBazaar_SalatStealer_047_6204b27f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6204b27f17dd77358341cb3190c6abec6357daab1af105df8257f149c3d67c79"
    family = "SalatStealer"
    file_name = "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:39:19"
  condition:
    hash.sha256(0, filesize) == "6204b27f17dd77358341cb3190c6abec6357daab1af105df8257f149c3d67c79"
}

rule MalwareBazaar_SalatStealer_048_62c9f98e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d"
    family = "SalatStealer"
    file_name = "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:38:38"
  condition:
    hash.sha256(0, filesize) == "62c9f98edf33cfb6af81790593aaab841e3a5806fe4ede7bfe1776d48d558c1d"
}

rule MalwareBazaar_SalatStealer_049_5d91e967
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5d91e967b6dc6ff678ff83a10bda5b04b87f34f9d886bf1138f593e411bcef99"
    family = "SalatStealer"
    file_name = "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:32:16"
  condition:
    hash.sha256(0, filesize) == "5d91e967b6dc6ff678ff83a10bda5b04b87f34f9d886bf1138f593e411bcef99"
}

rule MalwareBazaar_SalatStealer_050_7be9b26d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b"
    family = "SalatStealer"
    file_name = "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:31:45"
  condition:
    hash.sha256(0, filesize) == "7be9b26d9f166944bbd806ce9368927396705c3281f9a31da3df7beed3ab505b"
}

rule MalwareBazaar_unknown_051_f6225d34
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6"
    family = "unknown"
    file_name = "f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:31:34"
  condition:
    hash.sha256(0, filesize) == "f6225d34167de297b4a53048261e66df6e7c5c7a3f995d4dea4caae611ef12e6"
}

rule MalwareBazaar_WARDENStealer_052_215bd89f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f"
    family = "WARDENStealer"
    file_name = "215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:27:36"
  condition:
    hash.sha256(0, filesize) == "215bd89fa1c2a6c4e33079bf9a5fef306f59c5a8fc43336d3dc2efc62934ac7f"
}

rule MalwareBazaar_unknown_053_fc535f9a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fc535f9ad0af6b02b9e0a9448fc699493f76c7fce539275cda17183f17c669bb"
    family = "unknown"
    file_name = "fc535f9ad0af6b02.js"
    file_type = "js"
    first_seen = "2026-11-16 00:27:18"
  condition:
    hash.sha256(0, filesize) == "fc535f9ad0af6b02b9e0a9448fc699493f76c7fce539275cda17183f17c669bb"
}

rule MalwareBazaar_unknown_054_de0b3ca6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa"
    family = "unknown"
    file_name = "de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:23:35"
  condition:
    hash.sha256(0, filesize) == "de0b3ca680c665b3c7d5f97b773d3fbd4417849f36d5121e4b78972d40d784fa"
}

rule MalwareBazaar_unknown_055_41269193
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5"
    family = "unknown"
    file_name = "41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:14:38"
  condition:
    hash.sha256(0, filesize) == "41269193f2807fc7280a2b6afa5d679fff43dbdf5d2dcffd95d8f78ebf3fa9c5"
}

rule MalwareBazaar_WARDENStealer_056_98b3cfaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5"
    family = "WARDENStealer"
    file_name = "98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:14:31"
  condition:
    hash.sha256(0, filesize) == "98b3cfaf8f37bae7bf7d111971dec85a5b17e8b6f5c142e77b1f5d03c1bf76c5"
}

rule MalwareBazaar_unknown_057_0112160f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc"
    family = "unknown"
    file_name = "0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:14:25"
  condition:
    hash.sha256(0, filesize) == "0112160ffe71e1c8378ae0ffa2f0676ae9baa58a135de4df02a5965c9dc314fc"
}

rule MalwareBazaar_unknown_058_8e132450
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f"
    family = "unknown"
    file_name = "8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:13:31"
  condition:
    hash.sha256(0, filesize) == "8e132450a915266946a2049189551efb553b99efa96915c5f00e184f0ddae71f"
}

rule MalwareBazaar_unknown_059_d04d3959
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e"
    family = "unknown"
    file_name = "d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e.bin"
    file_type = "macho"
    first_seen = "2026-11-16 00:13:26"
  condition:
    hash.sha256(0, filesize) == "d04d3959f49981e09b3f9a06cab8a363a570839f1a89ff476a6191013b31601e"
}

rule MalwareBazaar_unknown_060_0d0a8119
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d0a8119baab1ace1a56f8ce2270c0c0b06aaeff72aa9fb9331fa0568dc13c69"
    family = "unknown"
    file_name = "0d0a8119baab1ace.js"
    file_type = "js"
    first_seen = "2026-11-16 00:12:21"
  condition:
    hash.sha256(0, filesize) == "0d0a8119baab1ace1a56f8ce2270c0c0b06aaeff72aa9fb9331fa0568dc13c69"
}

rule MalwareBazaar_Mirai_061_3439d854
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4"
    family = "Mirai"
    file_name = "3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:12:03"
  condition:
    hash.sha256(0, filesize) == "3439d85429affb3755c83b7dba93a209bc0abc0592ad5c028c8add99bc7d59a4"
}

rule MalwareBazaar_Snowlight_062_35d2a8f9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d"
    family = "Snowlight"
    file_name = "35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:11:57"
  condition:
    hash.sha256(0, filesize) == "35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d"
}

rule MalwareBazaar_unknown_063_8207337a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b"
    family = "unknown"
    file_name = "8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b.bin"
    file_type = "macho"
    first_seen = "2026-11-16 00:11:53"
  condition:
    hash.sha256(0, filesize) == "8207337a41518f7d03ed22d36be40f8c6f2eb1ce37bbea3cdab850899997874b"
}

rule MalwareBazaar_unknown_064_6cfe0479
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c"
    family = "unknown"
    file_name = "6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:09:32"
  condition:
    hash.sha256(0, filesize) == "6cfe047998db42363b8f73af1d39b93a4e899d2d52a5f5902c80a62d4b7ffa2c"
}

rule MalwareBazaar_Mirai_065_94b10cb6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a"
    family = "Mirai"
    file_name = "94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:09:26"
  condition:
    hash.sha256(0, filesize) == "94b10cb6cb7f640bd5c1445cef4749c60e3ba16d576b59a4076038bb64c78a0a"
}

rule MalwareBazaar_CoinMiner_066_4dcb0202
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d"
    family = "CoinMiner"
    file_name = "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:09:21"
  condition:
    hash.sha256(0, filesize) == "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d"
}

rule MalwareBazaar_Snowlight_067_e689fc21
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac"
    family = "Snowlight"
    file_name = "e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:08:27"
  condition:
    hash.sha256(0, filesize) == "e689fc21c768fd7467eee1ac020196b892ee6dc8c18b146c09acd6463e25f5ac"
}

rule MalwareBazaar_unknown_068_b2a245b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a"
    family = "unknown"
    file_name = "b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a.bin"
    file_type = "macho"
    first_seen = "2026-11-16 00:07:03"
  condition:
    hash.sha256(0, filesize) == "b2a245b35db086da55b2cd3eb1c302397d5691d2cedccaa992525f5bcccb9a0a"
}

rule MalwareBazaar_Mirai_069_e0a15e5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c"
    family = "Mirai"
    file_name = "e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:06:57"
  condition:
    hash.sha256(0, filesize) == "e0a15e5c83b4c1362596bd07763311372a227c1b4146b935367a80294c2cae2c"
}

rule MalwareBazaar_Snowlight_070_15a04b36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef"
    family = "Snowlight"
    file_name = "15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:06:52"
  condition:
    hash.sha256(0, filesize) == "15a04b36da1976031eeff634ff1da3627a71121e2ca9ad447311c94e1c5cbdef"
}

rule MalwareBazaar_Mirai_071_29b34620
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8"
    family = "Mirai"
    file_name = "29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8.elf"
    file_type = "elf"
    first_seen = "2026-11-16 00:03:25"
  condition:
    hash.sha256(0, filesize) == "29b34620572119a0053e5c32de8c84b9d9552814cb059f3ffe795e86c479bfb8"
}

rule MalwareBazaar_unknown_072_b516047d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0"
    family = "unknown"
    file_name = "b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:02:30"
  condition:
    hash.sha256(0, filesize) == "b516047dbfe91c6be195646abfb80f20219bd080ae44309255c37ef9d673aac0"
}

rule MalwareBazaar_Babadeda_073_d315b6d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00"
    family = "Babadeda"
    file_name = "d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00.exe"
    file_type = "exe"
    first_seen = "2026-11-16 00:02:23"
  condition:
    hash.sha256(0, filesize) == "d315b6d2da5d28f03fac5ff150444a3cb65ccbfce56f874b37c70e856ada7d00"
}

rule MalwareBazaar_unknown_074_08508c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d"
    family = "unknown"
    file_name = "SMBC-Card.apk"
    file_type = "apk"
    first_seen = "2026-11-15 23:55:07"
  condition:
    hash.sha256(0, filesize) == "08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d"
}

rule MalwareBazaar_Mirai_075_c3f64d23
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:47:04"
  condition:
    hash.sha256(0, filesize) == "c3f64d23ea037172fdb1269b1d2b89c52facde6140d7eb15f5e4ad8a962ab0ad"
}

rule MalwareBazaar_Mirai_076_2ef0ef30
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:44:04"
  condition:
    hash.sha256(0, filesize) == "2ef0ef302b23311fdb43a26c21a3bfc562e47bb999ca459d4b6c6fddb34e6fb8"
}

rule MalwareBazaar_Mirai_077_57392f84
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:33:04"
  condition:
    hash.sha256(0, filesize) == "57392f84cdbeb0cb45687f77f8e292a7b9b92a4f9e64d8aa90582e54b0a3d15c"
}

rule MalwareBazaar_unknown_078_b1c79034
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851"
    family = "unknown"
    file_name = "iitm"
    file_type = "elf"
    first_seen = "2026-11-15 23:24:29"
  condition:
    hash.sha256(0, filesize) == "b1c7903423b432c0f02d062651e311da188d0343a3b24928020239769cd7b851"
}

rule MalwareBazaar_unknown_079_3c96e346
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7"
    family = "unknown"
    file_name = "iitms.sh"
    file_type = "sh"
    first_seen = "2026-11-15 23:24:27"
  condition:
    hash.sha256(0, filesize) == "3c96e3462baf4b78904f53b32654717c145058bca04c7de9813e3bd6101b2fb7"
}

rule MalwareBazaar_Prometei_080_6bca3c88
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6bca3c88150ce668a6d4604a057701f1b1d2314d9e6c97f10d53232bcea94920"
    family = "Prometei"
    file_name = "zsvc"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:46"
  condition:
    hash.sha256(0, filesize) == "6bca3c88150ce668a6d4604a057701f1b1d2314d9e6c97f10d53232bcea94920"
}

rule MalwareBazaar_Prometei_081_1b063de4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68"
    family = "Prometei"
    file_name = "zsvc"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:44"
  condition:
    hash.sha256(0, filesize) == "1b063de46a6665198358d6844785f4bd13b0014715af7dccabdc8cdcc4fd5c68"
}

rule MalwareBazaar_Prometei_082_a3b45ae6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3b45ae61c66a2f87b03e734b079bdf17a7e0f4be4414fd1d224ed7945d4e4bc"
    family = "Prometei"
    file_name = "zsvc"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:42"
  condition:
    hash.sha256(0, filesize) == "a3b45ae61c66a2f87b03e734b079bdf17a7e0f4be4414fd1d224ed7945d4e4bc"
}

rule MalwareBazaar_unknown_083_3263f21b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3263f21b34e559f70585f232cfc2e929c56bb9c8ab97692c5955ff7a435d2f33"
    family = "unknown"
    file_name = "load.sh"
    file_type = "sh"
    first_seen = "2026-11-15 23:23:40"
  condition:
    hash.sha256(0, filesize) == "3263f21b34e559f70585f232cfc2e929c56bb9c8ab97692c5955ff7a435d2f33"
}

rule MalwareBazaar_unknown_084_19cbc525
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "19cbc5253a3c932c096f33660c557a200cc2fadf1908379f8323d9bae6fc4195"
    family = "unknown"
    file_name = "kworker"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:38"
  condition:
    hash.sha256(0, filesize) == "19cbc5253a3c932c096f33660c557a200cc2fadf1908379f8323d9bae6fc4195"
}

rule MalwareBazaar_unknown_085_26ee0255
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "26ee025519438aa7963d470639eeff1cb6f41d1c026a396e03acd142959d3f03"
    family = "unknown"
    file_name = "imp_amd64"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:36"
  condition:
    hash.sha256(0, filesize) == "26ee025519438aa7963d470639eeff1cb6f41d1c026a396e03acd142959d3f03"
}

rule MalwareBazaar_Mirai_086_a07605f2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95"
    family = "Mirai"
    file_name = "llx.apk"
    file_type = "apk"
    first_seen = "2026-11-15 23:23:10"
  condition:
    hash.sha256(0, filesize) == "a07605f271a730f2a1a736b1e471b9a6e8efbdef3f119f50efa5d319d83edd95"
}

rule MalwareBazaar_Mirai_087_c4fb9139
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:23:05"
  condition:
    hash.sha256(0, filesize) == "c4fb91392c9addcf0336d6fe32b773f1c01fc18b2b69097c7f5e9509dee3e384"
}

rule MalwareBazaar_Mirai_088_10eb259b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-11-15 23:22:48"
  condition:
    hash.sha256(0, filesize) == "10eb259b4fdd9b455c48c2c67d8c07466f6b83e8bb7a8ce83c35d1d834497a45"
}

rule MalwareBazaar_Mirai_089_b3d162cf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-11-15 23:22:46"
  condition:
    hash.sha256(0, filesize) == "b3d162cff7c3915acdf18fda0edccb9b8c04fc7ce8b6351aab515199e86edc50"
}

rule MalwareBazaar_Mirai_090_6ba0ddb2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d"
    family = "Mirai"
    file_name = "cc9x86"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:58"
  condition:
    hash.sha256(0, filesize) == "6ba0ddb2dc99ab116cb84d7b2a52446f9c0b5f9a69ee8383ccb8899206b3b50d"
}

rule MalwareBazaar_Mirai_091_b8b9264e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b8b9264e0acef29c0502c7836dfdcf9d9c13aaec23b04b37d0e167036a6f84e5"
    family = "Mirai"
    file_name = "cc9mips"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:56"
  condition:
    hash.sha256(0, filesize) == "b8b9264e0acef29c0502c7836dfdcf9d9c13aaec23b04b37d0e167036a6f84e5"
}

rule MalwareBazaar_Mirai_092_4a7af39b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4a7af39b0d7496404ee3c5435c46e99a831137ebf2d1b7fe62d0a0a62c658621"
    family = "Mirai"
    file_name = "cc9mpsl"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:54"
  condition:
    hash.sha256(0, filesize) == "4a7af39b0d7496404ee3c5435c46e99a831137ebf2d1b7fe62d0a0a62c658621"
}

rule MalwareBazaar_Gafgyt_093_eff6664c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eff6664c9de3d6bd06e88fa4edf5074e8d67efee8d9f35bbd5c80e051f53d5ae"
    family = "Gafgyt"
    file_name = "bins.sh"
    file_type = "sh"
    first_seen = "2026-11-15 23:21:52"
  condition:
    hash.sha256(0, filesize) == "eff6664c9de3d6bd06e88fa4edf5074e8d67efee8d9f35bbd5c80e051f53d5ae"
}

rule MalwareBazaar_Mirai_094_597eb916
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "597eb9162a0410ae7cd21d19ad14a8f94f04cb7ffa290c918dd8c4425fee16e5"
    family = "Mirai"
    file_name = "cc9sh4"
    file_type = "elf"
    first_seen = "2026-11-15 23:21:50"
  condition:
    hash.sha256(0, filesize) == "597eb9162a0410ae7cd21d19ad14a8f94f04cb7ffa290c918dd8c4425fee16e5"
}

rule MalwareBazaar_unknown_095_2fe1dfb1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fe1dfb1fe30ea13afafbc95663258018d46fae1cbee45b08ab8c5d68303d298"
    family = "unknown"
    file_name = "tot"
    file_type = "sh"
    first_seen = "2026-11-15 23:14:04"
  condition:
    hash.sha256(0, filesize) == "2fe1dfb1fe30ea13afafbc95663258018d46fae1cbee45b08ab8c5d68303d298"
}

rule MalwareBazaar_Mirai_096_f4ce200a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4ce200ae8377344546c5f6bc8e75b6165c66b934254b6c6f7f42ce145304da7"
    family = "Mirai"
    file_name = "na"
    file_type = "elf"
    first_seen = "2026-11-15 23:07:04"
  condition:
    hash.sha256(0, filesize) == "f4ce200ae8377344546c5f6bc8e75b6165c66b934254b6c6f7f42ce145304da7"
}

rule MalwareBazaar_WARDENStealer_097_435e9e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "435e9e9e3f5f53506e6c137a9565a42d096ac5ad47d59d93d41130f1d56a0bfe"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:39:16"
  condition:
    hash.sha256(0, filesize) == "435e9e9e3f5f53506e6c137a9565a42d096ac5ad47d59d93d41130f1d56a0bfe"
}

rule MalwareBazaar_WARDENStealer_098_aa1a7ce3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aa1a7ce32192a1984384d1e1d3d104537175b5103cd176887f5862476fe4d8e5"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:38:39"
  condition:
    hash.sha256(0, filesize) == "aa1a7ce32192a1984384d1e1d3d104537175b5103cd176887f5862476fe4d8e5"
}

rule MalwareBazaar_WARDENStealer_099_2537279c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2537279c002df00c699d275b4a9da608300ea85691ddf7f876a2bdf3620d17d6"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:38:14"
  condition:
    hash.sha256(0, filesize) == "2537279c002df00c699d275b4a9da608300ea85691ddf7f876a2bdf3620d17d6"
}

rule MalwareBazaar_WARDENStealer_100_5e444e38
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e444e380ac29fd399033b5e640ef8790defd964747a1f26e37200072ce0f1ef"
    family = "WARDENStealer"
    file_name = "jli.dll"
    file_type = "exe"
    first_seen = "2026-11-15 22:37:47"
  condition:
    hash.sha256(0, filesize) == "5e444e380ac29fd399033b5e640ef8790defd964747a1f26e37200072ce0f1ef"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

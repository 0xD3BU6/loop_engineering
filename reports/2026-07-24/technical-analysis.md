# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-07-24

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 687 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 687 |
| Unique family labels | 11 |
| Unique file types | 9 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| unknown | 45 |
| Mirai | 25 |
| RemusStealer | 11 |
| CoinMiner | 5 |
| WannaCry | 4 |
| ACRStealer | 3 |
| LummaStealer | 2 |
| SalatStealer | 2 |
| Vidar | 1 |
| Havoc | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| exe | 49 |
| elf | 26 |
| sh | 13 |
| xapk | 4 |
| dll | 3 |
| lnk | 2 |
| vbs | 1 |
| zip | 1 |
| unknown | 1 |

## Per-Sample Analysis

### Sample 1: `a26b11101cc94ce5`

| Field | Value |
|---|---|
| SHA-256 | `a26b11101cc94ce54f1de9a77bf5ff3a712fd4d21968ea24314d70bd27d68f23` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-24 03:17:05` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `17fcd6f3e5f7c5683e48cfb1cbd80265` |
| SHA-1 | `6d425c0b69013b76518d496f666db6cdfb080e23` |
| SHA-256 | `a26b11101cc94ce54f1de9a77bf5ff3a712fd4d21968ea24314d70bd27d68f23` |
| SHA3-384 | `be9e81297cd433ee576e5ca3236ae30b3838a33bfe20e229fd4c6798570e220e3748027b9362886367cac35d167c8ed5` |
| TLSH | `T1CC040A41F8104B57C6C22BBBBB9F439D37335B1897DB3301AA24AEB42F8679C1E29511` |
| TELFHASH | `t1947174a8953c01d9de630c1964ad6bf34887f12922e5bb19ff16ccc4085e82cf268d0f` |
| SSDEEP | `3072:TDfwbxgOGFc4wKdEJER2CRtR0HSFXBnOOvzBGwoUZaErar/nHUXD:yxgfFc4wKiJopRkHSmOvzBGwoUZaEraK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_001_a26b1110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a26b11101cc94ce54f1de9a77bf5ff3a712fd4d21968ea24314d70bd27d68f23"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-24 03:17:05"
  condition:
    hash.sha256(0, filesize) == "a26b11101cc94ce54f1de9a77bf5ff3a712fd4d21968ea24314d70bd27d68f23"
}
```

### Sample 2: `1e43c851beb648ef`

| Field | Value |
|---|---|
| SHA-256 | `1e43c851beb648efe1af0c38c829432f0c41ccc26147cbc525a03b1e08e8d973` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-24 03:16:04` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `56b255a39c89b070f83e3aab93765777` |
| SHA-1 | `5536a39d8c94ae72538db370980bf8705248a6ae` |
| SHA-256 | `1e43c851beb648efe1af0c38c829432f0c41ccc26147cbc525a03b1e08e8d973` |
| SHA3-384 | `33b0d9038705fef2f569a354c3343e6917c8eef5e842dbd423bc5ee3b008c18f6393474655494a3e2b6503f3866d7e87` |
| TLSH | `T1DD34C7067BA19EF7C89FDD3302E6860110CEF45722A56B6B7374D61CBA0A94F49D3C98` |
| TELFHASH | `t1947174a8953c01d9de630c1964ad6bf34887f12922e5bb19ff16ccc4085e82cf268d0f` |
| SSDEEP | `6144:SXnBrFB10H61A0xN/58WzvgreG3Ai/a9vNYzpWe:ErbIcAORzvgreG3Ai/a9vNYzpWe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_1e43c851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e43c851beb648efe1af0c38c829432f0c41ccc26147cbc525a03b1e08e8d973"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-24 03:16:04"
  condition:
    hash.sha256(0, filesize) == "1e43c851beb648efe1af0c38c829432f0c41ccc26147cbc525a03b1e08e8d973"
}
```

### Sample 3: `3409830b6430e24f`

| Field | Value |
|---|---|
| SHA-256 | `3409830b6430e24f032982a4d7e838e8a0ee2742f005341b47bc71ad2db1e0b2` |
| Family label | `Mirai` |
| File name | `ppc` |
| File type | `elf` |
| First seen | `2026-07-24 03:16:02` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4f7071d4b7b6f3a533c86bdde55bde20` |
| SHA-1 | `c3318c279c2d46f42a84a1a6c389d8545c82394c` |
| SHA-256 | `3409830b6430e24f032982a4d7e838e8a0ee2742f005341b47bc71ad2db1e0b2` |
| SHA3-384 | `2f9121f4ff5573aaad295c6e35f6cdb6193209edbd15b805a83bff92cbcac59d44a1a7c89f10c7bb30dc8f1649b622d4` |
| TLSH | `T1D7042B03771C0A83C15B6EF03AFB27F187ABE95115A66280F21FFE845332AB06559F95` |
| TELFHASH | `t1a87162a8953c01d9de630c1964ad6be34887f12922e5bb19ff16ccc4085e82cf268d0f` |
| SSDEEP | `3072:8jQYjLyxQactlYC6UrVO9GdjM5/GKTK6vFBv7oxXkl2CLf5QwD:8/uxQamlYFnWO/FTK6vFBv7oxXkl2CL1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_3409830b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3409830b6430e24f032982a4d7e838e8a0ee2742f005341b47bc71ad2db1e0b2"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-24 03:16:02"
  condition:
    hash.sha256(0, filesize) == "3409830b6430e24f032982a4d7e838e8a0ee2742f005341b47bc71ad2db1e0b2"
}
```

### Sample 4: `a431fc7aa495e684`

| Field | Value |
|---|---|
| SHA-256 | `a431fc7aa495e68464d9855922889d77d2878a2725dd7c0a1abd842005252d40` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-24 03:11:25` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8730b60cd657da3f8b4ad42c410014f` |
| SHA-1 | `fe86010a3574c0493a9bce1d36fa2e8a72baebb7` |
| SHA-256 | `a431fc7aa495e68464d9855922889d77d2878a2725dd7c0a1abd842005252d40` |
| SHA3-384 | `bbcb7c00d636731c78bc7a549f3f0aa4a2792662e3697c98d778ca4b02d13430ec3e179a5ef3d2fc3d3b8e3bd7ed3f80` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T1FCD5239675F22E71D477C7BA8F53F0BEB21A779587208D47B6CCA6409D2318868323B1` |
| SSDEEP | `49152:9NLKG2x4aRY+eCmuU12crBYC3l1s+0+nP7uS5Ukrjdmmr7nCVBg1i7GXn:rLox4aReD1VrtV1YKJmPm` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_004_a431fc7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a431fc7aa495e68464d9855922889d77d2878a2725dd7c0a1abd842005252d40"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 03:11:25"
  condition:
    hash.sha256(0, filesize) == "a431fc7aa495e68464d9855922889d77d2878a2725dd7c0a1abd842005252d40"
}
```

### Sample 5: `dfde30238bbc2c40`

| Field | Value |
|---|---|
| SHA-256 | `dfde30238bbc2c40f9ca5b3c94957365e2dbdb6eadd9c9818985e3feba023715` |
| Family label | `ACRStealer` |
| File name | `j.pm` |
| File type | `dll` |
| First seen | `2026-07-24 03:10:16` |
| Reporter | `monitorsg` |
| Tags | `ACRStealer, ClearFake, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8546fec6e6182afc6d35436e3b06b88a` |
| SHA-1 | `3c5b77e7a683b7c7c21046237fc75ff982b3b46e` |
| SHA-256 | `dfde30238bbc2c40f9ca5b3c94957365e2dbdb6eadd9c9818985e3feba023715` |
| SHA3-384 | `920848d1ec84b6560489d37a78a4652a38ee873a95db923bb4fff5ba62f6dca119b65ac0ac3eea0841a4548543118ed2` |
| IMPHASH | `0b5c5659cbf56f68ad96d88107958893` |
| TLSH | `T138C5A3C7020C598FCDA81DBDC7EC7B9A913E612D56648F8F651984FC2C12623BDA858F` |
| SSDEEP | `6144:wDjOiGrjnaVd1h+IGAsj5H0ABIt2FVpDKOSesulTNaGkMZ6P2+B5eRoL/H97Tuck:a+huWWdx4kKrOoaWEOWZP1ZM+f3I` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_005_dfde3023
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfde30238bbc2c40f9ca5b3c94957365e2dbdb6eadd9c9818985e3feba023715"
    family = "ACRStealer"
    file_name = "j.pm"
    file_type = "dll"
    first_seen = "2026-07-24 03:10:16"
  condition:
    hash.sha256(0, filesize) == "dfde30238bbc2c40f9ca5b3c94957365e2dbdb6eadd9c9818985e3feba023715"
}
```

### Sample 6: `cf61df96aceb14da`

| Field | Value |
|---|---|
| SHA-256 | `cf61df96aceb14da9491e399dc28e801c3d384ea2b2ec34f146b932f18f52f01` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-24 02:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a73ce131df29e09f554701010346f096` |
| SHA-1 | `dc238ce3b6e8d85c2e3780f7a6ae5630c3660bf3` |
| SHA-256 | `cf61df96aceb14da9491e399dc28e801c3d384ea2b2ec34f146b932f18f52f01` |
| SHA3-384 | `6f895b8e5a05a0d47691e0e04e682868cc594d8a0f82ab670985cc063821c940799782cebe3df3325e8406fdb18dae65` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T115E63348E6E021FFD0B3513CAAF11164B665B8BA2373CA8B437887229E072E54D7D757` |
| SSDEEP | `393216:SMFPkkpXKM6veI1cCXMCHWUjXxcuI3/PGTAI:SWskpXz6verCXMb8XmH/O7` |
| ICON-DHASH | `71f0f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_006_cf61df96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf61df96aceb14da9491e399dc28e801c3d384ea2b2ec34f146b932f18f52f01"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-24 02:52:08"
  condition:
    hash.sha256(0, filesize) == "cf61df96aceb14da9491e399dc28e801c3d384ea2b2ec34f146b932f18f52f01"
}
```

### Sample 7: `7fc5cb22a222d216`

| Field | Value |
|---|---|
| SHA-256 | `7fc5cb22a222d2162d9412af7cd0befd9d194482b0545900c496ad2a74fe5f8d` |
| Family label | `unknown` |
| File name | `com.pictureclean.cleanplan_1.2.6.xapk` |
| File type | `xapk` |
| First seen | `2026-07-24 02:46:05` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff3d0cb75537555755472eeb6aef5ea2` |
| SHA-1 | `1f39196d6d6d95316ae810302cad3a53a704e80c` |
| SHA-256 | `7fc5cb22a222d2162d9412af7cd0befd9d194482b0545900c496ad2a74fe5f8d` |
| SHA3-384 | `2962b2b4f6ed04f79b4567299556c491681941b502c7edc1ded155b2c274b2892901f27c1b6383911177d57bde736e2d` |
| TLSH | `T14817231AF36ED92FC9BB60324A66133161271C464A469B63BD14760D69B3EC49F3EFC0` |
| SSDEEP | `393216:hokn2rLDJ+WVcQk1Kkb/baQQclD45NmAwCK:fnUDwWCQUKOB5hINmA3K` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_007_7fc5cb22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fc5cb22a222d2162d9412af7cd0befd9d194482b0545900c496ad2a74fe5f8d"
    family = "unknown"
    file_name = "com.pictureclean.cleanplan_1.2.6.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:46:05"
  condition:
    hash.sha256(0, filesize) == "7fc5cb22a222d2162d9412af7cd0befd9d194482b0545900c496ad2a74fe5f8d"
}
```

### Sample 8: `01b8d27f31cf1b25`

| Field | Value |
|---|---|
| SHA-256 | `01b8d27f31cf1b2590e5eec4fe6da5d00da282cbee66149d48e2b6d615b92fc7` |
| Family label | `Vidar` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-24 02:45:17` |
| Reporter | `Bitsight` |
| Tags | `B, dropped-by-GCleaner, exe, PMIX0.file, signed, Vidar` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `77cf2430f64096aa293a04bbd03fda99` |
| SHA-1 | `16ca0ee1a711cc518c3ceb1d8ab7957ee814b508` |
| SHA-256 | `01b8d27f31cf1b2590e5eec4fe6da5d00da282cbee66149d48e2b6d615b92fc7` |
| SHA3-384 | `d4b0239b47071e0247647773372d932924b18c3ee088e80e0fc9121592ae9d62905bb5d4ca852edd14620f18f801a809` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1ABF59D03FC9248F9D4AAA2318DB652463B75BC091B3267DB2E60B6783F327E05D79714` |
| SSDEEP | `49152:sXo/Nn8vEM7Oz/r03TOJHe2W6ASlbeKU/mwM6HSqvzEHrbNpKem+hld9DoVivWg3:suLz/sgHRHlFUOwXHSOzEHrbNpvXoWF` |

#### Technical Assessment

- The sample is tracked as `Vidar` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Vidar_008_01b8d27f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01b8d27f31cf1b2590e5eec4fe6da5d00da282cbee66149d48e2b6d615b92fc7"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:17"
  condition:
    hash.sha256(0, filesize) == "01b8d27f31cf1b2590e5eec4fe6da5d00da282cbee66149d48e2b6d615b92fc7"
}
```

### Sample 9: `4852391f807c55bf`

| Field | Value |
|---|---|
| SHA-256 | `4852391f807c55bf92aa89c874b739add2d284e2669a9c9c51e8e7e76882fa8a` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-24 02:45:17` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, CoinMiner, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9df42833b7883f44a56e12204d97c8ca` |
| SHA-1 | `eda9f79a062f143ec604ce7abdec3c40e982d86a` |
| SHA-256 | `4852391f807c55bf92aa89c874b739add2d284e2669a9c9c51e8e7e76882fa8a` |
| SHA3-384 | `75723de3422e56f1a19e914695b93b0c1d3a3b767563f615f704118607e4842f0ce4ead815929c413d115062f2710099` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T12236331A68CA1076D093C3795547B06EB33A77558A62BD5B3FEC28448FA7F08653E3C2` |
| SSDEEP | `98304:GccPqYITGlGCR360AKhYpFZ2VNGduxQ5HSb4YDggsZLqURh9YC2TARCAP:V+qfTiGI3iNrZ2VNorBS3Dgg8GURh9Yi` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_009_4852391f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4852391f807c55bf92aa89c874b739add2d284e2669a9c9c51e8e7e76882fa8a"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:17"
  condition:
    hash.sha256(0, filesize) == "4852391f807c55bf92aa89c874b739add2d284e2669a9c9c51e8e7e76882fa8a"
}
```

### Sample 10: `f2b90487ccf96640`

| Field | Value |
|---|---|
| SHA-256 | `f2b90487ccf966408996bd182314719a9be80a95a6e646cf71b98055be58691e` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-24 02:45:10` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `94286af26c9a9621483324dd64279afe` |
| SHA-1 | `270f3959b09da9a2425b95de3cb8ea073c300ffb` |
| SHA-256 | `f2b90487ccf966408996bd182314719a9be80a95a6e646cf71b98055be58691e` |
| SHA3-384 | `4072f1df5ce6e2601e72e934342d254809283135e0f0b68e329873c17c0c43c83795321ba9f994e7cd2c23fed64ddf84` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T181D52299A8F25D74C872C3B68F02E43EB465BB418B218D53FACDBA419E136056CB7371` |
| SSDEEP | `49152:0dMcgt44sLe4uQylQLVy5d7EJlNksLyVHWnwbtO0Nwtam/WcAl1:0ZbLFuQylQLSwJ4HtO+0bWv1` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_010_f2b90487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b90487ccf966408996bd182314719a9be80a95a6e646cf71b98055be58691e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:10"
  condition:
    hash.sha256(0, filesize) == "f2b90487ccf966408996bd182314719a9be80a95a6e646cf71b98055be58691e"
}
```

### Sample 11: `da97b7a5526123b0`

| Field | Value |
|---|---|
| SHA-256 | `da97b7a5526123b0c6e19b97d1a0fce298421d4762c42d2531956a05e6800527` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-24 02:45:01` |
| Reporter | `Bitsight` |
| Tags | `6e7868436f4d3b49f375773379ba9022, dropped-by-remus, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `638b5cd6de617fe14d37aad28dc18814` |
| SHA-1 | `37537be80e2c45635e3d7ff9b3f5fcaf17d6d5a9` |
| SHA-256 | `da97b7a5526123b0c6e19b97d1a0fce298421d4762c42d2531956a05e6800527` |
| SHA3-384 | `2e2bea89a475df6a2f1429c899bc7ce7f390fc1e4611372a7f9e4535012d7c20fd8afe2b4ef55f85a43c3c6e27e33353` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T111E5238CFCE27274F032D3F3539324EEB12D77599A759C9D3AC827205D11518AC3A6AA` |
| SSDEEP | `49152:ZX6LmM/o8zRZoOjvWEAg3OQhdvUnTLN6YO/a5BuV2aQxUBg7f8RfsqmASCepgqBP:dFeosRZoO1Ag3ObLN1BzaPBbE/PCmBP` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_011_da97b7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da97b7a5526123b0c6e19b97d1a0fce298421d4762c42d2531956a05e6800527"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:01"
  condition:
    hash.sha256(0, filesize) == "da97b7a5526123b0c6e19b97d1a0fce298421d4762c42d2531956a05e6800527"
}
```

### Sample 12: `5b024a63ee25fd79`

| Field | Value |
|---|---|
| SHA-256 | `5b024a63ee25fd79958bc723626d82fca9fac59828047b67dd986c91d1c4c175` |
| Family label | `unknown` |
| File name | `com.cleanfile.managerapp.coolfile_1.3.35.xapk` |
| File type | `xapk` |
| First seen | `2026-07-24 02:39:10` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd380fe51c98a268df0ea811c1d876cd` |
| SHA-1 | `2b9a38c8a0b5f34bc9a768264b3aa75d457e3c8c` |
| SHA-256 | `5b024a63ee25fd79958bc723626d82fca9fac59828047b67dd986c91d1c4c175` |
| SHA3-384 | `9a6d5246db8d90b9892680159a1b96158c51517f16eb409f720ab61c8bd71b4b8a54dd1b57f13c36f89c351f65e6c83d` |
| TLSH | `T173869D16AA323C31D61DD7B54DFE1749B3302ADB97D383831AA0A4E46F933C1571A6E8` |
| SSDEEP | `98304:J9j9/QtdP9OMnrcPC+axjQ1+1/htqErPEjE:tYLdn4PTaftqErs4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_5b024a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b024a63ee25fd79958bc723626d82fca9fac59828047b67dd986c91d1c4c175"
    family = "unknown"
    file_name = "com.cleanfile.managerapp.coolfile_1.3.35.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:39:10"
  condition:
    hash.sha256(0, filesize) == "5b024a63ee25fd79958bc723626d82fca9fac59828047b67dd986c91d1c4c175"
}
```

### Sample 13: `896620fec435d32e`

| Field | Value |
|---|---|
| SHA-256 | `896620fec435d32e0d65a8933f91fa41156f1ebaf45ec9a7f1f8a45f2cea18f8` |
| Family label | `unknown` |
| File name | `Go+Clean+Pro_2.0.8.xapk` |
| File type | `xapk` |
| First seen | `2026-07-24 02:36:59` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c8d908a085637acbc0ff0a88ea79f1b3` |
| SHA-1 | `755133883e4feba9c3c55d8187f99f308d7c03c3` |
| SHA-256 | `896620fec435d32e0d65a8933f91fa41156f1ebaf45ec9a7f1f8a45f2cea18f8` |
| SHA3-384 | `32b517a0ba059c24c40b1315e71b486c3e80549aef30a5eb800e87ae22f2ed34f4d725eae7f4b9bdecfee84fda1a1424` |
| TLSH | `T14E37224BD71DE86FD9D7A1798D3902239527AC219343D3D36921B12CADB3AC69F08BD0` |
| SSDEEP | `393216:KPLgXPhcMlhtd5iHZFqSIKXQALo/9JdcqCNRqQEIikZ0FRAskgNomIGDyljsPmE7:sL6hcMnoZYqXlUJd30hiJbkgNoOmjqjt` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_013_896620fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896620fec435d32e0d65a8933f91fa41156f1ebaf45ec9a7f1f8a45f2cea18f8"
    family = "unknown"
    file_name = "Go+Clean+Pro_2.0.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:36:59"
  condition:
    hash.sha256(0, filesize) == "896620fec435d32e0d65a8933f91fa41156f1ebaf45ec9a7f1f8a45f2cea18f8"
}
```

### Sample 14: `3c29697459936163`

| Field | Value |
|---|---|
| SHA-256 | `3c296974599361635eed48f91f3bfe43d09b4375deb0f7cc582b33874f06cfdb` |
| Family label | `unknown` |
| File name | `com.shrtsms.xxmessages_5.6.xapk` |
| File type | `xapk` |
| First seen | `2026-07-24 02:30:46` |
| Reporter | `anonymous` |
| Tags | `Joker, Malware, xapk` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bd90a300ae347b9882d2c3f6ae187dc7` |
| SHA-1 | `882d1ccc351303c92c938290f0e36dff4b9ce04f` |
| SHA-256 | `3c296974599361635eed48f91f3bfe43d09b4375deb0f7cc582b33874f06cfdb` |
| SHA3-384 | `774ec83222ec8c09f0d4a78192f58874d8d1101efa3a79447f9911f8c6291f63596bd046983ac42412f07e1a02bc19d7` |
| TLSH | `T16437128ADB6CF91AD876243BCC5D43337E0A96319BC296F63261070869575F3DB483E8` |
| SSDEEP | `393216:m6ss0u9beAtpmMc+JC5el5CR+g/yolTQq5OINJwdvBbjuUFHrhEdKT/NpuDdMwSW:m5svKAGMzJHqR+gqoL5OINKdZbjnLh12` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `xapk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_014_3c296974
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c296974599361635eed48f91f3bfe43d09b4375deb0f7cc582b33874f06cfdb"
    family = "unknown"
    file_name = "com.shrtsms.xxmessages_5.6.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:30:46"
  condition:
    hash.sha256(0, filesize) == "3c296974599361635eed48f91f3bfe43d09b4375deb0f7cc582b33874f06cfdb"
}
```

### Sample 15: `642905ce09772b7e`

| Field | Value |
|---|---|
| SHA-256 | `642905ce09772b7ee37efac563f1d14581b2d677a738aa8f44244659d331f921` |
| Family label | `unknown` |
| File name | `TENDER-20005953911.vbs` |
| File type | `vbs` |
| First seen | `2026-07-24 02:22:58` |
| Reporter | `threatcat_ch` |
| Tags | `vbs` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f52d4fd0fed3a7a77b8c1dcf6463ebea` |
| SHA-1 | `310ae09bbecf35553ca6d73ac4c642f41590abc4` |
| SHA-256 | `642905ce09772b7ee37efac563f1d14581b2d677a738aa8f44244659d331f921` |
| SHA3-384 | `05230bfeba16db559580ae0427b832a47611096ac060e94ad091999b5b950a45298fc99e72e7ff63239aea47516ac400` |
| TLSH | `T1B703EED6C4624FE35DD3C224F84CB340EE2DA4CAB96A6E155C1D7D0E80A0B5426B7DE9` |
| SSDEEP | `192:9RJj7tb0RZCURg0CxCr/E9CXpWWhC9r/ERC3R070O9CXwj7tb0RZCL/CKRO0pWWM:qDRB5i9N7fs2n7lr5/Y0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `vbs`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_015_642905ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "642905ce09772b7ee37efac563f1d14581b2d677a738aa8f44244659d331f921"
    family = "unknown"
    file_name = "TENDER-20005953911.vbs"
    file_type = "vbs"
    first_seen = "2026-07-24 02:22:58"
  condition:
    hash.sha256(0, filesize) == "642905ce09772b7ee37efac563f1d14581b2d677a738aa8f44244659d331f921"
}
```

### Sample 16: `6546d4bcaf4bd284`

| Field | Value |
|---|---|
| SHA-256 | `6546d4bcaf4bd2848d6f5d86def14961a312b482302a12c7850f5dd1d58601cf` |
| Family label | `ACRStealer` |
| File name | `j.pem` |
| File type | `dll` |
| First seen | `2026-07-24 02:07:29` |
| Reporter | `monitorsg` |
| Tags | `ACRStealer, ClearFake, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de1d167e0e42a518c464c5df1a687b21` |
| SHA-1 | `1c91259e7d9ba7bebaef410bfb9dce4325c437b8` |
| SHA-256 | `6546d4bcaf4bd2848d6f5d86def14961a312b482302a12c7850f5dd1d58601cf` |
| SHA3-384 | `ea57136c5a686872df155acbd6ddcd512c2ad6bb66833df3777d36d433731c9aefb2622628bd5992b07f19f285b18ab1` |
| IMPHASH | `0b5c5659cbf56f68ad96d88107958893` |
| TLSH | `T12BC593DA0629188FDE781CBEDBEC7BAA445C646806705F9B1D01C0F82D065637DEA78F` |
| SSDEEP | `12288:iLtNKzwpHj8CS49hIW0SBegWR4P94Hk9N2D6aQF080bZJuvRtf/UCHbGOIr2Y:m0dksyzD0` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_016_6546d4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6546d4bcaf4bd2848d6f5d86def14961a312b482302a12c7850f5dd1d58601cf"
    family = "ACRStealer"
    file_name = "j.pem"
    file_type = "dll"
    first_seen = "2026-07-24 02:07:29"
  condition:
    hash.sha256(0, filesize) == "6546d4bcaf4bd2848d6f5d86def14961a312b482302a12c7850f5dd1d58601cf"
}
```

### Sample 17: `f4eabc26ada6bbe0`

| Field | Value |
|---|---|
| SHA-256 | `f4eabc26ada6bbe04591abbcbbefd73a4e9c517508a2c45cec565c434c462974` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-24 02:04:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `33af9d47b1efc1b9adb163eb4c393fa7` |
| SHA-1 | `44092f321336d5bc4c006a42af822cabdf395d0d` |
| SHA-256 | `f4eabc26ada6bbe04591abbcbbefd73a4e9c517508a2c45cec565c434c462974` |
| SHA3-384 | `290742914852c0a37bd31722dd5a29c1514cadc5b9771e597adf495ac9f011bbc0099ab39584bbf2b2bf0e53fd2bd7f6` |
| TLSH | `T166C31902B9C18DFDC085C134577FB93AD825F0AE0238B2AB6BD4AF27694DED11A1DE45` |
| TELFHASH | `t14a217b742ee7395ca2d7438a730fee3ad5f20a216cc2b5969f0b7dd88905fc41d82462` |
| SSDEEP | `3072:nHPA2sqGzlNlHN4SsvHICh9eARJCURIFfrTl0ihXN7r:nvA2sqGzlNlt4SyHIC3EtThXN7r` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_017_f4eabc26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4eabc26ada6bbe04591abbcbbefd73a4e9c517508a2c45cec565c434c462974"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-24 02:04:49"
  condition:
    hash.sha256(0, filesize) == "f4eabc26ada6bbe04591abbcbbefd73a4e9c517508a2c45cec565c434c462974"
}
```

### Sample 18: `6b232621c7d31c73`

| Field | Value |
|---|---|
| SHA-256 | `6b232621c7d31c73bee8fd4462106f68b9a060810a504ce4383470cd9c0c47d4` |
| Family label | `Mirai` |
| File name | `nz.x86_64` |
| File type | `elf` |
| First seen | `2026-07-24 02:03:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6637ece78593a2d04c6b7d10a7fc535f` |
| SHA-1 | `f47288984e2d4860787ac493506395134bd0e179` |
| SHA-256 | `6b232621c7d31c73bee8fd4462106f68b9a060810a504ce4383470cd9c0c47d4` |
| SHA3-384 | `fe109bd0fc9c7273713fec471e6d1d40cd8a6bd43ce0c268c48e8e06aa35eb4e16a3ee0f311e33d6df53065fb1655702` |
| TLSH | `T1AE23F2B36137A9F9C91E31F720AFF684BA72F88245231727418979FF6357986A631103` |
| SSDEEP | `768:XU0rM9TBFAddLNB8SZ/ppI4ZF2DbK9zh5W8dFkXofVPYATTN8H4x02x:ESMJBWdLb/ZES9zhpX3BYcvDx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_018_6b232621
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b232621c7d31c73bee8fd4462106f68b9a060810a504ce4383470cd9c0c47d4"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-24 02:03:32"
  condition:
    hash.sha256(0, filesize) == "6b232621c7d31c73bee8fd4462106f68b9a060810a504ce4383470cd9c0c47d4"
}
```

### Sample 19: `53d826779abf284e`

| Field | Value |
|---|---|
| SHA-256 | `53d826779abf284ea492ff4c09865e1566c3c62836c28d3c5ad7729f0a8d523a` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-24 01:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5174460710efac2beec5915d5ac0de7a` |
| SHA-1 | `7ca4e69dfb8f3e2b6027e933e216cdaa92ee482d` |
| SHA-256 | `53d826779abf284ea492ff4c09865e1566c3c62836c28d3c5ad7729f0a8d523a` |
| SHA3-384 | `efce47c7ea3c93c7cd90b170e56b9a0d7c3163b3d14521a9b89878dc4f76465e5392cb7740e889939e182724b8b260ce` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T1BEE6330CAC9011FAE5B3113CBEE06189E4A6B4960775C6DF97E887B9EE531E0493DB43` |
| SSDEEP | `393216:/oVIGnFXh1MV0Th3k95HQU3YXMCHWUjXIcuI3/PGTAI:/oVIGFMV0l3k9UXMb8X9H/O7` |
| ICON-DHASH | `71f8d0f0e0e8f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_019_53d82677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53d826779abf284ea492ff4c09865e1566c3c62836c28d3c5ad7729f0a8d523a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-24 01:52:08"
  condition:
    hash.sha256(0, filesize) == "53d826779abf284ea492ff4c09865e1566c3c62836c28d3c5ad7729f0a8d523a"
}
```

### Sample 20: `d96053c4a362bf44`

| Field | Value |
|---|---|
| SHA-256 | `d96053c4a362bf445aed2840f95f6014d0acec1f3710c1cd3ea1a8e2f2a7c379` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-24 01:17:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2d478441e93854bd2e9bd475fd9c1e44` |
| SHA-1 | `d811135137dcd9b4c61661721a2bc8aee7de1843` |
| SHA-256 | `d96053c4a362bf445aed2840f95f6014d0acec1f3710c1cd3ea1a8e2f2a7c379` |
| SHA3-384 | `82efff055302ccb0b404f046931148271dbe9453f30dd5b252ed3715dcdb227fe3fc22e5b43f86abfbcd9bead3472715` |
| TLSH | `T17DC32A41F8829622C6D727BAF66E21CD332163E9E3DB7107CE255F21378658B0D67B81` |
| TELFHASH | `t1b531c157ef501bdc27f5869890b9e42611fc35dc1e2022065b2cab9b8cc39d9b01d92b` |
| SSDEEP | `1536:ub4vAze7/gUOBeVhEN10hb3j6GuMRrOrvzB2/PUpqhyMyKJ1/jIt+3EczvSHF5l:ub4vAJUO74EMPEqhFDBSHF5l` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_020_d96053c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96053c4a362bf445aed2840f95f6014d0acec1f3710c1cd3ea1a8e2f2a7c379"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-24 01:17:25"
  condition:
    hash.sha256(0, filesize) == "d96053c4a362bf445aed2840f95f6014d0acec1f3710c1cd3ea1a8e2f2a7c379"
}
```

### Sample 21: `5bafd8445d3cefd6`

| Field | Value |
|---|---|
| SHA-256 | `5bafd8445d3cefd61274fa18b4dc51fa53de1a9d37bbea6a88c126d0b910964f` |
| Family label | `Mirai` |
| File name | `nz.arm` |
| File type | `elf` |
| First seen | `2026-07-24 01:17:21` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1439a45250bca7d28fbd0d3230bb2c90` |
| SHA-1 | `abd494ed1b4718468c0857d8235547151e7eb99b` |
| SHA-256 | `5bafd8445d3cefd61274fa18b4dc51fa53de1a9d37bbea6a88c126d0b910964f` |
| SHA3-384 | `bcce4a8a1f4efbfbf74844ef58fa9b12bb5bf250e383a080e1a86b2162148bd52acbee59b1f6ecc2193793e243f69ee5` |
| TLSH | `T19B2301118C03EDB0EFB1BE3DD2B6D4823E8747B0D624345911C844966266F4BB2FA68F` |
| SSDEEP | `768:dpC1BRBzk/mUMkDoYzQB0+fEoYppb5oKbYv8B8BHdr1L8uZfL77nHEo3YNH0VWAF:d09IJkB0+MoYhzYTrxlEo3i4N4+zJ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_021_5bafd844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bafd8445d3cefd61274fa18b4dc51fa53de1a9d37bbea6a88c126d0b910964f"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-24 01:17:21"
  condition:
    hash.sha256(0, filesize) == "5bafd8445d3cefd61274fa18b4dc51fa53de1a9d37bbea6a88c126d0b910964f"
}
```

### Sample 22: `30d51cc7e46c06f9`

| Field | Value |
|---|---|
| SHA-256 | `30d51cc7e46c06f93cf8d5589611ef5555eb22ae54d420bb9dae8d01164d51ba` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-24 01:00:07` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9a6f548604fac0b4a135dd83080cf8d6` |
| SHA-1 | `ffb4acf8d4daf449b356c12c4488cbed5d128854` |
| SHA-256 | `30d51cc7e46c06f93cf8d5589611ef5555eb22ae54d420bb9dae8d01164d51ba` |
| SHA3-384 | `ef9da2e94543f43a6cfb5b63c424385177dc8b58942e9a7d7423206b4bd2f8424f81721abde08894168177578df57e37` |
| TLSH | `T147C28D966A867C44BDC98A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C12F9CD618B1A` |
| SSDEEP | `768:i8vCB+25j6es8Ra9FYpMSUpi+20qUpi+20YQX:i8l25JMd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_022_30d51cc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30d51cc7e46c06f93cf8d5589611ef5555eb22ae54d420bb9dae8d01164d51ba"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-24 01:00:07"
  condition:
    hash.sha256(0, filesize) == "30d51cc7e46c06f93cf8d5589611ef5555eb22ae54d420bb9dae8d01164d51ba"
}
```

### Sample 23: `5b5785181f501722`

| Field | Value |
|---|---|
| SHA-256 | `5b5785181f5017228be7f0cd094a4e9eef4a90dde8e9f927eefcab320efce782` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-24 00:57:37` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9daad0ff27cdf2518d5a656d94157fec` |
| SHA-1 | `0c73a88856b95c4661e001fa6c36fb1c24eeb591` |
| SHA-256 | `5b5785181f5017228be7f0cd094a4e9eef4a90dde8e9f927eefcab320efce782` |
| SHA3-384 | `2c2ffccc96b1d80269ddbd0f8e2db337c7ca1ab8efe4332e2c51f81d60ef13da4912ec4d806b999ddd1b7f99d642b5c3` |
| IMPHASH | `f4ba87d240d23c07beba123157bb57f8` |
| TLSH | `T1B7E5338BFB023108F69B657569894E67B07225C149012B3DA4E1EFB79C373CD913E9CA` |
| SSDEEP | `49152:2fBCJqk7E3jz7WhagEmAtFtNIAgynYmMXoLlDn1A9rHLfgk75hJUEPbVnNboz0br:2fB8qIuH9/D/3jWXu1ANsk7eOZnNNbr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_5b578518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5785181f5017228be7f0cd094a4e9eef4a90dde8e9f927eefcab320efce782"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 00:57:37"
  condition:
    hash.sha256(0, filesize) == "5b5785181f5017228be7f0cd094a4e9eef4a90dde8e9f927eefcab320efce782"
}
```

### Sample 24: `5654de2cff9abd8e`

| Field | Value |
|---|---|
| SHA-256 | `5654de2cff9abd8eb423a4b396a30aa374020eb35ec6246bce863445e7656b67` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-24 00:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3bfb985f23d9e7f7add58c773720c34` |
| SHA-1 | `afd95ecef33050f6fc3230412398e8c563a74f39` |
| SHA-256 | `5654de2cff9abd8eb423a4b396a30aa374020eb35ec6246bce863445e7656b67` |
| SHA3-384 | `f6162612fb57b6c482b5b697e36c875ad383d0f6d9cf94687497029709b1fcd4747c7cc92e39fd7725ed239a9de7031e` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T15EE63354F7F012DEE6B3413DAED168D4E416B0711B71CA6F036842B9BE6B1E24E38B52` |
| SSDEEP | `393216:RY2TsVN+b0KudQvc9Luzf9GnVWWXMCHWUjXOcuI3/PGTAI:R1s6b0KudQvc5cf9GcWXMb8XjH/O7` |
| ICON-DHASH | `70f8f8dccce4f070` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_024_5654de2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5654de2cff9abd8eb423a4b396a30aa374020eb35ec6246bce863445e7656b67"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-24 00:52:08"
  condition:
    hash.sha256(0, filesize) == "5654de2cff9abd8eb423a4b396a30aa374020eb35ec6246bce863445e7656b67"
}
```

### Sample 25: `e29d2acf2b80343d`

| Field | Value |
|---|---|
| SHA-256 | `e29d2acf2b80343dbe5c7f7a878ee599da6560ea5d26e90d240b2d25509b5161` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-24 00:49:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cbae845676411c9c7c6514de79e62224` |
| SHA-1 | `2b134765d9c6d3bbf486e217e1658b750e75a074` |
| SHA-256 | `e29d2acf2b80343dbe5c7f7a878ee599da6560ea5d26e90d240b2d25509b5161` |
| SHA3-384 | `d849b363fdef98b88d064f74d3e9d822d0bc16fb556b0b840ee93ca39d98d652a12fe09a4c1a1e1545b8d1c2aaf621c5` |
| TLSH | `T13FB34CC4E643D1F9EC6705302136FB3B9E72E4BA112DDA43D7F89A66BC52681C80679C` |
| TELFHASH | `t19631c5b8616608986bc09842b18daf32cd1e272b321477fb4df7652531a3592877bc39` |
| SSDEEP | `3072:50U2ysTT8NIsq7VMQ3bXh14fd+S2NUsDEHHUnwnx:50U2ysTsIsq7OaXh1fEHHUwx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_e29d2acf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e29d2acf2b80343dbe5c7f7a878ee599da6560ea5d26e90d240b2d25509b5161"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-24 00:49:48"
  condition:
    hash.sha256(0, filesize) == "e29d2acf2b80343dbe5c7f7a878ee599da6560ea5d26e90d240b2d25509b5161"
}
```

### Sample 26: `9f6476d569eb59de`

| Field | Value |
|---|---|
| SHA-256 | `9f6476d569eb59de3436b98b4001177b1b8cf4c723f9b23f7917eaec4de09ba9` |
| Family label | `Mirai` |
| File name | `nz.x86` |
| File type | `elf` |
| First seen | `2026-07-24 00:49:25` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0114f64c9e52255050f9578f27d8f9c8` |
| SHA-1 | `9c2a1e285491291493a2b37fac32d2aaf495d8bd` |
| SHA-256 | `9f6476d569eb59de3436b98b4001177b1b8cf4c723f9b23f7917eaec4de09ba9` |
| SHA3-384 | `fd5a38251780a08661a595352e93eb219b5914adf50b32b7ef8d0554f80d8af9ec46db4157e7cd204094bb7b838d7143` |
| TLSH | `T1D82301E3967F69EEF37D10BA4CD4BA0E2F44AD01433D54A7EBC834A509D6F52A604B90` |
| SSDEEP | `768:JFP/mPbUrMr/YGuMRXsXmi960F4FnLH++NVn3QSoOyn26R+7PUS+cZ4OeYznCnbh:JFPUbDr/ZRs6T0+NOOK26Q7MBYGnouyq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_9f6476d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f6476d569eb59de3436b98b4001177b1b8cf4c723f9b23f7917eaec4de09ba9"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-24 00:49:25"
  condition:
    hash.sha256(0, filesize) == "9f6476d569eb59de3436b98b4001177b1b8cf4c723f9b23f7917eaec4de09ba9"
}
```

### Sample 27: `890d12eb74c66e0e`

| Field | Value |
|---|---|
| SHA-256 | `890d12eb74c66e0e05848d307cf0c111f1cc63377a22f65cd70ef837ab850827` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-24 00:48:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `84cf64311987d2d12cc21ca51d0946f5` |
| SHA-1 | `2a610904b834d7f061342645862ac75a7daff310` |
| SHA-256 | `890d12eb74c66e0e05848d307cf0c111f1cc63377a22f65cd70ef837ab850827` |
| SHA3-384 | `013b714376541f246a336e598619c0ca8654dad8f9e6c6add9d747e84f8da625a9f479752e730ddd12c8ed14152a013c` |
| TLSH | `T13DC31980F58F85F6C50B8D3060A6F63FDA31D5A981A3C66EDF949F72CA73581921238D` |
| TELFHASH | `t183313bb9f9660ced6fc04c03e34d9721ce0ee6bb382536bd19f6669036b25115079d39` |
| SSDEEP | `3072:SMi2qQo4lHF7O75FhI32k5sfP371+APRX9qsrHU:u2qQo4lH9C5TI3H6fJbCEHU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_890d12eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "890d12eb74c66e0e05848d307cf0c111f1cc63377a22f65cd70ef837ab850827"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-24 00:48:47"
  condition:
    hash.sha256(0, filesize) == "890d12eb74c66e0e05848d307cf0c111f1cc63377a22f65cd70ef837ab850827"
}
```

### Sample 28: `d4422ae2578d7643`

| Field | Value |
|---|---|
| SHA-256 | `d4422ae2578d764361e6b38c3ef4ba22663f3328ab958b785e5ab75672017dae` |
| Family label | `Mirai` |
| File name | `nz.i686` |
| File type | `elf` |
| First seen | `2026-07-24 00:48:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f190eefbd3b8f7474341700d0311e53b` |
| SHA-1 | `dcc9174eaa618efb7f7be67dbfaf4223e43662a1` |
| SHA-256 | `d4422ae2578d764361e6b38c3ef4ba22663f3328ab958b785e5ab75672017dae` |
| SHA3-384 | `262e4ec8ccdaa3e26c1ceffd9a5b0e2a5d7dc478eb516f2d96b1355efc33061e4e7b789cf53bd4a254486dcd5b876d94` |
| TLSH | `T18423F12941C8CA22F1AF01F58C3775591512C74621B9C6AACFC5A2835AFDB1EBE3D2D3` |
| SSDEEP | `1536:WiO/m0BemUNYmIz3/EoBjTGhoHIoC3eKLnouy8HyX:hOnBqIz/B/44jIboutA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_d4422ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4422ae2578d764361e6b38c3ef4ba22663f3328ab958b785e5ab75672017dae"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-24 00:48:16"
  condition:
    hash.sha256(0, filesize) == "d4422ae2578d764361e6b38c3ef4ba22663f3328ab958b785e5ab75672017dae"
}
```

### Sample 29: `8b0ed9933f178974`

| Field | Value |
|---|---|
| SHA-256 | `8b0ed9933f1789745e5553d79a5c3b471be1518a95fda91c96898d8281bf9388` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-24 00:44:29` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `454aecba993bc56b779954431eb10b5b` |
| SHA-1 | `c8f59c3035f0a84ebcb766fe07085e8be43f10a9` |
| SHA-256 | `8b0ed9933f1789745e5553d79a5c3b471be1518a95fda91c96898d8281bf9388` |
| SHA3-384 | `080dcb1269197df9c4be6c1e635e291764535aa1039f52c93b6bd8ba14a546d85592364032fb885ee62ce9a3fcad8093` |
| TLSH | `T112137D6956857C24AE99883B1C7E2F0CB9A983E1310451EDBFCB3CF58C19ADCE21971D` |
| SSDEEP | `768:k0+g9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:k0+dco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_029_8b0ed993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0ed9933f1789745e5553d79a5c3b471be1518a95fda91c96898d8281bf9388"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-24 00:44:29"
  condition:
    hash.sha256(0, filesize) == "8b0ed9933f1789745e5553d79a5c3b471be1518a95fda91c96898d8281bf9388"
}
```

### Sample 30: `d9de17aca9359bb1`

| Field | Value |
|---|---|
| SHA-256 | `d9de17aca9359bb153ec9d62bdfbeadb170e043616358f5f8eabc33a4a0c24ea` |
| Family label | `unknown` |
| File name | `launcher.dll` |
| File type | `exe` |
| First seen | `2026-07-24 00:09:36` |
| Reporter | `skocherhan` |
| Tags | `185-149-120-3, exe, undetected-always-com` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fe0b1723a840ba33d2891e1130547a82` |
| SHA-1 | `c3ccb08c1e3f9433b25967312932c52b3a503d59` |
| SHA-256 | `d9de17aca9359bb153ec9d62bdfbeadb170e043616358f5f8eabc33a4a0c24ea` |
| SHA3-384 | `96be09509a2249e9197defbc7d4bfb0c72ec78bf25ab245d14f296a258a0fc264bc4b8ce913dcfcf25af23769f6c67f2` |
| IMPHASH | `c2c82ee05fa0dfa58ae8f11d56986818` |
| TLSH | `T156F69D6BB9A900E9D47ED0B8CA436627F7717819437097CB16A057AA1F63BE05F3E340` |
| SSDEEP | `196608:igAI4gQnYFIl+V3fig/j5F+uQwz1Cfa5KtCC:ip3gQncIoV3figFFZQo1CfPoC` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_030_d9de17ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9de17aca9359bb153ec9d62bdfbeadb170e043616358f5f8eabc33a4a0c24ea"
    family = "unknown"
    file_name = "launcher.dll"
    file_type = "exe"
    first_seen = "2026-07-24 00:09:36"
  condition:
    hash.sha256(0, filesize) == "d9de17aca9359bb153ec9d62bdfbeadb170e043616358f5f8eabc33a4a0c24ea"
}
```

### Sample 31: `7c04b423f7277ee2`

| Field | Value |
|---|---|
| SHA-256 | `7c04b423f7277ee260c545f9c9f9ccd1ac46ccc19d622a9d4d7dbd27dfbbca7e` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-24 00:08:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d91bb84d08160e03369093aca9f3b62` |
| SHA-1 | `6824b0e0fb83febf27661d4daa51fd73a2cfbeb3` |
| SHA-256 | `7c04b423f7277ee260c545f9c9f9ccd1ac46ccc19d622a9d4d7dbd27dfbbca7e` |
| SHA3-384 | `40305d806b8901964d65642cf2f75a99e401a50f29537e2da7e4c6154f5a95afbb5d5b6e98785d58c0e2dc775037ace3` |
| TLSH | `T122C28D956A867C44BEC94A3E4CBD2B0D6DF5C3D1324952AC3D8B3C719C11FACC618B1A` |
| SSDEEP | `768:L8vCB+25j6es8RE9FYpMSUpi+20qUpi+20YQX:L8l25Jid2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_031_7c04b423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c04b423f7277ee260c545f9c9f9ccd1ac46ccc19d622a9d4d7dbd27dfbbca7e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-24 00:08:14"
  condition:
    hash.sha256(0, filesize) == "7c04b423f7277ee260c545f9c9f9ccd1ac46ccc19d622a9d4d7dbd27dfbbca7e"
}
```

### Sample 32: `29cb2a27e1da8d39`

| Field | Value |
|---|---|
| SHA-256 | `29cb2a27e1da8d39c121e5f1808ba68b9791b31110baceaac14d648ce4133611` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-24 00:08:13` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b9ade2e115096bd4024393569f87c139` |
| SHA-1 | `bcba133fa7fe0a05686f9c2472549725b039a03b` |
| SHA-256 | `29cb2a27e1da8d39c121e5f1808ba68b9791b31110baceaac14d648ce4133611` |
| SHA3-384 | `c594dcd14df10fc0d6c9800b3cfe0de921dfd8789c02e47e8a4bd25cab924960830ceccdd191852f96e9627db8e15c9e` |
| TLSH | `T1F3136C6566913C28AE9998371D7E1F0CBDAA83E2310491DDBFCB3CF18C59A9CD21871D` |
| SSDEEP | `768:3XRWNGxVP29GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:RlxRzco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_032_29cb2a27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29cb2a27e1da8d39c121e5f1808ba68b9791b31110baceaac14d648ce4133611"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-24 00:08:13"
  condition:
    hash.sha256(0, filesize) == "29cb2a27e1da8d39c121e5f1808ba68b9791b31110baceaac14d648ce4133611"
}
```

### Sample 33: `9c62ae7e69f26419`

| Field | Value |
|---|---|
| SHA-256 | `9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e` |
| Family label | `unknown` |
| File name | `9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e` |
| File type | `sh` |
| First seen | `2026-07-24 00:01:21` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f4473954168eeeaa3445f7fd7aa36fe3` |
| SHA-1 | `ca445484e635fdfcbf2bfef859ed67159a30ada8` |
| SHA-256 | `9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e` |
| SHA3-384 | `5d8177379d30785f2aa65c876206e710533da5a66f1472f1f6321ef77af0e07a14fdbda4f47778609cfa0442f10965c2` |
| TLSH | `T11331729E01105A362217CACEB7A33589B10C86FB2D9BD3D4D84C9FED52495CC7261FD9` |
| SSDEEP | `24:btT6TqdrQRH2h6JkeFt+pKz27QhkTT6OL+ccqQ:bpciQN2h6JkemKzaVYqQ` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_9c62ae7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e"
    family = "unknown"
    file_name = "9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e"
    file_type = "sh"
    first_seen = "2026-07-24 00:01:21"
  condition:
    hash.sha256(0, filesize) == "9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e"
}
```

### Sample 34: `9135685a26d5517c`

| Field | Value |
|---|---|
| SHA-256 | `9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95` |
| Family label | `unknown` |
| File name | `9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95` |
| File type | `sh` |
| First seen | `2026-07-24 00:00:59` |
| Reporter | `anonymous` |
| Tags | `cowrie, hermes-noc, honeypot, sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `73fce6d34602b7e5c7be0ba0b4c894b3` |
| SHA-1 | `1c822278f81525e5300a1854b0b90dd3f7677380` |
| SHA-256 | `9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95` |
| SHA3-384 | `0bae18abca8d80d74e672c4c40d27b33387fdb3666ba896ca03afc981c09924521e68580538fd89cdb7856e6a1742278` |
| TLSH | `T136314DDF44141A395613CADE73B33688A51C85FB289BDF94EC480EEE81495DC72A6FD0` |
| SSDEEP | `12:UbNi6bNhLkk72dc6+hmYwoDN/6NdPlJV6Jq9b96l7i6l7VB7O5DII6IfFtLo9nb7:IzRl2CmjwjrXfYfFloGpbm9H0lLly8xA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_034_9135685a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95"
    family = "unknown"
    file_name = "9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95"
    file_type = "sh"
    first_seen = "2026-07-24 00:00:59"
  condition:
    hash.sha256(0, filesize) == "9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95"
}
```

### Sample 35: `8363a28a214a59c1`

| Field | Value |
|---|---|
| SHA-256 | `8363a28a214a59c195ed87fd69d72bd766bc87bd949ba64b4706d0fe8eb8fd81` |
| Family label | `Mirai` |
| File name | `nz.spc` |
| File type | `elf` |
| First seen | `2026-07-23 23:57:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `99db0a77a7cd98e132b5732931ec0dc2` |
| SHA-1 | `9f420528b12dcf6c79fad7e1e6f24a9d893032d2` |
| SHA-256 | `8363a28a214a59c195ed87fd69d72bd766bc87bd949ba64b4706d0fe8eb8fd81` |
| SHA3-384 | `f117122dec4484bb8f4c555f7de5bef28a84eb61e41537a9c9a899bcb6c358eafe5dd378a94e1e410df947e042af4d7d` |
| TLSH | `T19AC36D22B5391E27C4E0947A12F75766F2F257CD14A8CA0E7E720E5EFF152902907BB8` |
| SSDEEP | `1536:UlITTILIMV1nW/cQM3PK8A6kT6ciM8GvTyEeodvcHyHq4gsawJ1AT9St+UQPYm5C:TmXH3SeoZHz1E0cUeYOQuIXSy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_8363a28a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8363a28a214a59c195ed87fd69d72bd766bc87bd949ba64b4706d0fe8eb8fd81"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-23 23:57:15"
  condition:
    hash.sha256(0, filesize) == "8363a28a214a59c195ed87fd69d72bd766bc87bd949ba64b4706d0fe8eb8fd81"
}
```

### Sample 36: `e8647ccecf457abe`

| Field | Value |
|---|---|
| SHA-256 | `e8647ccecf457abe547c4211d4bcde013492a904ed1675cf3e7abb4069eead1f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 23:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6c154a8bba08272231c01be87c450ff` |
| SHA-1 | `93f02968432ca15be4d77592184b8a215d8c6a21` |
| SHA-256 | `e8647ccecf457abe547c4211d4bcde013492a904ed1675cf3e7abb4069eead1f` |
| SHA3-384 | `19da2ecc7fc98274e1b6aea3e0055794139b451dcbab0c972deaa01eaf845656fa6a81eb5a26badbaa27ddd412f52e96` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T16EE6334C99E402EDF6B3503DE4E421E3D597746607B2CADB47B487E8AD232E18D39263` |
| SSDEEP | `393216:BNWVZbYK2kgNN4i14BjcPwXMCHWUjXFcuI3/PGTAI:B2YjkmNTgXMb8XyH/O7` |
| ICON-DHASH | `5471f0e8e8e0f030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_036_e8647cce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8647ccecf457abe547c4211d4bcde013492a904ed1675cf3e7abb4069eead1f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 23:52:08"
  condition:
    hash.sha256(0, filesize) == "e8647ccecf457abe547c4211d4bcde013492a904ed1675cf3e7abb4069eead1f"
}
```

### Sample 37: `8724f2b346f97cdb`

| Field | Value |
|---|---|
| SHA-256 | `8724f2b346f97cdba0d1aaaea8cc4d10ac5cf58a0b2fdbaf413db48b1ac8243e` |
| Family label | `Havoc` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 23:50:08` |
| Reporter | `Bitsight` |
| Tags | `d52f85, dropped-by-Amadey, exe, Havoc` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6206c459bad4054f64f2916532e44ce2` |
| SHA-1 | `b312eb1fb0d71b7e90bd9f05ca080c48f70beff1` |
| SHA-256 | `8724f2b346f97cdba0d1aaaea8cc4d10ac5cf58a0b2fdbaf413db48b1ac8243e` |
| SHA3-384 | `f57ac172d568e69ae651ec96f1794b6309f91536bd67bfebee2041ef4ae618c2c5e4a5785461f573cb49d1f057582f53` |
| IMPHASH | `3f050e1dac20c57b76b18bcc7e3839c4` |
| TLSH | `T18F849C936DD54CDBC905123B719E8231E6F8BEA085D28B1B6D1CB2350E33AF36DCA615` |
| SSDEEP | `6144:g02DzijfVQY6m+mPrQ3ZxDQKOCnHBJezfFc5Z/UAEwMP5iLLMdnwSPOoVd1l:OEfVQX8rsznhJyuXILYLwFwyO61l` |
| ICON-DHASH | `9595958595959595` |

#### Technical Assessment

- The sample is tracked as `Havoc` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Havoc_037_8724f2b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8724f2b346f97cdba0d1aaaea8cc4d10ac5cf58a0b2fdbaf413db48b1ac8243e"
    family = "Havoc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:50:08"
  condition:
    hash.sha256(0, filesize) == "8724f2b346f97cdba0d1aaaea8cc4d10ac5cf58a0b2fdbaf413db48b1ac8243e"
}
```

### Sample 38: `b7ce2cf4c4a9cf3a`

| Field | Value |
|---|---|
| SHA-256 | `b7ce2cf4c4a9cf3a2906bd3f53fff00f2c3e8ae4200451bf6194b00d94617490` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 23:29:40` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f547fc905221d41397fba715e7c578f` |
| SHA-1 | `e5183f5b14a57bc3e06ad108940757eaaa0eb948` |
| SHA-256 | `b7ce2cf4c4a9cf3a2906bd3f53fff00f2c3e8ae4200451bf6194b00d94617490` |
| SHA3-384 | `5bbb317f0b855da0d591daca994ef67120c0e8444edfd3ffe24f2d81cf940cfca1bd3c9285e40485ae2575493e862b3a` |
| IMPHASH | `3d303175fced9345f14b8a51817a6c63` |
| TLSH | `T111C5335A7128B7B0C91A4733E6050F3110D671D09F7B5AC70B961BB09A93AE64833EFB` |
| SSDEEP | `49152:VdB+Ul6gn/CSS8EHC9s6Au6TiB/BcZZMV9GdR1dYiERjVEBfVm8sRi:cU0gnKSS8ls6AFmTcjMzGouQR` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_038_b7ce2cf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7ce2cf4c4a9cf3a2906bd3f53fff00f2c3e8ae4200451bf6194b00d94617490"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:29:40"
  condition:
    hash.sha256(0, filesize) == "b7ce2cf4c4a9cf3a2906bd3f53fff00f2c3e8ae4200451bf6194b00d94617490"
}
```

### Sample 39: `ae8868d7d2ccc713`

| Field | Value |
|---|---|
| SHA-256 | `ae8868d7d2ccc713edea9da8988cb6668a2a4fb13b2942ebdf2c1bec10418fe0` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 23:09:29` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-phorpiex, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `12664b948f26835464650d6ccb052537` |
| SHA-1 | `eeedd839996e4051ed841d26e6f265f224670519` |
| SHA-256 | `ae8868d7d2ccc713edea9da8988cb6668a2a4fb13b2942ebdf2c1bec10418fe0` |
| SHA3-384 | `841b98434f38afd05f5e4661483bbffd973d7442986ed50a90128f4de92bdd4f27618d3f1794e209410919d5fd501fb3` |
| IMPHASH | `8fd6b27e4deb150227d1cf6ead9a96fb` |
| TLSH | `T115A36C2134C5C472E15621778865C7B58E2EF8700F36AACB7BC547AD8F266D2CE26387` |
| SSDEEP | `1536:DD8MoMpFwJQmJ2cpzLBdOpuSsxI+MUWo45QuW:38V5lpzLbO1VUT45QuW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_039_ae8868d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae8868d7d2ccc713edea9da8988cb6668a2a4fb13b2942ebdf2c1bec10418fe0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:09:29"
  condition:
    hash.sha256(0, filesize) == "ae8868d7d2ccc713edea9da8988cb6668a2a4fb13b2942ebdf2c1bec10418fe0"
}
```

### Sample 40: `051661deb65c018c`

| Field | Value |
|---|---|
| SHA-256 | `051661deb65c018c8c127fe12a6de824e6a72812db0091d505de1751e740b451` |
| Family label | `ACRStealer` |
| File name | `j.pem` |
| File type | `dll` |
| First seen | `2026-07-23 23:07:50` |
| Reporter | `monitorsg` |
| Tags | `ACRStealer, ClearFake, dll` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fcf169b75f09d0fa020b33ac1423a91b` |
| SHA-1 | `9d112519e4468c1a15f95d149fc4fb42598eea21` |
| SHA-256 | `051661deb65c018c8c127fe12a6de824e6a72812db0091d505de1751e740b451` |
| SHA3-384 | `da9512552846655dae37010d14230ce9c2eafe5081be9b015ddcceebc6c2f6181f2331e4e9fffaf3ece4c8ec63d999b0` |
| IMPHASH | `0b5c5659cbf56f68ad96d88107958893` |
| TLSH | `T115C5A5DA1119258FDC284CBDEFDC3FC599AE906951B85E8B8505E0FC7C46AA33CA904F` |
| SSDEEP | `12288:PRQvXa+kdlC+rNHUfoGnspVbX30mZNUbQPW2YB51tXcFB8ReWjIeWDLNMR6N1LaY:Z8q+7kNF04SNEO4P/uu8` |

#### Technical Assessment

- The sample is tracked as `ACRStealer` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_ACRStealer_040_051661de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "051661deb65c018c8c127fe12a6de824e6a72812db0091d505de1751e740b451"
    family = "ACRStealer"
    file_name = "j.pem"
    file_type = "dll"
    first_seen = "2026-07-23 23:07:50"
  condition:
    hash.sha256(0, filesize) == "051661deb65c018c8c127fe12a6de824e6a72812db0091d505de1751e740b451"
}
```

### Sample 41: `842cd640dae0c4ea`

| Field | Value |
|---|---|
| SHA-256 | `842cd640dae0c4eae792cfa2057774bbef7ccfe94cc8bcf3b189dbc03370e2d2` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 23:00:42` |
| Reporter | `Bitsight` |
| Tags | `54e64e, CoinMiner, dropped-by-Amadey, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d7fc03db4dbafa9111ff068ea6abf692` |
| SHA-1 | `601bc609b1ec105dfe3cd65d5880e440cb9c8121` |
| SHA-256 | `842cd640dae0c4eae792cfa2057774bbef7ccfe94cc8bcf3b189dbc03370e2d2` |
| SHA3-384 | `e424ef83b1258fae58ea5d4bff175ceeebaf8ee9249d47c1c1708b96bd2489225f0aa6ad7e25bc6fc89aad9d209b5787` |
| IMPHASH | `cf923ad36f44d7b4d8b61ed873ea4dc7` |
| TLSH | `T109C53358D3C1EF9FE36860FDC966A432B001A0615772F6EA7DD7C8BA97CD2851B39840` |
| SSDEEP | `49152:IM6Y/bKfQ7e6iOTJdEuHWtx9XRoJDFYT3bUWnCMsxhKXFTMU6t:IM6UbKfQ7eG3EuH8x9XRotFibUWnCMsV` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_041_842cd640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "842cd640dae0c4eae792cfa2057774bbef7ccfe94cc8bcf3b189dbc03370e2d2"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:00:42"
  condition:
    hash.sha256(0, filesize) == "842cd640dae0c4eae792cfa2057774bbef7ccfe94cc8bcf3b189dbc03370e2d2"
}
```

### Sample 42: `63c0d317645dc716`

| Field | Value |
|---|---|
| SHA-256 | `63c0d317645dc7169da2a6413cf1fcc8e300dd95af8c54ea06a4a3dc45a28275` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 22:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3547903e5ea6ddbec14c21c9a91d2000` |
| SHA-1 | `9f356fe1b075f9e76ffb28280d69f52f6121e5cc` |
| SHA-256 | `63c0d317645dc7169da2a6413cf1fcc8e300dd95af8c54ea06a4a3dc45a28275` |
| SHA3-384 | `e2d6b64661cfd98df3b7566d0c0bdd0bd915b2c505749e96d1923929568ef271e38d8d630a60d8b11faec4337f945723` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T198E6331C96E002FED9BB407DDED142A2D195B4A58773CBC7AB9843767D1B1A00C3EA1E` |
| SSDEEP | `196608:A7GvWDZrYaRJiQtDi1+A9kFnVZcrOqCXMCHGLLc54i1wN+MCyPIcu9KYK39sI3PJ:A7aWDWWyYYCXMCHWUjXdcuI3/PGTAI` |
| ICON-DHASH | `007860c0dcf9f104` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_042_63c0d317
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c0d317645dc7169da2a6413cf1fcc8e300dd95af8c54ea06a4a3dc45a28275"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 22:52:09"
  condition:
    hash.sha256(0, filesize) == "63c0d317645dc7169da2a6413cf1fcc8e300dd95af8c54ea06a4a3dc45a28275"
}
```

### Sample 43: `fe2e5dc794bf4beb`

| Field | Value |
|---|---|
| SHA-256 | `fe2e5dc794bf4bebe2092e45422fe5f9c5e8083e7ef32b5f9c17018941e19fa1` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-23 22:32:31` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4d50c4e095a68108c8602d9df24dc703` |
| SHA-1 | `0de5bb0435d34ef39e8711f8fd651cb14cd01234` |
| SHA-256 | `fe2e5dc794bf4bebe2092e45422fe5f9c5e8083e7ef32b5f9c17018941e19fa1` |
| SHA3-384 | `122c4d2f5587b60047c9f6d3a47cc27d92d1a712953b4520b4473e329a92da8e53b9d90046c32ac69500fe050bd9e23e` |
| TLSH | `T1A0C28D966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:0G8vCB+25j6es8RV9FYpMSUpi+20qUpi+20YQX:0G8l25Jzd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_043_fe2e5dc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe2e5dc794bf4bebe2092e45422fe5f9c5e8083e7ef32b5f9c17018941e19fa1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 22:32:31"
  condition:
    hash.sha256(0, filesize) == "fe2e5dc794bf4bebe2092e45422fe5f9c5e8083e7ef32b5f9c17018941e19fa1"
}
```

### Sample 44: `a172b48466dd433c`

| Field | Value |
|---|---|
| SHA-256 | `a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f` |
| Family label | `WannaCry` |
| File name | `a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f` |
| File type | `exe` |
| First seen | `2026-07-23 22:15:39` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7fafca318429821b25627fd61fc74b2f` |
| SHA-1 | `5ea9d359c111143bdfae6533b2c89c8e6315e71e` |
| SHA-256 | `a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f` |
| SHA3-384 | `b20e7ce31b76eb2977bbc448990c7718c1ab17582ebe439a674d1c9a82d8e9a9f54c586de77b160e3d48181d91727c85` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T153363358726CA1BCE045097444A38E16F7B33C6A67B9570F8B80B66B0D33B56FFA4742` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUDk36SAEdhvxWa9PB3R8yAVp2H:DXDqPe1Cxcxk3ZAEUadpR8yc4H` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_044_a172b484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f"
    family = "WannaCry"
    file_name = "a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f"
    file_type = "exe"
    first_seen = "2026-07-23 22:15:39"
  condition:
    hash.sha256(0, filesize) == "a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f"
}
```

### Sample 45: `7c1f748cb0bbf61e`

| Field | Value |
|---|---|
| SHA-256 | `7c1f748cb0bbf61e14a4b8170004ff8ece96a9a7838a4972c7b0ca92af35c53f` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 21:52:09` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `564e620b553954006c5c6137f1b799d5` |
| SHA-1 | `730cb94f048db262fc64a1ed15f39bf77455084c` |
| SHA-256 | `7c1f748cb0bbf61e14a4b8170004ff8ece96a9a7838a4972c7b0ca92af35c53f` |
| SHA3-384 | `0b6308a779929c6452020aa9a84151700a726848904aebafcd1d8daff129b5f6d314d0962dde3b632357a555d683ac5a` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T182E6338C6AC012FED7634238DDE211D2D6B7B83A17B2C9AF1B9453555EA30F60C3CA56` |
| SSDEEP | `393216:Y2hHSbm/9V0PkaPHsoXMCHWUjX9cuI3/PGTAI:YVbm/9VsFPRXMb8XKH/O7` |
| ICON-DHASH | `e8e864e0d8e8ec5a` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_045_7c1f748c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c1f748cb0bbf61e14a4b8170004ff8ece96a9a7838a4972c7b0ca92af35c53f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 21:52:09"
  condition:
    hash.sha256(0, filesize) == "7c1f748cb0bbf61e14a4b8170004ff8ece96a9a7838a4972c7b0ca92af35c53f"
}
```

### Sample 46: `029a364b81370e6f`

| Field | Value |
|---|---|
| SHA-256 | `029a364b81370e6f680886c2e1a0751cc45d1539db9ef0b9b55265def3422259` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 21:34:42` |
| Reporter | `Bitsight` |
| Tags | `CoinMiner, dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `286281abd97aefc9ac9aebd4b9783990` |
| SHA-1 | `e49d6874f6e27e55f6216c399f73d6dd2b1c830d` |
| SHA-256 | `029a364b81370e6f680886c2e1a0751cc45d1539db9ef0b9b55265def3422259` |
| SHA3-384 | `844d010724c5142b8eb6bcc634e74f863fae2be6cea63382c92c5a5826bd22ffc61a316c16d361aa202b1e73f812c606` |
| IMPHASH | `35171f6f6a1bfee47cbc04cb345c411f` |
| TLSH | `T1CC36339B68C355B9D082C7B8AD0220BDB1FE7BA14A607D5B3ADC5A014E5FF08247D3D6` |
| SSDEEP | `98304:Zs3dQoj+A6UyiJVgPD6of3qxteoiXNZYjYnrNcZrXlsWbKdDbJy4ka:OdQoP/VUeof3zBXEjZZr6RcVa` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_046_029a364b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029a364b81370e6f680886c2e1a0751cc45d1539db9ef0b9b55265def3422259"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:42"
  condition:
    hash.sha256(0, filesize) == "029a364b81370e6f680886c2e1a0751cc45d1539db9ef0b9b55265def3422259"
}
```

### Sample 47: `4b33ef08b2517ca1`

| Field | Value |
|---|---|
| SHA-256 | `4b33ef08b2517ca180b3ecb2917c5196965cbcde84e3bb8a83b156ee55c4a622` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 21:34:34` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `64de4b84d193dd1bb8355fd1f0589677` |
| SHA-1 | `c12db5fe21bb9be8c8a6c0cf393f6b7946aa0438` |
| SHA-256 | `4b33ef08b2517ca180b3ecb2917c5196965cbcde84e3bb8a83b156ee55c4a622` |
| SHA3-384 | `2bc6da9da5cd61ccc52f9d0ab805304af498fd4fdac684e7d73ed6ca810802564ef5bf6fc26a3b0e74a8509e562bf9a0` |
| IMPHASH | `44140cbbe125df54636c585913f74c75` |
| TLSH | `T1A8D5238ABDF21274D836C3B28FC3E8AD707A379847708D4B76CD19818E125986D36779` |
| SSDEEP | `49152:TqY87hKbX93MD4uKfzF5JoicPPlDVu+7QZSh0PFbTL4nF0celIUfOVJ0Ae:TySX93M8uKZ52PPlDVRMSuN3L2F0/0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_047_4b33ef08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b33ef08b2517ca180b3ecb2917c5196965cbcde84e3bb8a83b156ee55c4a622"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:34"
  condition:
    hash.sha256(0, filesize) == "4b33ef08b2517ca180b3ecb2917c5196965cbcde84e3bb8a83b156ee55c4a622"
}
```

### Sample 48: `467f21fcf8946527`

| Field | Value |
|---|---|
| SHA-256 | `467f21fcf89465270557faeaa93c95fdea23d50fd89f5f1f8d55ad0899270044` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 21:34:28` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5c19d88aadb015681bffd0e14372f00a` |
| SHA-1 | `bbc262a582b943e19175f90cc651d37125acc6f5` |
| SHA-256 | `467f21fcf89465270557faeaa93c95fdea23d50fd89f5f1f8d55ad0899270044` |
| SHA3-384 | `ddd2e7a845cbe82c12f3dcee61d6f94c115d13b3add3d0ebd12d0804ae0f257ea1f7f1f5121141249fbbec21034b0723` |
| IMPHASH | `1799eb3c1092391ae174afa4eee4cba2` |
| TLSH | `T181D5238AFEAE7136E472C3B3869761EEB1193B418A709D4E37D857401E525282C7B33D` |
| SSDEEP | `49152:fxKQnr8iyr63a+JStflm/bcqfsGrxuiHMeUU8EtbUu/dIUswTXW43nC:fxK8rzyJHibcqUaYimU1TswK43` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_048_467f21fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467f21fcf89465270557faeaa93c95fdea23d50fd89f5f1f8d55ad0899270044"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:28"
  condition:
    hash.sha256(0, filesize) == "467f21fcf89465270557faeaa93c95fdea23d50fd89f5f1f8d55ad0899270044"
}
```

### Sample 49: `ae0b4d8fe724c2dd`

| Field | Value |
|---|---|
| SHA-256 | `ae0b4d8fe724c2dde60289f1a3fdec7d2db6aefce7d65e0ed1ebcde54d3ba735` |
| Family label | `unknown` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-07-23 21:34:22` |
| Reporter | `Bitsight` |
| Tags | `dropped-by-remus, exe, f9d3d96cfe614ce8cced68416cbd16ba` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `43720a8b59cffbd1f611744e6078eba7` |
| SHA-1 | `253467ab48e606eb8d68ad5bb97adf0741fb8083` |
| SHA-256 | `ae0b4d8fe724c2dde60289f1a3fdec7d2db6aefce7d65e0ed1ebcde54d3ba735` |
| SHA3-384 | `84685705e1903a2ff1b2e9efeb1ad5c38120d32195dca82feb60e8467da131b6913d92320b922c73f36cb3e8e5c2c99d` |
| IMPHASH | `f5bec796b7b3c2932293afa8281cdeed` |
| TLSH | `T169D5239ABDF28A74D432C3B28EC3F03EB12877404AB25E9776CC1A004D5765AAD75778` |
| SSDEEP | `49152:+xJ+cHfD1ARCjJWjlS0LNHzqHJxSsJeE0HrnlcqhKyPwsLl9jnnabsx+GaE:+xJlBARCjJWpSut+Dchchyhw4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_049_ae0b4d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0b4d8fe724c2dde60289f1a3fdec7d2db6aefce7d65e0ed1ebcde54d3ba735"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:22"
  condition:
    hash.sha256(0, filesize) == "ae0b4d8fe724c2dde60289f1a3fdec7d2db6aefce7d65e0ed1ebcde54d3ba735"
}
```

### Sample 50: `c0582c6cd2a17fe2`

| Field | Value |
|---|---|
| SHA-256 | `c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241` |
| Family label | `Mirai` |
| File name | `c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241` |
| File type | `sh` |
| First seen | `2026-07-23 21:23:00` |
| Reporter | `c2hunter` |
| Tags | `Mirai, sh, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `856a2837632518946ae0a6020b4da4e3` |
| SHA-1 | `813f03e01dcf4e96a68cf2353efb77bbae47c1a3` |
| SHA-256 | `c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241` |
| SHA3-384 | `9bd280f82045a4a7061d14f6263551e9b4dbea07cd52d15f6889ee9fa518eaf39ea73bc672e4efe8ce7fef260c77aa67` |
| TLSH | `T18B3143AF02145E3A1742CEDE73A23548B50C86F72DEBD7989C881EEE534878C7166BC5` |
| SSDEEP | `24:iXuXzBDedoh90/yJVhV9fLeyep7vul/l24eF7EOIFvm:iXuXFXj0/ohV9fLeyep7w/l24SEOIFvm` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_c0582c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241"
    family = "Mirai"
    file_name = "c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241"
    file_type = "sh"
    first_seen = "2026-07-23 21:23:00"
  condition:
    hash.sha256(0, filesize) == "c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241"
}
```

### Sample 51: `f31d77a3954013a6`

| Field | Value |
|---|---|
| SHA-256 | `f31d77a3954013a6d02743d3bccab31cce7a44764b797d8cef7eae5bb3f586d2` |
| Family label | `unknown` |
| File name | `dllhost.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:21:05` |
| Reporter | `anonymous` |
| Tags | `exe, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff37476c18b4b3b3e30f7a9b34ef29b2` |
| SHA-1 | `974c1d3554692bd19daef0bd3459179ae643d536` |
| SHA-256 | `f31d77a3954013a6d02743d3bccab31cce7a44764b797d8cef7eae5bb3f586d2` |
| SHA3-384 | `802abe07b5c957fe16a581bbb1a51693f12f6f1a6d001b95154d196c0fb6a69f3c02bc09e2d42bef3c94a5edf44be833` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T144C64987F86101E8C4AAD171CA295613BB703C894F3063D76B51F7B82F36BD4AA7A354` |
| SSDEEP | `98304:m4CguCzEic6VfHptwPfj2YiArSFg9UFr9+jvfvFviv2ELQBrvJPpyX5djye71MzY:y6DJMrEHrcBdoJhye71Mz` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_051_f31d77a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f31d77a3954013a6d02743d3bccab31cce7a44764b797d8cef7eae5bb3f586d2"
    family = "unknown"
    file_name = "dllhost.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:21:05"
  condition:
    hash.sha256(0, filesize) == "f31d77a3954013a6d02743d3bccab31cce7a44764b797d8cef7eae5bb3f586d2"
}
```

### Sample 52: `9767724a6dd381d9`

| Field | Value |
|---|---|
| SHA-256 | `9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af` |
| Family label | `WannaCry` |
| File name | `9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af` |
| File type | `exe` |
| First seen | `2026-07-23 21:15:39` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `28d54ff78c8a467dd5e215f44c48ca3b` |
| SHA-1 | `33a069410229b9a55ed76599531cafe9553a486a` |
| SHA-256 | `9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af` |
| SHA3-384 | `39285e4bb7fe5a72a5b35b5d4943f7d23ea697a5e0ef3ad858253eb92fac4aba4b95958ef3b2a6f2e1a933df05be8226` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T14336E027ABD6DB32E9B75A7320BF97001B3136206557571E2621918E0CB3F488EE677C` |
| SSDEEP | `49152:jnXnAQqMSPbcBVQej/1INRx+TSqTdX1HkQo6SAAM7kju1RnrH5CWu816SIfb:DXDqPoBhz1aRxcSUDk36SAbGv26B` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_052_9767724a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af"
    family = "WannaCry"
    file_name = "9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af"
    file_type = "exe"
    first_seen = "2026-07-23 21:15:39"
  condition:
    hash.sha256(0, filesize) == "9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af"
}
```

### Sample 53: `f1299aac53a76228`

| Field | Value |
|---|---|
| SHA-256 | `f1299aac53a762281c12f1ffef0fef6e74cbc913fb851d7cc97c7f2a88b9d91a` |
| Family label | `LummaStealer` |
| File name | `xqAAE.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:10:36` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, exe, hypercorevector9-lol, id-exhumepacifier-cc, not-LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c2ecaa75f36469ba0d2591d8dc94b62c` |
| SHA-1 | `c2e85ce2455b5cbfdcbe96ced48a8408e2277adc` |
| SHA-256 | `f1299aac53a762281c12f1ffef0fef6e74cbc913fb851d7cc97c7f2a88b9d91a` |
| SHA3-384 | `140b53a4600696be124f6847b08a7418f97f78f113ba44caf9590f78a1c6a32ccd80c90c508ace5638f6c5f4362cdc8a` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T15ED54810FD8749F6E503163249E762AF2339AE050F369B97EA407A7DF9776E50832309` |
| SSDEEP | `49152:wj5t7mA6lGPSdYWSlSViOMHaXYbQhBxGaCC:QP7mA6sPivoS7MUhrnCC` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_053_f1299aac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1299aac53a762281c12f1ffef0fef6e74cbc913fb851d7cc97c7f2a88b9d91a"
    family = "LummaStealer"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:10:36"
  condition:
    hash.sha256(0, filesize) == "f1299aac53a762281c12f1ffef0fef6e74cbc913fb851d7cc97c7f2a88b9d91a"
}
```

### Sample 54: `6a0dbbafcc53b79c`

| Field | Value |
|---|---|
| SHA-256 | `6a0dbbafcc53b79c1deadba56dc0f6f653c1e54975b1aa1e7ed48f88d3f2ac05` |
| Family label | `unknown` |
| File name | `r2.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:09:48` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb6b481eacc941898f73ac1c96111579` |
| SHA-1 | `3bf9afbb19aa41d7d7bb4ceff3b20895e4240d57` |
| SHA-256 | `6a0dbbafcc53b79c1deadba56dc0f6f653c1e54975b1aa1e7ed48f88d3f2ac05` |
| SHA3-384 | `71f78a164b6b2dd46eb54873df042d81a1cb67b4e40c7b1db9e00cbee725dd9f885832aa798e9af8e492b6e0b163e91e` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T19AC54907FCD149EAC09EA23289B691927B75BC481B3223D72E90B7782FB27D05D35B54` |
| SSDEEP | `24576:fKyBpoEhebldB+CmEsKtB7N2Rv5vrTexpw69GxGIt2ClMvAoBele5I92GKOqcsJP:fKy/LhMlH+CxJvgF69IGIwCl/t9P4dnj` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_054_6a0dbbaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a0dbbafcc53b79c1deadba56dc0f6f653c1e54975b1aa1e7ed48f88d3f2ac05"
    family = "unknown"
    file_name = "r2.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:09:48"
  condition:
    hash.sha256(0, filesize) == "6a0dbbafcc53b79c1deadba56dc0f6f653c1e54975b1aa1e7ed48f88d3f2ac05"
}
```

### Sample 55: `f85de96394b9d070`

| Field | Value |
|---|---|
| SHA-256 | `f85de96394b9d070487ad7a1a3be9eef62f166273b28d85a0a7ac5b0e382dd73` |
| Family label | `RemusStealer` |
| File name | `ojujn.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:08:57` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36f3d12ace3dc08c4db62ed39024082b` |
| SHA-1 | `1121b2c1eccb89e9fe41cd6ce38d72fb9a5be2df` |
| SHA-256 | `f85de96394b9d070487ad7a1a3be9eef62f166273b28d85a0a7ac5b0e382dd73` |
| SHA3-384 | `20bfe8170588983e6ffe1d31e0f6436062737556a5af7a44a95345c3800567cc1decb376d9d5179ef9ec8440f86fb45f` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T14DC54907FCD149EAC09DA23289B692927B75BC482B3223DB2E90B7782F727D05D35754` |
| SSDEEP | `24576:UZv4E/ayKwOsv3XB7kOW0gAdwwTGFTXem06AZOW3mfO6uAD7jy9SevAoBele5I9P:UZvzyy3Rv3lkyn5nmhO6uyumt8lL5Q` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_055_f85de963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f85de96394b9d070487ad7a1a3be9eef62f166273b28d85a0a7ac5b0e382dd73"
    family = "RemusStealer"
    file_name = "ojujn.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:08:57"
  condition:
    hash.sha256(0, filesize) == "f85de96394b9d070487ad7a1a3be9eef62f166273b28d85a0a7ac5b0e382dd73"
}
```

### Sample 56: `83ee5526840106e0`

| Field | Value |
|---|---|
| SHA-256 | `83ee5526840106e0df497edc91a1ae5e11405fe8da9a67038dddcd46df3dc681` |
| Family label | `unknown` |
| File name | `wr.php` |
| File type | `sh` |
| First seen | `2026-07-23 21:07:19` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `50c033bd0662498d9ffee982e06b28d6` |
| SHA-1 | `c364cf1f58ef666851ac861a1237d57985dae2ca` |
| SHA-256 | `83ee5526840106e0df497edc91a1ae5e11405fe8da9a67038dddcd46df3dc681` |
| SHA3-384 | `77ed01b369c6f153299bf59c936e28660f5e74238039552856c30e8d03048b5c8b2fb4c24e0b474f15f361d2861d94ed` |
| TLSH | `T168C28E966A867C44BEC94A3E4CBD2B1D6DF5C3D1324942AC3D8B3C719C11FACD618B1A` |
| SSDEEP | `768:Vb8vCB+25j6es8RD9FYpMSUpi+20qUpi+20YQX:Vb8l25JFd2QX` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_056_83ee5526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83ee5526840106e0df497edc91a1ae5e11405fe8da9a67038dddcd46df3dc681"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 21:07:19"
  condition:
    hash.sha256(0, filesize) == "83ee5526840106e0df497edc91a1ae5e11405fe8da9a67038dddcd46df3dc681"
}
```

### Sample 57: `3846db9620475d5f`

| Field | Value |
|---|---|
| SHA-256 | `3846db9620475d5f24b73bff02babc2ea275e718116805203ca258dee7d35621` |
| Family label | `RemusStealer` |
| File name | `KLLNMF.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:07:07` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9dc9a8598c19cf0e87f308c9cc7b8f42` |
| SHA-1 | `f963958fa39547600468e3556cb4a6be08c8b642` |
| SHA-256 | `3846db9620475d5f24b73bff02babc2ea275e718116805203ca258dee7d35621` |
| SHA3-384 | `947677714c94140d6418b313b398e0f74506221a93dd5506a3ceca09c930e27e9d6c1e2da6cce14bed0de448685ea54d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T112D54A17ECA149F6C199A331C97396527776BC081B3237EB2E90AB782E727C05D3A714` |
| SSDEEP | `49152:nBMu9ce/8ypoZu64EdYhnEAjz/gqUGuAsC88NnC:nRRzxbVY78NC` |
| ICON-DHASH | `b27170f0e869e0c4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_057_3846db96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3846db9620475d5f24b73bff02babc2ea275e718116805203ca258dee7d35621"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:07:07"
  condition:
    hash.sha256(0, filesize) == "3846db9620475d5f24b73bff02babc2ea275e718116805203ca258dee7d35621"
}
```

### Sample 58: `0d716e4ab464c5b9`

| Field | Value |
|---|---|
| SHA-256 | `0d716e4ab464c5b97d2767ae6d8af267b9f050941332a9601f0a35f53ec79819` |
| Family label | `RemusStealer` |
| File name | `kliulij.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:06:09` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `29c064107986a6cce15f1a118dd6706c` |
| SHA-1 | `5b262e55d2ba9eeee074b3311b07754750b777c4` |
| SHA-256 | `0d716e4ab464c5b97d2767ae6d8af267b9f050941332a9601f0a35f53ec79819` |
| SHA3-384 | `2e10936176e2a4868f2962dd2fb7fa9b4682c321d167dc8d48ebadecb16574316b00b0982e54a3cdd275e4bda8c4e859` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T193C54A07FCD149FAC09EA23289A691927B75BC491B3223D72EA0B7782FB27D05C35754` |
| SSDEEP | `24576:4AwsVZUavfcqK4nc+5HPPmNf6MUj+S83Dgj8DvDBJ4gOzjAHxZi29ptvAoBele5T:4Aw0ZUGfS4nV5HGsmJb1OOi2yt0jrnf` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_058_0d716e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d716e4ab464c5b97d2767ae6d8af267b9f050941332a9601f0a35f53ec79819"
    family = "RemusStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:06:09"
  condition:
    hash.sha256(0, filesize) == "0d716e4ab464c5b97d2767ae6d8af267b9f050941332a9601f0a35f53ec79819"
}
```

### Sample 59: `6369ca003c58f5eb`

| Field | Value |
|---|---|
| SHA-256 | `6369ca003c58f5ebad82e2f1d9a7eece2cc3d3799062b41a148dece9a35f134a` |
| Family label | `LummaStealer` |
| File name | `KLHdfs.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:05:15` |
| Reporter | `iamaachum` |
| Tags | `ACRStealer, app-api-metricsengine-cc, exe, hypercorevector9-lol, not-LummaStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d777f7028547b710b411a15047ab8c2` |
| SHA-1 | `b388ff1a4bcfb76ec2a935e7d3042f5defcbe0a4` |
| SHA-256 | `6369ca003c58f5ebad82e2f1d9a7eece2cc3d3799062b41a148dece9a35f134a` |
| SHA3-384 | `68cfa878db95a758109f25806bb349e60be611328b395283246a2b40cf12b9d3bbed57e0c0d6e9e5487d19a1207432b1` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T1DEE55A00FDC745F6E903167284EB62AF2739AD054F36DB87EA447A7DE9772E50822309` |
| SSDEEP | `24576:+rlgPnMpKYg/LxRCCeLVgEQLkEzkKlifpRNMCBc3mNp/Iv3XW31YLQp/2ioA2huu:+pgXWVNrtsUp/2iN2cSbQhmfcu` |
| ICON-DHASH | `706951f0f8f8d4e8` |

#### Technical Assessment

- The sample is tracked as `LummaStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_LummaStealer_059_6369ca00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6369ca003c58f5ebad82e2f1d9a7eece2cc3d3799062b41a148dece9a35f134a"
    family = "LummaStealer"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:05:15"
  condition:
    hash.sha256(0, filesize) == "6369ca003c58f5ebad82e2f1d9a7eece2cc3d3799062b41a148dece9a35f134a"
}
```

### Sample 60: `b1e488d82afc1ab0`

| Field | Value |
|---|---|
| SHA-256 | `b1e488d82afc1ab098ed4c771172a1c9bbd2bf0f48fedf9cc1c52344d71d7d47` |
| Family label | `RemusStealer` |
| File name | `kJHGFDs.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:04:25` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f99d5000f88ac891aea42a8ff85d5be3` |
| SHA-1 | `8f2a1a7c80064e2691548189e2ecb7dc00e8b55a` |
| SHA-256 | `b1e488d82afc1ab098ed4c771172a1c9bbd2bf0f48fedf9cc1c52344d71d7d47` |
| SHA3-384 | `b74ace7ce9d30fa5dc5e7abc51d8955afdd1c0cf7ccb40ecf9073f0d92b64d7e33cb2e11d03412fbac03eede563e271d` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T139D54917ECE548E6C09EA23189B396567B75BC081B3223E72E90BB782F727C05D35764` |
| SSDEEP | `24576:MK/Q+iiK0daO71s+ZrhUSZa8bVzBig4eI2q65r94m05SxvAoBele5I9DeK9HpsJD:MK/xjKXOps+ZqMTVzB2ek6x0sycBpxl` |
| ICON-DHASH | `706951f0f8f8d4e8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_060_b1e488d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1e488d82afc1ab098ed4c771172a1c9bbd2bf0f48fedf9cc1c52344d71d7d47"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:04:25"
  condition:
    hash.sha256(0, filesize) == "b1e488d82afc1ab098ed4c771172a1c9bbd2bf0f48fedf9cc1c52344d71d7d47"
}
```

### Sample 61: `8083bda9833da620`

| Field | Value |
|---|---|
| SHA-256 | `8083bda9833da6206a28cfc5b4c91a3ac2488d6bcf50d146450aa708413d6886` |
| Family label | `RemusStealer` |
| File name | `jhgkuyyg.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:03:22` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8abdbd508906231a5a1f48f8c03c4868` |
| SHA-1 | `63f5c8e914945964a9abce21407665f4abf50c87` |
| SHA-256 | `8083bda9833da6206a28cfc5b4c91a3ac2488d6bcf50d146450aa708413d6886` |
| SHA3-384 | `8c37f352021104d7d42810a427836c3c0933f6c626fca9b63f3c6b070022657f9dc4491c868ae79f7243473c2cc634b8` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1BDC54907FCD549E6C09EA23289B682927B75BC482B3223D72E90B7782FB27D05D35754` |
| SSDEEP | `24576:91E8sOKDCmNi8JdZsQWWpavrisg43b10PPdtFuQvns7ZXi+vAoBele5I92GKOqWP:91EdOCCX8J3sSqL1wvjnGZ+tjqP2V` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_061_8083bda9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8083bda9833da6206a28cfc5b4c91a3ac2488d6bcf50d146450aa708413d6886"
    family = "RemusStealer"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:03:22"
  condition:
    hash.sha256(0, filesize) == "8083bda9833da6206a28cfc5b4c91a3ac2488d6bcf50d146450aa708413d6886"
}
```

### Sample 62: `00d5b68d01d72c7d`

| Field | Value |
|---|---|
| SHA-256 | `00d5b68d01d72c7dff69763f1514284a6542f6a1acab9431cfb8c66439bfcf20` |
| Family label | `RemusStealer` |
| File name | `hnmh.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:02:26` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `96c9362dc59b33d7e0f492d64b620ac2` |
| SHA-1 | `79b90ce86def8ec97ab2ed8c44d3528f373379dc` |
| SHA-256 | `00d5b68d01d72c7dff69763f1514284a6542f6a1acab9431cfb8c66439bfcf20` |
| SHA3-384 | `27898d682bfbb6cd0bc110c40478cede2175f3ae3a3f67bffc6b30cf3cae6f6f41c8c915859a8e799e08871873b36a10` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T182C54A03ECD149FAC09EA23289B692927B75BC482B3223D72E90B7782F727D05D75754` |
| SSDEEP | `24576:+tSI8kqBHuHbjhquE+lVMSjiI0M3WD9AYm+iYHVwB7efxtwqFkvAoBele5I92GKD:+tSLxBCbjNEc3TYDoKVqiTHt/5PJa` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_062_00d5b68d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00d5b68d01d72c7dff69763f1514284a6542f6a1acab9431cfb8c66439bfcf20"
    family = "RemusStealer"
    file_name = "hnmh.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:02:26"
  condition:
    hash.sha256(0, filesize) == "00d5b68d01d72c7dff69763f1514284a6542f6a1acab9431cfb8c66439bfcf20"
}
```

### Sample 63: `e8fca6d589613ccb`

| Field | Value |
|---|---|
| SHA-256 | `e8fca6d589613ccb2d1341e2d144bf896d3f73956794dcb00a047d73750641b6` |
| Family label | `RemusStealer` |
| File name | `hjbk.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:01:48` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1a4217180610739b194f8d3aaf1091f2` |
| SHA-1 | `bd43d7a7f0201d300c278c894b2316d10d7d8ab0` |
| SHA-256 | `e8fca6d589613ccb2d1341e2d144bf896d3f73956794dcb00a047d73750641b6` |
| SHA3-384 | `e176c2834be96127da495a1c92a546b2ede2b46fbe7b66e5af06aa884359f955d802e05446294b56e542a19024c523e3` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T17DC55A07FCD109EAC49DA23289B691927B35BC492B3223DB2E90B7782FB27D05D35754` |
| SSDEEP | `24576:0EcIwpmlEelbomRHcK3uqarZ73lBnzJCmdsp6a7fvLXd4mvAoBele5I92GKOqLs4:0EcTp4zKmR8uuqqBru7fvLNwtMRDKF+` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_063_e8fca6d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8fca6d589613ccb2d1341e2d144bf896d3f73956794dcb00a047d73750641b6"
    family = "RemusStealer"
    file_name = "hjbk.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:01:48"
  condition:
    hash.sha256(0, filesize) == "e8fca6d589613ccb2d1341e2d144bf896d3f73956794dcb00a047d73750641b6"
}
```

### Sample 64: `e5282342ac6494b5`

| Field | Value |
|---|---|
| SHA-256 | `e5282342ac6494b5f02b194e3194e5838809e342795c1183a30d638264598a5a` |
| Family label | `RemusStealer` |
| File name | `crazy.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:01:03` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `35d176134ff6981333828bf782881f09` |
| SHA-1 | `3f1940fe57481b9382a19e53b598231ab0268730` |
| SHA-256 | `e5282342ac6494b5f02b194e3194e5838809e342795c1183a30d638264598a5a` |
| SHA3-384 | `0f401200dfa333076b7c90339844b86e4e4bb46d1c0d6252c0025794afa09bd583513a8101592559990bfeedeb2daf88` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1AED54917ECD548E6C09DA23188B396567B71BC081B3223E72EA07B782F727D09D79764` |
| SSDEEP | `24576:Cw69H/jAH8DHGFxpP6MFRw6e9DjvtlcL16Q5+pqH2uhvAoBele5I9DeK9HisJ5pd:Cw6pkHEG/pP6MgPFvtlO5RNCcQpc` |
| ICON-DHASH | `706951f0f8f8d4e8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_064_e5282342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5282342ac6494b5f02b194e3194e5838809e342795c1183a30d638264598a5a"
    family = "RemusStealer"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:01:03"
  condition:
    hash.sha256(0, filesize) == "e5282342ac6494b5f02b194e3194e5838809e342795c1183a30d638264598a5a"
}
```

### Sample 65: `0d4aee37b4b0916b`

| Field | Value |
|---|---|
| SHA-256 | `0d4aee37b4b0916bdef43762494a424079c71e928621231f3c0a5a020c95b070` |
| Family label | `RemusStealer` |
| File name | `beb.exe` |
| File type | `exe` |
| First seen | `2026-07-23 21:00:04` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b22aec9556850dbced5a3637e970d67b` |
| SHA-1 | `1fc667f64c71cfc9fa06b5a2a2e431a5fc822fe4` |
| SHA-256 | `0d4aee37b4b0916bdef43762494a424079c71e928621231f3c0a5a020c95b070` |
| SHA3-384 | `9eec834291f385f3b21facfc82c6d8755ecb538ac986f8449a9584e94acb3773c4770dc0e7028cd5d23862bd0cd3148c` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T15AC54A07ECD109FAC0ADA23289B691927B75BC491B3223DB2E90B7782FB67D05C35754` |
| SSDEEP | `24576:bLRfIcj6o1wgz8kb7Hdl34JbVJQT0YUTldQ0HQEIlHsc9I9LvAoBele5I92GKOqt:bLRAMj1z8eHcTC0CI9ctTUTIqP` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_065_0d4aee37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4aee37b4b0916bdef43762494a424079c71e928621231f3c0a5a020c95b070"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:00:04"
  condition:
    hash.sha256(0, filesize) == "0d4aee37b4b0916bdef43762494a424079c71e928621231f3c0a5a020c95b070"
}
```

### Sample 66: `5905e577d0c5ec50`

| Field | Value |
|---|---|
| SHA-256 | `5905e577d0c5ec50e0297efbcbfc988cbf446f69b8d798fcaa08c2ea48a821c4` |
| Family label | `RemusStealer` |
| File name | `arFtU.exe` |
| File type | `exe` |
| First seen | `2026-07-23 20:59:11` |
| Reporter | `iamaachum` |
| Tags | `exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4baac6c40283af88a17844f56c126dab` |
| SHA-1 | `07be448795ca2d98cad8b62b294dcaa7b7e8afc4` |
| SHA-256 | `5905e577d0c5ec50e0297efbcbfc988cbf446f69b8d798fcaa08c2ea48a821c4` |
| SHA3-384 | `95e2b3a27f3ef849c030e739c2e3e4c9d65524309d5f82eb2625d51b1b3d821d9ee5c4921720f8813d272116b67a3f6b` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T160D55A03FCD208F6C099A23189B662567B75BC491B3227D72E90BB782F727D05D79B18` |
| SSDEEP | `24576:sAKOGlrG2ioyk43s19AqAzQb8dDYa/7C/SZ4GcoLi4+FoBeletI92OiTVtKPaJwn:sAKFlrTiTZ3srqkwdlco+dViVJwcs` |
| ICON-DHASH | `706951f0f8f8d4e8` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_066_5905e577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5905e577d0c5ec50e0297efbcbfc988cbf446f69b8d798fcaa08c2ea48a821c4"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:59:11"
  condition:
    hash.sha256(0, filesize) == "5905e577d0c5ec50e0297efbcbfc988cbf446f69b8d798fcaa08c2ea48a821c4"
}
```

### Sample 67: `f0a3765399fac3d6`

| Field | Value |
|---|---|
| SHA-256 | `f0a3765399fac3d6a2da13a67af4dd7d6b9a78ce09c97ec054d13bf36324b4f1` |
| Family label | `RemusStealer` |
| File name | `bjbh.exe` |
| File type | `exe` |
| First seen | `2026-07-23 20:57:02` |
| Reporter | `iamaachum` |
| Tags | `dropped-by-Adware.DownloadAssistant, exe, hypercorevector9-lol, RemusStealer, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ae3ec96312831ed7f34a86210319e18a` |
| SHA-1 | `c0fd906af5531957003326f5b80fa47c4463578d` |
| SHA-256 | `f0a3765399fac3d6a2da13a67af4dd7d6b9a78ce09c97ec054d13bf36324b4f1` |
| SHA3-384 | `2da83919ac29581ac991823b95fc541e31ab33ba349ebf808cda1df0605e1dce7b7b443e836452628706431fb474ef76` |
| IMPHASH | `d42595b695fc008ef2c56aabd8efd68e` |
| TLSH | `T1C6C54907FCD549EAC09EA23289B682927B75BC492B3223D72E90B7782F727D05C35754` |
| SSDEEP | `24576:gZNbeHVdgrM5e6xWe7XZZwuAEsW64twBQfWPLAzB3ZvAoBele5I92GKOqCsJJ2H3:gZNiHbgKe6YedZeLPLAhKtVI4Tf` |
| ICON-DHASH | `f071f0f0f8e8d4d4` |

#### Technical Assessment

- The sample is tracked as `RemusStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_RemusStealer_067_f0a37653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0a3765399fac3d6a2da13a67af4dd7d6b9a78ce09c97ec054d13bf36324b4f1"
    family = "RemusStealer"
    file_name = "bjbh.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:57:02"
  condition:
    hash.sha256(0, filesize) == "f0a3765399fac3d6a2da13a67af4dd7d6b9a78ce09c97ec054d13bf36324b4f1"
}
```

### Sample 68: `762d34adaef9bdd6`

| Field | Value |
|---|---|
| SHA-256 | `762d34adaef9bdd6a5a6e2d894bb4c5bda434e8740360adf82a399d7d1f7f46c` |
| Family label | `CoinMiner` |
| File name | `svchost.exe` |
| File type | `exe` |
| First seen | `2026-07-23 20:55:44` |
| Reporter | `iamaachum` |
| Tags | `CoinMiner, exe, KeygenGuru` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0616f526dd47ddc0b69bc9e8ddc946a0` |
| SHA-1 | `555f645eba8002c57ff8dd8c4a92a1533f0d8882` |
| SHA-256 | `762d34adaef9bdd6a5a6e2d894bb4c5bda434e8740360adf82a399d7d1f7f46c` |
| SHA3-384 | `766333dd42b4d5b8a672d0262497e41c8cef6337b2c654481a56b360eba935ae9577644d355668167275db8307a06522` |
| IMPHASH | `551ecb3b372a1fbe06ac044eaeaf6b23` |
| TLSH | `T1EB668D15BA9A58ADC49AC474834A4B636E3170CA0B36B9FF05C482353F6ABF42F3D355` |
| SSDEEP | `98304:WY5HAEC5ohAc6HyBzOV+8QeDVWWRgIlGWF22Jj6xN3AfuH+:ht6HywVRbV7j4+ANd` |
| ICON-DHASH | `e0cecece8e86c2e2` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_068_762d34ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "762d34adaef9bdd6a5a6e2d894bb4c5bda434e8740360adf82a399d7d1f7f46c"
    family = "CoinMiner"
    file_name = "svchost.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:55:44"
  condition:
    hash.sha256(0, filesize) == "762d34adaef9bdd6a5a6e2d894bb4c5bda434e8740360adf82a399d7d1f7f46c"
}
```

### Sample 69: `501cc0d06ebf10f9`

| Field | Value |
|---|---|
| SHA-256 | `501cc0d06ebf10f9ec74d1ea2139ffca45631f52b769c6a5712aab160c0d1ffd` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 20:52:11` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4449efafd54e9f2228f923111f2ff45a` |
| SHA-1 | `ebf8594d85c1cf21150768e39fc0413fee82da8f` |
| SHA-256 | `501cc0d06ebf10f9ec74d1ea2139ffca45631f52b769c6a5712aab160c0d1ffd` |
| SHA3-384 | `55004c85714bf8459e8e459c0132982a51063e5a170ec0574de3d2a31bd9f0a7169fc61f975d8357f755921d852d42cf` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T18EE633489AD112FBF4334078DDD25286D57474B24BB2C8EF4BA883E12F933E45A3965B` |
| SSDEEP | `393216:GCqEnnbTkCtmDhQUgI2sPXA8FY0XMCHWUjXQcuI3/PGTAI:Go8CtmDhQUg5svpFbXMb8XFH/O7` |
| ICON-DHASH | `18dcf8f8dcf8e040` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_069_501cc0d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "501cc0d06ebf10f9ec74d1ea2139ffca45631f52b769c6a5712aab160c0d1ffd"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 20:52:11"
  condition:
    hash.sha256(0, filesize) == "501cc0d06ebf10f9ec74d1ea2139ffca45631f52b769c6a5712aab160c0d1ffd"
}
```

### Sample 70: `717180c51bd69d7e`

| Field | Value |
|---|---|
| SHA-256 | `717180c51bd69d7eb6128d6a8a03f15179235bb8ce12c3b07dd22855943ba444` |
| Family label | `unknown` |
| File name | `Game.exe` |
| File type | `exe` |
| First seen | `2026-07-23 20:17:41` |
| Reporter | `lfr` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d2d5ef0de2e9f8473ca6e55a00a1bb8` |
| SHA-1 | `98b2af59a87b6b68f3863edcf20937674977e3e9` |
| SHA-256 | `717180c51bd69d7eb6128d6a8a03f15179235bb8ce12c3b07dd22855943ba444` |
| SHA3-384 | `d8d7a2844411ab58bafb1b5fe5d81e14303f59e0b3fcfafcaef7e5064d08d06ca6c6e7a392475e905ed332711eb24e7b` |
| IMPHASH | `2057790ae7855765d51bdc4142e62f9c` |
| TLSH | `T1B8D7335DC2BD94FFD67FE03296826118DBB37C5A13A9129B437864E76FA2BD01021B31` |
| SSDEEP | `1572864:4cZDv+/jS/ueVkMx7FOJGsUjdeKTyUI8MxyfKPSoCX7F:ZCbovy4FOcbZeKTIFwSPo` |
| ICON-DHASH | `6810686971b00028` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_070_717180c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "717180c51bd69d7eb6128d6a8a03f15179235bb8ce12c3b07dd22855943ba444"
    family = "unknown"
    file_name = "Game.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:17:41"
  condition:
    hash.sha256(0, filesize) == "717180c51bd69d7eb6128d6a8a03f15179235bb8ce12c3b07dd22855943ba444"
}
```

### Sample 71: `e212aae52a3a683b`

| Field | Value |
|---|---|
| SHA-256 | `e212aae52a3a683be857bb52c57fa8efdba908ab8909580568c7c3f96bb94823` |
| Family label | `unknown` |
| File name | `tftp` |
| File type | `elf` |
| First seen | `2026-07-23 20:16:29` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb78a4867dd1ca25c642437c33763b76` |
| SHA-1 | `423e83cb501e185596c7703b82b579344f96663d` |
| SHA-256 | `e212aae52a3a683be857bb52c57fa8efdba908ab8909580568c7c3f96bb94823` |
| SHA3-384 | `c1efcdc7bf86854becea663396a6d1f439a6b5bf619cbef1c0afaf6d8be1eb2c390240c989ea9ca943a469aa3910b4f2` |
| TLSH | `T1D1A30A96F8A28B56C4C557B7FB4FC75637231795E3DF36038A184E34278B50A8E3AA01` |
| SSDEEP | `3072:9LOuh02xHCKQnqZ9YfMXKgyLlBZSyPj4Xs:FOuhPHCKsqZ9YfM6g23ZJL4Xs` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_071_e212aae5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e212aae52a3a683be857bb52c57fa8efdba908ab8909580568c7c3f96bb94823"
    family = "unknown"
    file_name = "tftp"
    file_type = "elf"
    first_seen = "2026-07-23 20:16:29"
  condition:
    hash.sha256(0, filesize) == "e212aae52a3a683be857bb52c57fa8efdba908ab8909580568c7c3f96bb94823"
}
```

### Sample 72: `924037d098c031bf`

| Field | Value |
|---|---|
| SHA-256 | `924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda` |
| Family label | `WannaCry` |
| File name | `924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda` |
| File type | `exe` |
| First seen | `2026-07-23 20:15:41` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9edc84b317015c1912a9ba0485659886` |
| SHA-1 | `cbca755c26be38363944c234584d7da4b9e03de0` |
| SHA-256 | `924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda` |
| SHA3-384 | `82ab9e6826ca6b01e510eb5acd5b82daeee1a8d483ef926bfadb2010fcda4530a17561d9b618d275a635be6e466811a1` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T181368D43E24204BDD02D8631819B4FA0DD775DB5766D614A2F23B61E3EB33D2BA92E43` |
| SSDEEP | `98304:DXDqPoBhz1aRxcSUDk36SAEdh8FiOPY/Dm6C6KQ:DXDqPe1Cxcxk3ZAENT/s6F` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_072_924037d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda"
    family = "WannaCry"
    file_name = "924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda"
    file_type = "exe"
    first_seen = "2026-07-23 20:15:41"
  condition:
    hash.sha256(0, filesize) == "924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda"
}
```

### Sample 73: `e5dfa97e05cec266`

| Field | Value |
|---|---|
| SHA-256 | `e5dfa97e05cec26677edca609b13a1aa9987b907e31bc4f5c0e45527728d407a` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-07-23 20:10:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68c51f9b8262060bc5beabcc13f32700` |
| SHA-1 | `3d08200546b066a6a3356af56d6155f49545d2e2` |
| SHA-256 | `e5dfa97e05cec26677edca609b13a1aa9987b907e31bc4f5c0e45527728d407a` |
| SHA3-384 | `b86923f51e2a785817f2ace0be85086037fb14baabb7a86fb802bca32b763154c66791fe6e6b68b9e0a0c2603a1936f7` |
| TLSH | `T16F635AC5F643C4F5E96705304137EB7BAA32F2B90229EB87E77482327C92642D90678C` |
| TELFHASH | `t14d31f0f71dbe0cd9b7d56810c31e5f922a59e23b2a5132a0056398b133a7fc150b9c3a` |
| SSDEEP | `1536:RaZsGDExpTGAtV+/C8eQBW2OnEGc8z3WyL35IUfA5PGFjfnP5:zGYxpTGASC4XT8yyLpIoYPsP5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_e5dfa97e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5dfa97e05cec26677edca609b13a1aa9987b907e31bc4f5c0e45527728d407a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-23 20:10:17"
  condition:
    hash.sha256(0, filesize) == "e5dfa97e05cec26677edca609b13a1aa9987b907e31bc4f5c0e45527728d407a"
}
```

### Sample 74: `2d4fd69dd3f412b6`

| Field | Value |
|---|---|
| SHA-256 | `2d4fd69dd3f412b6b318af9c9840d7cd762b011346ad787eaf31da3e6990ed05` |
| Family label | `Mirai` |
| File name | `mpsl` |
| File type | `elf` |
| First seen | `2026-07-23 20:08:32` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a65034e5a9091a3da220a555abac258f` |
| SHA-1 | `4897bcbe63baab9a98eb72dc8f195a83ce887a85` |
| SHA-256 | `2d4fd69dd3f412b6b318af9c9840d7cd762b011346ad787eaf31da3e6990ed05` |
| SHA3-384 | `eecc7a9a0009cbc5636aec6c6126a473213597609b631678acf587180338215b04834c7f0d4dfe24431d9e2d0aa1c53e` |
| TLSH | `T12704F80AAF600EF7E86FCD3B02E94B0625CC655722A53B757574E528F60A64F0AE3C74` |
| SSDEEP | `3072:o+Is7WyG+RBfmdz0MLzS0obxAvK1e+FWDRHSAlnb4M:hIs7h8zS0ob4f0WDR/4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_2d4fd69d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d4fd69dd3f412b6b318af9c9840d7cd762b011346ad787eaf31da3e6990ed05"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-23 20:08:32"
  condition:
    hash.sha256(0, filesize) == "2d4fd69dd3f412b6b318af9c9840d7cd762b011346ad787eaf31da3e6990ed05"
}
```

### Sample 75: `649e11e2df456a58`

| Field | Value |
|---|---|
| SHA-256 | `649e11e2df456a582709acdf39b916a02a828957f0b13d9d0f61575e8a05282c` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-23 20:01:25` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9831730f14771da652fc709168df9ce4` |
| SHA-1 | `a6d2b1a3e5acbf53ad5a948466a844dcc6c95282` |
| SHA-256 | `649e11e2df456a582709acdf39b916a02a828957f0b13d9d0f61575e8a05282c` |
| SHA3-384 | `de4c87c2fdee84c5eb789d72d99385b9de78ae44fefc28d28cce4736221c0e86da65365b556ed3212837697102266322` |
| TLSH | `T1B3137D6956857C24AE99883B1C7E2F0CB9A983E1310451EDBFCB3CF58C49B9CD219B1D` |
| SSDEEP | `768:9+S9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:9+3co` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_075_649e11e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649e11e2df456a582709acdf39b916a02a828957f0b13d9d0f61575e8a05282c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 20:01:25"
  condition:
    hash.sha256(0, filesize) == "649e11e2df456a582709acdf39b916a02a828957f0b13d9d0f61575e8a05282c"
}
```

### Sample 76: `60d74ab66cb37bda`

| Field | Value |
|---|---|
| SHA-256 | `60d74ab66cb37bdaa5877d21d17fdcfdbf741796fcf38425fb2681250c9cf9f9` |
| Family label | `SalatStealer` |
| File name | `SecuriteInfo.com.Trojan.PWS.Salat.390.9009.22233` |
| File type | `exe` |
| First seen | `2026-07-23 19:52:46` |
| Reporter | `abuse_ch` |
| Tags | `exe, SalatStealer, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb3856e810c990828d31ee1a32d285b4` |
| SHA-1 | `b87d0c7358e671867ca3e715f1b80001aece23d3` |
| SHA-256 | `60d74ab66cb37bdaa5877d21d17fdcfdbf741796fcf38425fb2681250c9cf9f9` |
| SHA3-384 | `f8f8655d270adc4d28b0a2d1ca1d81c3b04851bfab2d2f5521e198580c2952b5898671c381ab9cfef0bea917ae023f60` |
| IMPHASH | `1aae8bf580c846f39c71c05898e57e88` |
| TLSH | `T18BC66B11FACB58F1E903583140ABB27F63315D048B38DB9BEB143B6AF87B6A11976705` |
| SSDEEP | `98304:szxwfsG35rWoi7GrtP9LVVPMgoLsE6I4BG20CGE7:SGIJG5P9LQgohRfm7` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_076_60d74ab6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60d74ab66cb37bdaa5877d21d17fdcfdbf741796fcf38425fb2681250c9cf9f9"
    family = "SalatStealer"
    file_name = "SecuriteInfo.com.Trojan.PWS.Salat.390.9009.22233"
    file_type = "exe"
    first_seen = "2026-07-23 19:52:46"
  condition:
    hash.sha256(0, filesize) == "60d74ab66cb37bdaa5877d21d17fdcfdbf741796fcf38425fb2681250c9cf9f9"
}
```

### Sample 77: `de35fbf32bd90601`

| Field | Value |
|---|---|
| SHA-256 | `de35fbf32bd9060123a1c4475d2c5e5a455c1f752e198fc2fc4fcb0cd9805fc1` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 19:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a38c8335bcd727525b892201493e19f3` |
| SHA-1 | `122c963c28baba261a0872fbf461663fcca13895` |
| SHA-256 | `de35fbf32bd9060123a1c4475d2c5e5a455c1f752e198fc2fc4fcb0cd9805fc1` |
| SHA3-384 | `ba8824f9423d618257f4e455b5857654aaf8c8ca5f7ac65bee5c9dbc9540b39740c2e09f8d03c947cfed2b454cb7c653` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T19EE6331C57E012FFDA73417DEDA258E4E1AB70625B32CACB439885766E4B1C48D3CA63` |
| SSDEEP | `393216:Jgro5lpmDz6byg7uRXMCHWUjXYcuI3/PGTAI:JgEWzAuRXMb8XtH/O7` |
| ICON-DHASH | `71d89ea29ac6e471` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_077_de35fbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de35fbf32bd9060123a1c4475d2c5e5a455c1f752e198fc2fc4fcb0cd9805fc1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 19:52:08"
  condition:
    hash.sha256(0, filesize) == "de35fbf32bd9060123a1c4475d2c5e5a455c1f752e198fc2fc4fcb0cd9805fc1"
}
```

### Sample 78: `0b93ca2778b5ac0a`

| Field | Value |
|---|---|
| SHA-256 | `0b93ca2778b5ac0ae2be58985b0ffecb7d6ce6870815c1f85d14505e4005b9e9` |
| Family label | `SalatStealer` |
| File name | `SecuriteInfo.com.Trojan.PWS.Salat.390.9009.22233` |
| File type | `exe` |
| First seen | `2026-07-23 19:51:42` |
| Reporter | `SecuriteInfoCom` |
| Tags | `exe, SalatStealer, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e9df38cda2f3f8924b6c0a5bb3b38a09` |
| SHA-1 | `e5a04864ed50e152d8c0e7a1d6e7bc0cfa21ed63` |
| SHA-256 | `0b93ca2778b5ac0ae2be58985b0ffecb7d6ce6870815c1f85d14505e4005b9e9` |
| SHA3-384 | `e395d9d1487ccbc236f77f2ce56d209278ffcd9a46062dec40a8193b757aa09132bc4f69724a556e78f1a7e4a0102efb` |
| IMPHASH | `6ed4f5f04d62b18d96b26d6db7c18840` |
| TLSH | `T1E0F533AE613F9266E72BC7736C8AE80105F534C10EEF53D430B96DF825F611486AB1B5` |
| SSDEEP | `98304:1FjYe2xSG9I8n1LRemvRSvo9dRIV+Xrh:XjYe20HepOwRX` |

#### Technical Assessment

- The sample is tracked as `SalatStealer` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_SalatStealer_078_0b93ca27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b93ca2778b5ac0ae2be58985b0ffecb7d6ce6870815c1f85d14505e4005b9e9"
    family = "SalatStealer"
    file_name = "SecuriteInfo.com.Trojan.PWS.Salat.390.9009.22233"
    file_type = "exe"
    first_seen = "2026-07-23 19:51:42"
  condition:
    hash.sha256(0, filesize) == "0b93ca2778b5ac0ae2be58985b0ffecb7d6ce6870815c1f85d14505e4005b9e9"
}
```

### Sample 79: `8a50ed3d9d9e90c9`

| Field | Value |
|---|---|
| SHA-256 | `8a50ed3d9d9e90c971100e211b7f5c8c7128ccbf9164cf3bd1beed8a49da6ab6` |
| Family label | `unknown` |
| File name | `Spysok_Mayna.zip` |
| File type | `lnk` |
| First seen | `2026-07-23 19:45:35` |
| Reporter | `smica83` |
| Tags | `lnk, UKR` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3fc7b9e02c80f93cf8a1af6f980901d6` |
| SHA-1 | `6c540c5cb35a95960c1372791810c27179bcddb6` |
| SHA-256 | `8a50ed3d9d9e90c971100e211b7f5c8c7128ccbf9164cf3bd1beed8a49da6ab6` |
| SHA3-384 | `12d356cf3ed3a5e54b5f4e036b3abd60004eaf87c3607ee0ff48b2a4c2bbdd39dbd6bbb74bec479d9282e445e26480fb` |
| TLSH | `T194D1872435E50119E2F3EB352CF8A6D98EABFAD3753501562482130A4910A60EA15F3B` |
| SSDEEP | `24:8d/6ii7jr8aRJWInZNTCH7DBEpmJL7rGvlxPlpYZ+6JuJMc:8l6HjlnvCbNE+L7C9bAN4` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_079_8a50ed3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a50ed3d9d9e90c971100e211b7f5c8c7128ccbf9164cf3bd1beed8a49da6ab6"
    family = "unknown"
    file_name = "Spysok_Mayna.zip"
    file_type = "lnk"
    first_seen = "2026-07-23 19:45:35"
  condition:
    hash.sha256(0, filesize) == "8a50ed3d9d9e90c971100e211b7f5c8c7128ccbf9164cf3bd1beed8a49da6ab6"
}
```

### Sample 80: `962bd2fdde0752a0`

| Field | Value |
|---|---|
| SHA-256 | `962bd2fdde0752a0ba60650f3808a99a3dfe1068b0a8c7a50360134ea8bb1f92` |
| Family label | `unknown` |
| File name | `АКТ приема передачи (дроны164) 18.07.2026.docx.lnk` |
| File type | `lnk` |
| First seen | `2026-07-23 19:44:30` |
| Reporter | `smica83` |
| Tags | `lnk, RUS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `892957ba7ebfb6f5df09a0e1f10ca897` |
| SHA-1 | `f2d6ffbfe17b1ff957a852dd0e282306ab58cad6` |
| SHA-256 | `962bd2fdde0752a0ba60650f3808a99a3dfe1068b0a8c7a50360134ea8bb1f92` |
| SHA3-384 | `c6d31fa0a93b85365098393073d249f6cfc02701ec2e41a400424f3377bf60e1903700133a0b78706e06f5a4a0031a69` |
| TLSH | `T17371AD402DDA10D8F2261BB567DBB5BB0B96F8F4D42E2DB412C15A7047F3980B8ADB74` |
| SSDEEP | `96:8XIewHZbppFHZbpFHH8poq6gp9xkoRh5HE6lYYMxBpu:8Xa5bpr5bp9cWqDj5rlIv` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `lnk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_080_962bd2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "962bd2fdde0752a0ba60650f3808a99a3dfe1068b0a8c7a50360134ea8bb1f92"
    family = "unknown"
    file_name = "АКТ приема передачи (дроны164) 18.07.2026.docx.lnk"
    file_type = "lnk"
    first_seen = "2026-07-23 19:44:30"
  condition:
    hash.sha256(0, filesize) == "962bd2fdde0752a0ba60650f3808a99a3dfe1068b0a8c7a50360134ea8bb1f92"
}
```

### Sample 81: `e388e7ce2449ba41`

| Field | Value |
|---|---|
| SHA-256 | `e388e7ce2449ba4100483186d9242e96f0cf74196d2519d37b581df682c57de6` |
| Family label | `unknown` |
| File name | `ProtokolZatrimannya.zip` |
| File type | `zip` |
| First seen | `2026-07-23 19:43:34` |
| Reporter | `smica83` |
| Tags | `UKR, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0ee9d5a615750d757c48370b1afffa6b` |
| SHA-1 | `590f9421b0506246424f3531924a0081cd770ac1` |
| SHA-256 | `e388e7ce2449ba4100483186d9242e96f0cf74196d2519d37b581df682c57de6` |
| SHA3-384 | `a258b463ad9c62fc913e2788e18be35ef314df561122ba47455cd87e0b7da3ab5fcf799f06a50c0e5689cd7ea2bd50d1` |
| TLSH | `T13AA3FD3475E80119E9F3EFB26DF4BBC99EABB6B369311259189103194C01E40FE65B3B` |
| SSDEEP | `192:zCcCThgrScIAfITsceXQKUFcyUScIAcKwQKEH:zCcuqWcIvTscGQKUFc1ScIEwQKEH` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_081_e388e7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e388e7ce2449ba4100483186d9242e96f0cf74196d2519d37b581df682c57de6"
    family = "unknown"
    file_name = "ProtokolZatrimannya.zip"
    file_type = "zip"
    first_seen = "2026-07-23 19:43:34"
  condition:
    hash.sha256(0, filesize) == "e388e7ce2449ba4100483186d9242e96f0cf74196d2519d37b581df682c57de6"
}
```

### Sample 82: `5e845612d64df534`

| Field | Value |
|---|---|
| SHA-256 | `5e845612d64df5342ea509eed924bcfd9c9d2195f1db8ae7c2d69f9503c21c0b` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-23 19:35:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5b38d295620dfa80dfcdd34878bdd114` |
| SHA-1 | `b34d79da16135a794ce66af9e4304c62af781ea5` |
| SHA-256 | `5e845612d64df5342ea509eed924bcfd9c9d2195f1db8ae7c2d69f9503c21c0b` |
| SHA3-384 | `dfd150c80db983746aaba8a94d8680b827417d8012b7284e802dead126097564c59d7886fe8f85214eabcefc7d8b1d36` |
| TLSH | `T14FC32A59FC819A12C6C2167BFE5F82CD772723A8E3EA3117DD245F25378B81A0E6B141` |
| SSDEEP | `3072:OQlqMmNkvxTksX2YFEe6wyIPiTF+CqfaO8yYnbr:OAqMmNgxTlGphmqR+CsCykr` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_5e845612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e845612d64df5342ea509eed924bcfd9c9d2195f1db8ae7c2d69f9503c21c0b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 19:35:50"
  condition:
    hash.sha256(0, filesize) == "5e845612d64df5342ea509eed924bcfd9c9d2195f1db8ae7c2d69f9503c21c0b"
}
```

### Sample 83: `06c4ddabac5e976f`

| Field | Value |
|---|---|
| SHA-256 | `06c4ddabac5e976f152f482a47581313fdb95e2cbee564d56279648bbaf5694a` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-07-23 19:34:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1da638aacac4ac10885e5acc098b43dd` |
| SHA-1 | `89bd3c3dfdd30ac7ed08287f1d151466656ddd83` |
| SHA-256 | `06c4ddabac5e976f152f482a47581313fdb95e2cbee564d56279648bbaf5694a` |
| SHA3-384 | `c63c59051a7dca3b4421cff77c5c9cf7ada5c28e2f50496819e5140ca2dcc3910064ae18ab5c63a4c63d785875801006` |
| TLSH | `T12A14A75D2E228F7EF678C73447F74A24976C73DA26E1D684D2ACD1102F2424E641FBA8` |
| TELFHASH | `t16c4167180e7813f097355d9e45adff3696a330db7e126d378e11e85aeb699834d10c1c` |
| SSDEEP | `3072:R20gQLhVOgorO70jb6qgEcNxcK8jIdbnujzkSq:R20B+J5eqglNf8j0Sjzvq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_06c4ddab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06c4ddabac5e976f152f482a47581313fdb95e2cbee564d56279648bbaf5694a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-23 19:34:28"
  condition:
    hash.sha256(0, filesize) == "06c4ddabac5e976f152f482a47581313fdb95e2cbee564d56279648bbaf5694a"
}
```

### Sample 84: `672f654f31e91cdb`

| Field | Value |
|---|---|
| SHA-256 | `672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-07-23 19:23:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `00a8f54e5b4ea0ad931fcd250f23cd06` |
| SHA-1 | `643e9739e423bb91534e1b933a152e82750e1c89` |
| SHA-256 | `672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95` |
| SHA3-384 | `9fba782dab50c03a3487f1137cae147d7d27b56c9750b02d5bbe68af34eee7e5f1c747db0e4ebd6dafc828272d27faf6` |
| TLSH | `T1AFE3F849F9518F22C6C215BBFF4E428D7B2617A8D3EA72039D156F25378B85B0E3B142` |
| SSDEEP | `1536:qlrsEbvm7QNpmIDdowZBemoGeFWP1nQM2uFF4V65TOTYVvTKtSRjOhR6K9V6CXKT:mprow+2eoxQMv4uC0VvO0YBxsnuv4` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_084_672f654f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-23 19:23:45"
  condition:
    hash.sha256(0, filesize) == "672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95"
}
```

### Sample 85: `9d8e694d18e3c976`

| Field | Value |
|---|---|
| SHA-256 | `9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-07-23 19:21:15` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `49b03595c3506b6b9a93d3eac5753d83` |
| SHA-1 | `b87382022a6254affd671428fd3d2346844acabd` |
| SHA-256 | `9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262` |
| SHA3-384 | `3c6416c50b5f9f6013c7f2795b83111212f7f0542412b68145b095a586d5a2008f203363b037b1f533d942814b9b50cd` |
| TLSH | `T165D3F849F8919F22C6C615FBFB4E828C772617A8D3EE720399146F25379B85B0E3B141` |
| TELFHASH | `t126e026736b451ecc4be7d482908a2b3963fcf5164b42280e4d9c1e1ad8d3147f41f013` |
| SSDEEP | `3072:rtjm6YoqeWCI28R451kA7sUtk98Vf5EnuDQ:rtagwhR45CA7xe98VXDQ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_9d8e694d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 19:21:15"
  condition:
    hash.sha256(0, filesize) == "9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262"
}
```

### Sample 86: `731fc822a6bdfe76`

| Field | Value |
|---|---|
| SHA-256 | `731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b` |
| Family label | `WannaCry` |
| File name | `731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b` |
| File type | `exe` |
| First seen | `2026-07-23 19:15:30` |
| Reporter | `pawscobbler` |
| Tags | `dionaea, exe, WannaCry` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `71fc38575f3641e70a22e1a291e55395` |
| SHA-1 | `9b390674150f32ad0f2b7944f3afe21c01f84dbb` |
| SHA-256 | `731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b` |
| SHA3-384 | `51a212d5b0db369aa96f7d763ca8f253b1ec1cc4e7df99ad800278272dcbf1427fcf654081227d79c13de97df7938018` |
| IMPHASH | `0cdadfa1098d845dd3b4cf92625b5f04` |
| TLSH | `T1E936D015A2E82B64E7F35EB2217B871047757E4589AB924E1760A04F0C33F5CDEB2F29` |
| SSDEEP | `49152:jnsnsEMSPbcBVQejl+TSqTdX1HkQo6SAA:DMfPoBhhcSUDk36SA` |

#### Technical Assessment

- The sample is tracked as `WannaCry` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_WannaCry_086_731fc822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b"
    family = "WannaCry"
    file_name = "731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b"
    file_type = "exe"
    first_seen = "2026-07-23 19:15:30"
  condition:
    hash.sha256(0, filesize) == "731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b"
}
```

### Sample 87: `1d8f6366efd827ab`

| Field | Value |
|---|---|
| SHA-256 | `1d8f6366efd827ab0a2036904c05223064cf73dd547a6cb02e23eb52c77c4db0` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-23 19:10:14` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7d39fba473c2500f77d7e84f8a20efcf` |
| SHA-1 | `3a97b5bcaae4dbfaae00cf8844225950d57b8efd` |
| SHA-256 | `1d8f6366efd827ab0a2036904c05223064cf73dd547a6cb02e23eb52c77c4db0` |
| SHA3-384 | `f6fba3e11b7b2bad1485fa46949ae409bc47730890b949641ffa6a2df77334cd0b2c7c7195b0a12baef48707f3fe7a4a` |
| TLSH | `T160137D695A953C259E9988371D7E2F0CB9AA83E5300851DDBFCB3CF28C45ADCE21871D` |
| SSDEEP | `768:TVEJVIhtMmj9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:pEJ2Mmkco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_1d8f6366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8f6366efd827ab0a2036904c05223064cf73dd547a6cb02e23eb52c77c4db0"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 19:10:14"
  condition:
    hash.sha256(0, filesize) == "1d8f6366efd827ab0a2036904c05223064cf73dd547a6cb02e23eb52c77c4db0"
}
```

### Sample 88: `8f08d169740c185e`

| Field | Value |
|---|---|
| SHA-256 | `8f08d169740c185efcb8dd7f7e507e7a368a06dc920ebfe7686102e22feab391` |
| Family label | `unknown` |
| File name | `bot.mips` |
| File type | `elf` |
| First seen | `2026-07-23 19:07:20` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a803d52cb0e664204f123b6f161063d5` |
| SHA-1 | `24f228adf8fc23031bfda7cc796d3f588dc76cc7` |
| SHA-256 | `8f08d169740c185efcb8dd7f7e507e7a368a06dc920ebfe7686102e22feab391` |
| SHA3-384 | `0a53951293da234ce3bc68a147009b95a001fa389442cc538ad3fc101226774a7d352171956ffdbef69377e8712328c5` |
| TLSH | `T1E0056B233722CFA4E359C57009B3CA555AD521A21AF244C9B27CD31C7EA162D3E5FEE8` |
| TELFHASH | `t14251b3a8093813e4a3755c5d0aedff36d5e234ef7a161c378d10e45ea72aa824d14c0d` |
| SSDEEP | `12288:qyB4WcoXtbmJdZOIhdJ8Il0nDYB9UF0qurlWekGhun6u8pJJ1K66w:J4WcoXt+LJ8o0DYBp5rlWeJiOYTw` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_8f08d169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f08d169740c185efcb8dd7f7e507e7a368a06dc920ebfe7686102e22feab391"
    family = "unknown"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-07-23 19:07:20"
  condition:
    hash.sha256(0, filesize) == "8f08d169740c185efcb8dd7f7e507e7a368a06dc920ebfe7686102e22feab391"
}
```

### Sample 89: `c3433dd61c7a5704`

| Field | Value |
|---|---|
| SHA-256 | `c3433dd61c7a5704d780be6f3a1e40492baf6171a45266c2dc363a5c165f2a0f` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-23 19:01:22` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8a23b1204d1e5e8bd354dddb69e26b29` |
| SHA-1 | `bfc55e6e14f8200fe31cc73e19d475edaf3b9d41` |
| SHA-256 | `c3433dd61c7a5704d780be6f3a1e40492baf6171a45266c2dc363a5c165f2a0f` |
| SHA3-384 | `7e99af8ad83bd171b854107164415f8270b31bf065674bcefde73a7005185ce56851cb6cffd1d4e9d26d1d90fcfb74f1` |
| TLSH | `T1F0137D695A953C259E9988371D7E2F0CB9AA83E5300851DDBFCB3CF28C45ADCE21871D` |
| SSDEEP | `768:rVEJVIhtMP9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:REJ2Moco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_089_c3433dd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3433dd61c7a5704d780be6f3a1e40492baf6171a45266c2dc363a5c165f2a0f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 19:01:22"
  condition:
    hash.sha256(0, filesize) == "c3433dd61c7a5704d780be6f3a1e40492baf6171a45266c2dc363a5c165f2a0f"
}
```

### Sample 90: `23e1c6ab1e36a9a4`

| Field | Value |
|---|---|
| SHA-256 | `23e1c6ab1e36a9a43bcea0f55c3c3dbc32622df5dabd7e6dae1fc03ddc59e970` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-07-23 18:55:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e4f66c0de3efa19600a01e30be20f5e4` |
| SHA-1 | `2fdcc82cb9a44851d4a9b1c52a546015462c07f7` |
| SHA-256 | `23e1c6ab1e36a9a43bcea0f55c3c3dbc32622df5dabd7e6dae1fc03ddc59e970` |
| SHA3-384 | `0f9a6f15b6fcf3a909ecc277ec7399be0da8a4ba288afab82dcdc7da981cd801df7e71d7e2b19db8b6bfc590a5ff5b7d` |
| TLSH | `T175E3179AF8829F11D4D625BAFE5E518D332327ACE3EE7112DD245F2532CA91B0E3B501` |
| TELFHASH | `t117d0a772e07544ecc35084318299922f3e83bbbd9f4510b18d4a6c922fc3c267e65003` |
| SSDEEP | `3072:p3d1PQ5Mkp2tsnwe4hDEiyVcYH2ZcN09WgVTmarC0lS8Ews3IvmEKYb39QnbJ:ZfPQ5MkuCwHFycYOcNT2TmarC0lS8EFn` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_090_23e1c6ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23e1c6ab1e36a9a43bcea0f55c3c3dbc32622df5dabd7e6dae1fc03ddc59e970"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-23 18:55:40"
  condition:
    hash.sha256(0, filesize) == "23e1c6ab1e36a9a43bcea0f55c3c3dbc32622df5dabd7e6dae1fc03ddc59e970"
}
```

### Sample 91: `51c7abd74c3de141`

| Field | Value |
|---|---|
| SHA-256 | `51c7abd74c3de141108d7f229d2c54df93a1b4f28fb6e95987aa7676e3c88480` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-07-23 18:53:14` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ea0048c21522a901d050e1e82d6c267` |
| SHA-1 | `b2b95b8d0c4d608b94505836e10633ff9a990172` |
| SHA-256 | `51c7abd74c3de141108d7f229d2c54df93a1b4f28fb6e95987aa7676e3c88480` |
| SHA3-384 | `2a592cde950c8518f308bc663abb9042d595ebe7092464c08666eaa4f6788706e03af1d52dfab458ee51be95ed36a564` |
| TLSH | `T1F014B80AAF610EFBD8ABDD3306E90B0535CCA54722A43B753574D528F64A94F4AD3CB8` |
| SSDEEP | `3072:piWdUlf3JScK8sDUVzv1w7E4OYFWBnu2yGX:p8lf3JoDKbHwd2y` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_51c7abd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c7abd74c3de141108d7f229d2c54df93a1b4f28fb6e95987aa7676e3c88480"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-23 18:53:14"
  condition:
    hash.sha256(0, filesize) == "51c7abd74c3de141108d7f229d2c54df93a1b4f28fb6e95987aa7676e3c88480"
}
```

### Sample 92: `2d373d72472f7d9d`

| Field | Value |
|---|---|
| SHA-256 | `2d373d72472f7d9d11a3fc7d4874cf423b4260bed2e080d745ee127bcef237e6` |
| Family label | `unknown` |
| File name | `default.dat` |
| File type | `exe` |
| First seen | `2026-07-23 18:52:08` |
| Reporter | `iamaachum` |
| Tags | `ClickFix, Efimer, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `88340d0e1960fa34bd570682d58fc991` |
| SHA-1 | `752e43384f79c2982a6f4e66f5968fe8fcd77c7c` |
| SHA-256 | `2d373d72472f7d9d11a3fc7d4874cf423b4260bed2e080d745ee127bcef237e6` |
| SHA3-384 | `dd2f20dab4f7030e10621b6724a5c680c6ef97ed783f731331b724fa3e11cbf40f5775a5975dd87ce3af19e2cc74f98c` |
| IMPHASH | `dcaf48c1f10b0efa0a4472200f3850ed` |
| TLSH | `T141E633046EE016FEF6B3013CD9E141A2A5A574A24B32CAD747CC83D67D671E14E3CAA7` |
| SSDEEP | `393216:Hjg0FGUi/7L/hVj//hu9j7n9wXMCHWUjX3cuI3/PGTAI:HjbW7L/Hj/gFiXMb8XMH/O7` |
| ICON-DHASH | `7471d4d8c8ecf030` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_2d373d72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d373d72472f7d9d11a3fc7d4874cf423b4260bed2e080d745ee127bcef237e6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 18:52:08"
  condition:
    hash.sha256(0, filesize) == "2d373d72472f7d9d11a3fc7d4874cf423b4260bed2e080d745ee127bcef237e6"
}
```

### Sample 93: `11dab4308daadc75`

| Field | Value |
|---|---|
| SHA-256 | `11dab4308daadc7569ca0ae38faeed467b5108e66efc9272546e302d5281f734` |
| Family label | `unknown` |
| File name | `268575def2db78e185cded3bdd3c9157.exe` |
| File type | `exe` |
| First seen | `2026-07-23 18:45:53` |
| Reporter | `abuse_ch` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `268575def2db78e185cded3bdd3c9157` |
| SHA-1 | `d58c95d35b5f850fcf00af53723588b8a0025856` |
| SHA-256 | `11dab4308daadc7569ca0ae38faeed467b5108e66efc9272546e302d5281f734` |
| SHA3-384 | `7afa7d2fa2d9954437413d3e347482f1b88b40610152a776080f4e5e8d2ce69fce7493024268b9b77e1afd242c8225d5` |
| IMPHASH | `b81a571f8c08eff9589abe19c33b96b2` |
| TLSH | `T14CB48C22F65113ACC46AC0798356B632B231709C9BE1A9FF16E807743E5AEF06B3D754` |
| SSDEEP | `6144:yKwTCtziA0FvTR+rUCJOzLb+3zrOm/M8sV725kb0CfGm/czVly7vp:yKw3vHDze4btuep` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_093_11dab430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11dab4308daadc7569ca0ae38faeed467b5108e66efc9272546e302d5281f734"
    family = "unknown"
    file_name = "268575def2db78e185cded3bdd3c9157.exe"
    file_type = "exe"
    first_seen = "2026-07-23 18:45:53"
  condition:
    hash.sha256(0, filesize) == "11dab4308daadc7569ca0ae38faeed467b5108e66efc9272546e302d5281f734"
}
```

### Sample 94: `2618a8ed67c07427`

| Field | Value |
|---|---|
| SHA-256 | `2618a8ed67c07427965f10cd2c43676f4b929083d85e821d55edee8ea17cd94f` |
| Family label | `unknown` |
| File name | `o.xml` |
| File type | `unknown` |
| First seen | `2026-07-23 18:45:13` |
| Reporter | `abuse_ch` |
| Tags | `none` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c258e69b9e96664f96b06878d86448d` |
| SHA-256 | `2618a8ed67c07427965f10cd2c43676f4b929083d85e821d55edee8ea17cd94f` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `unknown`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_094_2618a8ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2618a8ed67c07427965f10cd2c43676f4b929083d85e821d55edee8ea17cd94f"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-07-23 18:45:13"
  condition:
    hash.sha256(0, filesize) == "2618a8ed67c07427965f10cd2c43676f4b929083d85e821d55edee8ea17cd94f"
}
```

### Sample 95: `3de28e0230e64b89`

| Field | Value |
|---|---|
| SHA-256 | `3de28e0230e64b890a6162d4d60330aa70be23b496287d1740c7847738cce1c0` |
| Family label | `unknown` |
| File name | `k.php` |
| File type | `sh` |
| First seen | `2026-07-23 18:43:40` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b08b22d66dd65a7256d667d2d8ba0d96` |
| SHA-1 | `aa617a368882df4f869f71146e27a5302e42ec6e` |
| SHA-256 | `3de28e0230e64b890a6162d4d60330aa70be23b496287d1740c7847738cce1c0` |
| SHA3-384 | `d7bfd56267afe0e9e1d3a5a8cf7655707fc79a658f922c58d2886d4517a19b3af723f0f32bc18b640acb8bbeed291efa` |
| TLSH | `T1E9136C6526953C25AE99883B5C7F2F0CBDA983E2304491DDBFCA3CF18C15A9CE318719` |
| SSDEEP | `768:Vr9NyXsZztCn9GKYpr9GKYp82fkR4nnA9GKYpr9GKYp82fkR4nnx:9HusZtco` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_095_3de28e02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3de28e0230e64b890a6162d4d60330aa70be23b496287d1740c7847738cce1c0"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 18:43:40"
  condition:
    hash.sha256(0, filesize) == "3de28e0230e64b890a6162d4d60330aa70be23b496287d1740c7847738cce1c0"
}
```

### Sample 96: `23075f5c503344af`

| Field | Value |
|---|---|
| SHA-256 | `23075f5c503344af0a808631698c1bb092425f95a3ff8dd03cc7a8564ebc2d8d` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnpowerpcxnxn` |
| File type | `elf` |
| First seen | `2026-07-23 18:42:57` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5d93f7681447768176fe6627184f9aa8` |
| SHA-1 | `4a1a13f58c6b11da958681a37fe3dc8f58a71ca1` |
| SHA-256 | `23075f5c503344af0a808631698c1bb092425f95a3ff8dd03cc7a8564ebc2d8d` |
| SHA3-384 | `53fde41ed281b67f0b5eed7de971db3c666db1cfe4ab13a6bca94e990d6e8d9e68a563fa867650c3064fbf6e9e010c02` |
| TLSH | `T166145A05FB0C0463CA931CF48E3F0BFAA3621A9115F99115250D7F5A1A32DB7A68BFD9` |
| SSDEEP | `3072:ESZAGIiEgACYrerYqlNSwppHaecY4NXvUaN:HZ15BTYCrYq1QDY684` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_23075f5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23075f5c503344af0a808631698c1bb092425f95a3ff8dd03cc7a8564ebc2d8d"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:42:57"
  condition:
    hash.sha256(0, filesize) == "23075f5c503344af0a808631698c1bb092425f95a3ff8dd03cc7a8564ebc2d8d"
}
```

### Sample 97: `5f2979cd7d8192bb`

| Field | Value |
|---|---|
| SHA-256 | `5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591` |
| Family label | `PureRAT` |
| File name | `13aa55915fe8418214edc3f57138e29e.exe` |
| File type | `exe` |
| First seen | `2026-07-23 18:42:55` |
| Reporter | `abuse_ch` |
| Tags | `exe, PureRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `13aa55915fe8418214edc3f57138e29e` |
| SHA-1 | `1f0018007ed4f8c86b7954cdcb91b7081ae25afe` |
| SHA-256 | `5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591` |
| SHA3-384 | `ae779359648aa4a865d7865027d50305afb48141f0e4363b3ae6d9460d6ce8b3f34a6b1660df387be625dc2e0ecc9dbc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1C1943B3A36918E21C24A5373C5D7490087EB9A8777ABEB0B358423D60D473FEDE46297` |
| SSDEEP | `6144:NBC+YXkcg+Qaqnwgmf+S14rFmvzxfD2cONhCvARr:5YZQhwgAd2FmvV2cOrCmr` |

#### Technical Assessment

- The sample is tracked as `PureRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_PureRAT_097_5f2979cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591"
    family = "PureRAT"
    file_name = "13aa55915fe8418214edc3f57138e29e.exe"
    file_type = "exe"
    first_seen = "2026-07-23 18:42:55"
  condition:
    hash.sha256(0, filesize) == "5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591"
}
```

### Sample 98: `f107ff44d5cbfc85`

| Field | Value |
|---|---|
| SHA-256 | `f107ff44d5cbfc85f5e42b0d9c8a5729663eb34da34fac97e03f2591949bb4b2` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnpowerpcxnxn` |
| File type | `elf` |
| First seen | `2026-07-23 18:42:29` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6e47e034184dadf379413aadf89e4bc` |
| SHA-1 | `2ae4637ae97fc476f34f86a1749e8759eeed4f86` |
| SHA-256 | `f107ff44d5cbfc85f5e42b0d9c8a5729663eb34da34fac97e03f2591949bb4b2` |
| SHA3-384 | `56b5f9838dcf2c14a2d6df24101634382f8512d7a3538405796e4f84760e519214738553204d513ea395f4c68afc19e2` |
| TLSH | `T11A631247FFDC1F9CFCD91BF907AA22CB13619431947380A409EA589A915FA7111DB8CD` |
| SSDEEP | `1536:27MbwKNGjjH+Xq34n/q8Zu41zmX3sDgorP1:27Mbp2L+Xqdfoz2sXrP1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_098_f107ff44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f107ff44d5cbfc85f5e42b0d9c8a5729663eb34da34fac97e03f2591949bb4b2"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:42:29"
  condition:
    hash.sha256(0, filesize) == "f107ff44d5cbfc85f5e42b0d9c8a5729663eb34da34fac97e03f2591949bb4b2"
}
```

### Sample 99: `a161f36eea166dfa`

| Field | Value |
|---|---|
| SHA-256 | `a161f36eea166dfad68afa2f686af99adcaa1067c53d0ef56fdc5504b2ea594e` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmipsxnxn` |
| File type | `elf` |
| First seen | `2026-07-23 18:41:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6d7a8347f0f042b2ef820b8be687c657` |
| SHA-1 | `354e2a7491e7aca36659684bf590294db47b1d6d` |
| SHA-256 | `a161f36eea166dfad68afa2f686af99adcaa1067c53d0ef56fdc5504b2ea594e` |
| SHA3-384 | `12fc63c861d50fc41b9dba42d83e60073f75afd26dba65a7a837899a8c4a4378309037701e655080c0f7256fdb3453aa` |
| TLSH | `T123F33B47B7208FB1C368D67109B3CB67A6E6269216E19985E66DCD107E3035C6C3FFA0` |
| TELFHASH | `t1d9c002145c7457f15108dd5540dc7f29c5f51dcf15431d1fd9183c654631d831f00d59` |
| SSDEEP | `3072:93VJgTdgahP/2o/ZrTheIsnjCWRXFm4UpM1wLxpPNNOziHofam:9FJMgWPZr8IaCWReS1WpPeR7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_099_a161f36e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a161f36eea166dfad68afa2f686af99adcaa1067c53d0ef56fdc5504b2ea594e"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:41:56"
  condition:
    hash.sha256(0, filesize) == "a161f36eea166dfad68afa2f686af99adcaa1067c53d0ef56fdc5504b2ea594e"
}
```

### Sample 100: `2da61d02faca4daf`

| Field | Value |
|---|---|
| SHA-256 | `2da61d02faca4dafea3fd8e731f57148fee7b3431f1050d6528a88a774f7f81a` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmicroblazexnxn` |
| File type | `elf` |
| First seen | `2026-07-23 18:41:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e1ff845d88b82c41483b39b965e595f` |
| SHA-1 | `2fa76bfc221d49bfc01f6023c8d25beaa22ec466` |
| SHA-256 | `2da61d02faca4dafea3fd8e731f57148fee7b3431f1050d6528a88a774f7f81a` |
| SHA3-384 | `a45243eef25f2901a9e78e309c1cabe7a37bc91c37c0cacc061159994ca943b5555f82c32ef06f45d4f13e8e3ac54da4` |
| TLSH | `T1F9148120FA0663B1CC731A34A79A2E5A6E7704559FEB26312D1F533CDE628509B31F8D` |
| SSDEEP | `3072:IcHZcggt1NJmeDQBwnKUDMaVsb3pjr1lCRqUKG:IcY5JpMByVs9jSVf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_2da61d02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2da61d02faca4dafea3fd8e731f57148fee7b3431f1050d6528a88a774f7f81a"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmicroblazexnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:41:16"
  condition:
    hash.sha256(0, filesize) == "2da61d02faca4dafea3fd8e731f57148fee7b3431f1050d6528a88a774f7f81a"
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
 * Generated: 2026-07-24T03:48:50.779284+00:00
 */

rule MalwareBazaar_Mirai_001_a26b1110
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a26b11101cc94ce54f1de9a77bf5ff3a712fd4d21968ea24314d70bd27d68f23"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-24 03:17:05"
  condition:
    hash.sha256(0, filesize) == "a26b11101cc94ce54f1de9a77bf5ff3a712fd4d21968ea24314d70bd27d68f23"
}

rule MalwareBazaar_Mirai_002_1e43c851
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1e43c851beb648efe1af0c38c829432f0c41ccc26147cbc525a03b1e08e8d973"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-24 03:16:04"
  condition:
    hash.sha256(0, filesize) == "1e43c851beb648efe1af0c38c829432f0c41ccc26147cbc525a03b1e08e8d973"
}

rule MalwareBazaar_Mirai_003_3409830b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3409830b6430e24f032982a4d7e838e8a0ee2742f005341b47bc71ad2db1e0b2"
    family = "Mirai"
    file_name = "ppc"
    file_type = "elf"
    first_seen = "2026-07-24 03:16:02"
  condition:
    hash.sha256(0, filesize) == "3409830b6430e24f032982a4d7e838e8a0ee2742f005341b47bc71ad2db1e0b2"
}

rule MalwareBazaar_unknown_004_a431fc7a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a431fc7aa495e68464d9855922889d77d2878a2725dd7c0a1abd842005252d40"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 03:11:25"
  condition:
    hash.sha256(0, filesize) == "a431fc7aa495e68464d9855922889d77d2878a2725dd7c0a1abd842005252d40"
}

rule MalwareBazaar_ACRStealer_005_dfde3023
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dfde30238bbc2c40f9ca5b3c94957365e2dbdb6eadd9c9818985e3feba023715"
    family = "ACRStealer"
    file_name = "j.pm"
    file_type = "dll"
    first_seen = "2026-07-24 03:10:16"
  condition:
    hash.sha256(0, filesize) == "dfde30238bbc2c40f9ca5b3c94957365e2dbdb6eadd9c9818985e3feba023715"
}

rule MalwareBazaar_unknown_006_cf61df96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cf61df96aceb14da9491e399dc28e801c3d384ea2b2ec34f146b932f18f52f01"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-24 02:52:08"
  condition:
    hash.sha256(0, filesize) == "cf61df96aceb14da9491e399dc28e801c3d384ea2b2ec34f146b932f18f52f01"
}

rule MalwareBazaar_unknown_007_7fc5cb22
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7fc5cb22a222d2162d9412af7cd0befd9d194482b0545900c496ad2a74fe5f8d"
    family = "unknown"
    file_name = "com.pictureclean.cleanplan_1.2.6.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:46:05"
  condition:
    hash.sha256(0, filesize) == "7fc5cb22a222d2162d9412af7cd0befd9d194482b0545900c496ad2a74fe5f8d"
}

rule MalwareBazaar_Vidar_008_01b8d27f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "01b8d27f31cf1b2590e5eec4fe6da5d00da282cbee66149d48e2b6d615b92fc7"
    family = "Vidar"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:17"
  condition:
    hash.sha256(0, filesize) == "01b8d27f31cf1b2590e5eec4fe6da5d00da282cbee66149d48e2b6d615b92fc7"
}

rule MalwareBazaar_CoinMiner_009_4852391f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4852391f807c55bf92aa89c874b739add2d284e2669a9c9c51e8e7e76882fa8a"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:17"
  condition:
    hash.sha256(0, filesize) == "4852391f807c55bf92aa89c874b739add2d284e2669a9c9c51e8e7e76882fa8a"
}

rule MalwareBazaar_unknown_010_f2b90487
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f2b90487ccf966408996bd182314719a9be80a95a6e646cf71b98055be58691e"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:10"
  condition:
    hash.sha256(0, filesize) == "f2b90487ccf966408996bd182314719a9be80a95a6e646cf71b98055be58691e"
}

rule MalwareBazaar_unknown_011_da97b7a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "da97b7a5526123b0c6e19b97d1a0fce298421d4762c42d2531956a05e6800527"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 02:45:01"
  condition:
    hash.sha256(0, filesize) == "da97b7a5526123b0c6e19b97d1a0fce298421d4762c42d2531956a05e6800527"
}

rule MalwareBazaar_unknown_012_5b024a63
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b024a63ee25fd79958bc723626d82fca9fac59828047b67dd986c91d1c4c175"
    family = "unknown"
    file_name = "com.cleanfile.managerapp.coolfile_1.3.35.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:39:10"
  condition:
    hash.sha256(0, filesize) == "5b024a63ee25fd79958bc723626d82fca9fac59828047b67dd986c91d1c4c175"
}

rule MalwareBazaar_unknown_013_896620fe
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "896620fec435d32e0d65a8933f91fa41156f1ebaf45ec9a7f1f8a45f2cea18f8"
    family = "unknown"
    file_name = "Go+Clean+Pro_2.0.8.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:36:59"
  condition:
    hash.sha256(0, filesize) == "896620fec435d32e0d65a8933f91fa41156f1ebaf45ec9a7f1f8a45f2cea18f8"
}

rule MalwareBazaar_unknown_014_3c296974
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3c296974599361635eed48f91f3bfe43d09b4375deb0f7cc582b33874f06cfdb"
    family = "unknown"
    file_name = "com.shrtsms.xxmessages_5.6.xapk"
    file_type = "xapk"
    first_seen = "2026-07-24 02:30:46"
  condition:
    hash.sha256(0, filesize) == "3c296974599361635eed48f91f3bfe43d09b4375deb0f7cc582b33874f06cfdb"
}

rule MalwareBazaar_unknown_015_642905ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "642905ce09772b7ee37efac563f1d14581b2d677a738aa8f44244659d331f921"
    family = "unknown"
    file_name = "TENDER-20005953911.vbs"
    file_type = "vbs"
    first_seen = "2026-07-24 02:22:58"
  condition:
    hash.sha256(0, filesize) == "642905ce09772b7ee37efac563f1d14581b2d677a738aa8f44244659d331f921"
}

rule MalwareBazaar_ACRStealer_016_6546d4bc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6546d4bcaf4bd2848d6f5d86def14961a312b482302a12c7850f5dd1d58601cf"
    family = "ACRStealer"
    file_name = "j.pem"
    file_type = "dll"
    first_seen = "2026-07-24 02:07:29"
  condition:
    hash.sha256(0, filesize) == "6546d4bcaf4bd2848d6f5d86def14961a312b482302a12c7850f5dd1d58601cf"
}

rule MalwareBazaar_Mirai_017_f4eabc26
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4eabc26ada6bbe04591abbcbbefd73a4e9c517508a2c45cec565c434c462974"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-24 02:04:49"
  condition:
    hash.sha256(0, filesize) == "f4eabc26ada6bbe04591abbcbbefd73a4e9c517508a2c45cec565c434c462974"
}

rule MalwareBazaar_Mirai_018_6b232621
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6b232621c7d31c73bee8fd4462106f68b9a060810a504ce4383470cd9c0c47d4"
    family = "Mirai"
    file_name = "nz.x86_64"
    file_type = "elf"
    first_seen = "2026-07-24 02:03:32"
  condition:
    hash.sha256(0, filesize) == "6b232621c7d31c73bee8fd4462106f68b9a060810a504ce4383470cd9c0c47d4"
}

rule MalwareBazaar_unknown_019_53d82677
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "53d826779abf284ea492ff4c09865e1566c3c62836c28d3c5ad7729f0a8d523a"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-24 01:52:08"
  condition:
    hash.sha256(0, filesize) == "53d826779abf284ea492ff4c09865e1566c3c62836c28d3c5ad7729f0a8d523a"
}

rule MalwareBazaar_Mirai_020_d96053c4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d96053c4a362bf445aed2840f95f6014d0acec1f3710c1cd3ea1a8e2f2a7c379"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-24 01:17:25"
  condition:
    hash.sha256(0, filesize) == "d96053c4a362bf445aed2840f95f6014d0acec1f3710c1cd3ea1a8e2f2a7c379"
}

rule MalwareBazaar_Mirai_021_5bafd844
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5bafd8445d3cefd61274fa18b4dc51fa53de1a9d37bbea6a88c126d0b910964f"
    family = "Mirai"
    file_name = "nz.arm"
    file_type = "elf"
    first_seen = "2026-07-24 01:17:21"
  condition:
    hash.sha256(0, filesize) == "5bafd8445d3cefd61274fa18b4dc51fa53de1a9d37bbea6a88c126d0b910964f"
}

rule MalwareBazaar_unknown_022_30d51cc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "30d51cc7e46c06f93cf8d5589611ef5555eb22ae54d420bb9dae8d01164d51ba"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-24 01:00:07"
  condition:
    hash.sha256(0, filesize) == "30d51cc7e46c06f93cf8d5589611ef5555eb22ae54d420bb9dae8d01164d51ba"
}

rule MalwareBazaar_unknown_023_5b578518
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5b5785181f5017228be7f0cd094a4e9eef4a90dde8e9f927eefcab320efce782"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-24 00:57:37"
  condition:
    hash.sha256(0, filesize) == "5b5785181f5017228be7f0cd094a4e9eef4a90dde8e9f927eefcab320efce782"
}

rule MalwareBazaar_unknown_024_5654de2c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5654de2cff9abd8eb423a4b396a30aa374020eb35ec6246bce863445e7656b67"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-24 00:52:08"
  condition:
    hash.sha256(0, filesize) == "5654de2cff9abd8eb423a4b396a30aa374020eb35ec6246bce863445e7656b67"
}

rule MalwareBazaar_Mirai_025_e29d2acf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e29d2acf2b80343dbe5c7f7a878ee599da6560ea5d26e90d240b2d25509b5161"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-24 00:49:48"
  condition:
    hash.sha256(0, filesize) == "e29d2acf2b80343dbe5c7f7a878ee599da6560ea5d26e90d240b2d25509b5161"
}

rule MalwareBazaar_Mirai_026_9f6476d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9f6476d569eb59de3436b98b4001177b1b8cf4c723f9b23f7917eaec4de09ba9"
    family = "Mirai"
    file_name = "nz.x86"
    file_type = "elf"
    first_seen = "2026-07-24 00:49:25"
  condition:
    hash.sha256(0, filesize) == "9f6476d569eb59de3436b98b4001177b1b8cf4c723f9b23f7917eaec4de09ba9"
}

rule MalwareBazaar_Mirai_027_890d12eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "890d12eb74c66e0e05848d307cf0c111f1cc63377a22f65cd70ef837ab850827"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-24 00:48:47"
  condition:
    hash.sha256(0, filesize) == "890d12eb74c66e0e05848d307cf0c111f1cc63377a22f65cd70ef837ab850827"
}

rule MalwareBazaar_Mirai_028_d4422ae2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d4422ae2578d764361e6b38c3ef4ba22663f3328ab958b785e5ab75672017dae"
    family = "Mirai"
    file_name = "nz.i686"
    file_type = "elf"
    first_seen = "2026-07-24 00:48:16"
  condition:
    hash.sha256(0, filesize) == "d4422ae2578d764361e6b38c3ef4ba22663f3328ab958b785e5ab75672017dae"
}

rule MalwareBazaar_unknown_029_8b0ed993
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8b0ed9933f1789745e5553d79a5c3b471be1518a95fda91c96898d8281bf9388"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-24 00:44:29"
  condition:
    hash.sha256(0, filesize) == "8b0ed9933f1789745e5553d79a5c3b471be1518a95fda91c96898d8281bf9388"
}

rule MalwareBazaar_unknown_030_d9de17ac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9de17aca9359bb153ec9d62bdfbeadb170e043616358f5f8eabc33a4a0c24ea"
    family = "unknown"
    file_name = "launcher.dll"
    file_type = "exe"
    first_seen = "2026-07-24 00:09:36"
  condition:
    hash.sha256(0, filesize) == "d9de17aca9359bb153ec9d62bdfbeadb170e043616358f5f8eabc33a4a0c24ea"
}

rule MalwareBazaar_unknown_031_7c04b423
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c04b423f7277ee260c545f9c9f9ccd1ac46ccc19d622a9d4d7dbd27dfbbca7e"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-24 00:08:14"
  condition:
    hash.sha256(0, filesize) == "7c04b423f7277ee260c545f9c9f9ccd1ac46ccc19d622a9d4d7dbd27dfbbca7e"
}

rule MalwareBazaar_unknown_032_29cb2a27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29cb2a27e1da8d39c121e5f1808ba68b9791b31110baceaac14d648ce4133611"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-24 00:08:13"
  condition:
    hash.sha256(0, filesize) == "29cb2a27e1da8d39c121e5f1808ba68b9791b31110baceaac14d648ce4133611"
}

rule MalwareBazaar_unknown_033_9c62ae7e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e"
    family = "unknown"
    file_name = "9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e"
    file_type = "sh"
    first_seen = "2026-07-24 00:01:21"
  condition:
    hash.sha256(0, filesize) == "9c62ae7e69f2641908484452aecde7e2dde2ea4a5133521f13767f0afa338b8e"
}

rule MalwareBazaar_unknown_034_9135685a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95"
    family = "unknown"
    file_name = "9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95"
    file_type = "sh"
    first_seen = "2026-07-24 00:00:59"
  condition:
    hash.sha256(0, filesize) == "9135685a26d5517c154c17e4b8750f2cca02f06fbb5da620f3c520d4e313cc95"
}

rule MalwareBazaar_Mirai_035_8363a28a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8363a28a214a59c195ed87fd69d72bd766bc87bd949ba64b4706d0fe8eb8fd81"
    family = "Mirai"
    file_name = "nz.spc"
    file_type = "elf"
    first_seen = "2026-07-23 23:57:15"
  condition:
    hash.sha256(0, filesize) == "8363a28a214a59c195ed87fd69d72bd766bc87bd949ba64b4706d0fe8eb8fd81"
}

rule MalwareBazaar_unknown_036_e8647cce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8647ccecf457abe547c4211d4bcde013492a904ed1675cf3e7abb4069eead1f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 23:52:08"
  condition:
    hash.sha256(0, filesize) == "e8647ccecf457abe547c4211d4bcde013492a904ed1675cf3e7abb4069eead1f"
}

rule MalwareBazaar_Havoc_037_8724f2b3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8724f2b346f97cdba0d1aaaea8cc4d10ac5cf58a0b2fdbaf413db48b1ac8243e"
    family = "Havoc"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:50:08"
  condition:
    hash.sha256(0, filesize) == "8724f2b346f97cdba0d1aaaea8cc4d10ac5cf58a0b2fdbaf413db48b1ac8243e"
}

rule MalwareBazaar_CoinMiner_038_b7ce2cf4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b7ce2cf4c4a9cf3a2906bd3f53fff00f2c3e8ae4200451bf6194b00d94617490"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:29:40"
  condition:
    hash.sha256(0, filesize) == "b7ce2cf4c4a9cf3a2906bd3f53fff00f2c3e8ae4200451bf6194b00d94617490"
}

rule MalwareBazaar_unknown_039_ae8868d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae8868d7d2ccc713edea9da8988cb6668a2a4fb13b2942ebdf2c1bec10418fe0"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:09:29"
  condition:
    hash.sha256(0, filesize) == "ae8868d7d2ccc713edea9da8988cb6668a2a4fb13b2942ebdf2c1bec10418fe0"
}

rule MalwareBazaar_ACRStealer_040_051661de
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "051661deb65c018c8c127fe12a6de824e6a72812db0091d505de1751e740b451"
    family = "ACRStealer"
    file_name = "j.pem"
    file_type = "dll"
    first_seen = "2026-07-23 23:07:50"
  condition:
    hash.sha256(0, filesize) == "051661deb65c018c8c127fe12a6de824e6a72812db0091d505de1751e740b451"
}

rule MalwareBazaar_CoinMiner_041_842cd640
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "842cd640dae0c4eae792cfa2057774bbef7ccfe94cc8bcf3b189dbc03370e2d2"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 23:00:42"
  condition:
    hash.sha256(0, filesize) == "842cd640dae0c4eae792cfa2057774bbef7ccfe94cc8bcf3b189dbc03370e2d2"
}

rule MalwareBazaar_unknown_042_63c0d317
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "63c0d317645dc7169da2a6413cf1fcc8e300dd95af8c54ea06a4a3dc45a28275"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 22:52:09"
  condition:
    hash.sha256(0, filesize) == "63c0d317645dc7169da2a6413cf1fcc8e300dd95af8c54ea06a4a3dc45a28275"
}

rule MalwareBazaar_unknown_043_fe2e5dc7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "fe2e5dc794bf4bebe2092e45422fe5f9c5e8083e7ef32b5f9c17018941e19fa1"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 22:32:31"
  condition:
    hash.sha256(0, filesize) == "fe2e5dc794bf4bebe2092e45422fe5f9c5e8083e7ef32b5f9c17018941e19fa1"
}

rule MalwareBazaar_WannaCry_044_a172b484
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f"
    family = "WannaCry"
    file_name = "a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f"
    file_type = "exe"
    first_seen = "2026-07-23 22:15:39"
  condition:
    hash.sha256(0, filesize) == "a172b48466dd433ca36585641f5df51d69a426e2451411966b7d2268ede3703f"
}

rule MalwareBazaar_unknown_045_7c1f748c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7c1f748cb0bbf61e14a4b8170004ff8ece96a9a7838a4972c7b0ca92af35c53f"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 21:52:09"
  condition:
    hash.sha256(0, filesize) == "7c1f748cb0bbf61e14a4b8170004ff8ece96a9a7838a4972c7b0ca92af35c53f"
}

rule MalwareBazaar_CoinMiner_046_029a364b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "029a364b81370e6f680886c2e1a0751cc45d1539db9ef0b9b55265def3422259"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:42"
  condition:
    hash.sha256(0, filesize) == "029a364b81370e6f680886c2e1a0751cc45d1539db9ef0b9b55265def3422259"
}

rule MalwareBazaar_unknown_047_4b33ef08
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4b33ef08b2517ca180b3ecb2917c5196965cbcde84e3bb8a83b156ee55c4a622"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:34"
  condition:
    hash.sha256(0, filesize) == "4b33ef08b2517ca180b3ecb2917c5196965cbcde84e3bb8a83b156ee55c4a622"
}

rule MalwareBazaar_unknown_048_467f21fc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "467f21fcf89465270557faeaa93c95fdea23d50fd89f5f1f8d55ad0899270044"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:28"
  condition:
    hash.sha256(0, filesize) == "467f21fcf89465270557faeaa93c95fdea23d50fd89f5f1f8d55ad0899270044"
}

rule MalwareBazaar_unknown_049_ae0b4d8f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ae0b4d8fe724c2dde60289f1a3fdec7d2db6aefce7d65e0ed1ebcde54d3ba735"
    family = "unknown"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-07-23 21:34:22"
  condition:
    hash.sha256(0, filesize) == "ae0b4d8fe724c2dde60289f1a3fdec7d2db6aefce7d65e0ed1ebcde54d3ba735"
}

rule MalwareBazaar_Mirai_050_c0582c6c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241"
    family = "Mirai"
    file_name = "c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241"
    file_type = "sh"
    first_seen = "2026-07-23 21:23:00"
  condition:
    hash.sha256(0, filesize) == "c0582c6cd2a17fe2b02548249bc6929d1201ad08bac0d1bbcbe6e91215145241"
}

rule MalwareBazaar_unknown_051_f31d77a3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f31d77a3954013a6d02743d3bccab31cce7a44764b797d8cef7eae5bb3f586d2"
    family = "unknown"
    file_name = "dllhost.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:21:05"
  condition:
    hash.sha256(0, filesize) == "f31d77a3954013a6d02743d3bccab31cce7a44764b797d8cef7eae5bb3f586d2"
}

rule MalwareBazaar_WannaCry_052_9767724a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af"
    family = "WannaCry"
    file_name = "9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af"
    file_type = "exe"
    first_seen = "2026-07-23 21:15:39"
  condition:
    hash.sha256(0, filesize) == "9767724a6dd381d9401bcd0ea8c082d3b009c59ab949d6e25970f1de848354af"
}

rule MalwareBazaar_LummaStealer_053_f1299aac
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1299aac53a762281c12f1ffef0fef6e74cbc913fb851d7cc97c7f2a88b9d91a"
    family = "LummaStealer"
    file_name = "xqAAE.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:10:36"
  condition:
    hash.sha256(0, filesize) == "f1299aac53a762281c12f1ffef0fef6e74cbc913fb851d7cc97c7f2a88b9d91a"
}

rule MalwareBazaar_unknown_054_6a0dbbaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6a0dbbafcc53b79c1deadba56dc0f6f653c1e54975b1aa1e7ed48f88d3f2ac05"
    family = "unknown"
    file_name = "r2.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:09:48"
  condition:
    hash.sha256(0, filesize) == "6a0dbbafcc53b79c1deadba56dc0f6f653c1e54975b1aa1e7ed48f88d3f2ac05"
}

rule MalwareBazaar_RemusStealer_055_f85de963
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f85de96394b9d070487ad7a1a3be9eef62f166273b28d85a0a7ac5b0e382dd73"
    family = "RemusStealer"
    file_name = "ojujn.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:08:57"
  condition:
    hash.sha256(0, filesize) == "f85de96394b9d070487ad7a1a3be9eef62f166273b28d85a0a7ac5b0e382dd73"
}

rule MalwareBazaar_unknown_056_83ee5526
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "83ee5526840106e0df497edc91a1ae5e11405fe8da9a67038dddcd46df3dc681"
    family = "unknown"
    file_name = "wr.php"
    file_type = "sh"
    first_seen = "2026-07-23 21:07:19"
  condition:
    hash.sha256(0, filesize) == "83ee5526840106e0df497edc91a1ae5e11405fe8da9a67038dddcd46df3dc681"
}

rule MalwareBazaar_RemusStealer_057_3846db96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3846db9620475d5f24b73bff02babc2ea275e718116805203ca258dee7d35621"
    family = "RemusStealer"
    file_name = "KLLNMF.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:07:07"
  condition:
    hash.sha256(0, filesize) == "3846db9620475d5f24b73bff02babc2ea275e718116805203ca258dee7d35621"
}

rule MalwareBazaar_RemusStealer_058_0d716e4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d716e4ab464c5b97d2767ae6d8af267b9f050941332a9601f0a35f53ec79819"
    family = "RemusStealer"
    file_name = "kliulij.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:06:09"
  condition:
    hash.sha256(0, filesize) == "0d716e4ab464c5b97d2767ae6d8af267b9f050941332a9601f0a35f53ec79819"
}

rule MalwareBazaar_LummaStealer_059_6369ca00
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6369ca003c58f5ebad82e2f1d9a7eece2cc3d3799062b41a148dece9a35f134a"
    family = "LummaStealer"
    file_name = "KLHdfs.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:05:15"
  condition:
    hash.sha256(0, filesize) == "6369ca003c58f5ebad82e2f1d9a7eece2cc3d3799062b41a148dece9a35f134a"
}

rule MalwareBazaar_RemusStealer_060_b1e488d8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b1e488d82afc1ab098ed4c771172a1c9bbd2bf0f48fedf9cc1c52344d71d7d47"
    family = "RemusStealer"
    file_name = "kJHGFDs.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:04:25"
  condition:
    hash.sha256(0, filesize) == "b1e488d82afc1ab098ed4c771172a1c9bbd2bf0f48fedf9cc1c52344d71d7d47"
}

rule MalwareBazaar_RemusStealer_061_8083bda9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8083bda9833da6206a28cfc5b4c91a3ac2488d6bcf50d146450aa708413d6886"
    family = "RemusStealer"
    file_name = "jhgkuyyg.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:03:22"
  condition:
    hash.sha256(0, filesize) == "8083bda9833da6206a28cfc5b4c91a3ac2488d6bcf50d146450aa708413d6886"
}

rule MalwareBazaar_RemusStealer_062_00d5b68d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "00d5b68d01d72c7dff69763f1514284a6542f6a1acab9431cfb8c66439bfcf20"
    family = "RemusStealer"
    file_name = "hnmh.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:02:26"
  condition:
    hash.sha256(0, filesize) == "00d5b68d01d72c7dff69763f1514284a6542f6a1acab9431cfb8c66439bfcf20"
}

rule MalwareBazaar_RemusStealer_063_e8fca6d5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e8fca6d589613ccb2d1341e2d144bf896d3f73956794dcb00a047d73750641b6"
    family = "RemusStealer"
    file_name = "hjbk.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:01:48"
  condition:
    hash.sha256(0, filesize) == "e8fca6d589613ccb2d1341e2d144bf896d3f73956794dcb00a047d73750641b6"
}

rule MalwareBazaar_RemusStealer_064_e5282342
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5282342ac6494b5f02b194e3194e5838809e342795c1183a30d638264598a5a"
    family = "RemusStealer"
    file_name = "crazy.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:01:03"
  condition:
    hash.sha256(0, filesize) == "e5282342ac6494b5f02b194e3194e5838809e342795c1183a30d638264598a5a"
}

rule MalwareBazaar_RemusStealer_065_0d4aee37
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0d4aee37b4b0916bdef43762494a424079c71e928621231f3c0a5a020c95b070"
    family = "RemusStealer"
    file_name = "beb.exe"
    file_type = "exe"
    first_seen = "2026-07-23 21:00:04"
  condition:
    hash.sha256(0, filesize) == "0d4aee37b4b0916bdef43762494a424079c71e928621231f3c0a5a020c95b070"
}

rule MalwareBazaar_RemusStealer_066_5905e577
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5905e577d0c5ec50e0297efbcbfc988cbf446f69b8d798fcaa08c2ea48a821c4"
    family = "RemusStealer"
    file_name = "arFtU.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:59:11"
  condition:
    hash.sha256(0, filesize) == "5905e577d0c5ec50e0297efbcbfc988cbf446f69b8d798fcaa08c2ea48a821c4"
}

rule MalwareBazaar_RemusStealer_067_f0a37653
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f0a3765399fac3d6a2da13a67af4dd7d6b9a78ce09c97ec054d13bf36324b4f1"
    family = "RemusStealer"
    file_name = "bjbh.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:57:02"
  condition:
    hash.sha256(0, filesize) == "f0a3765399fac3d6a2da13a67af4dd7d6b9a78ce09c97ec054d13bf36324b4f1"
}

rule MalwareBazaar_CoinMiner_068_762d34ad
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "762d34adaef9bdd6a5a6e2d894bb4c5bda434e8740360adf82a399d7d1f7f46c"
    family = "CoinMiner"
    file_name = "svchost.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:55:44"
  condition:
    hash.sha256(0, filesize) == "762d34adaef9bdd6a5a6e2d894bb4c5bda434e8740360adf82a399d7d1f7f46c"
}

rule MalwareBazaar_unknown_069_501cc0d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "501cc0d06ebf10f9ec74d1ea2139ffca45631f52b769c6a5712aab160c0d1ffd"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 20:52:11"
  condition:
    hash.sha256(0, filesize) == "501cc0d06ebf10f9ec74d1ea2139ffca45631f52b769c6a5712aab160c0d1ffd"
}

rule MalwareBazaar_unknown_070_717180c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "717180c51bd69d7eb6128d6a8a03f15179235bb8ce12c3b07dd22855943ba444"
    family = "unknown"
    file_name = "Game.exe"
    file_type = "exe"
    first_seen = "2026-07-23 20:17:41"
  condition:
    hash.sha256(0, filesize) == "717180c51bd69d7eb6128d6a8a03f15179235bb8ce12c3b07dd22855943ba444"
}

rule MalwareBazaar_unknown_071_e212aae5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e212aae52a3a683be857bb52c57fa8efdba908ab8909580568c7c3f96bb94823"
    family = "unknown"
    file_name = "tftp"
    file_type = "elf"
    first_seen = "2026-07-23 20:16:29"
  condition:
    hash.sha256(0, filesize) == "e212aae52a3a683be857bb52c57fa8efdba908ab8909580568c7c3f96bb94823"
}

rule MalwareBazaar_WannaCry_072_924037d0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda"
    family = "WannaCry"
    file_name = "924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda"
    file_type = "exe"
    first_seen = "2026-07-23 20:15:41"
  condition:
    hash.sha256(0, filesize) == "924037d098c031bfaecaff406b20f1dfa0b1a0a22fefd3bfc5753513ef67bdda"
}

rule MalwareBazaar_Mirai_073_e5dfa97e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e5dfa97e05cec26677edca609b13a1aa9987b907e31bc4f5c0e45527728d407a"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-07-23 20:10:17"
  condition:
    hash.sha256(0, filesize) == "e5dfa97e05cec26677edca609b13a1aa9987b907e31bc4f5c0e45527728d407a"
}

rule MalwareBazaar_Mirai_074_2d4fd69d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d4fd69dd3f412b6b318af9c9840d7cd762b011346ad787eaf31da3e6990ed05"
    family = "Mirai"
    file_name = "mpsl"
    file_type = "elf"
    first_seen = "2026-07-23 20:08:32"
  condition:
    hash.sha256(0, filesize) == "2d4fd69dd3f412b6b318af9c9840d7cd762b011346ad787eaf31da3e6990ed05"
}

rule MalwareBazaar_unknown_075_649e11e2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "649e11e2df456a582709acdf39b916a02a828957f0b13d9d0f61575e8a05282c"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 20:01:25"
  condition:
    hash.sha256(0, filesize) == "649e11e2df456a582709acdf39b916a02a828957f0b13d9d0f61575e8a05282c"
}

rule MalwareBazaar_SalatStealer_076_60d74ab6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "60d74ab66cb37bdaa5877d21d17fdcfdbf741796fcf38425fb2681250c9cf9f9"
    family = "SalatStealer"
    file_name = "SecuriteInfo.com.Trojan.PWS.Salat.390.9009.22233"
    file_type = "exe"
    first_seen = "2026-07-23 19:52:46"
  condition:
    hash.sha256(0, filesize) == "60d74ab66cb37bdaa5877d21d17fdcfdbf741796fcf38425fb2681250c9cf9f9"
}

rule MalwareBazaar_unknown_077_de35fbf3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de35fbf32bd9060123a1c4475d2c5e5a455c1f752e198fc2fc4fcb0cd9805fc1"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 19:52:08"
  condition:
    hash.sha256(0, filesize) == "de35fbf32bd9060123a1c4475d2c5e5a455c1f752e198fc2fc4fcb0cd9805fc1"
}

rule MalwareBazaar_SalatStealer_078_0b93ca27
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0b93ca2778b5ac0ae2be58985b0ffecb7d6ce6870815c1f85d14505e4005b9e9"
    family = "SalatStealer"
    file_name = "SecuriteInfo.com.Trojan.PWS.Salat.390.9009.22233"
    file_type = "exe"
    first_seen = "2026-07-23 19:51:42"
  condition:
    hash.sha256(0, filesize) == "0b93ca2778b5ac0ae2be58985b0ffecb7d6ce6870815c1f85d14505e4005b9e9"
}

rule MalwareBazaar_unknown_079_8a50ed3d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8a50ed3d9d9e90c971100e211b7f5c8c7128ccbf9164cf3bd1beed8a49da6ab6"
    family = "unknown"
    file_name = "Spysok_Mayna.zip"
    file_type = "lnk"
    first_seen = "2026-07-23 19:45:35"
  condition:
    hash.sha256(0, filesize) == "8a50ed3d9d9e90c971100e211b7f5c8c7128ccbf9164cf3bd1beed8a49da6ab6"
}

rule MalwareBazaar_unknown_080_962bd2fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "962bd2fdde0752a0ba60650f3808a99a3dfe1068b0a8c7a50360134ea8bb1f92"
    family = "unknown"
    file_name = "АКТ приема передачи (дроны164) 18.07.2026.docx.lnk"
    file_type = "lnk"
    first_seen = "2026-07-23 19:44:30"
  condition:
    hash.sha256(0, filesize) == "962bd2fdde0752a0ba60650f3808a99a3dfe1068b0a8c7a50360134ea8bb1f92"
}

rule MalwareBazaar_unknown_081_e388e7ce
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e388e7ce2449ba4100483186d9242e96f0cf74196d2519d37b581df682c57de6"
    family = "unknown"
    file_name = "ProtokolZatrimannya.zip"
    file_type = "zip"
    first_seen = "2026-07-23 19:43:34"
  condition:
    hash.sha256(0, filesize) == "e388e7ce2449ba4100483186d9242e96f0cf74196d2519d37b581df682c57de6"
}

rule MalwareBazaar_Mirai_082_5e845612
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5e845612d64df5342ea509eed924bcfd9c9d2195f1db8ae7c2d69f9503c21c0b"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 19:35:50"
  condition:
    hash.sha256(0, filesize) == "5e845612d64df5342ea509eed924bcfd9c9d2195f1db8ae7c2d69f9503c21c0b"
}

rule MalwareBazaar_Mirai_083_06c4ddab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "06c4ddabac5e976f152f482a47581313fdb95e2cbee564d56279648bbaf5694a"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-07-23 19:34:28"
  condition:
    hash.sha256(0, filesize) == "06c4ddabac5e976f152f482a47581313fdb95e2cbee564d56279648bbaf5694a"
}

rule MalwareBazaar_Mirai_084_672f654f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-07-23 19:23:45"
  condition:
    hash.sha256(0, filesize) == "672f654f31e91cdb9766131ad3034d1284842fc8b56dc8b4e9a32e925b7f8e95"
}

rule MalwareBazaar_Mirai_085_9d8e694d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-07-23 19:21:15"
  condition:
    hash.sha256(0, filesize) == "9d8e694d18e3c976b45ada0041ae3f756ef7c795089c05537396dbe89d929262"
}

rule MalwareBazaar_WannaCry_086_731fc822
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b"
    family = "WannaCry"
    file_name = "731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b"
    file_type = "exe"
    first_seen = "2026-07-23 19:15:30"
  condition:
    hash.sha256(0, filesize) == "731fc822a6bdfe76804b1d55fdd08de05680ca6d99bd8c3216a466ece9a3f92b"
}

rule MalwareBazaar_unknown_087_1d8f6366
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d8f6366efd827ab0a2036904c05223064cf73dd547a6cb02e23eb52c77c4db0"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 19:10:14"
  condition:
    hash.sha256(0, filesize) == "1d8f6366efd827ab0a2036904c05223064cf73dd547a6cb02e23eb52c77c4db0"
}

rule MalwareBazaar_unknown_088_8f08d169
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f08d169740c185efcb8dd7f7e507e7a368a06dc920ebfe7686102e22feab391"
    family = "unknown"
    file_name = "bot.mips"
    file_type = "elf"
    first_seen = "2026-07-23 19:07:20"
  condition:
    hash.sha256(0, filesize) == "8f08d169740c185efcb8dd7f7e507e7a368a06dc920ebfe7686102e22feab391"
}

rule MalwareBazaar_unknown_089_c3433dd6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c3433dd61c7a5704d780be6f3a1e40492baf6171a45266c2dc363a5c165f2a0f"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 19:01:22"
  condition:
    hash.sha256(0, filesize) == "c3433dd61c7a5704d780be6f3a1e40492baf6171a45266c2dc363a5c165f2a0f"
}

rule MalwareBazaar_Mirai_090_23e1c6ab
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23e1c6ab1e36a9a43bcea0f55c3c3dbc32622df5dabd7e6dae1fc03ddc59e970"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-07-23 18:55:40"
  condition:
    hash.sha256(0, filesize) == "23e1c6ab1e36a9a43bcea0f55c3c3dbc32622df5dabd7e6dae1fc03ddc59e970"
}

rule MalwareBazaar_Mirai_091_51c7abd7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c7abd74c3de141108d7f229d2c54df93a1b4f28fb6e95987aa7676e3c88480"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-07-23 18:53:14"
  condition:
    hash.sha256(0, filesize) == "51c7abd74c3de141108d7f229d2c54df93a1b4f28fb6e95987aa7676e3c88480"
}

rule MalwareBazaar_unknown_092_2d373d72
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2d373d72472f7d9d11a3fc7d4874cf423b4260bed2e080d745ee127bcef237e6"
    family = "unknown"
    file_name = "default.dat"
    file_type = "exe"
    first_seen = "2026-07-23 18:52:08"
  condition:
    hash.sha256(0, filesize) == "2d373d72472f7d9d11a3fc7d4874cf423b4260bed2e080d745ee127bcef237e6"
}

rule MalwareBazaar_unknown_093_11dab430
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "11dab4308daadc7569ca0ae38faeed467b5108e66efc9272546e302d5281f734"
    family = "unknown"
    file_name = "268575def2db78e185cded3bdd3c9157.exe"
    file_type = "exe"
    first_seen = "2026-07-23 18:45:53"
  condition:
    hash.sha256(0, filesize) == "11dab4308daadc7569ca0ae38faeed467b5108e66efc9272546e302d5281f734"
}

rule MalwareBazaar_unknown_094_2618a8ed
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2618a8ed67c07427965f10cd2c43676f4b929083d85e821d55edee8ea17cd94f"
    family = "unknown"
    file_name = "o.xml"
    file_type = "unknown"
    first_seen = "2026-07-23 18:45:13"
  condition:
    hash.sha256(0, filesize) == "2618a8ed67c07427965f10cd2c43676f4b929083d85e821d55edee8ea17cd94f"
}

rule MalwareBazaar_unknown_095_3de28e02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3de28e0230e64b890a6162d4d60330aa70be23b496287d1740c7847738cce1c0"
    family = "unknown"
    file_name = "k.php"
    file_type = "sh"
    first_seen = "2026-07-23 18:43:40"
  condition:
    hash.sha256(0, filesize) == "3de28e0230e64b890a6162d4d60330aa70be23b496287d1740c7847738cce1c0"
}

rule MalwareBazaar_Mirai_096_23075f5c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23075f5c503344af0a808631698c1bb092425f95a3ff8dd03cc7a8564ebc2d8d"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:42:57"
  condition:
    hash.sha256(0, filesize) == "23075f5c503344af0a808631698c1bb092425f95a3ff8dd03cc7a8564ebc2d8d"
}

rule MalwareBazaar_PureRAT_097_5f2979cd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591"
    family = "PureRAT"
    file_name = "13aa55915fe8418214edc3f57138e29e.exe"
    file_type = "exe"
    first_seen = "2026-07-23 18:42:55"
  condition:
    hash.sha256(0, filesize) == "5f2979cd7d8192bb50266546557be153907b952d73f911122655c79c9ba73591"
}

rule MalwareBazaar_Mirai_098_f107ff44
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f107ff44d5cbfc85f5e42b0d9c8a5729663eb34da34fac97e03f2591949bb4b2"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:42:29"
  condition:
    hash.sha256(0, filesize) == "f107ff44d5cbfc85f5e42b0d9c8a5729663eb34da34fac97e03f2591949bb4b2"
}

rule MalwareBazaar_Mirai_099_a161f36e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a161f36eea166dfad68afa2f686af99adcaa1067c53d0ef56fdc5504b2ea594e"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:41:56"
  condition:
    hash.sha256(0, filesize) == "a161f36eea166dfad68afa2f686af99adcaa1067c53d0ef56fdc5504b2ea594e"
}

rule MalwareBazaar_Mirai_100_2da61d02
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2da61d02faca4dafea3fd8e731f57148fee7b3431f1050d6528a88a774f7f81a"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmicroblazexnxn"
    file_type = "elf"
    first_seen = "2026-07-23 18:41:16"
  condition:
    hash.sha256(0, filesize) == "2da61d02faca4dafea3fd8e731f57148fee7b3431f1050d6528a88a774f7f81a"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.

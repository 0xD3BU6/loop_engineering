# MalwareBazaar Sample-by-Sample Technical Analysis - 2026-10-11

## Executive Summary

The agent analyzed 100 recent MalwareBazaar submissions one by one and extracted 657 defensive IOCs. This is static metadata analysis: samples were not downloaded, unpacked, executed, or dynamically tested.

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
| Total IOCs | 657 |
| Unique family labels | 9 |
| Unique file types | 11 |

## Dataset Overview

### Top Families

| Family | Samples |
|---|---:|
| Mirai | 68 |
| unknown | 18 |
| VShell | 4 |
| QuasarRAT | 3 |
| AsyncRAT | 2 |
| AMOS | 2 |
| CoinMiner | 1 |
| Prometei | 1 |
| Formbook | 1 |

### File Type Distribution

| File type | Samples |
|---|---:|
| elf | 74 |
| exe | 14 |
| dll | 2 |
| macho | 2 |
| cmd | 2 |
| apk | 1 |
| sh | 1 |
| ps1 | 1 |
| msi | 1 |
| zip | 1 |

## Per-Sample Analysis

### Sample 1: `62c1694d0d13e669`

| Field | Value |
|---|---|
| SHA-256 | `62c1694d0d13e66958e9cbdadbc113406ac78b00f72ed928773d68ec28c60648` |
| Family label | `unknown` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-11 05:58:33` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c28a5865025eb30903f960cbe6c8e3ed` |
| SHA-1 | `7b5b8ac9e1605c6695ed0099ad1d717905dee8d5` |
| SHA-256 | `62c1694d0d13e66958e9cbdadbc113406ac78b00f72ed928773d68ec28c60648` |
| SHA3-384 | `ad63fcaa445b077ae6044a482bd031f9e3ff253d47bbf1b5db14b78a30dd1ec131ac4e33aa0cfa3ceace227e9399451d` |
| TLSH | `T19A140A85FC519A26C6D1667BFB6E428C372B1378D2EE31039E116F20379B82F0E7A551` |
| TELFHASH | `t178e068e0c91c19f0b589adad64bd66243b84ba04f509611885ee2fcab623896a03214b` |
| SSDEEP | `6144:egD0CpWjo/j8941j2CfNQL5HtE4x6axJ2VxOed2:egD05E/j8lIoE4x6av2WM2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_001_62c1694d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c1694d0d13e66958e9cbdadbc113406ac78b00f72ed928773d68ec28c60648"
    family = "unknown"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-11 05:58:33"
  condition:
    hash.sha256(0, filesize) == "62c1694d0d13e66958e9cbdadbc113406ac78b00f72ed928773d68ec28c60648"
}
```

### Sample 2: `7f4745b9eca5fcaf`

| Field | Value |
|---|---|
| SHA-256 | `7f4745b9eca5fcafcb5e6d291a7d9eb4730bc0f36f88c20e1906de6ef0f829b3` |
| Family label | `Mirai` |
| File name | `disspoor` |
| File type | `elf` |
| First seen | `2026-10-11 05:54:35` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `999c229cba1a195c0c1c68e96cdb5d50` |
| SHA-1 | `4a2019ab727a621baf88ef424ba88467ac967fb5` |
| SHA-256 | `7f4745b9eca5fcafcb5e6d291a7d9eb4730bc0f36f88c20e1906de6ef0f829b3` |
| SHA3-384 | `7bc28d3ef56d15638208046e53ce6b3f2f942c4a2d2e19247609bbc4189b8926271cd1c5077ce51138076d5c0c07aa3a` |
| TLSH | `T117246C00B71D0947E2672EF03B3F27D193EF9A9135F4EA442A0EBA499271D322585DDE` |
| SSDEEP | `6144:sY8uQoveKXS4WtGFIhxzjWLOSYRacW8MGI:tJS4GGFwjWMacWuI` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_002_7f4745b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f4745b9eca5fcafcb5e6d291a7d9eb4730bc0f36f88c20e1906de6ef0f829b3"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-11 05:54:35"
  condition:
    hash.sha256(0, filesize) == "7f4745b9eca5fcafcb5e6d291a7d9eb4730bc0f36f88c20e1906de6ef0f829b3"
}
```

### Sample 3: `633448526c55c233`

| Field | Value |
|---|---|
| SHA-256 | `633448526c55c23344eff36f102afe7ab443da3a24c6a1e81110324c0236484e` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-11 05:50:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `68630ac0564599632c7425c338691842` |
| SHA-1 | `eb3ae8d15f464d60d74d64750d331a14c8c02d1b` |
| SHA-256 | `633448526c55c23344eff36f102afe7ab443da3a24c6a1e81110324c0236484e` |
| SHA3-384 | `14a27f870838805ea64315d23e7f55e08e2b19f6a5ed0ce09aa6d794b071e1e862f2c512c991e96e77ae6511ba7d5e11` |
| TLSH | `T1E7E49E98BB8D7D43E387F33DCE8AC671322BB5E89712D2A23501425DD4C2EA9CBB1551` |
| SSDEEP | `12288:ySKFhxXVXcb/R86ehWRK5ti8LthRZjBBMAHozsCIQPs54XZv3:y/3VXcb/XhK5ti8LtLr9Hsh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_003_63344852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "633448526c55c23344eff36f102afe7ab443da3a24c6a1e81110324c0236484e"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-11 05:50:41"
  condition:
    hash.sha256(0, filesize) == "633448526c55c23344eff36f102afe7ab443da3a24c6a1e81110324c0236484e"
}
```

### Sample 4: `29d3de066fcbb6c3`

| Field | Value |
|---|---|
| SHA-256 | `29d3de066fcbb6c387b7ccbdd85146b8f28499ab98f699afb35904a28435593a` |
| Family label | `Mirai` |
| File name | `jklarm5` |
| File type | `elf` |
| First seen | `2026-10-11 05:46:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6de4d9cda7bc677ad762dd33015129ae` |
| SHA-1 | `c68378b51aa16bc9890a9d5230f8d65e03a8f305` |
| SHA-256 | `29d3de066fcbb6c387b7ccbdd85146b8f28499ab98f699afb35904a28435593a` |
| SHA3-384 | `a899cbbe0195dbf60f0b9ce6fc558b763b0a4cbbe7a8353598fd7f06fd5c34417b28b034fc126c2088c889ca0351dd83` |
| TLSH | `T110943A66BC809B51C6D15ABBFF5E8248331717B8D2EF71038A05EB3937DA8960E3B541` |
| TELFHASH | `t1554184424a8494cc72f647d8e15a261f91e835fe9f9024aa6b3cb36f87724c33036cb5` |
| SSDEEP | `12288:0+4FscRIYV43YLK+5LJsmpSsc/Gvq0in12STQzb:0+eXqYLK+ZJsmpSswB3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_004_29d3de06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d3de066fcbb6c387b7ccbdd85146b8f28499ab98f699afb35904a28435593a"
    family = "Mirai"
    file_name = "jklarm5"
    file_type = "elf"
    first_seen = "2026-10-11 05:46:40"
  condition:
    hash.sha256(0, filesize) == "29d3de066fcbb6c387b7ccbdd85146b8f28499ab98f699afb35904a28435593a"
}
```

### Sample 5: `c11464f548d27189`

| Field | Value |
|---|---|
| SHA-256 | `c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb` |
| Family label | `AsyncRAT` |
| File name | `c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb.exe` |
| File type | `exe` |
| First seen | `2026-10-11 05:40:06` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `902780450c82f0cfdce73134d7145842` |
| SHA-1 | `2d7eb4db27a5486b513511d18903eb370690f0a1` |
| SHA-256 | `c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb` |
| SHA3-384 | `4e73b36781c6e9f6b6c64d7ca91048ab0f6bce1aed3c945e33f8f66bd9fc2f57a1a8bfa9ddbd44c65d215cacb279f64b` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T116233D0437E9C12BF2BE4F74A8F22146857AF2673603D64D1CD842975A23FC696426FE` |
| SSDEEP | `768:NuYHKTsufqG9vSLjWUvlPRmo2qb7e3ufBPItu5joELf0bXRCUjA/yKL1W5rV0BDU:NuYHKTsjMvSX2fUetqM88bXQu7KB8VCQ` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_005_c11464f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb"
    family = "AsyncRAT"
    file_name = "c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb.exe"
    file_type = "exe"
    first_seen = "2026-10-11 05:40:06"
  condition:
    hash.sha256(0, filesize) == "c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb"
}
```

### Sample 6: `329706c148a26631`

| Field | Value |
|---|---|
| SHA-256 | `329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde` |
| Family label | `QuasarRAT` |
| File name | `329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde.exe` |
| File type | `exe` |
| First seen | `2026-10-11 05:32:48` |
| Reporter | `Tuxxin` |
| Tags | `exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6af89b4a89be1cf869a1d4c14674ee45` |
| SHA-1 | `94acf9c68414284c62963411c73f64d2ae9de6be` |
| SHA-256 | `329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde` |
| SHA3-384 | `e9247adbff0d7869fa1a874796a99c2392fa4fa155e1eaca04895027b34fa2377f5ac0ab4553d6533b4aed731d36becc` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T166E54A1477F85E62E16AD3B3D5F0542363F0F82AF3A3EB0B5191677A1C93B4098426A7` |
| SSDEEP | `49152:uvyI22SsaNYfdPBldt698dBcjH0eGmmOmz9foGdiTHHB72eh2NT:uvf22SsaNYfdPBldt6+dBcjH09mm1` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_006_329706c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde"
    family = "QuasarRAT"
    file_name = "329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde.exe"
    file_type = "exe"
    first_seen = "2026-10-11 05:32:48"
  condition:
    hash.sha256(0, filesize) == "329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde"
}
```

### Sample 7: `3ab040178b1408c3`

| Field | Value |
|---|---|
| SHA-256 | `3ab040178b1408c32f7977fa70dc3e2451d5744caa6e23707457080fe4a550f6` |
| Family label | `Mirai` |
| File name | `spc` |
| File type | `elf` |
| First seen | `2026-10-11 05:30:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f6a5171c1d1ecf8039d613acec304312` |
| SHA-1 | `28b37a581b4a23ca7167c6745802569ee99e3f37` |
| SHA-256 | `3ab040178b1408c32f7977fa70dc3e2451d5744caa6e23707457080fe4a550f6` |
| SHA3-384 | `4695ae319f737a280c0ccae9b6207b1a526476651043cb7436f21da989f21ff32587c8fd29bd49435249c5b6976030be` |
| TLSH | `T1AFA34B36B874192BC4D4A47E22F74721F5F247D925A8861E7EB20D8EBF206403653BB6` |
| SSDEEP | `1536:a7ZpFghRWSbbmLOnzavBUgOl2OpT30kbekbRlM5RAPwTTnt0o6j:bbbmPTO930bkbRl8866j` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_007_3ab04017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab040178b1408c32f7977fa70dc3e2451d5744caa6e23707457080fe4a550f6"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-11 05:30:40"
  condition:
    hash.sha256(0, filesize) == "3ab040178b1408c32f7977fa70dc3e2451d5744caa6e23707457080fe4a550f6"
}
```

### Sample 8: `1d2788e48a5f27ac`

| Field | Value |
|---|---|
| SHA-256 | `1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a` |
| Family label | `unknown` |
| File name | `1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a` |
| File type | `apk` |
| First seen | `2026-10-11 05:30:10` |
| Reporter | `EnthecSolutions` |
| Tags | `apk, enthec, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `215dbca2c5cfcf6ccfbf000b90c03b6b` |
| SHA-1 | `4b874dd573025ca50e2025a69332330b81f886fe` |
| SHA-256 | `1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a` |
| SHA3-384 | `7ae6b4f597c7883afeb5263f6b8e2a9a2ef2738d460b2cd6fa3ed234803d4ef3dd708de2494ca4a91e56f239ce0cafb3` |
| TLSH | `T1DA7533B6E6372E4EC09BDEF989C567BB4606BC0C40AD039783105A447FC5629D6BFB48` |
| SSDEEP | `49152:8Q12ksUMFUk41KqRwaV5jgYTrlmkV4V6r:x37Myk44eVqEmSr` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `apk`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_008_1d2788e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a"
    family = "unknown"
    file_name = "1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a"
    file_type = "apk"
    first_seen = "2026-10-11 05:30:10"
  condition:
    hash.sha256(0, filesize) == "1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a"
}
```

### Sample 9: `f4d3adaf236a38bb`

| Field | Value |
|---|---|
| SHA-256 | `f4d3adaf236a38bb28ea7b4c3139aa501ff60d81896d9e4ea6ae2781857cfdca` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-11 05:22:52` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d5c87aa99b312bea25cd9b11b434dc54` |
| SHA-1 | `2b5d277908675ed1e784cb4b51761b3e47c21f78` |
| SHA-256 | `f4d3adaf236a38bb28ea7b4c3139aa501ff60d81896d9e4ea6ae2781857cfdca` |
| SHA3-384 | `f897b2388d2267922f75983b1445b5772cefe668d2a0aa0fc0b028a4dbdbfe0d3541249a6f12af4e2d15594ab04485dc` |
| TLSH | `T18E561897B9D24942C4E43A77A8BE80C833631EBA9B8656575D04FE3C3EBE5D90E34314` |
| TELFHASH | `t169d0a5454f4c3ae42bd500e51414127f5af430fc11142f944f4d35df471157970c54dd` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:RkbLx0XGJcJlT3VurlGkkXzDnq6YqyxlxNKbhT88YIbrnbO5fTtKEW:RcGJlQW` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_009_f4d3adaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d3adaf236a38bb28ea7b4c3139aa501ff60d81896d9e4ea6ae2781857cfdca"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-11 05:22:52"
  condition:
    hash.sha256(0, filesize) == "f4d3adaf236a38bb28ea7b4c3139aa501ff60d81896d9e4ea6ae2781857cfdca"
}
```

### Sample 10: `e9ba70f1edc3f1f3`

| Field | Value |
|---|---|
| SHA-256 | `e9ba70f1edc3f1f31406ecc5e2d02efc2a7a7fa1088b518dacff89d9e10a7933` |
| Family label | `CoinMiner` |
| File name | `file` |
| File type | `exe` |
| First seen | `2026-10-11 05:02:20` |
| Reporter | `Bitsight` |
| Tags | `B, CoinMiner, dropped-by-GCleaner, exe, PMIX0.file` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4ecf88981e7726812fb94db1bb1688d1` |
| SHA-1 | `e03a2a50c6dd001c8419971ae4c46349e3cffde4` |
| SHA-256 | `e9ba70f1edc3f1f31406ecc5e2d02efc2a7a7fa1088b518dacff89d9e10a7933` |
| SHA3-384 | `1e35fc272351cd9f8deb4b83d5c8a9bb8ee560db843e2bfe023468aae91917f4f7b8ffe1dd55b46cce3098b77ed47510` |
| IMPHASH | `87898811f58bbcae4e2c4f2733f60593` |
| TLSH | `T1E0D5232FE7B284FCD17780709B8BD571A471F8180231691F1BC9DF362EAAC644B8EA54` |
| SSDEEP | `49152:fP17a9q5wzXcn/ofYehji4EXmDdcw5Zgr4CJshDQgdhEKY9wCzODBmdrNSrc7b8:H17JVonhji4EXQfZEveQgYoDBmRNe` |

#### Technical Assessment

- The sample is tracked as `CoinMiner` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_CoinMiner_010_e9ba70f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9ba70f1edc3f1f31406ecc5e2d02efc2a7a7fa1088b518dacff89d9e10a7933"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-11 05:02:20"
  condition:
    hash.sha256(0, filesize) == "e9ba70f1edc3f1f31406ecc5e2d02efc2a7a7fa1088b518dacff89d9e10a7933"
}
```

### Sample 11: `af5b59d2c3af86ee`

| Field | Value |
|---|---|
| SHA-256 | `af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5` |
| Family label | `QuasarRAT` |
| File name | `af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5.exe` |
| File type | `exe` |
| First seen | `2026-10-11 05:02:10` |
| Reporter | `Tuxxin` |
| Tags | `exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `675a6bcf1161098f7fc8e65cf6b07ec8` |
| SHA-1 | `c23a83c1459ed3bbbf81885dad9b0f249a30cf3e` |
| SHA-256 | `af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5` |
| SHA3-384 | `d393fb26532ad5acd339b659f46e7b73e04c31a6a90ced91bb681dfb6a0f782a88a6736e830080e0292af95b5e9ea603` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T131E55A543BF85E32E17BD6B3D5B0545263F0F82AF363EB0B6181677A1C93B4098426A7` |
| SSDEEP | `49152:2vUt62XlaSFNWPjljiFa2RoUYIfEUBqUoGdfgrTHHB72eh2NT:2vI62XlaSFNWPjljiFXRoUYIfEUb` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_011_af5b59d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5"
    family = "QuasarRAT"
    file_name = "af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5.exe"
    file_type = "exe"
    first_seen = "2026-10-11 05:02:10"
  condition:
    hash.sha256(0, filesize) == "af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5"
}
```

### Sample 12: `d0f2273f828b1039`

| Field | Value |
|---|---|
| SHA-256 | `d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229` |
| Family label | `unknown` |
| File name | `zblob_0951894_d0f2273f.bin` |
| File type | `exe` |
| First seen | `2026-10-11 04:40:17` |
| Reporter | `Daydream` |
| Tags | `ABE-bypass, dll, exe, SeroRAT, stealer` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `79145aeb30802f73692b4aed57ea50f3` |
| SHA-1 | `8b35496305c8b84dabf4d09e0945816d9db67ffd` |
| SHA-256 | `d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229` |
| SHA3-384 | `37689fae17af4d98da204632c0f152cb5cf48a7eb6447e1d56b3449df7aeed82ec1442868bb7198b39cbbd1c24cd4e50` |
| IMPHASH | `79d96ddb193101a84ed595d2fac07548` |
| TLSH | `T1B3A3395B72E600BBE1768638C8A70A49D776F8511761AFEF43A0425A1F273E18D3DF21` |
| SSDEEP | `3072:DJtP1P0mbIIpA6qxYNgk2GgNJlLJKJKfybKHUNzPyfUzUR:n9sWLzqxYqYbbfI` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_012_d0f2273f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229"
    family = "unknown"
    file_name = "zblob_0951894_d0f2273f.bin"
    file_type = "exe"
    first_seen = "2026-10-11 04:40:17"
  condition:
    hash.sha256(0, filesize) == "d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229"
}
```

### Sample 13: `5f924d5b8e190ee9`

| Field | Value |
|---|---|
| SHA-256 | `5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321` |
| Family label | `Mirai` |
| File name | `dissarm7` |
| File type | `elf` |
| First seen | `2026-10-11 04:21:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1874790bc9d09f33514182815e98045` |
| SHA-1 | `77d61004de10d986e70c84766b8450d884040fad` |
| SHA-256 | `5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321` |
| SHA3-384 | `0268a4554d9a1a36d10d69bbe795d533ed8bdbe3c95230a318d448710d60536a51fd94b142e60a4e2c6d073a706bac35` |
| TLSH | `T120141859FC81AF10D5D536BAFA5E428933671778E3FA7102AE205F2023CA91F0F7A516` |
| TELFHASH | `t10eb012c408032dc8772156c5c7fdd3063907e0270ed8002610c87ea6dd733b1c47209a` |
| SSDEEP | `6144:RLzAbIT5uTRFFyaUcyqGFTdd5mfmB/Qdp8IVN:RLzAsTwvFyaUcIFTddk+Bc8IVN` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_013_5f924d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-11 04:21:51"
  condition:
    hash.sha256(0, filesize) == "5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321"
}
```

### Sample 14: `92a4bdc95e0d9920`

| Field | Value |
|---|---|
| SHA-256 | `92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480` |
| Family label | `QuasarRAT` |
| File name | `92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480.exe` |
| File type | `exe` |
| First seen | `2026-10-11 04:21:09` |
| Reporter | `Tuxxin` |
| Tags | `exe, QuasarRAT` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1843db1abb66e726e081329dd239d6e8` |
| SHA-1 | `a8773af716f8811e9e3e8482a9bb3d1905ba5928` |
| SHA-256 | `92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480` |
| SHA3-384 | `8fefc9e29863841c8ae915eaab49e1d3e8d7c97ea4384b6381ef2dfb1d201d526a74f8b4d871bdf103f8fcc9fba97eb3` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T1E1E56B143BF85E27E1BBE277E5B0041267F0FC1AB363EB0B6581677A1C53B5098426A7` |
| SSDEEP | `49152:qvaY52fyaSZOrPWluWBuGG5g5heGRJ62bR3LoGdMjTHHB72eh2NT:qvv52fyaSZOrPWluWBDG5g5heGRJ6w` |

#### Technical Assessment

- The sample is tracked as `QuasarRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_QuasarRAT_014_92a4bdc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480"
    family = "QuasarRAT"
    file_name = "92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480.exe"
    file_type = "exe"
    first_seen = "2026-10-11 04:21:09"
  condition:
    hash.sha256(0, filesize) == "92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480"
}
```

### Sample 15: `093e027a709e9091`

| Field | Value |
|---|---|
| SHA-256 | `093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581` |
| Family label | `Mirai` |
| File name | `jklarm6` |
| File type | `elf` |
| First seen | `2026-10-11 04:17:46` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `de769b4d46c455e49ab9959b242e7772` |
| SHA-1 | `e0ce56d0a1cef507eeb722090d2f85d5fc773989` |
| SHA-256 | `093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581` |
| SHA3-384 | `8dfdd642c867bb381575578e0c3658493da84f84790cdf1b85ca0fa60d43bc9ab8be547d9db258d3f485eeece293700a` |
| TLSH | `T1D9A42B66FC809B91D5D11ABEFF2E924933131B78E2DF71139A04AB3967D68970E3B500` |
| TELFHASH | `t170f0d420088d44ccd5d181d5f0e6a317655144ab6960243e26e50d4f0ab74d8351d111` |
| SSDEEP | `12288:EUJ3HFxqH0BBrMtHmZ27X9gjYQ3iadcdLwgUFFtpr:EUhDW0CGK9gBy0S6t` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_015_093e027a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581"
    family = "Mirai"
    file_name = "jklarm6"
    file_type = "elf"
    first_seen = "2026-10-11 04:17:46"
  condition:
    hash.sha256(0, filesize) == "093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581"
}
```

### Sample 16: `85dfe92b43734f25`

| Field | Value |
|---|---|
| SHA-256 | `85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9` |
| Family label | `unknown` |
| File name | `85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9.exe.bin` |
| File type | `exe` |
| First seen | `2026-10-11 04:11:18` |
| Reporter | `Daydream` |
| Tags | `clipper, exe, HijackLoader, unpacked, ZigClipper` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `51c2c132d6fa4c099880fc0021b12f51` |
| SHA-1 | `8d97f501e4684bf4e00aeb893ad8e3e1f2d289eb` |
| SHA-256 | `85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9` |
| SHA3-384 | `4d09f639f7508a5b18356635f921bcac4ee658672bd9697d7bb88046f767a5dc6b0d898246ef63f4fd30630e663dc1ac` |
| IMPHASH | `e8004365bd43117befdfbe2206267aa8` |
| TLSH | `T149A39D1B78A40175D48180B4C95F5A5BCA23BC08273552F713F0B66A2F767E29F3AF62` |
| SSDEEP | `3072:5tVa/KWeiVlaBFYKyVyN9DXpGQqPxpWzpt:5nRelaUKyVyN9dGQEQD` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_016_85dfe92b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9"
    family = "unknown"
    file_name = "85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9.exe.bin"
    file_type = "exe"
    first_seen = "2026-10-11 04:11:18"
  condition:
    hash.sha256(0, filesize) == "85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9"
}
```

### Sample 17: `1b937dbaa72bc5d6`

| Field | Value |
|---|---|
| SHA-256 | `1b937dbaa72bc5d6196d45559037182ccf8ab038d4f4f45592b40630af40bfc6` |
| Family label | `unknown` |
| File name | `setup.exe` |
| File type | `exe` |
| First seen | `2026-10-11 03:59:48` |
| Reporter | `anonymous` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `89cf7f7629ff5d69e436f7974db3c328` |
| SHA-1 | `30fdb5f8c61ec8a4c6b93c4f0ed489326d222390` |
| SHA-256 | `1b937dbaa72bc5d6196d45559037182ccf8ab038d4f4f45592b40630af40bfc6` |
| SHA3-384 | `db9d8197632d076693edd6d6b75de046f3124831a904505624a80b7593674279a5ad2ae7c37064755ed7dd69e5678fcc` |
| TLSH | `T11E136C02B186C3F4C41AD174CDEA105BE2BAF485553645AF2BF2EE961F933209D39B27` |
| SSDEEP | `768:In6QXVYXQQZ8Zf7P7+mHlhQdnMZysEWl703M0poCwerDxNMsLP4cxWZBLN7VviDd:I6QlgzZQ+m/hEA0tXL5yo4c0BLNlA` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_017_1b937dba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b937dbaa72bc5d6196d45559037182ccf8ab038d4f4f45592b40630af40bfc6"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-10-11 03:59:48"
  condition:
    hash.sha256(0, filesize) == "1b937dbaa72bc5d6196d45559037182ccf8ab038d4f4f45592b40630af40bfc6"
}
```

### Sample 18: `a9fc1e7b49f06d3d`

| Field | Value |
|---|---|
| SHA-256 | `a9fc1e7b49f06d3d5161c78da1821de4849de3a9994955e0c9660d14e7031220` |
| Family label | `VShell` |
| File name | `inner-dll-a9fc1e7b.bin` |
| File type | `dll` |
| First seen | `2026-10-11 02:43:46` |
| Reporter | `Daydream` |
| Tags | `dll, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72e21dd9eec7ffc8c177379588598d85` |
| SHA-1 | `348010a919081972ed9573c4f9ed6a309a5bac3b` |
| SHA-256 | `a9fc1e7b49f06d3d5161c78da1821de4849de3a9994955e0c9660d14e7031220` |
| SHA3-384 | `b1b9dbe70c4510d0804ffe84cc3840129a04a7e53af06c791648bb357401b36393a5e71f6738d648a9319e2192a9f15d` |
| IMPHASH | `4c3a421376a9d506827feee41437d950` |
| TLSH | `T1F1763990F9DBC4B5DA036470045BA23F2634AD094B34DBC7DA447F9AE8737E21A3265B` |
| SSDEEP | `49152:cugW48+kfCjonu4ZVkGUCYv3WRhk0LIPMkxzf7kQbO078bXg5t21Dzu5bRakh1cM:cugp8QMnu4zkGBFzkX7iQzzzE5G` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_018_a9fc1e7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9fc1e7b49f06d3d5161c78da1821de4849de3a9994955e0c9660d14e7031220"
    family = "VShell"
    file_name = "inner-dll-a9fc1e7b.bin"
    file_type = "dll"
    first_seen = "2026-10-11 02:43:46"
  condition:
    hash.sha256(0, filesize) == "a9fc1e7b49f06d3d5161c78da1821de4849de3a9994955e0c9660d14e7031220"
}
```

### Sample 19: `cc84973917d7089a`

| Field | Value |
|---|---|
| SHA-256 | `cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5` |
| Family label | `VShell` |
| File name | `cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5.bin` |
| File type | `exe` |
| First seen | `2026-10-11 02:43:38` |
| Reporter | `Daydream` |
| Tags | `exe, stage, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9ad8d7e0d04807df2687325abf9bc90d` |
| SHA-1 | `6a066c096919e47177d36d116e04d8d13f17a224` |
| SHA-256 | `cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5` |
| SHA3-384 | `7390729e7c1ef60906c220990f54b5a8bfead98cc7b98185a0091748e3335b4889d26b20b7f4a51c53b03ff8c4e6e1a5` |
| IMPHASH | `42e4699ccef35d7497261b7a3541dafb` |
| TLSH | `T1D526E191F99B44B2E5026531486762BF23305E095F32CBC7E644BB6DECB39E20D371A6` |
| SSDEEP | `98304:4+Iggi13jQdBhYQDFtvM4pJSiFT0gQVmc0v:JIJxdceFlMnAIgum` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_019_cc849739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5"
    family = "VShell"
    file_name = "cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5.bin"
    file_type = "exe"
    first_seen = "2026-10-11 02:43:38"
  condition:
    hash.sha256(0, filesize) == "cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5"
}
```

### Sample 20: `eec3cf8a0e22c37a`

| Field | Value |
|---|---|
| SHA-256 | `eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028` |
| Family label | `VShell` |
| File name | `eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028.bin` |
| File type | `dll` |
| First seen | `2026-10-11 02:43:29` |
| Reporter | `Daydream` |
| Tags | `dll, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c1f042939d03f1dc3cf8e6a0d5319b0e` |
| SHA-1 | `a58a629268571913a0cad28b12902eb537b68a75` |
| SHA-256 | `eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028` |
| SHA3-384 | `fbe2f9b257f953315ef3c673acb364f313453c3a422b5b9043dbe7f363faf9fd85e1ce5fadf8fcda993374e5da2882c6` |
| IMPHASH | `4c3a421376a9d506827feee41437d950` |
| TLSH | `T146764A51F99BC0B5DA035431046B623F27346D094F24CBC7EA44BFAAE9B77E21E3251A` |
| SSDEEP | `49152:A1xUwe6llMWCv+JKIP50bAnUOWHntWWVBGg6J3nutCnLf6cFy8/NtmOir+kdq1D0:A1xXe/WxKI+AUOcGwteI6t1iq5ma/` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `dll`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_020_eec3cf8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028"
    family = "VShell"
    file_name = "eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028.bin"
    file_type = "dll"
    first_seen = "2026-10-11 02:43:29"
  condition:
    hash.sha256(0, filesize) == "eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028"
}
```

### Sample 21: `9697dead9eada8f6`

| Field | Value |
|---|---|
| SHA-256 | `9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0` |
| Family label | `VShell` |
| File name | `9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0.bin` |
| File type | `exe` |
| First seen | `2026-10-11 02:43:18` |
| Reporter | `Daydream` |
| Tags | `exe, stage, VShell` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2bd3df895000037833bec52611819495` |
| SHA-1 | `06eaf2925399622bdac065d834b3ad4d7ec451f7` |
| SHA-256 | `9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0` |
| SHA3-384 | `d22706940650a5c00f4091667495ab11a70863b7022b167a2ffcbbe0d043227bac6a47a035abe640ca549a96d523c7f5` |
| IMPHASH | `42e4699ccef35d7497261b7a3541dafb` |
| TLSH | `T19426E085FDAB14F1E503543144A762AF23309D165F36CBC7D640BBAAACB39E50D3326A` |
| SSDEEP | `98304:q7Cwfsl8FRpcRMgS9mCNZjylcLp5cSWfuLSVR:qCvlSpSMgS/Qw5cSPSV` |

#### Technical Assessment

- The sample is tracked as `VShell` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_VShell_021_9697dead
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0"
    family = "VShell"
    file_name = "9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0.bin"
    file_type = "exe"
    first_seen = "2026-10-11 02:43:18"
  condition:
    hash.sha256(0, filesize) == "9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0"
}
```

### Sample 22: `2a0bc1efd509f722`

| Field | Value |
|---|---|
| SHA-256 | `2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a` |
| Family label | `AsyncRAT` |
| File name | `2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a.exe` |
| File type | `exe` |
| First seen | `2026-10-11 02:35:53` |
| Reporter | `Tuxxin` |
| Tags | `AsyncRAT, exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dc1244712bae6d520128c5e70ce61ea9` |
| SHA-1 | `6fb87596fe6952db8d69dde9b709c819faf5bd67` |
| SHA-256 | `2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a` |
| SHA3-384 | `a7c0e280ac4372ed27135e90dde7ae9bbcaa0aee9694ec5e6d54b85f91e88a6320171fb9008c3d75a71dbc3659c40c01` |
| IMPHASH | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| TLSH | `T11E232C043BE9812BF2BE4F74A8F32245857AF6673603D65D1CC451975613FC28A42AFE` |
| SSDEEP | `768:UuYHKTsufqG9vSLjWUvlPRmo2qbZaGMgvgePIdRS8D0bCafLPPyD8cX1jAFZ6BBL:UuYHKTsjMvSX25iidRjobCafjKD1JBbd` |

#### Technical Assessment

- The sample is tracked as `AsyncRAT` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AsyncRAT_022_2a0bc1ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a"
    family = "AsyncRAT"
    file_name = "2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a.exe"
    file_type = "exe"
    first_seen = "2026-10-11 02:35:53"
  condition:
    hash.sha256(0, filesize) == "2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a"
}
```

### Sample 23: `f1692afdc0662c34`

| Field | Value |
|---|---|
| SHA-256 | `f1692afdc0662c3448563ba69eb6052b27d0981d48d3400c1d5bfaa5a339e0b1` |
| Family label | `unknown` |
| File name | `2026-10-10_cb69d574039e35b0fc6dbaf611212acc_elex_wannacry` |
| File type | `exe` |
| First seen | `2026-10-11 02:13:59` |
| Reporter | `NyxIndius` |
| Tags | `exe` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb69d574039e35b0fc6dbaf611212acc` |
| SHA-1 | `fc662f8f742681bb0606e0f3a988b1cfb1b612f3` |
| SHA-256 | `f1692afdc0662c3448563ba69eb6052b27d0981d48d3400c1d5bfaa5a339e0b1` |
| SHA3-384 | `207567df7176213d253d3ff973f57358c0b391b121d670837b25f575e37732fa8826a4b42748ea80a1c1d175a5398a44` |
| IMPHASH | `ba23a556ac1d6444f7f76feafd6c8867` |
| TLSH | `T1DC93AA2A4DEA207BE173E570A5E116F2BA1EA55E35C50D0E05C3C35D8D62E02BEE7D0E` |
| SSDEEP | `768:50w981IshKQLroA4/wQozzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzv:CEGI0oAlVunMxVS3c` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_023_f1692afd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1692afdc0662c3448563ba69eb6052b27d0981d48d3400c1d5bfaa5a339e0b1"
    family = "unknown"
    file_name = "2026-10-10_cb69d574039e35b0fc6dbaf611212acc_elex_wannacry"
    file_type = "exe"
    first_seen = "2026-10-11 02:13:59"
  condition:
    hash.sha256(0, filesize) == "f1692afdc0662c3448563ba69eb6052b27d0981d48d3400c1d5bfaa5a339e0b1"
}
```

### Sample 24: `47fa5cd944239c76`

| Field | Value |
|---|---|
| SHA-256 | `47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e` |
| Family label | `Mirai` |
| File name | `dissmips` |
| File type | `elf` |
| First seen | `2026-10-11 02:01:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff92a33f478ab5d8b1f8b634940d6e20` |
| SHA-1 | `0b5659a3d935113f1c1fa4c6537d0a7f71d0a09a` |
| SHA-256 | `47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e` |
| SHA3-384 | `88014423e6fc496c45c361c2839b15be29cfcdbd4444d3fdd28e90498f05ac7c324dc572b6bb1116a2440f46bc955003` |
| TLSH | `T1E744B65E6E729F7DF378873447B74B30A76922D627E1D681D1ACD2041E2034E681FBA8` |
| TELFHASH | `t1a151c31c19b813a0a2256c5e45ddff3bd6a331db7e162c378b10e86aa769f839d10c1c` |
| SSDEEP | `6144:gwC19+4BiL2fraQacz3MzA6sqAiIOirWylUlle/vgyr:aM4Qbxkik/Im` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_024_47fa5cd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-11 02:01:37"
  condition:
    hash.sha256(0, filesize) == "47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e"
}
```

### Sample 25: `ddaadef14a9fd703`

| Field | Value |
|---|---|
| SHA-256 | `ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755` |
| Family label | `Mirai` |
| File name | `ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755` |
| File type | `elf` |
| First seen | `2026-10-11 01:59:29` |
| Reporter | `ksi_digital` |
| Tags | `akuma, elf, mirai, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fd35a79721c98ed973e8c9efa4426cd6` |
| SHA-1 | `40eac47a1e8ffb9876b81dc49dfa0fd5c14f8393` |
| SHA-256 | `ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755` |
| SHA3-384 | `28ab883cd2ab37865dbcffd858fa1135294c0ae98afa5f70aa6042a539f20bc4153a19ec927d75953b3b03808626bec7` |
| TLSH | `T178B48D13E5D080B9C5E6C1385F8FE227F971BD8D6238766F22D06F126A39E60936D780` |
| TELFHASH | `t10af14330097a382172e7d515b303d6bc6c3a250584e631e17b6379eeddce9c49fba822` |
| SSDEEP | `6144:SxkQDmaF73v7jcnw1Y718kxuoHc/bd5/sCM87NJlxr1arMQskasSXFzuI373BzIL:9C73vEnJuTdpsmhJHrd0as2aI1knh5` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_025_ddaadef1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755"
    family = "Mirai"
    file_name = "ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755"
    file_type = "elf"
    first_seen = "2026-10-11 01:59:29"
  condition:
    hash.sha256(0, filesize) == "ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755"
}
```

### Sample 26: `ba268ec991a555c7`

| Field | Value |
|---|---|
| SHA-256 | `ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a` |
| Family label | `Mirai` |
| File name | `android-arm64` |
| File type | `elf` |
| First seen | `2026-10-11 01:57:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `74a806d4b375bf17d3bdc6a957ae83c9` |
| SHA-1 | `68671be65b5b18b6bf5c77d3fd01649a696f95f6` |
| SHA-256 | `ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a` |
| SHA3-384 | `c6abe4dd4c03e0175ddb239b2255f26e9f3c5db763f77d6e205c807026490eb74b0482f674f50bb98da18b23a125107b` |
| TLSH | `T1E0945D8C91F5E3DEE288F57892067C569872253630A3B2D5350FE5BB53AB2C449EDE30` |
| TELFHASH | `t19311eb46e97d97ae9ea34920aca927b18053db2271b1c730ef11ded4583f501f119e8f` |
| SSDEEP | `6144:vLAa9r281vRfLKAqKNa+euF8vIcVfNXBNgDyBI4:vLAa9Z++e8zcfgW3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_026_ba268ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a"
    family = "Mirai"
    file_name = "android-arm64"
    file_type = "elf"
    first_seen = "2026-10-11 01:57:36"
  condition:
    hash.sha256(0, filesize) == "ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a"
}
```

### Sample 27: `102bfe850243f122`

| Field | Value |
|---|---|
| SHA-256 | `102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b` |
| Family label | `Mirai` |
| File name | `dissmpsl` |
| File type | `elf` |
| First seen | `2026-10-11 01:37:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `36b81bf6cd8bdfe46602ef3434d89eea` |
| SHA-1 | `b2930ca37545f19e3f3629e9619f75291e450b85` |
| SHA-256 | `102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b` |
| SHA3-384 | `1161c1f7b04d20f82ff1184c9af7d58c5ae3e3883b8e49d8c031de3f49e9736efccae92f8b1e5e9df73c1b33fed4fb43` |
| TLSH | `T19144B649ABA10EFBE8ABDE3306E90B0225CC650712A43F3A7A74D514F55B54F49E3C78` |
| SSDEEP | `3072:YpK76P8rve/Zqoigxa3vd8IlU8Syzn3zaRZOQbG3qC:YpIlvKZqjgMjOMDBQbbC` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_027_102bfe85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-11 01:37:34"
  condition:
    hash.sha256(0, filesize) == "102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b"
}
```

### Sample 28: `81da78f52b2a92eb`

| Field | Value |
|---|---|
| SHA-256 | `81da78f52b2a92eb67e5490d8b296be00f3a253c71850b267138949ce2d50f73` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-11 01:26:17` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0451f7b68d21453b18d7c04e2b9bd5bd` |
| SHA-1 | `6a11d74462f2e82d4cbfbaa11e408b2a644c64df` |
| SHA-256 | `81da78f52b2a92eb67e5490d8b296be00f3a253c71850b267138949ce2d50f73` |
| SHA3-384 | `968e230f71d297dbf752d1406deddf166f54c7699bc92bc853e831fc4cf9581089d1f77bc38e8ee3338cd47bf78b736d` |
| TLSH | `T166C43A8953B1DFDDF324DA3103736E1769B6023335D3A685E16EE92227A124C58AFE70` |
| TELFHASH | `t1a6f05e1c183823f1c3c59d5eabedff30e8a181d759662e33cd54e4aaa7319868c00d2c` |
| SSDEEP | `6144:B2f83ZQ5zgh+IfuPh3Me8PIaSxOQ8YUlJByjVELJc+iSWumQXYmrdZEkps:RGlIYdql3yO+CrfEkW` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_028_81da78f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81da78f52b2a92eb67e5490d8b296be00f3a253c71850b267138949ce2d50f73"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-11 01:26:17"
  condition:
    hash.sha256(0, filesize) == "81da78f52b2a92eb67e5490d8b296be00f3a253c71850b267138949ce2d50f73"
}
```

### Sample 29: `7acedfec70eabc61`

| Field | Value |
|---|---|
| SHA-256 | `7acedfec70eabc61d8cd2ad45d6258d9473f52aaf47e1719f4f5ccfe93f01105` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-11 01:25:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2032d409bf19bf7a54d3b8738531c96b` |
| SHA-1 | `790729eb5cb7314eace53d8d5f5c2d6151f2831d` |
| SHA-256 | `7acedfec70eabc61d8cd2ad45d6258d9473f52aaf47e1719f4f5ccfe93f01105` |
| SHA3-384 | `90d6064da8d15f79419e5a7a425684abc8ed092d746a684f1f0a110eb50d7cf3f08ae5d516a1d978135a824b55f2076e` |
| TLSH | `T1B40412AE109ACBC5F957D8BD06568B50FA760F20E2776007EF95E00559F00DB39DA39C` |
| SSDEEP | `3072:r3m+MNgOMZP+12xyarsj7YjHLWn1aZgFyg4cVSyJnyIjxCRGud22zVabImTJqoz2:i+yg/ZP+kxyaYnYjLW1aRv4yIjRk22GS` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_029_7acedfec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7acedfec70eabc61d8cd2ad45d6258d9473f52aaf47e1719f4f5ccfe93f01105"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-11 01:25:43"
  condition:
    hash.sha256(0, filesize) == "7acedfec70eabc61d8cd2ad45d6258d9473f52aaf47e1719f4f5ccfe93f01105"
}
```

### Sample 30: `dda6f0c518eb6e05`

| Field | Value |
|---|---|
| SHA-256 | `dda6f0c518eb6e05eb68164000a1881c1790f346a9027c9b7fb7c9b1b89f247c` |
| Family label | `Mirai` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-11 01:21:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb3327fe9eafe687b2add018f82a51c8` |
| SHA-1 | `9b70ca471f6ba2a9d7f77957451a4912e888c240` |
| SHA-256 | `dda6f0c518eb6e05eb68164000a1881c1790f346a9027c9b7fb7c9b1b89f247c` |
| SHA3-384 | `f8b840d2ea1a26915e2ed3d8abc441a4270758a13fb3a68fdb7bea34a24b00cadb49aeb5c4c25ac84be250d56b2e6b8a` |
| TLSH | `T1F0145C16B5C1A0FDC8D6D27887AFE536EA36B44D1234B54F1B94AE222F1DE306B1CB50` |
| TELFHASH | `t1b161f1701ed2366871eb860ab34eed2dfa7208015dd6b2e9bf17acd4dd45bc44c53462` |
| SSDEEP | `3072:hjLmFpk+6k/ziAe4v9ESfNzbzfxJ893171GJ0F6iOOWq4qmV13hmFYxZ:FLmFpk+6DQ9jfE7x60r7xYxZ` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_030_dda6f0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dda6f0c518eb6e05eb68164000a1881c1790f346a9027c9b7fb7c9b1b89f247c"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-11 01:21:39"
  condition:
    hash.sha256(0, filesize) == "dda6f0c518eb6e05eb68164000a1881c1790f346a9027c9b7fb7c9b1b89f247c"
}
```

### Sample 31: `039454c2c6ca70c6`

| Field | Value |
|---|---|
| SHA-256 | `039454c2c6ca70c60baded0e22661564066d5654e893ec593a98a8e84b02971d` |
| Family label | `Mirai` |
| File name | `riscv64` |
| File type | `elf` |
| First seen | `2026-10-11 01:17:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0afb4920162b04e7e313334f10f95b55` |
| SHA-1 | `7242597fd56c240907d2af48d855648f450a1dfa` |
| SHA-256 | `039454c2c6ca70c60baded0e22661564066d5654e893ec593a98a8e84b02971d` |
| SHA3-384 | `93173dd369cee9688038d57191aabc2ee3552613fe6e33ffe3afe7e71ab9739e1cbda9cc6e993168e617e24468921f1f` |
| TLSH | `T11E844B8C92F1E3CEE158EA3953257C1A5C72463A3093728A719EF97313AB1944AFDD70` |
| SSDEEP | `6144:ZF3H3v6AmBJB9tRCXD/mr6TzAFSiJHwuDvToiF+ha9iv:z3X+PgfAUriEha9iv` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_031_039454c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "039454c2c6ca70c60baded0e22661564066d5654e893ec593a98a8e84b02971d"
    family = "Mirai"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:39"
  condition:
    hash.sha256(0, filesize) == "039454c2c6ca70c60baded0e22661564066d5654e893ec593a98a8e84b02971d"
}
```

### Sample 32: `b6ac689fb11fa67b`

| Field | Value |
|---|---|
| SHA-256 | `b6ac689fb11fa67b4cb32415b9b5cdd81b6234b2f4bb2c7672a048af96ea8e89` |
| Family label | `Mirai` |
| File name | `adissarm5` |
| File type | `elf` |
| First seen | `2026-10-11 01:17:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `66369f238b3da2e3b7410ff0654323ea` |
| SHA-1 | `c4eba2d5ed1232f4d90fde7bbdcfacd539d6f339` |
| SHA-256 | `b6ac689fb11fa67b4cb32415b9b5cdd81b6234b2f4bb2c7672a048af96ea8e89` |
| SHA3-384 | `213786066b4c94946638255918ba9a586b1d24bbe70758c40b9a569de44b2fc5b0306e0283f7d5f6a9ffdf0879e23773` |
| TLSH | `T181141A85FC509A23C6C1567BFB6E428C372B13B8D2EE31039D216F24379786E0E76656` |
| TELFHASH | `t199313324cecc095ca7d9885440dd223eeaa671b9272515255e3bbe0e8a53ce3306183f` |
| SSDEEP | `6144:K1dM6biThfo6M0kG28ulghOc/3h4Nq78N3Sj/6bWo1/:YdM6me6Mcul+/h4NqQN6/6Ko1/` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_032_b6ac689f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6ac689fb11fa67b4cb32415b9b5cdd81b6234b2f4bb2c7672a048af96ea8e89"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:36"
  condition:
    hash.sha256(0, filesize) == "b6ac689fb11fa67b4cb32415b9b5cdd81b6234b2f4bb2c7672a048af96ea8e89"
}
```

### Sample 33: `407eab618ddc11e8`

| Field | Value |
|---|---|
| SHA-256 | `407eab618ddc11e847b0498e9284de15db19bfe89720089cb176790659e34386` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-11 01:17:34` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `06a1fcb91c8d79759ed7468b31bb0e00` |
| SHA-1 | `ab48771b225cef1a3affdc44f2db8e96fdc10533` |
| SHA-256 | `407eab618ddc11e847b0498e9284de15db19bfe89720089cb176790659e34386` |
| SHA3-384 | `ca35c6eae42f5193c4ecd1d97f17a6f96a709f877be9a5eb62a54615fcccb465e58eeeea81ece72f5dcec316a009212c` |
| TLSH | `T16A561897B9D24942C4E43A77A8BE80C833631EBA9B8656575D04FE3C3EBE5D90E34314` |
| TELFHASH | `t169d0a5454f4c3ae42bd500e51414127f5af430fc11142f944f4d35df471157970c54dd` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `98304:uczL5kXe4cJlT3VurlGkkXzDnq6YqyxlxNKbhT88YIbrnbO5fTtbEu:u8DJlru` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_033_407eab61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "407eab618ddc11e847b0498e9284de15db19bfe89720089cb176790659e34386"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:34"
  condition:
    hash.sha256(0, filesize) == "407eab618ddc11e847b0498e9284de15db19bfe89720089cb176790659e34386"
}
```

### Sample 34: `7eb6bb0a620a2844`

| Field | Value |
|---|---|
| SHA-256 | `7eb6bb0a620a284423d2d1382605163063239ecb2c7630722c45d6fb692a0705` |
| Family label | `Mirai` |
| File name | `disssh4` |
| File type | `elf` |
| First seen | `2026-10-11 01:17:31` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9e7c891a89330f10f73ea817e4b8d8e3` |
| SHA-1 | `c2fde0eb15587d71f5975e50aeaa77407aec6adb` |
| SHA-256 | `7eb6bb0a620a284423d2d1382605163063239ecb2c7630722c45d6fb692a0705` |
| SHA3-384 | `7f3556abdb15fafb02af23e89a640d035a5095be2aad0415262ac47464b6d25a367435a33a6f58ddb92382220f2d2344` |
| TLSH | `T136049C62DC656E94C124E6B0F1F18F7A2B23965146431FBF59B6C2B88087D8CF6097BC` |
| SSDEEP | `3072:lC9s/mR4Lf7tnY805J1mVzj1khZ5EWuPUFp7j1W1szT8Cit:lC9s/mR2tY1mx1khZ5ERYA1szhU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_034_7eb6bb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eb6bb0a620a284423d2d1382605163063239ecb2c7630722c45d6fb692a0705"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:31"
  condition:
    hash.sha256(0, filesize) == "7eb6bb0a620a284423d2d1382605163063239ecb2c7630722c45d6fb692a0705"
}
```

### Sample 35: `7b3577b0310340ea`

| Field | Value |
|---|---|
| SHA-256 | `7b3577b0310340ea3f44f62f9f20c313d199aad41a07c3b3ac28fdd460c8122e` |
| Family label | `Mirai` |
| File name | `2` |
| File type | `elf` |
| First seen | `2026-10-11 01:09:39` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `65f9531ded1de635c410f3cc2a1ea7a0` |
| SHA-1 | `1e5a165b28f54cd0e5f332d651559bb662445831` |
| SHA-256 | `7b3577b0310340ea3f44f62f9f20c313d199aad41a07c3b3ac28fdd460c8122e` |
| SHA3-384 | `56f33a9de374cb28aed56261af3047a55511819f41ae23a16561e8f4fb2b03cca20af6f770ad83c0df72def2075139e0` |
| TLSH | `T1B2457D99D7C3D4F1F66300B1068FDBF7196062355043FAF6EB481DA7B432B926A1632A` |
| TELFHASH | `t1b8229eb329bd54ecabe04921871f7210ce59e43b25e03a725df32491bb72e435e76878` |
| SSDEEP | `24576:UgMft4Hhk5hYZ8cmfA8mp29ptOri/cAZWzUI5+vBNmysO1qVK/1:UgMftohk5hxcBdMftMi/covv6M/1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_035_7b3577b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b3577b0310340ea3f44f62f9f20c313d199aad41a07c3b3ac28fdd460c8122e"
    family = "Mirai"
    file_name = "2"
    file_type = "elf"
    first_seen = "2026-10-11 01:09:39"
  condition:
    hash.sha256(0, filesize) == "7b3577b0310340ea3f44f62f9f20c313d199aad41a07c3b3ac28fdd460c8122e"
}
```

### Sample 36: `10c32c43ffe6a500`

| Field | Value |
|---|---|
| SHA-256 | `10c32c43ffe6a500840cc577c56b8107efb9c23c5a9c7c2cbf00a84894328ae6` |
| Family label | `Mirai` |
| File name | `arm7` |
| File type | `elf` |
| First seen | `2026-10-11 01:05:40` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3956e5436517a87ac30f2556564746d5` |
| SHA-1 | `6c9cde925e976a31e2462fbf8fe7b793645739aa` |
| SHA-256 | `10c32c43ffe6a500840cc577c56b8107efb9c23c5a9c7c2cbf00a84894328ae6` |
| SHA3-384 | `ed16f4f0916783dbf3d78fb54b6c1ee82a65825c06a16d2cba5001f892d02033030c2d20e90b504a4c670b91300b4724` |
| TLSH | `T1EC941A88E1E0E7DAD2D4EA75B31D794D37230735B0DB3146E51DAA3223EB1890ABED11` |
| TELFHASH | `t12ef05414d8dc69e1dfc98dc74278001cd58d19046f33b8d15789750d8a03db3d4f5032` |
| SSDEEP | `6144:agEfKjwcLxZZ5oGz84YLBMYsMNduZ4Bp7tsuqpX0m3gICEvIwbi4s2e/dtQJJa9A:v5rxZoGzNYLBMYsMkh00sP4sDaa9T8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_036_10c32c43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c32c43ffe6a500840cc577c56b8107efb9c23c5a9c7c2cbf00a84894328ae6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-11 01:05:40"
  condition:
    hash.sha256(0, filesize) == "10c32c43ffe6a500840cc577c56b8107efb9c23c5a9c7c2cbf00a84894328ae6"
}
```

### Sample 37: `b3eef4ff40ffa389`

| Field | Value |
|---|---|
| SHA-256 | `b3eef4ff40ffa38977f41f2a016cd8b7bcf74d0ac564ae3508712c358798c799` |
| Family label | `unknown` |
| File name | `aarch64` |
| File type | `elf` |
| First seen | `2026-10-11 01:05:38` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dab72bff522ca79abddb3cd3b8802769` |
| SHA-1 | `27d39df2099b7f47035765f63e593fe7c1b96d2a` |
| SHA-256 | `b3eef4ff40ffa38977f41f2a016cd8b7bcf74d0ac564ae3508712c358798c799` |
| SHA3-384 | `683cae9d91d6e15bdfcd98a3bcc3d175102a6d3bd0c324626d36ae258e60530dafccb13f16edb3b3d9331fd17219b0b3` |
| TLSH | `T12F465A55FC1D74A2C9C9B6742F7212D53638AD489F82D3232A14BB3DAAF63948F12371` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:t3So4GvrzxkzkgG7+3UlA7VGbqz7v9+UY5LxV35Ey:t3SPGvrzve3UlAQGoU6xVpEy` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_037_b3eef4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3eef4ff40ffa38977f41f2a016cd8b7bcf74d0ac564ae3508712c358798c799"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-11 01:05:38"
  condition:
    hash.sha256(0, filesize) == "b3eef4ff40ffa38977f41f2a016cd8b7bcf74d0ac564ae3508712c358798c799"
}
```

### Sample 38: `2dccab5b3b7a88ab`

| Field | Value |
|---|---|
| SHA-256 | `2dccab5b3b7a88abf6a2e2c7e592fbf54a017ce6e465ce6a722c2f5fc656b553` |
| Family label | `unknown` |
| File name | `u.sh` |
| File type | `sh` |
| First seen | `2026-10-11 01:01:45` |
| Reporter | `abuse_ch` |
| Tags | `sh` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `95731ab9740275d019e4ff5965340d66` |
| SHA-1 | `42b4ed5083c524f94a92de78469c0c7e70137ad8` |
| SHA-256 | `2dccab5b3b7a88abf6a2e2c7e592fbf54a017ce6e465ce6a722c2f5fc656b553` |
| SHA3-384 | `63036698c4daeab4530c5f33a7050c16d6caf0b85cab5e69ced44e2885d59f921b406a93dcaa2b84172c90e830beaf75` |
| TLSH | `T14292E1AD2CE1EF07FA9C683361311A6D75B60A3B15CCEF4F70A24425029B5ECE971A15` |
| SSDEEP | `384:UzC5fhppHga9aSkAa89U+8y35CwnfZPg2me7P1m+yjqpxoJ7PJwPyfnGav:3BfpAWb958OCmZPeMNMmoJ7syfnj` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `sh`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_038_2dccab5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dccab5b3b7a88abf6a2e2c7e592fbf54a017ce6e465ce6a722c2f5fc656b553"
    family = "unknown"
    file_name = "u.sh"
    file_type = "sh"
    first_seen = "2026-10-11 01:01:45"
  condition:
    hash.sha256(0, filesize) == "2dccab5b3b7a88abf6a2e2c7e592fbf54a017ce6e465ce6a722c2f5fc656b553"
}
```

### Sample 39: `e2605e9e08fa9f7b`

| Field | Value |
|---|---|
| SHA-256 | `e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048` |
| Family label | `AMOS` |
| File name | `macho_e2605e9e08fa.bin` |
| File type | `macho` |
| First seen | `2026-10-11 00:56:28` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ce0cc5b78d6add16b5dc6ca0235113fb` |
| SHA-1 | `cd1ca412bd2961b94c2b9713582f1ae5601446b2` |
| SHA-256 | `e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048` |
| SHA3-384 | `fda522875be3c46516c065aad15b2b75894be53b44d05e26ab04f7c843b03ad005d9160b2933c39d7fa66c0dd93e6afc` |
| TLSH | `T12D55F100CEB250DAF8CCC6343A268D379F317555498856DA62A32FC89E353E3F56B26D` |
| SSDEEP | `24576:/kQ+NwQN9kUdcJkzXd8nTv7rwWMxOOMZw0qjE9kDRfyxd1rla:8Qmwi9kWa3wWMxu20WyZa` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_039_e2605e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048"
    family = "AMOS"
    file_name = "macho_e2605e9e08fa.bin"
    file_type = "macho"
    first_seen = "2026-10-11 00:56:28"
  condition:
    hash.sha256(0, filesize) == "e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048"
}
```

### Sample 40: `97b2e9c27879eb5a`

| Field | Value |
|---|---|
| SHA-256 | `97b2e9c27879eb5aa3e89358a97aa88249b27bee91923bd81350111ba91c5802` |
| Family label | `Mirai` |
| File name | `arm5` |
| File type | `elf` |
| First seen | `2026-10-11 00:45:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `314cb7a47585140504eb8d77c3d43757` |
| SHA-1 | `cb1f83f5d4c0d520d2b1f20d8e68259d57e746fc` |
| SHA-256 | `97b2e9c27879eb5aa3e89358a97aa88249b27bee91923bd81350111ba91c5802` |
| SHA3-384 | `da5958d17bf5f52e14645396a79f7b68287e3282df6e7aa956b7151943943a4002e29e1b9590e47432637c548aa7d014` |
| TLSH | `T141942A88E1E0E7DAD2D4AA75B31D784D3B230736E1DB3146E519EF3223EB1490ABD911` |
| TELFHASH | `t191f0d4900d391fe1d73744ca112a310a4e9f094553233ce21809761fce713817cf2e40` |
| SSDEEP | `6144:HzE1MSowpZ581NyJ5kq7DYztPNMTHo96xw01ArV/OwX/QIho1HPIFga9YM:QOSZZ581MTkqHzLpSPQeLaa9YM` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_040_97b2e9c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b2e9c27879eb5aa3e89358a97aa88249b27bee91923bd81350111ba91c5802"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-11 00:45:50"
  condition:
    hash.sha256(0, filesize) == "97b2e9c27879eb5aa3e89358a97aa88249b27bee91923bd81350111ba91c5802"
}
```

### Sample 41: `a14b14a477fc8f32`

| Field | Value |
|---|---|
| SHA-256 | `a14b14a477fc8f329f659e0bfa92c5888b478f4f5b35f71480c21ec7439728bc` |
| Family label | `Mirai` |
| File name | `dissx86` |
| File type | `elf` |
| First seen | `2026-10-11 00:41:48` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `cb7235f8fcb5c18cd623c4218658cdc0` |
| SHA-1 | `f43d8c2c5193390c1e3ee1fa260af5256c1cff04` |
| SHA-256 | `a14b14a477fc8f329f659e0bfa92c5888b478f4f5b35f71480c21ec7439728bc` |
| SHA3-384 | `93723b6f4536ad8d28abf5a17817cb40e5e0c30c6155eb4ef25b43eb6e17d1d877b2e941d8a82130702d59d40186fafc` |
| TLSH | `T17E145B0AB5C1A0FDC8C6C2784BAFA536EA32F45D0234B64F1BD49E222E5DE306B5D751` |
| TELFHASH | `t1d761ef382d96796c20ebc647b20ef95dfd7214109ef075e9ae677d84ce077c80ca2052` |
| SSDEEP | `3072:XjpoDRAr3buMBtlI2sSEkR9t04KOQ3MfPA9MIS9XdYNJ7KMfZEA:TpoDRArLuMBtlIABS+PbxgzEA` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_041_a14b14a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14b14a477fc8f329f659e0bfa92c5888b478f4f5b35f71480c21ec7439728bc"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-11 00:41:48"
  condition:
    hash.sha256(0, filesize) == "a14b14a477fc8f329f659e0bfa92c5888b478f4f5b35f71480c21ec7439728bc"
}
```

### Sample 42: `3073ae4acf3b53b1`

| Field | Value |
|---|---|
| SHA-256 | `3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3` |
| Family label | `Mirai` |
| File name | `dissarch64` |
| File type | `elf` |
| First seen | `2026-10-11 00:25:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b0b68d9a807c85124cf90ff2d4066cd` |
| SHA-1 | `51f938087af8a3fa286e09287b918f432899040e` |
| SHA-256 | `3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3` |
| SHA3-384 | `63d260da1b272ad57931d175790a7616a723b1da734b5a9c7e995e7299a37b9997552b6d17634c9f69817a290b32ffa6` |
| TLSH | `T19DE49E98BB8D7D43D387F33DCF8A8A71322BB5E99312C2A23501425DD5C6EA9CBB0551` |
| SSDEEP | `12288:WFR+uDxmq8c918XTyFNPnxzc3mZpPWYEAkHIDDLOd4WRYs5DOoF:WFDIq8c9yqPnxzc3mvvETHH4Nc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_042_3073ae4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-11 00:25:43"
  condition:
    hash.sha256(0, filesize) == "3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3"
}
```

### Sample 43: `89e6acf66ae0277b`

| Field | Value |
|---|---|
| SHA-256 | `89e6acf66ae0277b0f46c15a63e86d44ffa0671c88ea35f1d2b85b9dbc4f30a2` |
| Family label | `Mirai` |
| File name | `dissarm6` |
| File type | `elf` |
| First seen | `2026-10-11 00:21:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `aaef9707af209419285fe1031ed669e2` |
| SHA-1 | `8759e5e7791ab2ad5762b2af4fc275cc663b3471` |
| SHA-256 | `89e6acf66ae0277b0f46c15a63e86d44ffa0671c88ea35f1d2b85b9dbc4f30a2` |
| SHA3-384 | `f8ef82d9dc4427628b833532e5f08a52bc5a3a877a1241658d0772924b41d4148be3ddb0639831cc270347889cabfb6f` |
| TLSH | `T179142956F8819B11D1D016BAFE2E528D33231B78D2EE32169E246F70778B87F0E3A515` |
| TELFHASH | `t1c8b012d316443dedf6511c028cfd53136042917b435c444531c53c3609f30141033093` |
| SSDEEP | `3072:+8vo5OJLXd6V9QxNQrsHMXHv2EXkaDC7jkEJR3K++PDR/9DLC7y:BosFMQHQNXHv2E0au3ketK/PD/LCe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_043_89e6acf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89e6acf66ae0277b0f46c15a63e86d44ffa0671c88ea35f1d2b85b9dbc4f30a2"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-11 00:21:45"
  condition:
    hash.sha256(0, filesize) == "89e6acf66ae0277b0f46c15a63e86d44ffa0671c88ea35f1d2b85b9dbc4f30a2"
}
```

### Sample 44: `3e403ed81e6fb36d`

| Field | Value |
|---|---|
| SHA-256 | `3e403ed81e6fb36d16cdaeeac1f2c97cd7bcbb38cab758fa802c4592e03d1314` |
| Family label | `Mirai` |
| File name | `pid.ppc` |
| File type | `elf` |
| First seen | `2026-10-11 00:13:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `c5a64e862fee0f95ce207226db4db8dd` |
| SHA-1 | `094138bcb32695cfecc5a33cb37e21c256bba9ef` |
| SHA-256 | `3e403ed81e6fb36d16cdaeeac1f2c97cd7bcbb38cab758fa802c4592e03d1314` |
| SHA3-384 | `67df346b66b1623d67a2088a2b50e2ab032ca3c2e3b21478156360924bfbf2fedc0ea3b1db396ff5080849877c20ee01` |
| TLSH | `T17EA42A44B3B1D2DBD284DE7053362B279B6A463238E7B189610FBB7313B317545DAAE0` |
| SSDEEP | `6144:WuHuOnUB/f8JXCBbj+nzr5ImSVB22wVwK6GPhr4YnkgPzNV55X8el5JXJGOJJfsw:WuOvxij1LnH5ll5JsSQGRcETI0` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_044_3e403ed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e403ed81e6fb36d16cdaeeac1f2c97cd7bcbb38cab758fa802c4592e03d1314"
    family = "Mirai"
    file_name = "pid.ppc"
    file_type = "elf"
    first_seen = "2026-10-11 00:13:47"
  condition:
    hash.sha256(0, filesize) == "3e403ed81e6fb36d16cdaeeac1f2c97cd7bcbb38cab758fa802c4592e03d1314"
}
```

### Sample 45: `23116e8379bc88ed`

| Field | Value |
|---|---|
| SHA-256 | `23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf` |
| Family label | `Mirai` |
| File name | `pid.x86` |
| File type | `elf` |
| First seen | `2026-10-11 00:13:45` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `156c97817ab0a6821f325cb5fa25f54f` |
| SHA-1 | `e80550aeba9122a4d9b0dd9d90b8f139ba212781` |
| SHA-256 | `23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf` |
| SHA3-384 | `43c7b516b1dac2eaf587c27ab9156fbe4bc7855cfe6446f435f90e223363bf8fe96cf4f199e16ea5cddf689c956bc504` |
| TLSH | `T15A943A88E3E3E2FEF159D9701316BA0B5D3145363053F685E39EB97393B624045AEA38` |
| TELFHASH | `t1ce81d940dfbaecf1f3d3798443f3541616aa6985f313b4718662767d2e1629241e8e22` |
| SSDEEP | `12288:trkk4HVfkFBy8tJOQ/AmF2h7vhAXa9AJ:uuFY8tJOQ/AmF2h7vhAKe` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_045_23116e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf"
    family = "Mirai"
    file_name = "pid.x86"
    file_type = "elf"
    first_seen = "2026-10-11 00:13:45"
  condition:
    hash.sha256(0, filesize) == "23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf"
}
```

### Sample 46: `0f32004426163c3f`

| Field | Value |
|---|---|
| SHA-256 | `0f32004426163c3f3f93bbfd88193b22d570756d11b8d11d132e7b369444b6a0` |
| Family label | `Mirai` |
| File name | `adb.arm7` |
| File type | `elf` |
| First seen | `2026-10-11 00:13:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41fc60a365cba8322c2df2adf6804686` |
| SHA-1 | `082487a1d60802c3be59b28623a1e9a8f3d5eb67` |
| SHA-256 | `0f32004426163c3f3f93bbfd88193b22d570756d11b8d11d132e7b369444b6a0` |
| SHA3-384 | `a9d9d569ac3179414757ba44c80d92eb5256ca94bb4f429e37d961213a09315d38f21682ff3636a3a62bf9af2c4125da` |
| TLSH | `T1BB041749FC81AB10D5D536BAFA5E4189336757BCE3FA7112DE205B2123CA92F0F7A502` |
| TELFHASH | `t1e9b092884c024dc877831501f5ec1b13a018e0535b58044612c07cae7a73621c02581a` |
| SSDEEP | `3072:OWcXVRjTSJvyxuvekGLf9Vs8klzaiFtymkZlt2nb7A63Qb0+Vn3:wL/4axjDf9VB2zaiF4mkZltSb360+Vn3` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_046_0f320044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f32004426163c3f3f93bbfd88193b22d570756d11b8d11d132e7b369444b6a0"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-11 00:13:43"
  condition:
    hash.sha256(0, filesize) == "0f32004426163c3f3f93bbfd88193b22d570756d11b8d11d132e7b369444b6a0"
}
```

### Sample 47: `09f9c15779c88866`

| Field | Value |
|---|---|
| SHA-256 | `09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0` |
| Family label | `Mirai` |
| File name | `dissarm4` |
| File type | `elf` |
| First seen | `2026-10-11 00:09:38` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ad92b872e847bc7a998db5c6e65b6466` |
| SHA-1 | `559acb34fb1619c9785c8e619da31fec22ef93c0` |
| SHA-256 | `09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0` |
| SHA3-384 | `aaefc1f5d8517d5e40200685471eb8a072601081fb9f131665cc5e6e20f710cfdc2d975d53f50ecaadfee4760123186e` |
| TLSH | `T180141985FC519B23C6D166BBFB6E428C372B13B8D2EA31039D116F24379B46B0E7A541` |
| TELFHASH | `t106d02b22cc9409ed7280924fcc7e323613a4fa027bc5a00dd1ee7f75a992ce2e031497` |
| SSDEEP | `3072:GOIOeJ84QaCpQhkDyoZ++DkiuC8pK0qenGDbzBVG7kJRui42kT1JC9KysWuu3:G3OINCpQi+ocdFpK0qenYzLaWci49T1a` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_047_09f9c157
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-11 00:09:38"
  condition:
    hash.sha256(0, filesize) == "09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0"
}
```

### Sample 48: `15611a7793060cb4`

| Field | Value |
|---|---|
| SHA-256 | `15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef` |
| Family label | `Mirai` |
| File name | `mips64` |
| File type | `elf` |
| First seen | `2026-10-11 00:05:50` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3958274cec94cfc5f684ba0988c8b0e3` |
| SHA-1 | `28d03ac065d6d683660c9e53112f948cb3690150` |
| SHA-256 | `15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef` |
| SHA3-384 | `e26dd38f14bea4b3eb88bd8c9ec596149f3b796051c70e54687d8277b9645b1cc2e46d0770da478cecc3f8b4def016d2` |
| TLSH | `T1C3B45D8563E3E7DEF214E97443E3681A6CF5023334E7A587E37E752303A61A858ADD60` |
| SSDEEP | `12288:gDOPc3Ax0cLy/eFWTHWn4tNdwkGM2wADbY:cwxnkima4iylADb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_048_15611a77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-10-11 00:05:50"
  condition:
    hash.sha256(0, filesize) == "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
}
```

### Sample 49: `f1bdf69b0cc39004`

| Field | Value |
|---|---|
| SHA-256 | `f1bdf69b0cc39004ac8dc4e1139391e97ae2c6c7333497e567181220af46cd89` |
| Family label | `Mirai` |
| File name | `disspoor` |
| File type | `elf` |
| First seen | `2026-10-11 00:01:43` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `58d959916f25c371b1315d3edf6c48d7` |
| SHA-1 | `3551cc11dd013c3d81ab38b77291480ef31f9b22` |
| SHA-256 | `f1bdf69b0cc39004ac8dc4e1139391e97ae2c6c7333497e567181220af46cd89` |
| SHA3-384 | `bf1f56f30988cc8cc730c0b79b4b8af7cd2150435e03c061f4c4ed3f586f47c29ea9ea97bf87ec888c5f0600dacc094c` |
| TLSH | `T13B146C01B71D0547E2632EF03B3F27D1D3EFDA9125F4AA452A0EBA499272D322589DCD` |
| SSDEEP | `3072:N+FNqS8K0NEvxEipOdxoqXn0+KrTmBTftm4B:N+FNqSYNEvxE+OdxoqXn0brTaTflB` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_049_f1bdf69b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1bdf69b0cc39004ac8dc4e1139391e97ae2c6c7333497e567181220af46cd89"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-11 00:01:43"
  condition:
    hash.sha256(0, filesize) == "f1bdf69b0cc39004ac8dc4e1139391e97ae2c6c7333497e567181220af46cd89"
}
```

### Sample 50: `3df8dc1d5e463c66`

| Field | Value |
|---|---|
| SHA-256 | `3df8dc1d5e463c6653eb4405cd1cb722e0ed586d08b18f35782fc37693e84869` |
| Family label | `Mirai` |
| File name | `pid.arm` |
| File type | `elf` |
| First seen | `2026-10-10 23:57:41` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `fb5a91a3eaa9fbbe9da3a79147e46f26` |
| SHA-1 | `19befda5dd8b65275f2939c57d72d606ed6ab3f8` |
| SHA-256 | `3df8dc1d5e463c6653eb4405cd1cb722e0ed586d08b18f35782fc37693e84869` |
| SHA3-384 | `6b72968baf0bb52b2c5ecae9c479347e674261811f42a4c41046b90e4ade0bf6a0d2ba2e2274ab36f8f20fec028a944b` |
| TLSH | `T163942A88F1E0E7DAD2D4AA75B31C794E37230736E1D73146E519EB3223EB1490ABE911` |
| TELFHASH | `t1bdf027698a376d12977a88c9a20679b4ad3f181a6f1324f2d9e4210f8e222d114f1d12` |
| SSDEEP | `6144:SAaWdWdxsFXD8MtDdTOnqyn4Ns21fXqNl4rDPAjnJ12uV/Kwy/OIhul9PxFJa94M:pntFXQUwn3n4N+g4J8FOeWPa94M` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_050_3df8dc1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3df8dc1d5e463c6653eb4405cd1cb722e0ed586d08b18f35782fc37693e84869"
    family = "Mirai"
    file_name = "pid.arm"
    file_type = "elf"
    first_seen = "2026-10-10 23:57:41"
  condition:
    hash.sha256(0, filesize) == "3df8dc1d5e463c6653eb4405cd1cb722e0ed586d08b18f35782fc37693e84869"
}
```

### Sample 51: `2be31561bd8f5252`

| Field | Value |
|---|---|
| SHA-256 | `2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c` |
| Family label | `Mirai` |
| File name | `2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c.elf` |
| File type | `elf` |
| First seen | `2026-10-10 23:56:07` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e8f26f69c47e234b04e628804df87c22` |
| SHA-1 | `7e513ac8382309aedf84bb0279cff3d3bafbf92d` |
| SHA-256 | `2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c` |
| SHA3-384 | `520cbc16630478e54a0afa2a635ca4eb7bd368b60e3cc64b53d1e8d584c3e4aebb64ffeae8c4fc9171977f030267a5a2` |
| TLSH | `T1A2D3E80FAE639F6DF36CC6344BB78B25A795239523E0C545D26CEA001E6034D686FFA4` |
| TELFHASH | `t1f2114918893823f087b11cde66ecff76e49170ee0a215e378d40f9a99b6dd429d01c1c` |
| SSDEEP | `1536:padPvi1i4gMMyvrG22G2vD2iNM63L5H0Z+kh/fcoaXtmlMLevfkGC/fx8pRmYx:Ypi1D9nvGMUL5OZcoaXQdC/fxdYx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_051_2be31561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c"
    family = "Mirai"
    file_name = "2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 23:56:07"
  condition:
    hash.sha256(0, filesize) == "2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c"
}
```

### Sample 52: `a0a03d5fb69f3179`

| Field | Value |
|---|---|
| SHA-256 | `a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e` |
| Family label | `Mirai` |
| File name | `a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e.elf` |
| File type | `elf` |
| First seen | `2026-10-10 23:56:02` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `9b97b0334c06da4cbf2c91788e12e179` |
| SHA-1 | `267621b60b276921c691446e240966d348139d06` |
| SHA-256 | `a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e` |
| SHA3-384 | `39708cd9ebb49cc8f649ce8247347e7717e14079bf3e746c04300167f8eacd89a69c901fa3f6e9c9036685bdfa030051` |
| TLSH | `T12EA39E02CD74ACECE12A2D7120B99EF94B23A484951F6DFB3846C2651047E98F59F7F8` |
| SSDEEP | `1536:ZTI1Pb0bN259slVOM/MW5YKnnJNbrK7kZqx/MCM0+Y0rqfx8pRX:ZTI1Pb0bkklVOM153DbO7z/MoR6qfxq` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_052_a0a03d5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e"
    family = "Mirai"
    file_name = "a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e.elf"
    file_type = "elf"
    first_seen = "2026-10-10 23:56:02"
  condition:
    hash.sha256(0, filesize) == "a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e"
}
```

### Sample 53: `d9c5e1e5042f02a7`

| Field | Value |
|---|---|
| SHA-256 | `d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb` |
| Family label | `Prometei` |
| File name | `d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb` |
| File type | `elf` |
| First seen | `2026-10-10 23:54:13` |
| Reporter | `c2hunter` |
| Tags | `elf, Prometei, wraith` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `7ef586a5c9713d3562a1918141590d1f` |
| SHA-1 | `899ba845b31b87a04ee933a79a001355a897ab12` |
| SHA-256 | `d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb` |
| SHA3-384 | `7ce2a7a2330ffb699202d064ad3b2f3450228a52d3e37d87e789e338c6806011f34568d65d0ac0c1c48b45c08472a346` |
| TLSH | `T184A423B4F9219E9F6DD769B91B24831DE182C172589D4C2313AE94E34F3D632BF2C816` |
| SSDEEP | `12288:Fs+/py5fM2l+M5F7TsJwtY1yvr+bT1psS+6T6NCj76tsdZ:Fs6pyCC/Ya2hpi6T6N4v` |

#### Technical Assessment

- The sample is tracked as `Prometei` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Prometei_053_d9c5e1e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb"
    family = "Prometei"
    file_name = "d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb"
    file_type = "elf"
    first_seen = "2026-10-10 23:54:13"
  condition:
    hash.sha256(0, filesize) == "d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb"
}
```

### Sample 54: `1f033b961e57f63b`

| Field | Value |
|---|---|
| SHA-256 | `1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f` |
| Family label | `Mirai` |
| File name | `pid.m68k` |
| File type | `elf` |
| First seen | `2026-10-10 23:45:55` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `ff229417e41c831867292b1a0fec2236` |
| SHA-1 | `d1a0f54d47e92a018becabc71dc1ecd80bf7c9ea` |
| SHA-256 | `1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f` |
| SHA3-384 | `7cf3cc8315aa0323bd1ff5914eba3bb7f3880894e9f134c45bbd27157248ef38552f95f2f835b9ea06fb8550386ae81f` |
| TLSH | `T167942A88A2B5FBDEE296FE7983017C065C298B357883354570AEF97313B72410AFD961` |
| SSDEEP | `6144:u/1fvZU2MQ1Y8a34zKSOLemkSqEFwHtzRWweqvXE/veDMW:kXpY8vzE6XSRc3ieDR` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_054_1f033b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f"
    family = "Mirai"
    file_name = "pid.m68k"
    file_type = "elf"
    first_seen = "2026-10-10 23:45:55"
  condition:
    hash.sha256(0, filesize) == "1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f"
}
```

### Sample 55: `6203e04f7b366394`

| Field | Value |
|---|---|
| SHA-256 | `6203e04f7b366394835a952bc61ee7214c2c84f2f8a7567dbe2615b8e9c1add9` |
| Family label | `Mirai` |
| File name | `pid.x86_64` |
| File type | `elf` |
| First seen | `2026-10-10 23:45:52` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `3c64ee06c268789eb2509b6b16a329d1` |
| SHA-1 | `4745f198bc237d4a1efef4fe989b51328cedff86` |
| SHA-256 | `6203e04f7b366394835a952bc61ee7214c2c84f2f8a7567dbe2615b8e9c1add9` |
| SHA3-384 | `feeb89fc08e1d3d65c536fa89e35ec4a3f7e9a1c4b97ee4581b0ec5f45531b59eed07764a4168bf3f475e9696aaf3426` |
| TLSH | `T158656D19A2F3F1FCD157D134539BDA625931B43621327DBF22C8EA322E76D901369B22` |
| TELFHASH | `t12e02ef704af935b4b3dac910b352f4b0993204a6a6f43af45a626dd4ef95ec04ca6827` |
| SSDEEP | `24576:+TpFFgb1r8nF3NgtCY0dP9GEXEtnruOlMU:+TJHF3NgtCYUdER6` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_055_6203e04f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6203e04f7b366394835a952bc61ee7214c2c84f2f8a7567dbe2615b8e9c1add9"
    family = "Mirai"
    file_name = "pid.x86_64"
    file_type = "elf"
    first_seen = "2026-10-10 23:45:52"
  condition:
    hash.sha256(0, filesize) == "6203e04f7b366394835a952bc61ee7214c2c84f2f8a7567dbe2615b8e9c1add9"
}
```

### Sample 56: `8d4fc1e1797743de`

| Field | Value |
|---|---|
| SHA-256 | `8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b` |
| Family label | `AMOS` |
| File name | `macho_8d4fc1e17977.bin` |
| File type | `macho` |
| First seen | `2026-10-10 23:42:33` |
| Reporter | `c4ffeine` |
| Tags | `AMOS, ClickFix, Foxveil, loader, Mach-O, macho, macOS` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `53d3dad4b888701e5e277de4cf4bf8d4` |
| SHA-1 | `bc4aaa549201dbb1295f72841492319cc46cb9a5` |
| SHA-256 | `8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b` |
| SHA3-384 | `c7259ff48769e5fbcf670c786ceb934fd2437db6c2ae69856ed0cd953c1e9e72549dacb4420d87bafd48811e2b5db129` |
| TLSH | `T17A55F2028FB545A2F9C8DA342B2B89375F616570584912DAA3931B8D8F323D3F56B31F` |
| SSDEEP | `24576:h5cLqWST3LZFyx+JTgHVFVm5RpNGjItqaQVBdDX+1+ZvgtrBV6bT:hWOsxqTqa59Gje1GvUObT` |

#### Technical Assessment

- The sample is tracked as `AMOS` by MalwareBazaar metadata.
- The observed artifact type is `macho`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_AMOS_056_8d4fc1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b"
    family = "AMOS"
    file_name = "macho_8d4fc1e17977.bin"
    file_type = "macho"
    first_seen = "2026-10-10 23:42:33"
  condition:
    hash.sha256(0, filesize) == "8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b"
}
```

### Sample 57: `18a9a8e5b1b454fc`

| Field | Value |
|---|---|
| SHA-256 | `18a9a8e5b1b454fce79a86921febf23f5833364b39c7e7e678c4390d2caad61b` |
| Family label | `Mirai` |
| File name | `pid.ppc64` |
| File type | `elf` |
| First seen | `2026-10-10 23:41:56` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6e99ead006dd43a37af21d1732ec16d5` |
| SHA-1 | `a8b7adfb22f56a93ea5e81eb73fb32f162330a91` |
| SHA-256 | `18a9a8e5b1b454fce79a86921febf23f5833364b39c7e7e678c4390d2caad61b` |
| SHA3-384 | `ddf2b1f639776ce56229f46c693016e1756ad3b50d579217b1419607c87dcead4654bc2a8c78cc7a251f3f65c30f5ab3` |
| TLSH | `T197A42A54B3B1D2DFD244AE7492237B259B72057230B7B25A324EBB7313F327544DAAA0` |
| SSDEEP | `6144:Q151VyWUbNwh+Ct18dJhtmMEsV/xaey8LJBXCJY/YGp58IEUVEi7:u51iUEht9Meyqu+Sqei7` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_057_18a9a8e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18a9a8e5b1b454fce79a86921febf23f5833364b39c7e7e678c4390d2caad61b"
    family = "Mirai"
    file_name = "pid.ppc64"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:56"
  condition:
    hash.sha256(0, filesize) == "18a9a8e5b1b454fce79a86921febf23f5833364b39c7e7e678c4390d2caad61b"
}
```

### Sample 58: `2e3c04e63d5d722e`

| Field | Value |
|---|---|
| SHA-256 | `2e3c04e63d5d722ecca125da3f3da4b042c79e88af3a2e7686febf40aa0b364d` |
| Family label | `Mirai` |
| File name | `pid.arm6` |
| File type | `elf` |
| First seen | `2026-10-10 23:41:54` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1aff13b9632dafd462e03027096e88b3` |
| SHA-1 | `e5cf1ee8948280d25d13e213a47d3c90e8d52689` |
| SHA-256 | `2e3c04e63d5d722ecca125da3f3da4b042c79e88af3a2e7686febf40aa0b364d` |
| SHA3-384 | `dcbed127519d75a4f55a15b6e9022bd99c9cb0af2ac56348e5d8045d06f0c089385411bc99a961907a2b29af49c871e9` |
| TLSH | `T133942A88E1E0E7DAD2D4AA75B31D790D77230735F1DB3146E519AE3223FB0490ABE921` |
| TELFHASH | `t1b7f0dc5c088429f4f38a1141a97915223cbf2950971310d38bc1782dce13ae2eaf240f` |
| SSDEEP | `6144:62JmDbn5wwS98xlYAnmzPkw8bVf+F0C/lyV/pC1YOfw4CqThRi83zkFva9z8:6TIixlYwmjVNikOqF6la9z8` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_058_2e3c04e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e3c04e63d5d722ecca125da3f3da4b042c79e88af3a2e7686febf40aa0b364d"
    family = "Mirai"
    file_name = "pid.arm6"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:54"
  condition:
    hash.sha256(0, filesize) == "2e3c04e63d5d722ecca125da3f3da4b042c79e88af3a2e7686febf40aa0b364d"
}
```

### Sample 59: `878bc1be2448fc80`

| Field | Value |
|---|---|
| SHA-256 | `878bc1be2448fc80aa15ab8373e60567a0f76aa205a412f25b1b5c7be914a228` |
| Family label | `Mirai` |
| File name | `mipsel` |
| File type | `elf` |
| First seen | `2026-10-10 23:41:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5f2e2b2c56536a29033425d6e2c07803` |
| SHA-1 | `057751baf31d278ff98abee60f24b1554c7ab68e` |
| SHA-256 | `878bc1be2448fc80aa15ab8373e60567a0f76aa205a412f25b1b5c7be914a228` |
| SHA3-384 | `56f480dce7ac30c4a69379f82ce2f2e3f04502e3c33e0bb4c0094b02cc7945115bc6085a90179a8db4ce896b28c9c9ee` |
| TLSH | `T176C4398C9BB15BDFE06ECE3153296B0718BD493B71E377A6A17DD86232AB14505E3C20` |
| SSDEEP | `6144:4nSti8HgMJLFoPeGTJ0GL1HKigpVmzH+QBksEdHOkvENrS44a9Bsr:vI8HgMzjGt0GL1H+mzx+MNrS44a9Bs` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_059_878bc1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "878bc1be2448fc80aa15ab8373e60567a0f76aa205a412f25b1b5c7be914a228"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:51"
  condition:
    hash.sha256(0, filesize) == "878bc1be2448fc80aa15ab8373e60567a0f76aa205a412f25b1b5c7be914a228"
}
```

### Sample 60: `2048f05290563172`

| Field | Value |
|---|---|
| SHA-256 | `2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c` |
| Family label | `Mirai` |
| File name | `s390x` |
| File type | `elf` |
| First seen | `2026-10-10 23:41:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6213998ea8d4289ca1714d70a6715877` |
| SHA-1 | `932ad5ab71dc9c2b329a950ffc7dcb6ff6ebf05f` |
| SHA-256 | `2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c` |
| SHA3-384 | `2a705d24d9ad725c629ab83b5266d6e53a1ed21eb4b18c7676fce0db4fc2a22bcbb81c7549a4aefc73529da8041e08f6` |
| TLSH | `T158A4E7CC51B1E3CED064AD32D22579B68A66123734833ACC61DEEB7712F7256067AE31` |
| SSDEEP | `6144:fc3GpjLGJ0t8vnVo4DSEbF8AHp4APtZkR665C054q8jRK:fcWpXGJpo4DSEbF8AHHv65Pf8dK` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_060_2048f052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:49"
  condition:
    hash.sha256(0, filesize) == "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
}
```

### Sample 61: `8f700d2eeb4574e5`

| Field | Value |
|---|---|
| SHA-256 | `8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2` |
| Family label | `Mirai` |
| File name | `arm8` |
| File type | `elf` |
| First seen | `2026-10-10 23:41:47` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5304468eedc3d7f5f01774826ce254c` |
| SHA-1 | `d1435f14302af03f3cd990a86712e10505d51eb7` |
| SHA-256 | `8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2` |
| SHA3-384 | `4197348433330ba6a8384c783ae9684b8401c0c48496963dd7922d6cc544a79cc52ecef1e715b9d68a01b6d8d424e15b` |
| TLSH | `T1A6945C8C92FAFBCAD289FAB853117D17683325753093B1E5210AF57F53AB1D448EA831` |
| SSDEEP | `6144:LJrxFxs9cqnf2EsPowc6tx6H47vXDf2/i/KKa9zw:VtFxs9cqP89c6tx6Y7viIa9zw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_061_8f700d2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:47"
  condition:
    hash.sha256(0, filesize) == "8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2"
}
```

### Sample 62: `516fc82c9bbab563`

| Field | Value |
|---|---|
| SHA-256 | `516fc82c9bbab5637162194fa2bfc2f8edfa14ee174a94bb900e87c67c5d5d05` |
| Family label | `Mirai` |
| File name | `riscv32` |
| File type | `elf` |
| First seen | `2026-10-10 23:37:51` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `02c00d28a551948116ec0ac0f550f5cd` |
| SHA-1 | `6e3aaca4cbf9dbf8ec2399399156db32ec318824` |
| SHA-256 | `516fc82c9bbab5637162194fa2bfc2f8edfa14ee174a94bb900e87c67c5d5d05` |
| SHA3-384 | `7532b2325fc4d52fa61f6a4fb5de4d9e989543479b21407dcc6cf8690f45562c58d6680bcb65a02b00521c4a8e40ad41` |
| TLSH | `T150944B8CA2F2E3CDE158EA7553117C0B4D76063B3593728A219EF9B313BA1A446EDD70` |
| SSDEEP | `6144:PwdT7/jNEic6buBgtHTWfRgE3knUxU4LpuXFyw03jHB6Ka9Ei:Pw0iHuhRLJU4FuXgwS9Ta9Ei` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_062_516fc82c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "516fc82c9bbab5637162194fa2bfc2f8edfa14ee174a94bb900e87c67c5d5d05"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-10-10 23:37:51"
  condition:
    hash.sha256(0, filesize) == "516fc82c9bbab5637162194fa2bfc2f8edfa14ee174a94bb900e87c67c5d5d05"
}
```

### Sample 63: `191583f0ade7741d`

| Field | Value |
|---|---|
| SHA-256 | `191583f0ade7741dcef9abc0d0c19ca0ef6877d65056451cb237f01b27902cf5` |
| Family label | `Mirai` |
| File name | `android-arm` |
| File type | `elf` |
| First seen | `2026-10-10 23:37:49` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `886432633d5b841120b8b4af9649792b` |
| SHA-1 | `5ccac0ef159900506220f5006a8d5d49aca1186d` |
| SHA-256 | `191583f0ade7741dcef9abc0d0c19ca0ef6877d65056451cb237f01b27902cf5` |
| SHA3-384 | `38dd28605195e736697103da03715a598d08fcc87b78b1b90bcc34b7e39422d2b4d83b97972a97e22cdebb97c0b1ac84` |
| TLSH | `T113941DDCB1F1E6C9D1D4F9757219B88D3B234375B1DB3142A50AEE3223EF18909B9A60` |
| TELFHASH | `t11b11eb46e97d97ae9ea34920aca927b18053db227171c730ef11ded4583f101f119e8f` |
| SSDEEP | `12288:A6oa9d8B6ur7n5FxFpQ+qE6jLRW+SULNaR:A6Rvk5H/QLRWE` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_063_191583f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "191583f0ade7741dcef9abc0d0c19ca0ef6877d65056451cb237f01b27902cf5"
    family = "Mirai"
    file_name = "android-arm"
    file_type = "elf"
    first_seen = "2026-10-10 23:37:49"
  condition:
    hash.sha256(0, filesize) == "191583f0ade7741dcef9abc0d0c19ca0ef6877d65056451cb237f01b27902cf5"
}
```

### Sample 64: `d674e3bba48c3f07`

| Field | Value |
|---|---|
| SHA-256 | `d674e3bba48c3f07da03f2f16acecaaf07299922f17ac3c50ed4708bc7c99260` |
| Family label | `Mirai` |
| File name | `x86_64` |
| File type | `elf` |
| First seen | `2026-10-10 23:36:20` |
| Reporter | `ksi_digital` |
| Tags | `cowrie, elf, Gafgyt, honeypot, Mirai, x86-64` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a35a8f5291906b1d46a6c1e331dba025` |
| SHA-1 | `2c95e10996c7cdb5dea8ab9ff7598448d9f09da9` |
| SHA-256 | `d674e3bba48c3f07da03f2f16acecaaf07299922f17ac3c50ed4708bc7c99260` |
| SHA3-384 | `b0541eae61b2c761989e1f1008a5008bf9b4d0506f8b155edac55e7507fae195cd505c6e279f4470a77e3efbde94f036` |
| TLSH | `T183244B07BA85D9FFC0ABC1B847FA7537D930BC6D0538B25AA790FF621A19EA05718710` |
| TELFHASH | `t18461cf342ce53528a1e78657b30fd25dfe760802cae5b6e96e83f9e5da837c44c51023` |
| SSDEEP | `3072:fTq2+iqVbXsIG1YBRzhS99kLZkx7+XqvHf6u41nCLp28KS/zVnHiCx06WTwsAacd:fTq2+iyBh499kFEHvf6uBp2mCC2jc` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_064_d674e3bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d674e3bba48c3f07da03f2f16acecaaf07299922f17ac3c50ed4708bc7c99260"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-10 23:36:20"
  condition:
    hash.sha256(0, filesize) == "d674e3bba48c3f07da03f2f16acecaaf07299922f17ac3c50ed4708bc7c99260"
}
```

### Sample 65: `402810b8c0974368`

| Field | Value |
|---|---|
| SHA-256 | `402810b8c09743686d5c3eb9ea49bb2a4d0a0d5c42c46e5ac407059ef236615b` |
| Family label | `Mirai` |
| File name | `dissmpsl` |
| File type | `elf` |
| First seen | `2026-10-10 23:17:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2502ec2f5185c7aaa33332e3c8e655bc` |
| SHA-1 | `6b4ac974125ca9acad3f705da0f815cf412bbacb` |
| SHA-256 | `402810b8c09743686d5c3eb9ea49bb2a4d0a0d5c42c46e5ac407059ef236615b` |
| SHA3-384 | `2c270f22780416ba2d610d06ae0d605a0d2a75b0f5d1ad67e7ef1f2b6890e56b4c048b6b1e8f7050d3d3a75062749b2e` |
| TLSH | `T10944B60AAFA10EFBD8ABDE3706E90B0125CCA54712A43F7A3574D528F54A54F49E3C78` |
| SSDEEP | `3072:RkVwJRp5ut3z4OhylPjw/aobv7Cpj5Za2yMNReuDdR5nHL5WQd:Rk6RQ43lu+vZc+T5rcQd` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_065_402810b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "402810b8c09743686d5c3eb9ea49bb2a4d0a0d5c42c46e5ac407059ef236615b"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-10 23:17:26"
  condition:
    hash.sha256(0, filesize) == "402810b8c09743686d5c3eb9ea49bb2a4d0a0d5c42c46e5ac407059ef236615b"
}
```

### Sample 66: `97cb2ecc246e032d`

| Field | Value |
|---|---|
| SHA-256 | `97cb2ecc246e032dc1841bd848dfeaa3823a4671fb81199f78fa9aeba9091185` |
| Family label | `Formbook` |
| File name | `s3.exe` |
| File type | `exe` |
| First seen | `2026-10-10 22:40:45` |
| Reporter | `anonymous` |
| Tags | `exe, Formbook, packed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `5dc8b0f335fdf6dc6537e6fd61f07e05` |
| SHA-1 | `f4a4132297b751284a8b3c821f6963f48f58d9e4` |
| SHA-256 | `97cb2ecc246e032dc1841bd848dfeaa3823a4671fb81199f78fa9aeba9091185` |
| SHA3-384 | `28e12a576ca1d22eae9167fe71d936c1f9d0fa9f58c45f4e30ec0df303cf3fce821fd5d8836ffa4031c6709ab2673d77` |
| TLSH | `T11B5412C3C546D533EAA809BCCE6E8C7DA8F511FC1A3BE21763460C62A11D1655E23ADF` |
| SSDEEP | `6144:3/JEyWSXyqx34zT3nmrpM7kn2vJDgVSXFVGbqAwq+:vJbf3sim7k0JQS3Gbqnq+` |

#### Technical Assessment

- The sample is tracked as `Formbook` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Formbook_066_97cb2ecc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97cb2ecc246e032dc1841bd848dfeaa3823a4671fb81199f78fa9aeba9091185"
    family = "Formbook"
    file_name = "s3.exe"
    file_type = "exe"
    first_seen = "2026-10-10 22:40:45"
  condition:
    hash.sha256(0, filesize) == "97cb2ecc246e032dc1841bd848dfeaa3823a4671fb81199f78fa9aeba9091185"
}
```

### Sample 67: `2602c8ebac36cb9f`

| Field | Value |
|---|---|
| SHA-256 | `2602c8ebac36cb9fb34f2c7db7ebad82fdd8fc55ef804399edb5c13a43d19937` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-10 22:30:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85eb61c4ba353d268d6de3f73b9d2a3f` |
| SHA-1 | `053a87cd4c3ce6985a6c08cd382a16268f3168fc` |
| SHA-256 | `2602c8ebac36cb9fb34f2c7db7ebad82fdd8fc55ef804399edb5c13a43d19937` |
| SHA3-384 | `94cfe73050e0950124812ba815a31e2d2ab0b78fe8c92d85efc30a13eddbeeb61e91508d3b38da898de3f1e662b23cb2` |
| TLSH | `T18044A41A6A328F7DF378CB3447B74B30A75D22D616E1DA84E1ACD1041E2425E646FFAC` |
| TELFHASH | `t1d151c4a8097807b492456c5d45ddff2ac5e714ef3e1a2c339a50e42de762f838c25d09` |
| SSDEEP | `6144:TpHRpFeWBKNCbDv76CqzRns89RJ55kLbJPt1WbIh:TpxtL76CoRnskRJ55krh` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_067_2602c8eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2602c8ebac36cb9fb34f2c7db7ebad82fdd8fc55ef804399edb5c13a43d19937"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 22:30:26"
  condition:
    hash.sha256(0, filesize) == "2602c8ebac36cb9fb34f2c7db7ebad82fdd8fc55ef804399edb5c13a43d19937"
}
```

### Sample 68: `511e48979f24ea79`

| Field | Value |
|---|---|
| SHA-256 | `511e48979f24ea79abf1650411ce0ad2dc4830b53fc009dacdc966ac75f81639` |
| Family label | `Mirai` |
| File name | `mips` |
| File type | `elf` |
| First seen | `2026-10-10 22:30:00` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `97ad6db63d8ad44d37f259d79f80f3ae` |
| SHA-1 | `f3dfc81c9dbb1a1ba5580c87d38d88290fa46c98` |
| SHA-256 | `511e48979f24ea79abf1650411ce0ad2dc4830b53fc009dacdc966ac75f81639` |
| SHA3-384 | `93479b84833be0b6de6cc79e8738f985d43a208b5c695af899892d438401a3fce75b9703d6ef1f7ff05388ec66bdb648` |
| TLSH | `T1EC83027BA7050CC3DAAF63B403CD8EC07ED4AEA9E803EC564264174E9C9719627CE9D0` |
| SSDEEP | `1536:O52k5H+4xF3/yjCCX/361BMLYC3cT6gzN5p8xtSvWn0MxKZ0jAROl8VJub:42qHJF3/yjCCxLx3s6gzXytbKROl8VQb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_068_511e4897
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "511e48979f24ea79abf1650411ce0ad2dc4830b53fc009dacdc966ac75f81639"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 22:30:00"
  condition:
    hash.sha256(0, filesize) == "511e48979f24ea79abf1650411ce0ad2dc4830b53fc009dacdc966ac75f81639"
}
```

### Sample 69: `980abf36f7a59fb9`

| Field | Value |
|---|---|
| SHA-256 | `980abf36f7a59fb995746514840071af6463897f17de422d41c248de0dc03dda` |
| Family label | `Mirai` |
| File name | `x86` |
| File type | `elf` |
| First seen | `2026-10-10 22:16:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `da259c087b91c341a644150305aafd63` |
| SHA-1 | `e634fe6d9bc4871241c7c671fd936dea8067a41c` |
| SHA-256 | `980abf36f7a59fb995746514840071af6463897f17de422d41c248de0dc03dda` |
| SHA3-384 | `9443d7bc29565a249b6dce0dfebf0117a9639d7534601234e1808c77daece2cf0f107b356180bc2b4fe64291b75618c2` |
| TLSH | `T11C635AC5F643D4F5E96705344137EB7BAA32F2B90229EB87E77482327C92642D90678C` |
| TELFHASH | `t14d31f0f71dbe0cd9b7d56810c31e5f922a59e23b2a5132a0056398b133a7fc150b9c3a` |
| SSDEEP | `1536:RaZsGDExpTGAtV+/C8eQBW2OnEGcVz3WyL35IUfA5PGFjfnPL:zGYxpTGASC4XTVyyLpIoYPsPL` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_069_980abf36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "980abf36f7a59fb995746514840071af6463897f17de422d41c248de0dc03dda"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-10 22:16:34"
  condition:
    hash.sha256(0, filesize) == "980abf36f7a59fb995746514840071af6463897f17de422d41c248de0dc03dda"
}
```

### Sample 70: `9d9291d7e83f3488`

| Field | Value |
|---|---|
| SHA-256 | `9d9291d7e83f348872d24cbc60a7d6ef1cdbdd8f8dd214b5624c43a9cfd51aad` |
| Family label | `Mirai` |
| File name | `mbupload-orkiv9k0.bin` |
| File type | `elf` |
| First seen | `2026-10-10 22:01:33` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `27dae1cb1f64eccef00d24cd377a9c6b` |
| SHA-1 | `2a450082168d0733f13ab0187980005da45e8b1e` |
| SHA-256 | `9d9291d7e83f348872d24cbc60a7d6ef1cdbdd8f8dd214b5624c43a9cfd51aad` |
| SHA3-384 | `1713c8737bc7e10e501328505f9272549a1c1eebcb3a0fef65acbf546a056ef899f41a977f91a30495c3feee84f0b660` |
| TLSH | `T1F4B43955F8809FA1C6C12976F64D86AC331347B9C3EBB20699245B343BE786B0F3B645` |
| TELFHASH | `t1faf0e284fbb16ce4a6d280a855a1792dc5da309c53065503c6aa569eac92ed170b8433` |
| SSDEEP | `12288:aJo/zWLOZd4FNQc+z6Nv5Z0iigp11SVm:aJayLUdMNQcTfkV` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_070_9d9291d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d9291d7e83f348872d24cbc60a7d6ef1cdbdd8f8dd214b5624c43a9cfd51aad"
    family = "Mirai"
    file_name = "mbupload-orkiv9k0.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:33"
  condition:
    hash.sha256(0, filesize) == "9d9291d7e83f348872d24cbc60a7d6ef1cdbdd8f8dd214b5624c43a9cfd51aad"
}
```

### Sample 71: `9ea1f8e83c99a88d`

| Field | Value |
|---|---|
| SHA-256 | `9ea1f8e83c99a88df3c938529d76d343cca7fbb37c3948f1560a2b39da2bd4ab` |
| Family label | `Mirai` |
| File name | `mbupload-m20wvapr.bin` |
| File type | `elf` |
| First seen | `2026-10-10 22:01:18` |
| Reporter | `wristhulk` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `a861e569d9a615e9478ac609e7d44092` |
| SHA-1 | `4c07097e2271070efbe0889dd8f574ebccb8426a` |
| SHA-256 | `9ea1f8e83c99a88df3c938529d76d343cca7fbb37c3948f1560a2b39da2bd4ab` |
| SHA3-384 | `bfc1b2298a1daffcb120e3f98a7e87625ca5d5bc0fb61c8ca549861c684c59753a8c04b2cb2122127dbe9ad1801fc08a` |
| TLSH | `T1FAA4CF63F6605FD5C8224AB45CE9E2340704E2D213827681F2FE8D493C4F97ABE9E765` |
| SSDEEP | `12288:TPvspuaJEA9298QoQ3sFaoFmMQQp18lB:zMJgZHswb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_071_9ea1f8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea1f8e83c99a88df3c938529d76d343cca7fbb37c3948f1560a2b39da2bd4ab"
    family = "Mirai"
    file_name = "mbupload-m20wvapr.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:18"
  condition:
    hash.sha256(0, filesize) == "9ea1f8e83c99a88df3c938529d76d343cca7fbb37c3948f1560a2b39da2bd4ab"
}
```

### Sample 72: `de6a0b3f76eda058`

| Field | Value |
|---|---|
| SHA-256 | `de6a0b3f76eda0589d0bcd6f4308f1ba5287acd153b74d2c06af1899dabc0252` |
| Family label | `Mirai` |
| File name | `mbupload-h77j8s8j.bin` |
| File type | `elf` |
| First seen | `2026-10-10 22:01:12` |
| Reporter | `wristhulk` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `b149bb1dca9cbd1fc605528829930d46` |
| SHA-1 | `021f2d0e09a3ef97313e1d92d41cd34e53d45ac1` |
| SHA-256 | `de6a0b3f76eda0589d0bcd6f4308f1ba5287acd153b74d2c06af1899dabc0252` |
| SHA3-384 | `e19da19db9ce4587e4ab00872945713f11c56d6f549f0814a0c3cd183a02c9b2615d9224341a9db075e590cd7085b3ad` |
| TLSH | `T128A4BF46730D3EAED2B6B43BC0820B167F249F4095832F1762F5B55669631BB6F3C682` |
| SSDEEP | `12288:3D3WbyoRNC7JduJKNvmMRvhV140qlD1Ec:T3Q+Wy5VU` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_072_de6a0b3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6a0b3f76eda0589d0bcd6f4308f1ba5287acd153b74d2c06af1899dabc0252"
    family = "Mirai"
    file_name = "mbupload-h77j8s8j.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:12"
  condition:
    hash.sha256(0, filesize) == "de6a0b3f76eda0589d0bcd6f4308f1ba5287acd153b74d2c06af1899dabc0252"
}
```

### Sample 73: `729238bab5e3bb8a`

| Field | Value |
|---|---|
| SHA-256 | `729238bab5e3bb8ada801a6389cf2ebcbf1d6313d772ac20f998771248f9556f` |
| Family label | `Mirai` |
| File name | `mbupload-orkiv9k0.bin` |
| File type | `elf` |
| First seen | `2026-10-10 22:01:06` |
| Reporter | `wristhulk` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `d6063b30398eab095248a88bf74fa614` |
| SHA-1 | `15077bf1ba69ef933596a79dd5678da255452b92` |
| SHA-256 | `729238bab5e3bb8ada801a6389cf2ebcbf1d6313d772ac20f998771248f9556f` |
| SHA3-384 | `2955cc5ed384fb904143ed485c73a115fea2624666c7c1db14a902b714d5c668cce8c794e625d03847e64edb0dd84e0a` |
| TLSH | `T15404238DABD28CB5DB00CFE0FFFA62582DCF1970594E240D267DA539A37E99529D8103` |
| SSDEEP | `3072:Y1PCiOvFmoVEs4wtzF0xP25uej+1XkCrZ9eFPCZ8a0SUIk5uCNLS8UkLD:ipCFmNIOxPgNj+1XTrSFPCia0zIJCs8Z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_073_729238ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "729238bab5e3bb8ada801a6389cf2ebcbf1d6313d772ac20f998771248f9556f"
    family = "Mirai"
    file_name = "mbupload-orkiv9k0.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:06"
  condition:
    hash.sha256(0, filesize) == "729238bab5e3bb8ada801a6389cf2ebcbf1d6313d772ac20f998771248f9556f"
}
```

### Sample 74: `f4e87418b810b69c`

| Field | Value |
|---|---|
| SHA-256 | `f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c` |
| Family label | `Mirai` |
| File name | `f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:54:27` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f3bcf49f4769cb219c9f20e2e0a301b3` |
| SHA-1 | `52d1c478b17767bacb7931fc17dde7e3a13365a8` |
| SHA-256 | `f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c` |
| SHA3-384 | `f4375738c49507714a07e61125150c645f80f98ebb883253ffa166b28ec19de9be5b755421bd25ac5b2b20fd81c83f8b` |
| TLSH | `T17E941A88F1E0E7DAD2D4AA75B31C794E3B230736E1D73146E519EB3223EB1490ABD911` |
| TELFHASH | `t118f097004e745eb5d3b534cd122a3061a63e182aaa003cf09ef2314f8d2158138f3c0a` |
| SSDEEP | `6144:wdDQtx9DvstyJcPNfkFDuiQ8ZJoj7LE8c/JKveb/2qZtF5N/awf6TOh4FWyXvFJ5:KUdgty+WrQOJoiKMroTgMPa94z` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_074_f4e87418
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c"
    family = "Mirai"
    file_name = "f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:54:27"
  condition:
    hash.sha256(0, filesize) == "f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c"
}
```

### Sample 75: `0c0dd052789ca751`

| Field | Value |
|---|---|
| SHA-256 | `0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57` |
| Family label | `Mirai` |
| File name | `bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:54:19` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ef9edc71228fc9b305033561f68b124` |
| SHA-1 | `e364eea1423f9223e14c8bba9ffd714b70940844` |
| SHA-256 | `0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57` |
| SHA3-384 | `f11a31511d833aa3af89a0d838029bdc4b160f11ab83d5c74c6f04606a89435440a984150e98e36a5f3f932173460990` |
| TLSH | `T11FC43A8953B1DFDDF324DA3103736E1769B6023335D3A685E16EE92227A124C58AFE70` |
| TELFHASH | `t1a6f05e1c183823f1c3c59d5eabedff30e8a181d759662e33cd54e4aaa7319868c00d2c` |
| SSDEEP | `6144:rjZW9BCe12gt4IJGXhWMjJliK5xCvGMPshTrzbD+syjLdz7o5+Nwi2Lss6BaELw:/eteIipxU8qpjbXm6kELw` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_075_0c0dd052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
    family = "Mirai"
    file_name = "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:54:19"
  condition:
    hash.sha256(0, filesize) == "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
}
```

### Sample 76: `cbdb650d0d991d21`

| Field | Value |
|---|---|
| SHA-256 | `cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c` |
| Family label | `Mirai` |
| File name | `cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:53:49` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2c992b2c3ad2ff0629647ab11a0e55ec` |
| SHA-1 | `a27707dfc7e2ea1ee93cf1062db5f190b1fc2cdd` |
| SHA-256 | `cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c` |
| SHA3-384 | `ea8dc33f67c1ebe3cb1f2fc8716990031f72868d395c1de8637e3621c8047aab99bed8ac0abcd014ef7fcf08cdef49c8` |
| TLSH | `T134A42A44B3B1D3DBD284DE7053362B279B6A463238E7B189610EBB7313B317545DABA0` |
| SSDEEP | `6144:uOYI45egh59wgpS02YdYaVmIPP2+qcHPr65cVKgR6R03JUB5GpJNXKNzac7Fu6di:KDgWfacPKV03JCymu6dEsi` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_076_cbdb650d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c"
    family = "Mirai"
    file_name = "cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:49"
  condition:
    hash.sha256(0, filesize) == "cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c"
}
```

### Sample 77: `cb4c28fdc8a1bc56`

| Field | Value |
|---|---|
| SHA-256 | `cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a` |
| Family label | `Mirai` |
| File name | `cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:53:44` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `2a5950357dc6aa5cc2f6bbc82e2e69f4` |
| SHA-1 | `25f13ebdaf3d5fea070ff760ebc2472df7fe7907` |
| SHA-256 | `cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a` |
| SHA3-384 | `7092f2a6ce096ad8ec353fbf94369668224d2f721e35c8fc8338848888e5791d6774f3e7111605cb9168b19e7c0948e3` |
| TLSH | `T1B2942A88A2F5FBDEE296FE3983017C065C298B357883754560AEB97313B72410AFDD61` |
| SSDEEP | `6144:p+PHc7N2xQ698tV3SanKQK+qjcrck8uz5jAepvla/Ue82C:wHp98/SZ5+2crNvpe8R` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_077_cb4c28fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a"
    family = "Mirai"
    file_name = "cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:44"
  condition:
    hash.sha256(0, filesize) == "cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a"
}
```

### Sample 78: `972a8e1eb9cfa81b`

| Field | Value |
|---|---|
| SHA-256 | `972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787` |
| Family label | `Mirai` |
| File name | `972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:53:39` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1cc654021e04a45c40ada67e0bc8cd89` |
| SHA-1 | `5e0338ab82829f881d76c88bc537bf46b27c85b5` |
| SHA-256 | `972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787` |
| SHA3-384 | `2dc942a46d22c1713e1bc9b8b53de027cb071706afabcbf1facd55153922347fce43a39263308f01ef39c536b5b909ae` |
| TLSH | `T143942A88F1E0E7DAD2D4EA75B31D784E37230735E1DB3146A519AF3223EB1490ABD921` |
| TELFHASH | `t162f027a14d251de9d73b88d5719bb0761dde1c4997223ce18a56724e8e23a0128e3e00` |
| SSDEEP | `6144:M51Iy1CtG+ewsvIDFyJSc0KaIzTmTOS8te3N/+w+66Ohi7nX9vFga9Yzj3:4TMewswxyJjFsn6gIvaa9Yz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_078_972a8e1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787"
    family = "Mirai"
    file_name = "972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:39"
  condition:
    hash.sha256(0, filesize) == "972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787"
}
```

### Sample 79: `bafa2a82ec1bf371`

| Field | Value |
|---|---|
| SHA-256 | `bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49` |
| Family label | `Mirai` |
| File name | `bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:53:34` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f8949975ae2802e88746641938b4aaf1` |
| SHA-1 | `10f59921efe3a5b07d51e50dd84f5d4d2b55f702` |
| SHA-256 | `bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49` |
| SHA3-384 | `750a2bce6d7859dce8ac694c13988fdb573fca8f22077f9f088a17afdf19b1b811a575047d34b57cf8321ebed4810ac0` |
| TLSH | `T1AB04120D1420A613FF4FF4B7E06CA7502DA71325A87DC923D2197C5BC921B9A66CBCB6` |
| SSDEEP | `3072:EkIfeE+eRZkgOAXPA4nfSdqtbD2jB2oQ1MaloJWb+rR2/oNrHKwFXxPTtd9Ve:S1TZkXA3nKwtbD2j3Q4WarO+HKwFXxTy` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_079_bafa2a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49"
    family = "Mirai"
    file_name = "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:34"
  condition:
    hash.sha256(0, filesize) == "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49"
}
```

### Sample 80: `e81982006eb1a664`

| Field | Value |
|---|---|
| SHA-256 | `e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa` |
| Family label | `Mirai` |
| File name | `e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:53:29` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `1add423d29b9f4be4eec0ed0c3a6d0ca` |
| SHA-1 | `5ebbb572f360a65e5c9b0de06ba478fb345c6df3` |
| SHA-256 | `e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa` |
| SHA3-384 | `d241e7a11f98e1487e00b83a7d9fa3cd93ed2938fee02bcc9865fbcf1b94c455b74e7d23158b7c3ea50d9f65d0badbcd` |
| TLSH | `T122941A88E1E0E7DAD2D4EA75B31D794D3B230735B0D73146E51DAA3223EB1890ABED11` |
| TELFHASH | `t159f0dc05aeae11f9d7a55087423a4016e98c26046da2f8e24582b08e8b23d7364f2c1b` |
| SSDEEP | `6144:cdDbeA2WagaSuSYEqi2//CbOu1HHbIdyeXPCPQIhv/zwX3QrGeO30GoJa9Tz:UJag8SYfi2//C5IPwL2QrzZa9Tz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_080_e8198200
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa"
    family = "Mirai"
    file_name = "e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:29"
  condition:
    hash.sha256(0, filesize) == "e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa"
}
```

### Sample 81: `ee08d74477ee187a`

| Field | Value |
|---|---|
| SHA-256 | `ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f` |
| Family label | `Mirai` |
| File name | `ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f.elf` |
| File type | `elf` |
| First seen | `2026-10-10 21:53:24` |
| Reporter | `Tuxxin` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb54b8a66e7fe29cdb602edb18bb917e` |
| SHA-1 | `71b955da28d2480dad0a0cfaeaaed66dd7428053` |
| SHA-256 | `ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f` |
| SHA3-384 | `58931d5ef73350fcf13ae7bc84d8b69b48503ac925d9ffba9cadbc2b99a6b384807e96033bad829795676e100e15a2c0` |
| TLSH | `T154942A88E1E0E7DAD2D4AA75B31D790D77230735F1DB3146E519EE3223EB0890ABE911` |
| TELFHASH | `t1a3f0dc680c5ca5f4f7c4a18a6bba04503abe2d06072a15eb4e8bbd2d87061d3e0e2c07` |
| SSDEEP | `6144:5Q0CCWhRMipwpRo8JqJ5mcpptEUDNoea2eUhz5yuouOwNC5whJOlDKFva9zz:5m5oXJqLpppjbEV5GZla9zz` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_081_ee08d744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f"
    family = "Mirai"
    file_name = "ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:24"
  condition:
    hash.sha256(0, filesize) == "ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f"
}
```

### Sample 82: `db52c9367e0684de`

| Field | Value |
|---|---|
| SHA-256 | `db52c9367e0684debd435a6939d515ee7ed6becbe56fb777fd5ac36c7e9664a1` |
| Family label | `Mirai` |
| File name | `arm` |
| File type | `elf` |
| First seen | `2026-10-10 21:40:13` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `abbaac959e1b817c9167d59986d3bc4a` |
| SHA-1 | `76a01816fc5e82b269e083b59b273d8611030cce` |
| SHA-256 | `db52c9367e0684debd435a6939d515ee7ed6becbe56fb777fd5ac36c7e9664a1` |
| SHA3-384 | `cbf378290c22c61f46c759df49768cb0b995144cb179b09b66a15028e369e50ffbceb12136994b00190273a2ccafc47a` |
| TLSH | `T194932894B8419B17C6C612BBFA6E428E372623E8E2EB3217D9215F2037CB55F0D77941` |
| TELFHASH | `t1c1b0127343810bb923c64a49c4ef32450538f4fb480a2884c25478dea601b117042328` |
| SSDEEP | `1536:AGvMOjmOItNB8ny3D5wxroRiDkHonyZT3Bf4TD5v0uGupZJKvvs2Z:AGUJtkyYEETn0T32TDBf0nse` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_082_db52c936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db52c9367e0684debd435a6939d515ee7ed6becbe56fb777fd5ac36c7e9664a1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-10 21:40:13"
  condition:
    hash.sha256(0, filesize) == "db52c9367e0684debd435a6939d515ee7ed6becbe56fb777fd5ac36c7e9664a1"
}
```

### Sample 83: `aadec95fd8ed7ec1`

| Field | Value |
|---|---|
| SHA-256 | `aadec95fd8ed7ec15137b42cb3a28cc2f071ec499fd4dc9e4aa274c489e656c8` |
| Family label | `Mirai` |
| File name | `arm6` |
| File type | `elf` |
| First seen | `2026-10-10 21:31:16` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `bb5c06266b89b91bff1d16bd30ca0c77` |
| SHA-1 | `e3235a7812c8b81a9c3916bad3c242bce3bb87a0` |
| SHA-256 | `aadec95fd8ed7ec15137b42cb3a28cc2f071ec499fd4dc9e4aa274c489e656c8` |
| SHA3-384 | `13a5fc72563bdbc0884cb846605027ca1afd2254cd55769e34573bbcbd0e3b5c1acacd6a303772e78852a0c8b3b57963` |
| TLSH | `T153B33959B9818B22C5C212BAFA1E128E331357B8E3DF73179D241F6477C696B0E7B901` |
| TELFHASH | `t1dc018e55af0c5aec9be4910882ceb53d27c572a24b0a3505df09aa5f4506bd0b56903b` |
| SSDEEP | `3072:/gazwz102cpveoPaRl+UfacSAI8ywMJb:4azwz102cPPaRl+AS97Jb` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_083_aadec95f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aadec95fd8ed7ec15137b42cb3a28cc2f071ec499fd4dc9e4aa274c489e656c8"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 21:31:16"
  condition:
    hash.sha256(0, filesize) == "aadec95fd8ed7ec15137b42cb3a28cc2f071ec499fd4dc9e4aa274c489e656c8"
}
```

### Sample 84: `5898cab97f4e82f4`

| Field | Value |
|---|---|
| SHA-256 | `5898cab97f4e82f4b3fc1ded1f26c7c3451ab137dcffffeaa68e6360558ad607` |
| Family label | `unknown` |
| File name | `update.ps1` |
| File type | `ps1` |
| First seen | `2026-10-10 20:56:27` |
| Reporter | `smica83` |
| Tags | `ps1` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `41b3f3fc28d638d136c030290d30c29b` |
| SHA-1 | `cbb15747a58326f57a693d3b6d9dccbd619c70fb` |
| SHA-256 | `5898cab97f4e82f4b3fc1ded1f26c7c3451ab137dcffffeaa68e6360558ad607` |
| SHA3-384 | `7d2212307793b9e5dcc4c11361e51f8e63b298e91d8e862af75f52974f3932e9c914ed9c23cc3df482a69f01018b7f1c` |
| TLSH | `T13532B85ABF032058C6F3DBBFBCD35209EA524037898B3818B5EDD1952FB196847AD14C` |
| SSDEEP | `192:XNu4AkGDkQ4pj2qnukql7mZiIKFIx/3P+5KIQcCDP3CLiVj5I6gCYh5KIQcee:XMXKQlx6+5KIQzLMc8h5KIQE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `ps1`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_084_5898cab9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5898cab97f4e82f4b3fc1ded1f26c7c3451ab137dcffffeaa68e6360558ad607"
    family = "unknown"
    file_name = "update.ps1"
    file_type = "ps1"
    first_seen = "2026-10-10 20:56:27"
  condition:
    hash.sha256(0, filesize) == "5898cab97f4e82f4b3fc1ded1f26c7c3451ab137dcffffeaa68e6360558ad607"
}
```

### Sample 85: `b5647c0fd1277af2`

| Field | Value |
|---|---|
| SHA-256 | `b5647c0fd1277af2013a25e1f741c742edb64ddd33fcec597855798001bbc02d` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnsh2xnxn` |
| File type | `elf` |
| First seen | `2026-10-10 20:53:10` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8efe1391fa674fa2ad46c91823d2747b` |
| SHA-1 | `d150a43e879fcae48d0d31a90b66bcb07fb68324` |
| SHA-256 | `b5647c0fd1277af2013a25e1f741c742edb64ddd33fcec597855798001bbc02d` |
| SHA3-384 | `af6642d58aa632d764e59ad8297fa49991ceec2b72977be787acfed676210819d634e13a8e8e25fffec85e99bef5e916` |
| TLSH | `T1A3D3C021E4006DD1EC2129F578BA96BC0350EE700BDE1586EFFDE95E747BD98386D2A0` |
| SSDEEP | `3072:PHiBTNkAgcly+hoVpE6AKUjq+8biA7JBd/x+:PCdny+hovsmzbisJfY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_085_b5647c0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5647c0fd1277af2013a25e1f741c742edb64ddd33fcec597855798001bbc02d"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnsh2xnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:53:10"
  condition:
    hash.sha256(0, filesize) == "b5647c0fd1277af2013a25e1f741c742edb64ddd33fcec597855798001bbc02d"
}
```

### Sample 86: `994becb3008d8dac`

| Field | Value |
|---|---|
| SHA-256 | `994becb3008d8dacd064bf699bd2acb55b59e213143451f67b808edc261c4511` |
| Family label | `unknown` |
| File name | `HARMAN_TRANSPORT_USA_SETUP.cmd` |
| File type | `cmd` |
| First seen | `2026-10-10 20:49:02` |
| Reporter | `smica83` |
| Tags | `cmd` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `eff614fa1086367c5fbec7216b6fe93e` |
| SHA-1 | `d226f48b835103d4056fa94365ed1563d6d32721` |
| SHA-256 | `994becb3008d8dacd064bf699bd2acb55b59e213143451f67b808edc261c4511` |
| SHA3-384 | `370d1320145ad3cee444dea0cfa8bfed7feebe92fc2d8055d13549f9178305ccdc652c3e3eb41be67b268e2b277b8a13` |
| TLSH | `T112E12A5F52432735DE610734EEDC2816BF1C217519521680BA3E3BEE2B344A9A1B90FD` |
| SSDEEP | `96:wAKpq18Vvc4kGppXucO/Q4/KyWuRcAIDnTJHAK+B5yB+B81kX7foppsEPCIWiT:veDPXLO/Q4bWo0DnJ+WB+q67ABPCJ2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_086_994becb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994becb3008d8dacd064bf699bd2acb55b59e213143451f67b808edc261c4511"
    family = "unknown"
    file_name = "HARMAN_TRANSPORT_USA_SETUP.cmd"
    file_type = "cmd"
    first_seen = "2026-10-10 20:49:02"
  condition:
    hash.sha256(0, filesize) == "994becb3008d8dacd064bf699bd2acb55b59e213143451f67b808edc261c4511"
}
```

### Sample 87: `b59d9c911f11ddbe`

| Field | Value |
|---|---|
| SHA-256 | `b59d9c911f11ddbe5ac0cd7e2e6e311093a44ac31453b5cab801c31f6a170750` |
| Family label | `unknown` |
| File name | `Putty-x86_64.msi` |
| File type | `msi` |
| First seen | `2026-10-10 20:25:11` |
| Reporter | `SquiblydooBlog` |
| Tags | `msi, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0bf25ea6ad85a2552f50be59a69834e0` |
| SHA-1 | `ad640a34f29d203108c50f81817341eb294f6676` |
| SHA-256 | `b59d9c911f11ddbe5ac0cd7e2e6e311093a44ac31453b5cab801c31f6a170750` |
| SHA3-384 | `4864019521944eb4f57b62f560367623fcec972898a6ce334de68a6c3cbd70364a84b992d7d7dbf1eab18b11a2d2635a` |
| TLSH | `T1372533116B1073B1CD810FB24BA4C4533FA43D22DF99A86E213877BE6F726C25A566D2` |
| SSDEEP | `24576:NCu0HZ6ggLV7urqnxpnI/i0eGmGFoKpHXpwCiP57lR1:EkJuMQ6RGxXC91` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `msi`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_087_b59d9c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59d9c911f11ddbe5ac0cd7e2e6e311093a44ac31453b5cab801c31f6a170750"
    family = "unknown"
    file_name = "Putty-x86_64.msi"
    file_type = "msi"
    first_seen = "2026-10-10 20:25:11"
  condition:
    hash.sha256(0, filesize) == "b59d9c911f11ddbe5ac0cd7e2e6e311093a44ac31453b5cab801c31f6a170750"
}
```

### Sample 88: `5f8e4e776f1c5c38`

| Field | Value |
|---|---|
| SHA-256 | `5f8e4e776f1c5c38570718c50c67c66629648b0b265629acf144dc978e7f7b6a` |
| Family label | `unknown` |
| File name | `vnKMZWYyX.zip` |
| File type | `zip` |
| First seen | `2026-10-10 20:16:42` |
| Reporter | `DoberGroup` |
| Tags | `.NET, LOLBIN, MSBuild, MSIL, zip` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e5b6b04533e25027dab41c779c219bb8` |
| SHA-1 | `2d4d044fb51aa7a19097a1590c3e7e6d87859f2b` |
| SHA-256 | `5f8e4e776f1c5c38570718c50c67c66629648b0b265629acf144dc978e7f7b6a` |
| SHA3-384 | `05108113fae437c8aee8effe9b40904095815a41079a702a338cb3f6b1c1a41e3260acb98689b420dd029dd4a7bf990a` |
| TLSH | `T1F5F6337446D1926BBA73A41347928B7004C5A7DF1AFBEEC8EA9F4630E95C2CF107498D` |
| SSDEEP | `393216:SDjyYCEwKRpoO2DyH0lObqKbQD8JGOXNzOAt/UySJZBUdX8:+yYlwKRpoOmyHJuKEzOlOAdSJZ5` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `zip`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_088_5f8e4e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f8e4e776f1c5c38570718c50c67c66629648b0b265629acf144dc978e7f7b6a"
    family = "unknown"
    file_name = "vnKMZWYyX.zip"
    file_type = "zip"
    first_seen = "2026-10-10 20:16:42"
  condition:
    hash.sha256(0, filesize) == "5f8e4e776f1c5c38570718c50c67c66629648b0b265629acf144dc978e7f7b6a"
}
```

### Sample 89: `aef5338244d62e70`

| Field | Value |
|---|---|
| SHA-256 | `aef5338244d62e701ae13b668e784dd5029b949bcc2bdd6fc27beafbf58009f1` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmicroblazexnxn` |
| File type | `elf` |
| First seen | `2026-10-10 20:13:08` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `4c8078a615f6c70c47cb9b7b611b5031` |
| SHA-1 | `288de59a26967a01461f40c1419905f06579a020` |
| SHA-256 | `aef5338244d62e701ae13b668e784dd5029b949bcc2bdd6fc27beafbf58009f1` |
| SHA3-384 | `506e8edb0fa7d45bf38f3f55ae8c919c7d794bfd6df34dccfc670b0df9b2e342cbe015ae24872ec0da299a3e7826cc21` |
| TLSH | `T18C148120FA0663B1CC731A34A79A2E5A6E7704559FEB26312D1F533CDE628509B31F8D` |
| SSDEEP | `3072:BcHZcggFy1tJmajThwnKBDMOzsjJjL1lCR/UKG:BcYFAJ9/hjzsdjymf` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_089_aef53382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aef5338244d62e701ae13b668e784dd5029b949bcc2bdd6fc27beafbf58009f1"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmicroblazexnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:13:08"
  condition:
    hash.sha256(0, filesize) == "aef5338244d62e701ae13b668e784dd5029b949bcc2bdd6fc27beafbf58009f1"
}
```

### Sample 90: `1b2432c99b877ac7`

| Field | Value |
|---|---|
| SHA-256 | `1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71` |
| Family label | `unknown` |
| File name | `PLCleaner.exe` |
| File type | `exe` |
| First seen | `2026-10-10 20:05:58` |
| Reporter | `SquiblydooBlog` |
| Tags | `exe, signed` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `0a2c662438a6f3e2bad32220cb38dc36` |
| SHA-1 | `d69176cfcd109fc8714ffb6184428fcff44bf802` |
| SHA-256 | `1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71` |
| SHA3-384 | `a40191efe4e9e0a3c37210c14ef31673558f216f3ea41a6a90abf8a75aa47e338e50aad1938c2c4739f07d65c499d290` |
| IMPHASH | `d61098bb34ea41207b7b575f9f5f033b` |
| TLSH | `T1A0A6BE21F149CC2BE1ED15BC1D189F5AC238AD262B6180E772FE7B5E57764C23236B12` |
| SSDEEP | `196608:AxR5WgSinvc5qFOW6CpGqzmpTn/7LqVrdFEMNTpkQ93hrCIr:AxR5WgSinkkOW6CpGqkn/7grdiMDR3ht` |
| ICON-DHASH | `6d6de9c7b1b0a2c0` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `exe`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_090_1b2432c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71"
    family = "unknown"
    file_name = "PLCleaner.exe"
    file_type = "exe"
    first_seen = "2026-10-10 20:05:58"
  condition:
    hash.sha256(0, filesize) == "1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71"
}
```

### Sample 91: `51c51da7a6c6e3f2`

| Field | Value |
|---|---|
| SHA-256 | `51c51da7a6c6e3f26caf4508389ce7da0b23ac35a7f4a163394f778b33c7c341` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnriscv32xnxn` |
| File type | `elf` |
| First seen | `2026-10-10 20:04:07` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `e2c4f6bf7b6ddfc2c2c31cec22574327` |
| SHA-1 | `9bf26cbdc6c61ac37d71a2fa42a431c5d3afc46a` |
| SHA-256 | `51c51da7a6c6e3f26caf4508389ce7da0b23ac35a7f4a163394f778b33c7c341` |
| SHA3-384 | `af140253b274a321c9651fbc0b1bca02115fdce93f6588fbff7eb52973370a5b1c0ced9d6aaef2887d5f05562c218daa` |
| TLSH | `T1B4C3F185BB236991D0A342FDA4C00AC387912E318BE213080699F774387DDFB1F69DE9` |
| SSDEEP | `3072:SBdQK+TG2nIjnRdZaUXUSgkLCCVwHWiEiBtbMMTnD:eMQRtXU9kLCP8ifbxTnD` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_091_51c51da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c51da7a6c6e3f26caf4508389ce7da0b23ac35a7f4a163394f778b33c7c341"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnriscv32xnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:04:07"
  condition:
    hash.sha256(0, filesize) == "51c51da7a6c6e3f26caf4508389ce7da0b23ac35a7f4a163394f778b33c7c341"
}
```

### Sample 92: `2fb29f7b8d2c02d9`

| Field | Value |
|---|---|
| SHA-256 | `2fb29f7b8d2c02d956f1e1e1fc7eb26789130b80ae1ec06f9b04cc5bc56f06f2` |
| Family label | `unknown` |
| File name | `Verginia.cmd` |
| File type | `cmd` |
| First seen | `2026-10-10 20:02:23` |
| Reporter | `smica83` |
| Tags | `cmd` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `26ca10cdd07b4824c4bbdf39aed2ef06` |
| SHA-1 | `5485e797c944f9349098cee573850bf5fdd0e163` |
| SHA-256 | `2fb29f7b8d2c02d956f1e1e1fc7eb26789130b80ae1ec06f9b04cc5bc56f06f2` |
| SHA3-384 | `4ef7de779448f6d8e14c15a1dccdbd019072191a5be4fa07dea689b29dafe3877386740554726b1476093ecddcf97589` |
| TLSH | `T1D7D36F4C6D853C4F46E19265F3AA7BFF26D8E3FBF6D7028D28056E0402A6688D1CD45B` |
| SSDEEP | `3072:aiKy02VvSV+xrtoYLdJu1M1EdX7As+osIejtLZ85ZJO6:BhSV+xtbLdiM1EwXsJO6` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `cmd`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_092_2fb29f7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb29f7b8d2c02d956f1e1e1fc7eb26789130b80ae1ec06f9b04cc5bc56f06f2"
    family = "unknown"
    file_name = "Verginia.cmd"
    file_type = "cmd"
    first_seen = "2026-10-10 20:02:23"
  condition:
    hash.sha256(0, filesize) == "2fb29f7b8d2c02d956f1e1e1fc7eb26789130b80ae1ec06f9b04cc5bc56f06f2"
}
```

### Sample 93: `0866f7b0c7ec4002`

| Field | Value |
|---|---|
| SHA-256 | `0866f7b0c7ec400279e908add084bab581faf3dd831a468430dcfc03b23e9399` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmipsxnxn` |
| File type | `elf` |
| First seen | `2026-10-10 20:00:37` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `f1a2dc529695a009b9d2dd168ee2c4a7` |
| SHA-1 | `e0f1caa6b6a0b1603b4696d255abacf03b51629c` |
| SHA-256 | `0866f7b0c7ec400279e908add084bab581faf3dd831a468430dcfc03b23e9399` |
| SHA3-384 | `d681312ed29f838d996ffcfa08bdfb15d907b0af0a8625373e41c90e244754398130f5d8eb5d88d4a9dc7cbb7d4ad242` |
| TLSH | `T161F33C47B7208FB1C368D67009B3CB67A6E6269216E19985E76DCD107A3075C6C3FFA0` |
| TELFHASH | `t1d9c002145c7457f15108dd5540dc7f29c5f51dcf15431d1fd9183c654631d831f00d59` |
| SSDEEP | `3072:o3VJgzikZXyrNo/tqTHmnsHgCtEUQW0l/1wLxpvEcJz3nVfau:oFJMZBtqCnFCtE1R1WpvD9T` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_093_0866f7b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0866f7b0c7ec400279e908add084bab581faf3dd831a468430dcfc03b23e9399"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:00:37"
  condition:
    hash.sha256(0, filesize) == "0866f7b0c7ec400279e908add084bab581faf3dd831a468430dcfc03b23e9399"
}
```

### Sample 94: `210ba30c11352f4e`

| Field | Value |
|---|---|
| SHA-256 | `210ba30c11352f4e5b2c2d533b92de16b606a17dfb53ef98888554f29773c3af` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnmipsxnxn` |
| File type | `elf` |
| First seen | `2026-10-10 19:59:26` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `dfb85ff35a6a433f8816ba36912b2acf` |
| SHA-1 | `e4fde5bcbed6c8473b1715020f597fbbe6fb0daa` |
| SHA-256 | `210ba30c11352f4e5b2c2d533b92de16b606a17dfb53ef98888554f29773c3af` |
| SHA3-384 | `3c280c633debbf6f917d60e5e446bd486a3bfde7cba796d695308d4245a009755e2a8a89f8befd14356cb6a2d8f35d23` |
| TLSH | `T1C973022B914F0BB3D0E9ED33B0077F346B79B123E8F93B09F8519055A529DB25244A7A` |
| SSDEEP | `1536:rOlDJ9nqHLw+ZQeuFvQfPbYGiNw7VI/rW0wvnEJ3gzE94e/oh0bor1:ypn40+ZsvaTYbeO/VwP/zE99/oh0bS1` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_094_210ba30c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "210ba30c11352f4e5b2c2d533b92de16b606a17dfb53ef98888554f29773c3af"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:59:26"
  condition:
    hash.sha256(0, filesize) == "210ba30c11352f4e5b2c2d533b92de16b606a17dfb53ef98888554f29773c3af"
}
```

### Sample 95: `2858601dd1f5c353`

| Field | Value |
|---|---|
| SHA-256 | `2858601dd1f5c353ddebab879bec97d8d6e6d8c7199866127f301bc2d8d9e2e5` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnpowerpcxnxn` |
| File type | `elf` |
| First seen | `2026-10-10 19:50:28` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai, upx-dec` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `72d357fcf4130025ad93bb070dc4ff4d` |
| SHA-1 | `d29267fb5b0569682584c99da30e7ccb9fe0e95d` |
| SHA-256 | `2858601dd1f5c353ddebab879bec97d8d6e6d8c7199866127f301bc2d8d9e2e5` |
| SHA3-384 | `28b7772f53d014477d9ce8e0fcbf1ab005de4b54d09fc640428261f6e43de5e9d8eb96d35b5c3ac4f5263407b6261e9a` |
| TLSH | `T135144911FB0C0463CA931CF48E3F0BFAA3621A9115F99115250D7F5A1A32DB7A68BFD9` |
| SSDEEP | `3072:ty5+GoCEggi4NerYqltSwJpH6+cYstkfUat:o5H5BT48rYq1wjY2vY` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_095_2858601d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2858601dd1f5c353ddebab879bec97d8d6e6d8c7199866127f301bc2d8d9e2e5"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:50:28"
  condition:
    hash.sha256(0, filesize) == "2858601dd1f5c353ddebab879bec97d8d6e6d8c7199866127f301bc2d8d9e2e5"
}
```

### Sample 96: `4c2c641b63e14858`

| Field | Value |
|---|---|
| SHA-256 | `4c2c641b63e1485831e217b554a984a0a75c6f433fcb5edf3c94fa7a04a37519` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnpowerpcxnxn` |
| File type | `elf` |
| First seen | `2026-10-10 19:49:36` |
| Reporter | `abuse_ch` |
| Tags | `elf, upx` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8e0c91a6a83ebf6b0acac001b4f8afdc` |
| SHA-1 | `c00fb2cc3bbc6c0bbb0a7a46fc5d33963c3cd8ae` |
| SHA-256 | `4c2c641b63e1485831e217b554a984a0a75c6f433fcb5edf3c94fa7a04a37519` |
| SHA3-384 | `42c0767ed04e3947b4583a13ca3e8a521062ceabca01fcffcd4a87213f5142fd278749eb9b7988514bd940791dec4657` |
| TLSH | `T1766302B832EFC434E0DDB932164F22307331DA56A46B13ED3A8AB5D8E2665940917F68` |
| SSDEEP | `1536:hltrI7mDmde7Lletk8cghgLFPjihgulh6DoIO5hrPG:hl+YmdkLMk8c5PdulIOHrPG` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_096_4c2c641b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c2c641b63e1485831e217b554a984a0a75c6f433fcb5edf3c94fa7a04a37519"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:49:36"
  condition:
    hash.sha256(0, filesize) == "4c2c641b63e1485831e217b554a984a0a75c6f433fcb5edf3c94fa7a04a37519"
}
```

### Sample 97: `a3ee0e8d50872381`

| Field | Value |
|---|---|
| SHA-256 | `a3ee0e8d50872381618ffc45e809ac950d5005fd5e2e5e2e1c2d87e52d3ec5e1` |
| Family label | `Mirai` |
| File name | `xnxnxnxnxnxnxnxnm68kxnxn` |
| File type | `elf` |
| First seen | `2026-10-10 19:49:34` |
| Reporter | `abuse_ch` |
| Tags | `elf, Gafgyt, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `8d7d1584db2c43e8182357fb2438b2a8` |
| SHA-1 | `e6c185492ef2700de417464a096d01688d68358e` |
| SHA-256 | `a3ee0e8d50872381618ffc45e809ac950d5005fd5e2e5e2e1c2d87e52d3ec5e1` |
| SHA3-384 | `a68ad6eb2cf5d57c0c06853a9787be866e8eb746e9024adead94c9d6181a4dd7ab1ef4fcaf229456bca25f088d808949` |
| TLSH | `T1CCB3BF87B2907ABEF0A45E3FC4135E26A6259F705583273D71BDF9906E3A3503292E42` |
| SSDEEP | `1536:toOxCg+uUGWkCqYUqwaJ1XqfXg5AcS5blaZeCtjHXNLdCS2T15OvhSkzI8rSx:t1xKlGWnqTUcXgZS5gZ7CSXhSBUSx` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_097_a3ee0e8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3ee0e8d50872381618ffc45e809ac950d5005fd5e2e5e2e1c2d87e52d3ec5e1"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnm68kxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:49:34"
  condition:
    hash.sha256(0, filesize) == "a3ee0e8d50872381618ffc45e809ac950d5005fd5e2e5e2e1c2d87e52d3ec5e1"
}
```

### Sample 98: `458195a5ae155997`

| Field | Value |
|---|---|
| SHA-256 | `458195a5ae155997cda578ceb12959b271027e6e23e87b5033d777ff09c44ce3` |
| Family label | `unknown` |
| File name | `armv7l` |
| File type | `elf` |
| First seen | `2026-10-10 19:49:32` |
| Reporter | `abuse_ch` |
| Tags | `elf` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6ac042f7fe8104d34cc3adf18f67bb33` |
| SHA-1 | `7f379a248e180a2fe3f1b8c027ed1993636301ce` |
| SHA-256 | `458195a5ae155997cda578ceb12959b271027e6e23e87b5033d777ff09c44ce3` |
| SHA3-384 | `07f096ff6a6c8867ed62a5940fba0ecc1f5096e28a6c126c671c536a9bb88b53b39eff14f6aee04c3a65be09e860b37f` |
| TLSH | `T190761957B8924942C4E43A37B8BE81C432634EBA8BC7125B6D15FE383EBE5D90E35744` |
| TELFHASH | `t1b9d01285ce5c53dc62d7546a050406189ab176ed4d20b958de8eb7af1d02481f08e021` |
| GIMPHASH | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| SSDEEP | `49152:1hjG7NR4KEyCbZ0GENsNhsmmMKau7DYBJtTpiB+MuS5E2:1s7QKEyCbZ0GENsg7UJtdiB+2E2` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_098_458195a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "458195a5ae155997cda578ceb12959b271027e6e23e87b5033d777ff09c44ce3"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 19:49:32"
  condition:
    hash.sha256(0, filesize) == "458195a5ae155997cda578ceb12959b271027e6e23e87b5033d777ff09c44ce3"
}
```

### Sample 99: `580f37844785d2f6`

| Field | Value |
|---|---|
| SHA-256 | `580f37844785d2f631a22026d8bc8b1ff903b2b8a5fe1800dc0d431923112afc` |
| Family label | `unknown` |
| File name | `payload.bat` |
| File type | `bat` |
| First seen | `2026-10-10 19:46:17` |
| Reporter | `smica83` |
| Tags | `bat` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `85a030c2d119e585862280aaa69dd079` |
| SHA-1 | `8a72bbedfbd2cadbc4dcc87c6a990af1f83e0833` |
| SHA-256 | `580f37844785d2f631a22026d8bc8b1ff903b2b8a5fe1800dc0d431923112afc` |
| SHA3-384 | `d33c7b25f33ef3ef00e38fc4c51a68acd7f5c492430dc9ace33f232051a26ee09e72410c3b385de7b115bbc5d684e366` |
| TLSH | `T132D1759AAF063E944FDE5F8E1A8D75C2348E2B8F10615D7F110FB6238A150E26CDF065` |
| SSDEEP | `96:NArCPNW9oT+8rQoM8e5hPubxPtRuKFtsxnYLkX4Gj7a6j:sC0PnubPRV2Y+mE` |

#### Technical Assessment

- The sample is tracked as `unknown` by MalwareBazaar metadata.
- The observed artifact type is `bat`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_unknown_099_580f3784
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "580f37844785d2f631a22026d8bc8b1ff903b2b8a5fe1800dc0d431923112afc"
    family = "unknown"
    file_name = "payload.bat"
    file_type = "bat"
    first_seen = "2026-10-10 19:46:17"
  condition:
    hash.sha256(0, filesize) == "580f37844785d2f631a22026d8bc8b1ff903b2b8a5fe1800dc0d431923112afc"
}
```

### Sample 100: `679c506907266a9c`

| Field | Value |
|---|---|
| SHA-256 | `679c506907266a9c45436c9eca86359e07b1626a933c927f0bb9a5cd429692e6` |
| Family label | `Mirai` |
| File name | `m68k` |
| File type | `elf` |
| First seen | `2026-10-10 19:39:27` |
| Reporter | `abuse_ch` |
| Tags | `elf, Mirai` |

#### Per-Sample IOC Table

| Type | Value |
|---|---|
| MD5 | `6b7a73d794cdd1565b89fbed9ab97421` |
| SHA-1 | `8588c5754bf4019a21c1f460f4e90cfefca6e156` |
| SHA-256 | `679c506907266a9c45436c9eca86359e07b1626a933c927f0bb9a5cd429692e6` |
| SHA3-384 | `289984b00ab2c4de52b6cf416fd8a67ea50c5952926191203fa952e452cbf62c507e971277f5a25b7d7d5c58cb64d4bd` |
| TLSH | `T12FA35E97F401EEBDF80BD5BA04674A0AF630E3E11B930B366397BD57ED351A50826E81` |
| SSDEEP | `1536:iPhR5NHVp0DbRfIzpBN8H9/oRLfZAufjW1t0NPtwCkm+:ipRD2bipBsKLhzvNPtwCkm+` |

#### Technical Assessment

- The sample is tracked as `Mirai` by MalwareBazaar metadata.
- The observed artifact type is `elf`; analysis here is limited to metadata and hash IOCs.
- No behavior, capability, persistence, or C2 claims are made without static source/byte features.
- Use the hash indicators for exact-match triage, enrichment, and known-sample hunting.

#### Sample YARA Rule

```yara
rule MalwareBazaar_Mirai_100_679c5069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679c506907266a9c45436c9eca86359e07b1626a933c927f0bb9a5cd429692e6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-10 19:39:27"
  condition:
    hash.sha256(0, filesize) == "679c506907266a9c45436c9eca86359e07b1626a933c927f0bb9a5cd429692e6"
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
 * Generated: 2026-10-11T05:58:53.139474+00:00
 */

rule MalwareBazaar_unknown_001_62c1694d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "62c1694d0d13e66958e9cbdadbc113406ac78b00f72ed928773d68ec28c60648"
    family = "unknown"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-11 05:58:33"
  condition:
    hash.sha256(0, filesize) == "62c1694d0d13e66958e9cbdadbc113406ac78b00f72ed928773d68ec28c60648"
}

rule MalwareBazaar_Mirai_002_7f4745b9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7f4745b9eca5fcafcb5e6d291a7d9eb4730bc0f36f88c20e1906de6ef0f829b3"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-11 05:54:35"
  condition:
    hash.sha256(0, filesize) == "7f4745b9eca5fcafcb5e6d291a7d9eb4730bc0f36f88c20e1906de6ef0f829b3"
}

rule MalwareBazaar_Mirai_003_63344852
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "633448526c55c23344eff36f102afe7ab443da3a24c6a1e81110324c0236484e"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-11 05:50:41"
  condition:
    hash.sha256(0, filesize) == "633448526c55c23344eff36f102afe7ab443da3a24c6a1e81110324c0236484e"
}

rule MalwareBazaar_Mirai_004_29d3de06
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "29d3de066fcbb6c387b7ccbdd85146b8f28499ab98f699afb35904a28435593a"
    family = "Mirai"
    file_name = "jklarm5"
    file_type = "elf"
    first_seen = "2026-10-11 05:46:40"
  condition:
    hash.sha256(0, filesize) == "29d3de066fcbb6c387b7ccbdd85146b8f28499ab98f699afb35904a28435593a"
}

rule MalwareBazaar_AsyncRAT_005_c11464f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb"
    family = "AsyncRAT"
    file_name = "c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb.exe"
    file_type = "exe"
    first_seen = "2026-10-11 05:40:06"
  condition:
    hash.sha256(0, filesize) == "c11464f548d27189b733bfb8ecca375d91bf5550b7b51a3962554ab4e74831cb"
}

rule MalwareBazaar_QuasarRAT_006_329706c1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde"
    family = "QuasarRAT"
    file_name = "329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde.exe"
    file_type = "exe"
    first_seen = "2026-10-11 05:32:48"
  condition:
    hash.sha256(0, filesize) == "329706c148a26631625f413212a3a09a0c2fbdab23c6ab5f4ba671101a15ecde"
}

rule MalwareBazaar_Mirai_007_3ab04017
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3ab040178b1408c32f7977fa70dc3e2451d5744caa6e23707457080fe4a550f6"
    family = "Mirai"
    file_name = "spc"
    file_type = "elf"
    first_seen = "2026-10-11 05:30:40"
  condition:
    hash.sha256(0, filesize) == "3ab040178b1408c32f7977fa70dc3e2451d5744caa6e23707457080fe4a550f6"
}

rule MalwareBazaar_unknown_008_1d2788e4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a"
    family = "unknown"
    file_name = "1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a"
    file_type = "apk"
    first_seen = "2026-10-11 05:30:10"
  condition:
    hash.sha256(0, filesize) == "1d2788e48a5f27ac18a57fe4cff158c5439a530ce9468d654248c90ff94e944a"
}

rule MalwareBazaar_unknown_009_f4d3adaf
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4d3adaf236a38bb28ea7b4c3139aa501ff60d81896d9e4ea6ae2781857cfdca"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-11 05:22:52"
  condition:
    hash.sha256(0, filesize) == "f4d3adaf236a38bb28ea7b4c3139aa501ff60d81896d9e4ea6ae2781857cfdca"
}

rule MalwareBazaar_CoinMiner_010_e9ba70f1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e9ba70f1edc3f1f31406ecc5e2d02efc2a7a7fa1088b518dacff89d9e10a7933"
    family = "CoinMiner"
    file_name = "file"
    file_type = "exe"
    first_seen = "2026-10-11 05:02:20"
  condition:
    hash.sha256(0, filesize) == "e9ba70f1edc3f1f31406ecc5e2d02efc2a7a7fa1088b518dacff89d9e10a7933"
}

rule MalwareBazaar_QuasarRAT_011_af5b59d2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5"
    family = "QuasarRAT"
    file_name = "af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5.exe"
    file_type = "exe"
    first_seen = "2026-10-11 05:02:10"
  condition:
    hash.sha256(0, filesize) == "af5b59d2c3af86ee2d97b9bb459dec7b83e5033cfc9b53fb319dbcdddb79e5d5"
}

rule MalwareBazaar_unknown_012_d0f2273f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229"
    family = "unknown"
    file_name = "zblob_0951894_d0f2273f.bin"
    file_type = "exe"
    first_seen = "2026-10-11 04:40:17"
  condition:
    hash.sha256(0, filesize) == "d0f2273f828b10391adcf877ff0775924e4b63435ec240b1047d89a1fa95a229"
}

rule MalwareBazaar_Mirai_013_5f924d5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321"
    family = "Mirai"
    file_name = "dissarm7"
    file_type = "elf"
    first_seen = "2026-10-11 04:21:51"
  condition:
    hash.sha256(0, filesize) == "5f924d5b8e190ee9022fc821ee30bfbc0d91c7c8a96bac1a8d2cefc1c3878321"
}

rule MalwareBazaar_QuasarRAT_014_92a4bdc9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480"
    family = "QuasarRAT"
    file_name = "92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480.exe"
    file_type = "exe"
    first_seen = "2026-10-11 04:21:09"
  condition:
    hash.sha256(0, filesize) == "92a4bdc95e0d99200c7e703b2739ffdc1c0dd6b974bd4e97a375ad5a09b1e480"
}

rule MalwareBazaar_Mirai_015_093e027a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581"
    family = "Mirai"
    file_name = "jklarm6"
    file_type = "elf"
    first_seen = "2026-10-11 04:17:46"
  condition:
    hash.sha256(0, filesize) == "093e027a709e90916e7a15076711c5a07674b2a29f742632e4e2b3a85c2de581"
}

rule MalwareBazaar_unknown_016_85dfe92b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9"
    family = "unknown"
    file_name = "85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9.exe.bin"
    file_type = "exe"
    first_seen = "2026-10-11 04:11:18"
  condition:
    hash.sha256(0, filesize) == "85dfe92b43734f2573a30e0f295a602111cbcecffc8260534a2f41386a6025d9"
}

rule MalwareBazaar_unknown_017_1b937dba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b937dbaa72bc5d6196d45559037182ccf8ab038d4f4f45592b40630af40bfc6"
    family = "unknown"
    file_name = "setup.exe"
    file_type = "exe"
    first_seen = "2026-10-11 03:59:48"
  condition:
    hash.sha256(0, filesize) == "1b937dbaa72bc5d6196d45559037182ccf8ab038d4f4f45592b40630af40bfc6"
}

rule MalwareBazaar_VShell_018_a9fc1e7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a9fc1e7b49f06d3d5161c78da1821de4849de3a9994955e0c9660d14e7031220"
    family = "VShell"
    file_name = "inner-dll-a9fc1e7b.bin"
    file_type = "dll"
    first_seen = "2026-10-11 02:43:46"
  condition:
    hash.sha256(0, filesize) == "a9fc1e7b49f06d3d5161c78da1821de4849de3a9994955e0c9660d14e7031220"
}

rule MalwareBazaar_VShell_019_cc849739
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5"
    family = "VShell"
    file_name = "cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5.bin"
    file_type = "exe"
    first_seen = "2026-10-11 02:43:38"
  condition:
    hash.sha256(0, filesize) == "cc84973917d7089aa43eab0b5307b1bb052da6c68931be0ba20444a9ae84d9d5"
}

rule MalwareBazaar_VShell_020_eec3cf8a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028"
    family = "VShell"
    file_name = "eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028.bin"
    file_type = "dll"
    first_seen = "2026-10-11 02:43:29"
  condition:
    hash.sha256(0, filesize) == "eec3cf8a0e22c37a3f3faa406d01d5a3d39dedc15de1b60a9947764f1c02d028"
}

rule MalwareBazaar_VShell_021_9697dead
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0"
    family = "VShell"
    file_name = "9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0.bin"
    file_type = "exe"
    first_seen = "2026-10-11 02:43:18"
  condition:
    hash.sha256(0, filesize) == "9697dead9eada8f60adf9a7855c8bdf1468f151ebf91089acb1c4bcb52b26aa0"
}

rule MalwareBazaar_AsyncRAT_022_2a0bc1ef
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a"
    family = "AsyncRAT"
    file_name = "2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a.exe"
    file_type = "exe"
    first_seen = "2026-10-11 02:35:53"
  condition:
    hash.sha256(0, filesize) == "2a0bc1efd509f72273c3f9e3143a3f108edfa4d33dc9c1ba4a86ce362deea86a"
}

rule MalwareBazaar_unknown_023_f1692afd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1692afdc0662c3448563ba69eb6052b27d0981d48d3400c1d5bfaa5a339e0b1"
    family = "unknown"
    file_name = "2026-10-10_cb69d574039e35b0fc6dbaf611212acc_elex_wannacry"
    file_type = "exe"
    first_seen = "2026-10-11 02:13:59"
  condition:
    hash.sha256(0, filesize) == "f1692afdc0662c3448563ba69eb6052b27d0981d48d3400c1d5bfaa5a339e0b1"
}

rule MalwareBazaar_Mirai_024_47fa5cd9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e"
    family = "Mirai"
    file_name = "dissmips"
    file_type = "elf"
    first_seen = "2026-10-11 02:01:37"
  condition:
    hash.sha256(0, filesize) == "47fa5cd944239c76582ab0956582fef2367a33392d02bbd10535edc012cd9c2e"
}

rule MalwareBazaar_Mirai_025_ddaadef1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755"
    family = "Mirai"
    file_name = "ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755"
    file_type = "elf"
    first_seen = "2026-10-11 01:59:29"
  condition:
    hash.sha256(0, filesize) == "ddaadef14a9fd7036b92e9e941c9bfd965eaa7a616fcf11f1d20cce72e745755"
}

rule MalwareBazaar_Mirai_026_ba268ec9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a"
    family = "Mirai"
    file_name = "android-arm64"
    file_type = "elf"
    first_seen = "2026-10-11 01:57:36"
  condition:
    hash.sha256(0, filesize) == "ba268ec991a555c7e30325c4d88102c174d56657422b0ace511fa153658e803a"
}

rule MalwareBazaar_Mirai_027_102bfe85
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-11 01:37:34"
  condition:
    hash.sha256(0, filesize) == "102bfe850243f122aa9bf9066c113d1832b7bec6547de230e5f084da5ef8121b"
}

rule MalwareBazaar_Mirai_028_81da78f5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "81da78f52b2a92eb67e5490d8b296be00f3a253c71850b267138949ce2d50f73"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-11 01:26:17"
  condition:
    hash.sha256(0, filesize) == "81da78f52b2a92eb67e5490d8b296be00f3a253c71850b267138949ce2d50f73"
}

rule MalwareBazaar_Mirai_029_7acedfec
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7acedfec70eabc61d8cd2ad45d6258d9473f52aaf47e1719f4f5ccfe93f01105"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-11 01:25:43"
  condition:
    hash.sha256(0, filesize) == "7acedfec70eabc61d8cd2ad45d6258d9473f52aaf47e1719f4f5ccfe93f01105"
}

rule MalwareBazaar_Mirai_030_dda6f0c5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "dda6f0c518eb6e05eb68164000a1881c1790f346a9027c9b7fb7c9b1b89f247c"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-11 01:21:39"
  condition:
    hash.sha256(0, filesize) == "dda6f0c518eb6e05eb68164000a1881c1790f346a9027c9b7fb7c9b1b89f247c"
}

rule MalwareBazaar_Mirai_031_039454c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "039454c2c6ca70c60baded0e22661564066d5654e893ec593a98a8e84b02971d"
    family = "Mirai"
    file_name = "riscv64"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:39"
  condition:
    hash.sha256(0, filesize) == "039454c2c6ca70c60baded0e22661564066d5654e893ec593a98a8e84b02971d"
}

rule MalwareBazaar_Mirai_032_b6ac689f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b6ac689fb11fa67b4cb32415b9b5cdd81b6234b2f4bb2c7672a048af96ea8e89"
    family = "Mirai"
    file_name = "adissarm5"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:36"
  condition:
    hash.sha256(0, filesize) == "b6ac689fb11fa67b4cb32415b9b5cdd81b6234b2f4bb2c7672a048af96ea8e89"
}

rule MalwareBazaar_unknown_033_407eab61
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "407eab618ddc11e847b0498e9284de15db19bfe89720089cb176790659e34386"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:34"
  condition:
    hash.sha256(0, filesize) == "407eab618ddc11e847b0498e9284de15db19bfe89720089cb176790659e34386"
}

rule MalwareBazaar_Mirai_034_7eb6bb0a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7eb6bb0a620a284423d2d1382605163063239ecb2c7630722c45d6fb692a0705"
    family = "Mirai"
    file_name = "disssh4"
    file_type = "elf"
    first_seen = "2026-10-11 01:17:31"
  condition:
    hash.sha256(0, filesize) == "7eb6bb0a620a284423d2d1382605163063239ecb2c7630722c45d6fb692a0705"
}

rule MalwareBazaar_Mirai_035_7b3577b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "7b3577b0310340ea3f44f62f9f20c313d199aad41a07c3b3ac28fdd460c8122e"
    family = "Mirai"
    file_name = "2"
    file_type = "elf"
    first_seen = "2026-10-11 01:09:39"
  condition:
    hash.sha256(0, filesize) == "7b3577b0310340ea3f44f62f9f20c313d199aad41a07c3b3ac28fdd460c8122e"
}

rule MalwareBazaar_Mirai_036_10c32c43
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "10c32c43ffe6a500840cc577c56b8107efb9c23c5a9c7c2cbf00a84894328ae6"
    family = "Mirai"
    file_name = "arm7"
    file_type = "elf"
    first_seen = "2026-10-11 01:05:40"
  condition:
    hash.sha256(0, filesize) == "10c32c43ffe6a500840cc577c56b8107efb9c23c5a9c7c2cbf00a84894328ae6"
}

rule MalwareBazaar_unknown_037_b3eef4ff
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b3eef4ff40ffa38977f41f2a016cd8b7bcf74d0ac564ae3508712c358798c799"
    family = "unknown"
    file_name = "aarch64"
    file_type = "elf"
    first_seen = "2026-10-11 01:05:38"
  condition:
    hash.sha256(0, filesize) == "b3eef4ff40ffa38977f41f2a016cd8b7bcf74d0ac564ae3508712c358798c799"
}

rule MalwareBazaar_unknown_038_2dccab5b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2dccab5b3b7a88abf6a2e2c7e592fbf54a017ce6e465ce6a722c2f5fc656b553"
    family = "unknown"
    file_name = "u.sh"
    file_type = "sh"
    first_seen = "2026-10-11 01:01:45"
  condition:
    hash.sha256(0, filesize) == "2dccab5b3b7a88abf6a2e2c7e592fbf54a017ce6e465ce6a722c2f5fc656b553"
}

rule MalwareBazaar_AMOS_039_e2605e9e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048"
    family = "AMOS"
    file_name = "macho_e2605e9e08fa.bin"
    file_type = "macho"
    first_seen = "2026-10-11 00:56:28"
  condition:
    hash.sha256(0, filesize) == "e2605e9e08fa9f7b1cc23497fec745f290a97a212cc7056c87459544325ac048"
}

rule MalwareBazaar_Mirai_040_97b2e9c2
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97b2e9c27879eb5aa3e89358a97aa88249b27bee91923bd81350111ba91c5802"
    family = "Mirai"
    file_name = "arm5"
    file_type = "elf"
    first_seen = "2026-10-11 00:45:50"
  condition:
    hash.sha256(0, filesize) == "97b2e9c27879eb5aa3e89358a97aa88249b27bee91923bd81350111ba91c5802"
}

rule MalwareBazaar_Mirai_041_a14b14a4
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a14b14a477fc8f329f659e0bfa92c5888b478f4f5b35f71480c21ec7439728bc"
    family = "Mirai"
    file_name = "dissx86"
    file_type = "elf"
    first_seen = "2026-10-11 00:41:48"
  condition:
    hash.sha256(0, filesize) == "a14b14a477fc8f329f659e0bfa92c5888b478f4f5b35f71480c21ec7439728bc"
}

rule MalwareBazaar_Mirai_042_3073ae4a
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3"
    family = "Mirai"
    file_name = "dissarch64"
    file_type = "elf"
    first_seen = "2026-10-11 00:25:43"
  condition:
    hash.sha256(0, filesize) == "3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3"
}

rule MalwareBazaar_Mirai_043_89e6acf6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "89e6acf66ae0277b0f46c15a63e86d44ffa0671c88ea35f1d2b85b9dbc4f30a2"
    family = "Mirai"
    file_name = "dissarm6"
    file_type = "elf"
    first_seen = "2026-10-11 00:21:45"
  condition:
    hash.sha256(0, filesize) == "89e6acf66ae0277b0f46c15a63e86d44ffa0671c88ea35f1d2b85b9dbc4f30a2"
}

rule MalwareBazaar_Mirai_044_3e403ed8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3e403ed81e6fb36d16cdaeeac1f2c97cd7bcbb38cab758fa802c4592e03d1314"
    family = "Mirai"
    file_name = "pid.ppc"
    file_type = "elf"
    first_seen = "2026-10-11 00:13:47"
  condition:
    hash.sha256(0, filesize) == "3e403ed81e6fb36d16cdaeeac1f2c97cd7bcbb38cab758fa802c4592e03d1314"
}

rule MalwareBazaar_Mirai_045_23116e83
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf"
    family = "Mirai"
    file_name = "pid.x86"
    file_type = "elf"
    first_seen = "2026-10-11 00:13:45"
  condition:
    hash.sha256(0, filesize) == "23116e8379bc88edd4de1e6bf83a09f92bf2fd2d645de18a5ef04c6c9a0441bf"
}

rule MalwareBazaar_Mirai_046_0f320044
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0f32004426163c3f3f93bbfd88193b22d570756d11b8d11d132e7b369444b6a0"
    family = "Mirai"
    file_name = "adb.arm7"
    file_type = "elf"
    first_seen = "2026-10-11 00:13:43"
  condition:
    hash.sha256(0, filesize) == "0f32004426163c3f3f93bbfd88193b22d570756d11b8d11d132e7b369444b6a0"
}

rule MalwareBazaar_Mirai_047_09f9c157
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0"
    family = "Mirai"
    file_name = "dissarm4"
    file_type = "elf"
    first_seen = "2026-10-11 00:09:38"
  condition:
    hash.sha256(0, filesize) == "09f9c15779c888660864160eed3892e172c3df47a6a5110b0ae708a9af178ac0"
}

rule MalwareBazaar_Mirai_048_15611a77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
    family = "Mirai"
    file_name = "mips64"
    file_type = "elf"
    first_seen = "2026-10-11 00:05:50"
  condition:
    hash.sha256(0, filesize) == "15611a7793060cb4f4ada63149aace40b3cdead90f41c9a7c35803e84bd413ef"
}

rule MalwareBazaar_Mirai_049_f1bdf69b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f1bdf69b0cc39004ac8dc4e1139391e97ae2c6c7333497e567181220af46cd89"
    family = "Mirai"
    file_name = "disspoor"
    file_type = "elf"
    first_seen = "2026-10-11 00:01:43"
  condition:
    hash.sha256(0, filesize) == "f1bdf69b0cc39004ac8dc4e1139391e97ae2c6c7333497e567181220af46cd89"
}

rule MalwareBazaar_Mirai_050_3df8dc1d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "3df8dc1d5e463c6653eb4405cd1cb722e0ed586d08b18f35782fc37693e84869"
    family = "Mirai"
    file_name = "pid.arm"
    file_type = "elf"
    first_seen = "2026-10-10 23:57:41"
  condition:
    hash.sha256(0, filesize) == "3df8dc1d5e463c6653eb4405cd1cb722e0ed586d08b18f35782fc37693e84869"
}

rule MalwareBazaar_Mirai_051_2be31561
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c"
    family = "Mirai"
    file_name = "2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 23:56:07"
  condition:
    hash.sha256(0, filesize) == "2be31561bd8f52525db38009dc5c6730e82441b907960e617bff97ded4fe602c"
}

rule MalwareBazaar_Mirai_052_a0a03d5f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e"
    family = "Mirai"
    file_name = "a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e.elf"
    file_type = "elf"
    first_seen = "2026-10-10 23:56:02"
  condition:
    hash.sha256(0, filesize) == "a0a03d5fb69f31799f722a1b6ea113b0a53bc4bb3fde026609d17a33c2898d0e"
}

rule MalwareBazaar_Prometei_053_d9c5e1e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb"
    family = "Prometei"
    file_name = "d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb"
    file_type = "elf"
    first_seen = "2026-10-10 23:54:13"
  condition:
    hash.sha256(0, filesize) == "d9c5e1e5042f02a7ae9b1ba5da1c500fbed835886b4feb4610f18e4f7970c9bb"
}

rule MalwareBazaar_Mirai_054_1f033b96
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f"
    family = "Mirai"
    file_name = "pid.m68k"
    file_type = "elf"
    first_seen = "2026-10-10 23:45:55"
  condition:
    hash.sha256(0, filesize) == "1f033b961e57f63b7dc2735bb21abebd94ebca07c2b2b08068f0faf8af18623f"
}

rule MalwareBazaar_Mirai_055_6203e04f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "6203e04f7b366394835a952bc61ee7214c2c84f2f8a7567dbe2615b8e9c1add9"
    family = "Mirai"
    file_name = "pid.x86_64"
    file_type = "elf"
    first_seen = "2026-10-10 23:45:52"
  condition:
    hash.sha256(0, filesize) == "6203e04f7b366394835a952bc61ee7214c2c84f2f8a7567dbe2615b8e9c1add9"
}

rule MalwareBazaar_AMOS_056_8d4fc1e1
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b"
    family = "AMOS"
    file_name = "macho_8d4fc1e17977.bin"
    file_type = "macho"
    first_seen = "2026-10-10 23:42:33"
  condition:
    hash.sha256(0, filesize) == "8d4fc1e1797743dec4c00583dfe989820eb3c2785cf414feaaf440e54719bd6b"
}

rule MalwareBazaar_Mirai_057_18a9a8e5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "18a9a8e5b1b454fce79a86921febf23f5833364b39c7e7e678c4390d2caad61b"
    family = "Mirai"
    file_name = "pid.ppc64"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:56"
  condition:
    hash.sha256(0, filesize) == "18a9a8e5b1b454fce79a86921febf23f5833364b39c7e7e678c4390d2caad61b"
}

rule MalwareBazaar_Mirai_058_2e3c04e6
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2e3c04e63d5d722ecca125da3f3da4b042c79e88af3a2e7686febf40aa0b364d"
    family = "Mirai"
    file_name = "pid.arm6"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:54"
  condition:
    hash.sha256(0, filesize) == "2e3c04e63d5d722ecca125da3f3da4b042c79e88af3a2e7686febf40aa0b364d"
}

rule MalwareBazaar_Mirai_059_878bc1be
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "878bc1be2448fc80aa15ab8373e60567a0f76aa205a412f25b1b5c7be914a228"
    family = "Mirai"
    file_name = "mipsel"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:51"
  condition:
    hash.sha256(0, filesize) == "878bc1be2448fc80aa15ab8373e60567a0f76aa205a412f25b1b5c7be914a228"
}

rule MalwareBazaar_Mirai_060_2048f052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
    family = "Mirai"
    file_name = "s390x"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:49"
  condition:
    hash.sha256(0, filesize) == "2048f05290563172de52dd6b0123339d6de47392536f9b8643e88463780b9b6c"
}

rule MalwareBazaar_Mirai_061_8f700d2e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2"
    family = "Mirai"
    file_name = "arm8"
    file_type = "elf"
    first_seen = "2026-10-10 23:41:47"
  condition:
    hash.sha256(0, filesize) == "8f700d2eeb4574e5aec68dcbf8c396df582723e1cd57ac16c8c32b1570b19da2"
}

rule MalwareBazaar_Mirai_062_516fc82c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "516fc82c9bbab5637162194fa2bfc2f8edfa14ee174a94bb900e87c67c5d5d05"
    family = "Mirai"
    file_name = "riscv32"
    file_type = "elf"
    first_seen = "2026-10-10 23:37:51"
  condition:
    hash.sha256(0, filesize) == "516fc82c9bbab5637162194fa2bfc2f8edfa14ee174a94bb900e87c67c5d5d05"
}

rule MalwareBazaar_Mirai_063_191583f0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "191583f0ade7741dcef9abc0d0c19ca0ef6877d65056451cb237f01b27902cf5"
    family = "Mirai"
    file_name = "android-arm"
    file_type = "elf"
    first_seen = "2026-10-10 23:37:49"
  condition:
    hash.sha256(0, filesize) == "191583f0ade7741dcef9abc0d0c19ca0ef6877d65056451cb237f01b27902cf5"
}

rule MalwareBazaar_Mirai_064_d674e3bb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "d674e3bba48c3f07da03f2f16acecaaf07299922f17ac3c50ed4708bc7c99260"
    family = "Mirai"
    file_name = "x86_64"
    file_type = "elf"
    first_seen = "2026-10-10 23:36:20"
  condition:
    hash.sha256(0, filesize) == "d674e3bba48c3f07da03f2f16acecaaf07299922f17ac3c50ed4708bc7c99260"
}

rule MalwareBazaar_Mirai_065_402810b8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "402810b8c09743686d5c3eb9ea49bb2a4d0a0d5c42c46e5ac407059ef236615b"
    family = "Mirai"
    file_name = "dissmpsl"
    file_type = "elf"
    first_seen = "2026-10-10 23:17:26"
  condition:
    hash.sha256(0, filesize) == "402810b8c09743686d5c3eb9ea49bb2a4d0a0d5c42c46e5ac407059ef236615b"
}

rule MalwareBazaar_Formbook_066_97cb2ecc
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "97cb2ecc246e032dc1841bd848dfeaa3823a4671fb81199f78fa9aeba9091185"
    family = "Formbook"
    file_name = "s3.exe"
    file_type = "exe"
    first_seen = "2026-10-10 22:40:45"
  condition:
    hash.sha256(0, filesize) == "97cb2ecc246e032dc1841bd848dfeaa3823a4671fb81199f78fa9aeba9091185"
}

rule MalwareBazaar_Mirai_067_2602c8eb
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2602c8ebac36cb9fb34f2c7db7ebad82fdd8fc55ef804399edb5c13a43d19937"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 22:30:26"
  condition:
    hash.sha256(0, filesize) == "2602c8ebac36cb9fb34f2c7db7ebad82fdd8fc55ef804399edb5c13a43d19937"
}

rule MalwareBazaar_Mirai_068_511e4897
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "511e48979f24ea79abf1650411ce0ad2dc4830b53fc009dacdc966ac75f81639"
    family = "Mirai"
    file_name = "mips"
    file_type = "elf"
    first_seen = "2026-10-10 22:30:00"
  condition:
    hash.sha256(0, filesize) == "511e48979f24ea79abf1650411ce0ad2dc4830b53fc009dacdc966ac75f81639"
}

rule MalwareBazaar_Mirai_069_980abf36
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "980abf36f7a59fb995746514840071af6463897f17de422d41c248de0dc03dda"
    family = "Mirai"
    file_name = "x86"
    file_type = "elf"
    first_seen = "2026-10-10 22:16:34"
  condition:
    hash.sha256(0, filesize) == "980abf36f7a59fb995746514840071af6463897f17de422d41c248de0dc03dda"
}

rule MalwareBazaar_Mirai_070_9d9291d7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9d9291d7e83f348872d24cbc60a7d6ef1cdbdd8f8dd214b5624c43a9cfd51aad"
    family = "Mirai"
    file_name = "mbupload-orkiv9k0.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:33"
  condition:
    hash.sha256(0, filesize) == "9d9291d7e83f348872d24cbc60a7d6ef1cdbdd8f8dd214b5624c43a9cfd51aad"
}

rule MalwareBazaar_Mirai_071_9ea1f8e8
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "9ea1f8e83c99a88df3c938529d76d343cca7fbb37c3948f1560a2b39da2bd4ab"
    family = "Mirai"
    file_name = "mbupload-m20wvapr.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:18"
  condition:
    hash.sha256(0, filesize) == "9ea1f8e83c99a88df3c938529d76d343cca7fbb37c3948f1560a2b39da2bd4ab"
}

rule MalwareBazaar_Mirai_072_de6a0b3f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "de6a0b3f76eda0589d0bcd6f4308f1ba5287acd153b74d2c06af1899dabc0252"
    family = "Mirai"
    file_name = "mbupload-h77j8s8j.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:12"
  condition:
    hash.sha256(0, filesize) == "de6a0b3f76eda0589d0bcd6f4308f1ba5287acd153b74d2c06af1899dabc0252"
}

rule MalwareBazaar_Mirai_073_729238ba
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "729238bab5e3bb8ada801a6389cf2ebcbf1d6313d772ac20f998771248f9556f"
    family = "Mirai"
    file_name = "mbupload-orkiv9k0.bin"
    file_type = "elf"
    first_seen = "2026-10-10 22:01:06"
  condition:
    hash.sha256(0, filesize) == "729238bab5e3bb8ada801a6389cf2ebcbf1d6313d772ac20f998771248f9556f"
}

rule MalwareBazaar_Mirai_074_f4e87418
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c"
    family = "Mirai"
    file_name = "f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:54:27"
  condition:
    hash.sha256(0, filesize) == "f4e87418b810b69cf43ef33d876c7b119718f15a3cbc8562e344c32a74e2c26c"
}

rule MalwareBazaar_Mirai_075_0c0dd052
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
    family = "Mirai"
    file_name = "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:54:19"
  condition:
    hash.sha256(0, filesize) == "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
}

rule MalwareBazaar_Mirai_076_cbdb650d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c"
    family = "Mirai"
    file_name = "cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:49"
  condition:
    hash.sha256(0, filesize) == "cbdb650d0d991d2102d4bbe24130c63130908c0e50ee381c4c9ca495d4cdf08c"
}

rule MalwareBazaar_Mirai_077_cb4c28fd
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a"
    family = "Mirai"
    file_name = "cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:44"
  condition:
    hash.sha256(0, filesize) == "cb4c28fdc8a1bc5671a48cd81c5aac5438d64001ca1ad2a2ef6b133d3c79493a"
}

rule MalwareBazaar_Mirai_078_972a8e1e
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787"
    family = "Mirai"
    file_name = "972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:39"
  condition:
    hash.sha256(0, filesize) == "972a8e1eb9cfa81b96888ba74120917eed6a2d9c9b77c4de8105026e4fc04787"
}

rule MalwareBazaar_Mirai_079_bafa2a82
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49"
    family = "Mirai"
    file_name = "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:34"
  condition:
    hash.sha256(0, filesize) == "bafa2a82ec1bf371ef0c28e94730091c43302f50492a72fcc429403ba0889f49"
}

rule MalwareBazaar_Mirai_080_e8198200
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa"
    family = "Mirai"
    file_name = "e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:29"
  condition:
    hash.sha256(0, filesize) == "e81982006eb1a6643b10b103c8e94b5ee63d6ef293cc21d53a2b3ba9a93ba0fa"
}

rule MalwareBazaar_Mirai_081_ee08d744
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f"
    family = "Mirai"
    file_name = "ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f.elf"
    file_type = "elf"
    first_seen = "2026-10-10 21:53:24"
  condition:
    hash.sha256(0, filesize) == "ee08d74477ee187ac5694e07f6deace4f1cec4b8955468df9cc9059ee20bc63f"
}

rule MalwareBazaar_Mirai_082_db52c936
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "db52c9367e0684debd435a6939d515ee7ed6becbe56fb777fd5ac36c7e9664a1"
    family = "Mirai"
    file_name = "arm"
    file_type = "elf"
    first_seen = "2026-10-10 21:40:13"
  condition:
    hash.sha256(0, filesize) == "db52c9367e0684debd435a6939d515ee7ed6becbe56fb777fd5ac36c7e9664a1"
}

rule MalwareBazaar_Mirai_083_aadec95f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aadec95fd8ed7ec15137b42cb3a28cc2f071ec499fd4dc9e4aa274c489e656c8"
    family = "Mirai"
    file_name = "arm6"
    file_type = "elf"
    first_seen = "2026-10-10 21:31:16"
  condition:
    hash.sha256(0, filesize) == "aadec95fd8ed7ec15137b42cb3a28cc2f071ec499fd4dc9e4aa274c489e656c8"
}

rule MalwareBazaar_unknown_084_5898cab9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5898cab97f4e82f4b3fc1ded1f26c7c3451ab137dcffffeaa68e6360558ad607"
    family = "unknown"
    file_name = "update.ps1"
    file_type = "ps1"
    first_seen = "2026-10-10 20:56:27"
  condition:
    hash.sha256(0, filesize) == "5898cab97f4e82f4b3fc1ded1f26c7c3451ab137dcffffeaa68e6360558ad607"
}

rule MalwareBazaar_Mirai_085_b5647c0f
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b5647c0fd1277af2013a25e1f741c742edb64ddd33fcec597855798001bbc02d"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnsh2xnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:53:10"
  condition:
    hash.sha256(0, filesize) == "b5647c0fd1277af2013a25e1f741c742edb64ddd33fcec597855798001bbc02d"
}

rule MalwareBazaar_unknown_086_994becb3
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "994becb3008d8dacd064bf699bd2acb55b59e213143451f67b808edc261c4511"
    family = "unknown"
    file_name = "HARMAN_TRANSPORT_USA_SETUP.cmd"
    file_type = "cmd"
    first_seen = "2026-10-10 20:49:02"
  condition:
    hash.sha256(0, filesize) == "994becb3008d8dacd064bf699bd2acb55b59e213143451f67b808edc261c4511"
}

rule MalwareBazaar_unknown_087_b59d9c91
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "b59d9c911f11ddbe5ac0cd7e2e6e311093a44ac31453b5cab801c31f6a170750"
    family = "unknown"
    file_name = "Putty-x86_64.msi"
    file_type = "msi"
    first_seen = "2026-10-10 20:25:11"
  condition:
    hash.sha256(0, filesize) == "b59d9c911f11ddbe5ac0cd7e2e6e311093a44ac31453b5cab801c31f6a170750"
}

rule MalwareBazaar_unknown_088_5f8e4e77
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "5f8e4e776f1c5c38570718c50c67c66629648b0b265629acf144dc978e7f7b6a"
    family = "unknown"
    file_name = "vnKMZWYyX.zip"
    file_type = "zip"
    first_seen = "2026-10-10 20:16:42"
  condition:
    hash.sha256(0, filesize) == "5f8e4e776f1c5c38570718c50c67c66629648b0b265629acf144dc978e7f7b6a"
}

rule MalwareBazaar_Mirai_089_aef53382
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "aef5338244d62e701ae13b668e784dd5029b949bcc2bdd6fc27beafbf58009f1"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmicroblazexnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:13:08"
  condition:
    hash.sha256(0, filesize) == "aef5338244d62e701ae13b668e784dd5029b949bcc2bdd6fc27beafbf58009f1"
}

rule MalwareBazaar_unknown_090_1b2432c9
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71"
    family = "unknown"
    file_name = "PLCleaner.exe"
    file_type = "exe"
    first_seen = "2026-10-10 20:05:58"
  condition:
    hash.sha256(0, filesize) == "1b2432c99b877ac71a37d505ca7165f8d46cb4fc9a98762d54c529c7aef26d71"
}

rule MalwareBazaar_Mirai_091_51c51da7
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "51c51da7a6c6e3f26caf4508389ce7da0b23ac35a7f4a163394f778b33c7c341"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnriscv32xnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:04:07"
  condition:
    hash.sha256(0, filesize) == "51c51da7a6c6e3f26caf4508389ce7da0b23ac35a7f4a163394f778b33c7c341"
}

rule MalwareBazaar_unknown_092_2fb29f7b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2fb29f7b8d2c02d956f1e1e1fc7eb26789130b80ae1ec06f9b04cc5bc56f06f2"
    family = "unknown"
    file_name = "Verginia.cmd"
    file_type = "cmd"
    first_seen = "2026-10-10 20:02:23"
  condition:
    hash.sha256(0, filesize) == "2fb29f7b8d2c02d956f1e1e1fc7eb26789130b80ae1ec06f9b04cc5bc56f06f2"
}

rule MalwareBazaar_Mirai_093_0866f7b0
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "0866f7b0c7ec400279e908add084bab581faf3dd831a468430dcfc03b23e9399"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 20:00:37"
  condition:
    hash.sha256(0, filesize) == "0866f7b0c7ec400279e908add084bab581faf3dd831a468430dcfc03b23e9399"
}

rule MalwareBazaar_Mirai_094_210ba30c
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "210ba30c11352f4e5b2c2d533b92de16b606a17dfb53ef98888554f29773c3af"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnmipsxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:59:26"
  condition:
    hash.sha256(0, filesize) == "210ba30c11352f4e5b2c2d533b92de16b606a17dfb53ef98888554f29773c3af"
}

rule MalwareBazaar_Mirai_095_2858601d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "2858601dd1f5c353ddebab879bec97d8d6e6d8c7199866127f301bc2d8d9e2e5"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:50:28"
  condition:
    hash.sha256(0, filesize) == "2858601dd1f5c353ddebab879bec97d8d6e6d8c7199866127f301bc2d8d9e2e5"
}

rule MalwareBazaar_Mirai_096_4c2c641b
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "4c2c641b63e1485831e217b554a984a0a75c6f433fcb5edf3c94fa7a04a37519"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnpowerpcxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:49:36"
  condition:
    hash.sha256(0, filesize) == "4c2c641b63e1485831e217b554a984a0a75c6f433fcb5edf3c94fa7a04a37519"
}

rule MalwareBazaar_Mirai_097_a3ee0e8d
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "a3ee0e8d50872381618ffc45e809ac950d5005fd5e2e5e2e1c2d87e52d3ec5e1"
    family = "Mirai"
    file_name = "xnxnxnxnxnxnxnxnm68kxnxn"
    file_type = "elf"
    first_seen = "2026-10-10 19:49:34"
  condition:
    hash.sha256(0, filesize) == "a3ee0e8d50872381618ffc45e809ac950d5005fd5e2e5e2e1c2d87e52d3ec5e1"
}

rule MalwareBazaar_unknown_098_458195a5
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "458195a5ae155997cda578ceb12959b271027e6e23e87b5033d777ff09c44ce3"
    family = "unknown"
    file_name = "armv7l"
    file_type = "elf"
    first_seen = "2026-10-10 19:49:32"
  condition:
    hash.sha256(0, filesize) == "458195a5ae155997cda578ceb12959b271027e6e23e87b5033d777ff09c44ce3"
}

rule MalwareBazaar_unknown_099_580f3784
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "580f37844785d2f631a22026d8bc8b1ff903b2b8a5fe1800dc0d431923112afc"
    family = "unknown"
    file_name = "payload.bat"
    file_type = "bat"
    first_seen = "2026-10-10 19:46:17"
  condition:
    hash.sha256(0, filesize) == "580f37844785d2f631a22026d8bc8b1ff903b2b8a5fe1800dc0d431923112afc"
}

rule MalwareBazaar_Mirai_100_679c5069
{
  meta:
    source = "MalwareBazaar"
    analysis = "metadata-only exact hash IOC; sample not executed"
    sha256 = "679c506907266a9c45436c9eca86359e07b1626a933c927f0bb9a5cd429692e6"
    family = "Mirai"
    file_name = "m68k"
    file_type = "elf"
    first_seen = "2026-10-10 19:39:27"
  condition:
    hash.sha256(0, filesize) == "679c506907266a9c45436c9eca86359e07b1626a933c927f0bb9a5cd429692e6"
}
```

## Limitations

- Metadata cannot prove runtime behavior, capabilities, persistence, or C2 logic.
- `unknown` family labels mean MalwareBazaar did not provide a signature for that sample.
- Hash YARA rules match only exact known samples.
- Source-like samples should be analyzed with `analyze-source` for real static code findings.
